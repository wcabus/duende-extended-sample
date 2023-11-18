// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using System.Security.Claims;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Services;
using GotSharp.IdSrv.Host.Configuration;
using IdentityExpress.Identity;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace GotSharp.IdSrv.Host.Controllers.Account
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class ExternalController : Controller
    {
        private readonly UserManager<IdentityExpressUser> _userManager;
        private readonly SignInManager<IdentityExpressUser> _signInManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IEventService _events;
        private readonly ILogger<ExternalController> _logger;

        public ExternalController(
            UserManager<IdentityExpressUser> userManager,
            SignInManager<IdentityExpressUser> signInManager,
            IIdentityServerInteractionService interaction,
            IEventService events,
            ILogger<ExternalController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _interaction = interaction;
            _events = events;
            _logger = logger;
        }

        /// <summary>
        /// initiate roundtrip to external authentication provider
        /// </summary>
        [HttpGet]
        [Route("~/challenge")]
        [NoCache]
        public IActionResult Challenge(string scheme, string returnUrl, string loginHint = null, string prompt = null, string upn = null)
        {
            if (string.IsNullOrEmpty(returnUrl)) returnUrl = "~/";

            // validate returnUrl - either it is a valid OIDC URL or back to a local page
            if (Url.IsLocalUrl(returnUrl) == false && _interaction.IsValidReturnUrl(returnUrl) == false)
            {
                // user might have clicked on a malicious link - should be logged
                throw new Exception("invalid return URL");
            }
            
            // start challenge and roundtrip the return URL and scheme 
            var props = new AuthenticationProperties
            {
                RedirectUri = Url.Action(nameof(Callback)), 
                Items =
                {
                    { "returnUrl", returnUrl }, 
                    { "scheme", scheme }
                }
            };

            if (!string.IsNullOrEmpty(loginHint))
            {
                props.SetParameter("login_hint", loginHint);
            }

            if (!string.IsNullOrEmpty(prompt))
            {
                props.SetParameter("prompt", prompt);
            }

            if (!string.IsNullOrEmpty(upn))
            {
                props.SetParameter("upn", upn);
            }

            return Challenge(props, scheme);
        }

        /// <summary>
        /// Post processing of external authentication
        /// </summary>
        [HttpGet]
        [Route("~/challenge-callback")]
        [NoCache]
        public async Task<IActionResult> Callback()
        {
            // read external identity from the temporary cookie
            var result = await HttpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
            if (result?.Succeeded != true)
            {
                throw new Exception("External authentication error");
            }

            if (_logger.IsEnabled(LogLevel.Debug))
            {
                var externalClaims = result.Principal.Claims.Select(c => $"{c.Type}: {c.Value}");
                _logger.LogDebug("External claims: {@claims}", externalClaims);
            }

            // lookup our user and external provider info
            var (user, provider, providerUserId, claims) = await FindUserFromExternalProviderAsync(result);
            if (user == null)
            {
                // this might be where you might initiate a custom workflow for user registration
                // in this sample we don't show how that would be done, as our sample implementation
                // simply auto-provisions new external user
                user = await AutoProvisionUserAsync(provider, providerUserId, claims);
            }
            else
            {
                user = await UpdateUsernameAndEmail(user, provider, claims);
            }

            // this allows us to collect any additional claims or properties
            // for the specific protocols used and store them in the local auth cookie.
            // this is typically used to store data needed for signout from those protocols.
            var additionalLocalClaims = new List<Claim>();
            var localSignInProps = new AuthenticationProperties();
            ProcessLoginCallback(result, additionalLocalClaims, localSignInProps);
            
            // issue authentication cookie for user
            // we must issue the cookie manually, and can't use the SignInManager because
            // it doesn't expose an API to issue additional claims from the login workflow
            var principal = await _signInManager.CreateUserPrincipalAsync(user);
            additionalLocalClaims.AddRange(principal.Claims);
            var name = principal.FindFirst(JwtClaimTypes.Name)?.Value ?? user.Id;
            
            var isuser = new IdentityServerUser(user.Id)
            {
                DisplayName = name,
                IdentityProvider = provider,
                AdditionalClaims = additionalLocalClaims
            };

            await HttpContext.SignInAsync(isuser, localSignInProps);

            // delete temporary cookie used during external authentication
            await HttpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

            // retrieve return URL
            var returnUrl = result.Properties.Items["returnUrl"] ?? "~/";

            // check if external login is in the context of an OIDC request
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            await _events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, user.Id, name, true, context?.Client.ClientId));

            if (context != null)
            {
                if (context.IsNativeClient())
                {
                    // The client is native, so this change in how to
                    // return the response is for better UX for the end user.
                    return this.LoadingPage("Redirect", returnUrl);
                }
            }

            return Redirect(returnUrl);
        }

        private async Task<(IdentityExpressUser user, string provider, string providerUserId, IEnumerable<Claim> claims)> FindUserFromExternalProviderAsync(AuthenticateResult result)
        {
            var externalUser = result.Principal;

            // try to determine the unique id of the external user (issued by the provider)
            // the most common claim type for that are the sub claim and the NameIdentifier
            // depending on the external provider, some other claim type might be used
            var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                              externalUser.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier) ??
                              throw new Exception("Unknown userid");

            // remove the user id claim so we don't include it as an extra claim if/when we provision the user
            var claims = externalUser.Claims.ToList();
            claims.Remove(userIdClaim);

            var provider = result.Properties.Items["scheme"];
            var providerUserId = userIdClaim.Value;

            // find external user
            var user = await _userManager.FindByLoginAsync(provider, providerUserId);

            return (user, provider, providerUserId, claims);
        }

        private async Task<IdentityExpressUser> AutoProvisionUserAsync(string provider, string providerUserId, IEnumerable<Claim> claims)
        {
            // create a list of claims that we want to transfer into our store
            var filtered = new List<Claim>();

            // user ID
            var sub = Guid.NewGuid().ToString();

            // user's display name
            var name = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Name)?.Value ??
                claims.FirstOrDefault(x => x.Type == System.Security.Claims.ClaimTypes.Name)?.Value;
            if (name != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Name, name));
            }
            else
            {
                var first = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName)?.Value ??
                    claims.FirstOrDefault(x => x.Type == System.Security.Claims.ClaimTypes.GivenName)?.Value;
                var last = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName)?.Value ??
                    claims.FirstOrDefault(x => x.Type == System.Security.Claims.ClaimTypes.Surname)?.Value;
                if (first != null && last != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, first + " " + last));
                }
                else if (first != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, first));
                }
                else if (last != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, last));
                }
            }

            // email
            var email = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email)?.Value ??
               claims.FirstOrDefault(x => x.Type == System.Security.Claims.ClaimTypes.Email)?.Value;
            
            // When logging in using Azure AD, if no email claim is present: use the UPN claim value.
            if (string.IsNullOrEmpty(email) && string.Equals(provider, AuthProviders.AzureAD, StringComparison.OrdinalIgnoreCase))
            {
                email = claims.FirstOrDefault(x => x.Type == System.Security.Claims.ClaimTypes.Upn)?.Value;
            }

            if (email != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Email, email));
            }

            var username = email;
            switch (provider)
            {
                case AuthProviders.AzureAD:
                    // When logging in using Azure AD, use the UPN claim value for username.
                    username = claims.FirstOrDefault(x => x.Type == System.Security.Claims.ClaimTypes.Upn)?.Value ?? email;
                    break;

                default:
                    // Else, attempt to use the preferred_username claim
                    username = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.PreferredUserName)?.Value ?? email;
                    break;
            }

            // In case email is now (still) null or empty, but we have a username, then use username for the email address.
            // Normally we wouldn't end up in this case however.
            if (string.IsNullOrEmpty(email))
            {
                email = username;
            }

            var user = new IdentityExpressUser
            {
                Id = sub,
                UserName = username,
                Email = email,
                EmailConfirmed = true,
                FirstName = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName)?.Value ?? claims.FirstOrDefault(x =>x.Type == System.Security.Claims.ClaimTypes.GivenName)?.Value,
                LastName = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName)?.Value ?? claims.FirstOrDefault(x => x.Type == System.Security.Claims.ClaimTypes.Surname)?.Value
            };
            var identityResult = await _userManager.CreateAsync(user);
            if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);

            if (filtered.Any())
            {
                identityResult = await _userManager.AddClaimsAsync(user, filtered);
                if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);
            }

            identityResult = await _userManager.AddLoginAsync(user, new UserLoginInfo(provider, providerUserId, provider));
            if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);

            return user;
        }

        // if the external login is OIDC-based, there are certain things we need to preserve to make logout work
        // this will be different for WS-Fed, SAML2p or other protocols
        private void ProcessLoginCallback(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
            // if the external system sent a session id claim, copy it over
            // so we can use it for single sign-out
            var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
            if (sid != null)
            {
                localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
            }

            // if the external provider issued an id_token, we'll keep it for signout
            var idToken = externalResult.Properties.GetTokenValue("id_token");
            if (idToken != null)
            {
                localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = idToken } });
            }
        }

        private async Task<IdentityExpressUser> UpdateUsernameAndEmail(IdentityExpressUser user, string provider, IEnumerable<Claim> claims)
        {
            user = await _userManager.FindByIdAsync(user.Id); // loads claims as well

            var upnClaim = claims.FirstOrDefault(x => x.Type == System.Security.Claims.ClaimTypes.Upn)?.Value;

            Claim emailClaim = null;
            var email = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email)?.Value ??
               claims.FirstOrDefault(x => x.Type == System.Security.Claims.ClaimTypes.Email)?.Value;

            // When logging in using Azure AD, if no email claim is present: use the UPN claim value.
            if (string.IsNullOrEmpty(email) && string.Equals(provider, AuthProviders.AzureAD, StringComparison.OrdinalIgnoreCase))
            {
                email = claims.FirstOrDefault(x => x.Type == System.Security.Claims.ClaimTypes.Upn)?.Value;
            }

            if (email != null)
            {
                emailClaim = new Claim(JwtClaimTypes.Email, email);
            }

            if (!string.Equals(user.Email, email, StringComparison.OrdinalIgnoreCase))
            {
                var oldEmail = user.Email;
                user.Email = email;
                if (user.Claims.Any(x => x.ClaimType == JwtClaimTypes.Email) && emailClaim != null)
                {
                    await _userManager.ReplaceClaimAsync(user, new Claim(JwtClaimTypes.Email, oldEmail), emailClaim);
                    emailClaim = null;
                }
            }

            if (!string.IsNullOrWhiteSpace(upnClaim) &&
                !string.Equals(user.NormalizedUserName, upnClaim, StringComparison.OrdinalIgnoreCase))
            {
                user.UserName = upnClaim;
                user.NormalizedUserName = upnClaim.ToUpperInvariant();
            }

            var identityResult = await _userManager.UpdateAsync(user);
            if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);

            if (emailClaim != null)
            {
                if (user.Claims.Any(x => x.ClaimType == emailClaim.Type))
                {
                    var oldClaim = user.Claims.FirstOrDefault(x => x.ClaimType == emailClaim.Type && x.ClaimValue != emailClaim.Value);
                    if (oldClaim != null)
                    {
                        identityResult = await _userManager.ReplaceClaimAsync(user, oldClaim.ToClaim(), emailClaim);
                    }
                    else
                    {
                        // there is an email claim but only with the up-to-date value
                        identityResult = IdentityResult.Success;
                    }
                }
                else
                {
                    identityResult = await _userManager.AddClaimAsync(user, emailClaim);
                }
                
                if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);
            }

            return user;
        }
    }
}