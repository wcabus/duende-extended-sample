using Duende.IdentityServer.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using GotSharp.IdSrv.Host.Internal;

namespace GotSharp.IdSrv.Host.Services;

public class SignInManager<TUser> : Microsoft.AspNetCore.Identity.SignInManager<TUser> where TUser : class
{
    public SignInManager(
        UserManager<TUser> userManager,
        IHttpContextAccessor contextAccessor,
        IUserClaimsPrincipalFactory<TUser> claimsFactory,
        IOptions<IdentityOptions> optionsAccessor,
        ILogger<SignInManager<TUser>> logger,
        IAuthenticationSchemeProvider schemes,
        IUserConfirmation<TUser> confirmation
    ) : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
    {

    }

    private async Task<bool> IsTfaEnabled(TUser user, AuthorizationRequest request = null)
    {
        if (!UserManager.SupportsUserTwoFactor)
        {
            return false;
        }

        var clientTwoFactorRequired = (request?.Client?.IsMultiFactorRequired() == true);

        return (clientTwoFactorRequired || await UserManager.GetTwoFactorEnabledAsync(user)) &&
               (await UserManager.GetValidTwoFactorProvidersAsync(user)).Count > 0;
    }

    public async Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure, AuthorizationRequest request = null)
    {
        var user = await UserManager.FindByNameAsync(userName);
        if (user == null)
        {
            return SignInResult.Failed;
        }

        return await PasswordSignInAsync(user, password, isPersistent, lockoutOnFailure, request);
    }

    public async Task<SignInResult> PasswordSignInAsync(TUser user, string password, bool isPersistent, bool lockoutOnFailure, AuthorizationRequest request = null)
    {
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        var attempt = await CheckPasswordSignInAsync(user, password, lockoutOnFailure);

        var bypassTwoFactor = false;
        if (request != null)
        {
            bypassTwoFactor = request.Client.BypassMultiFactor();
        }

        return attempt.Succeeded
            ? await SignInOrTwoFactorAsync(user, isPersistent, bypassTwoFactor: bypassTwoFactor, request: request)
            : attempt;
    }

    protected async Task<SignInResult> SignInOrTwoFactorAsync(TUser user, bool isPersistent, string loginProvider = null, bool bypassTwoFactor = false, AuthorizationRequest request = null)
    {
        if (!bypassTwoFactor && await IsTfaEnabled(user, request))
        {
            if (!await IsTwoFactorClientRememberedAsync(user))
            {
                // Store the userId for use after two factor check
                var userId = await UserManager.GetUserIdAsync(user);
                await Context.SignInAsync(IdentityConstants.TwoFactorUserIdScheme, StoreTwoFactorInfo(userId, loginProvider));
                return SignInResult.TwoFactorRequired;
            }
        }
        // Cleanup external cookie
        if (loginProvider != null)
        {
            await Context.SignOutAsync(IdentityConstants.ExternalScheme);
        }
        if (loginProvider == null)
        {
            await SignInWithClaimsAsync(user, isPersistent, new[] { new Claim("amr", "pwd") });
        }
        else
        {
            await SignInAsync(user, isPersistent, loginProvider);
        }
        return SignInResult.Success;
    }

    /// <summary>
    /// Creates a claims principal for the specified 2fa information.
    /// </summary>
    /// <param name="userId">The user whose is logging in via 2fa.</param>
    /// <param name="loginProvider">The 2fa provider.</param>
    /// <returns>A <see cref="ClaimsPrincipal"/> containing the user 2fa information.</returns>
    internal ClaimsPrincipal StoreTwoFactorInfo(string userId, string loginProvider)
    {
        var identity = new ClaimsIdentity(IdentityConstants.TwoFactorUserIdScheme);
        identity.AddClaim(new Claim(System.Security.Claims.ClaimTypes.Name, userId));
        if (loginProvider != null)
        {
            identity.AddClaim(new Claim(System.Security.Claims.ClaimTypes.AuthenticationMethod, loginProvider));
        }
        return new ClaimsPrincipal(identity);
    }
}