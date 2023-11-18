// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using IdentityExpress.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Options;
using GotSharp.IdSrv.Host.Configuration;
using GotSharp.IdSrv.Host.Services;
using GotSharp.IdSrv.Host.Events;
using GotSharp.IdSrv.Host.Internal;
using GotSharp.IdSrv.Host.Recaptcha;

namespace GotSharp.IdSrv.Host.Controllers.Account
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly Services.UserManager<IdentityExpressUser> _userManager;
        private readonly Services.SignInManager<IdentityExpressUser> _signInManager;
        private readonly ForgotPasswordService _forgotPasswordService;
        private readonly UserActivationService _userActivationService;
        private readonly EmailSender _emailSender;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;
        private readonly IStringLocalizer<AccountController> _localizer;
        private readonly GoogleRecaptchaService _recaptchaService;
        private readonly HomeRealmDiscoveryService _homeRealmDiscoveryService;
        private readonly ILogger<AccountController> _logger;
        private readonly GeneralOptions _generalOptions;

        private const string LoginEmailKey = "login-email";

        public AccountController(
            Services.UserManager<IdentityExpressUser> userManager, 
            Services.SignInManager<IdentityExpressUser> signInManager,
            ForgotPasswordService forgotPasswordService,
            UserActivationService userActivationService,
            EmailSender emailSender,
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            IStringLocalizer<AccountController> localizer,
            GoogleRecaptchaService recaptchaService,
            HomeRealmDiscoveryService homeRealmDiscoveryService,
            IOptionsSnapshot<GeneralOptions> generalOptionsAccessor,
            ILogger<AccountController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _forgotPasswordService = forgotPasswordService;
            _userActivationService = userActivationService;
            _emailSender = emailSender;
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
            _localizer = localizer;
            _recaptchaService = recaptchaService;
            _homeRealmDiscoveryService = homeRealmDiscoveryService;
            _logger = logger;
            _generalOptions = generalOptionsAccessor.Value;
        }

        [HttpGet]
        [Route("~/login")]
        [Route("~/account/login")]
        [NoCache]
        public IActionResult LoginRedirects(string returnUrl)
        {
            return RedirectToAction(nameof(Login), new { returnUrl });
        }

        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpGet]
        [Route("~/login/identifier")]
        [NoCache]
        public async Task<IActionResult> Login(string returnUrl)
        {
            var sessionUsername = HttpContext.Session.GetString(LoginEmailKey);

            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(returnUrl, sessionUsername, false);

            if (vm.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                string prompt = null, upn = null;
                if (Request.Query.ContainsKey("prompt"))
                {
                    prompt = Request.Query["prompt"];
                }
                if (Request.Query.ContainsKey("upn"))
                {
                    upn = Request.Query["upn"];
                }

                return RedirectToAction("Challenge", "External", new { scheme = vm.ExternalLoginScheme, returnUrl, prompt, upn });
            }

            return View(vm);
        }

        /// <summary>
        /// Handle postback for home realm discovery
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Route("~/login/identifier")]
        [NoCache]
        public async Task<IActionResult> Login(LoginUsernameInputModel model, string action)
        {
            // check if we are in the context of an authorization request
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            // the user clicked the "cancel" button
            if (!string.Equals(action, "continue", StringComparison.Ordinal))
            {
                return await CancelLogin(model.ReturnUrl, context);
            }

            if (ModelState.IsValid)
            {
                return await DiscoverHomeRealm(model);
            }

            // something went wrong, show form with error
            var vm = await BuildLoginViewModelAsync(model);

            return View(vm);
        }

        private async Task<IActionResult> CancelLogin(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            return await CancelLogin(returnUrl, context);
        }

        private async Task<IActionResult> CancelLogin(string returnUrl, AuthorizationRequest context)
        {
            if (context != null)
            {
                // if the user cancels, send a result back into IdentityServer as if they 
                // denied the consent (even if this client does not require consent).
                // this will send back an access denied OIDC error response to the client.
                await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                if (context.IsNativeClient())
                {
                    // The client is native, so this change in how to
                    // return the response is for better UX for the end user.
                    return this.LoadingPage("Redirect", returnUrl);
                }

                return Redirect(returnUrl);
            }

            // since we don't have a valid context, then we just go back to the home page
            return Redirect("~/");
        }

        [HttpGet]
        [Route("~/login/password")]
        [NoCache]
        public async Task<IActionResult> LoginLocally(string returnUrl)
        {
            var sessionUsername = HttpContext.Session.GetString(LoginEmailKey);
            if (string.IsNullOrEmpty(sessionUsername))
            {
                return RedirectToAction(nameof(Login), new { returnUrl });
            }

            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(returnUrl, sessionUsername, true);
            if (vm.IsExternalLoginOnly)
            {
                string prompt = null, upn = null;
                if (Request.Query.ContainsKey("prompt"))
                {
                    prompt = Request.Query["prompt"];
                }
                if (Request.Query.ContainsKey("upn"))
                {
                    upn = Request.Query["upn"];
                }

                // we only have one option for logging in and it's an external provider
                return RedirectToAction("Challenge", "External", new { scheme = vm.ExternalLoginScheme, returnUrl, loginHint = vm.Username, prompt, upn });
            }

            return View("LoginLocally", vm);
        }

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Route("~/login/password")]
        [NoCache]
        public async Task<IActionResult> LoginLocally(LoginInputModel model, string action, [FromForm(Name = "grecaptcha")] string captchaToken)
        {
            // check if we are in the context of an authorization request
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            // the user clicked the "cancel" button
            if (!string.Equals(action, "login", StringComparison.Ordinal))
            {
                return await CancelLogin(model.ReturnUrl, context);
            }

            // Reset the username from the session in case the user tried to change it manually in the form
            var username = HttpContext.Session.GetString(LoginEmailKey);
            model.Username = username;
            TryValidateModel(model);

            if (ModelState.IsValid && !string.IsNullOrWhiteSpace(captchaToken))
            {
                var response = await _recaptchaService.CreateAssessment(captchaToken, GoogleRecaptchaService.Actions.Login);
                await _recaptchaService.Delay(response);

                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberLogin, lockoutOnFailure: true, request: context);
                if (result.Succeeded)
                {
                    // TODO Based on the score (for example, when <= 0.3), we could trigger MFA using email verification.
                    var user = await _userManager.FindByNameAsync(model.Username);
                    return await AfterUserSignInAsync(user, context, model.ReturnUrl);
                }

                // TODO We could improve the Recaptcha model by giving feedback (in this case, negative feedback on "positive" scores and vice-versa) depending on the type of error.

                var eventErrorMessage = "invalid credentials"; // when result == SignInResult.Failed

                if (result.RequiresTwoFactor)
                {
                    eventErrorMessage = "user requires two-factor authentication";
                    await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, eventErrorMessage, clientId: context?.Client.ClientId));

                    return RedirectToAction("LoginWithTwoFactorAuth", new { returnUrl = model.ReturnUrl, rememberMe = model.RememberLogin });
                }
                
                if (result.IsLockedOut)
                {
                    eventErrorMessage = "user is locked out";
                    await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, eventErrorMessage, clientId: context?.Client.ClientId));

                    return RedirectToAction("LockedOut");
                }
                
                if (result.IsNotAllowed)
                {
                    eventErrorMessage = "user is not allowed to sign in yet (email or account not yet confirmed)";
                }

                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, eventErrorMessage, clientId: context?.Client.ClientId));
                ModelState.AddModelError(string.Empty, _localizer["InvalidCredentials"]);
            }

            // something went wrong, show form with error
            var vm = await BuildLoginViewModelAsync(model);

            return View(vm);
        }

        [HttpGet]
        [Route("~/login/2fa")]
        [NoCache]
        public async Task<IActionResult> LoginWithTwoFactorAuth(bool rememberMe, string returnUrl = null, string selectedProvider = null)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user is null)
            {
                return RedirectToAction("Login", new { returnUrl });
            }

            var twoFactorProviders = await _userManager.GetValidTwoFactorProvidersAsync(user);
            if (twoFactorProviders.Count == 0)
            {
                throw new InvalidOperationException("Missing two-factor authentication user details.");
            }

            string preferredMethod;
            if (twoFactorProviders.Count > 1)
            {
                preferredMethod = await _userManager.GetPreferredTwoFactorMethod(user) ?? FallbackPreferredMfaMethod(twoFactorProviders);
                if (preferredMethod is null)
                {
                    throw new InvalidOperationException("Missing two-factor authentication user details.");
                }

                // Switch to the selected token provider if a valid one was selected
                if (preferredMethod != selectedProvider && !string.IsNullOrWhiteSpace(selectedProvider) && twoFactorProviders.Contains(selectedProvider))
                {
                    preferredMethod = selectedProvider;
                }
            }
            else
            {
                // count == 1
                preferredMethod = twoFactorProviders[0]; // Don't look at the preferences since we only have a single option
            }

            await PrepareTwoFactorAuth(user, preferredMethod);

            return View(new TwoFactorAuthViewModel
            {
                ReturnUrl = returnUrl,
                RememberMe = rememberMe,
                RecaptchaSiteKey = _recaptchaService.SiteKey,
                TokenProvider = preferredMethod,
                OtherTokenProviders = twoFactorProviders.Where(x => x != preferredMethod).ToArray()
            });
        }
        
        [HttpPost]
        [Route("~/login/2fa")]
        [NoCache]
        public async Task<IActionResult> LoginWithTwoFactorAuth(TwoFactorAuthViewModel model, [FromForm(Name = "grecaptcha")] string captchaToken, [FromQuery] string returnUrl = null)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user is null)
            {
                return RedirectToAction("Login", new { returnUrl });
            }

            model.RecaptchaSiteKey = _recaptchaService.SiteKey;
            model.ReturnUrl = returnUrl;

            // Re-retrieve the token providers to give the user the option to switch when something goes wrong during the MFA step.
            var twoFactorProviders = await _userManager.GetValidTwoFactorProvidersAsync(user);
            model.OtherTokenProviders = twoFactorProviders.Where(x => x != model.TokenProvider).ToArray();

            if (string.IsNullOrEmpty(model.TokenProvider))
            {
                throw new InvalidOperationException("Missing two-factor authentication user details.");
            }

            if (!ModelState.IsValid || string.IsNullOrWhiteSpace(captchaToken))
            {
                return View(model);
            }

            var response = await _recaptchaService.CreateAssessment(captchaToken, GoogleRecaptchaService.Actions.MFA);
            await _recaptchaService.Delay(response);

            var authenticatorCode = model.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);
            var result = await _signInManager.TwoFactorSignInAsync(model.TokenProvider, authenticatorCode, model.RememberMe, model.RememberDevice);

            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);

            if (result.Succeeded)
            {
                user = await _userManager.FindByNameAsync(user.UserName);
                return await AfterUserSignInAsync(user, context, returnUrl);
            }

            if (result.IsLockedOut)
            {
                await _events.RaiseAsync(new UserLoginFailureEvent(user.UserName, "user is locked out", clientId: context?.Client.ClientId));

                return RedirectToAction("LockedOut");
            }

            // two factor auth failed
            await _events.RaiseAsync(new UserLoginFailureEvent(user.UserName, "invalid authenticator code provided", clientId: context?.Client.ClientId));

            ModelState.AddModelError(string.Empty, _localizer["Invalid authenticator code."]);
            return View(model);
        }

        private async Task PrepareTwoFactorAuth(IdentityExpressUser user, string tokenProvider)
        {
            if (tokenProvider == TokenOptions.DefaultEmailProvider)
            {
                await GenerateMfaTokenForEmail(user);
                return;
            }

            if (tokenProvider == TokenOptions.DefaultAuthenticatorProvider)
            {
                // Just show the view, the user can enter a token generated by their app.
                return;
            }

            // Phone or something else: unsupported (for now)
            throw new InvalidOperationException("Missing two-factor authentication user details.");
        }

        private async Task GenerateMfaTokenForEmail(IdentityExpressUser user)
        {
            var code = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
            var languageCode = await _userManager.GetLocaleAsync(user);
            var location = HttpContext.Connection.RemoteIpAddress?.ToString() ?? _localizer["an unknown location"];

            await _emailSender.SendTwoFactorAuthenticationCodeViaMailAsync(user.UserName, user.Email, user.FirstName ?? "", code, location, languageCode: languageCode);
        }

        private string FallbackPreferredMfaMethod(ICollection<string> twoFactorProviders)
        {
            if (twoFactorProviders.Contains(TokenOptions.DefaultAuthenticatorProvider))
            {
                return TokenOptions.DefaultAuthenticatorProvider;
            }

            if (twoFactorProviders.Contains(TokenOptions.DefaultEmailProvider))
            {
                return TokenOptions.DefaultEmailProvider;
            }

            if (twoFactorProviders.Contains(TokenOptions.DefaultPhoneProvider))
            {
                return TokenOptions.DefaultPhoneProvider;
            }

            return null;
        }

        [HttpGet]
        [Route("~/login/2fa/use-recovery-code")]
        [NoCache]
        public async Task<IActionResult> LoginWithRecoveryCode(string returnUrl = null)
        {
            // Ensure the user has gone through the username & password screen first
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return RedirectToAction("Login", new { returnUrl });
            }

            return View(new LoginWithRecoveryCodeViewModel
            {
                ReturnUrl = returnUrl,
                RecaptchaSiteKey = _recaptchaService.SiteKey
            });
        }

        [HttpPost]
        [Route("~/login/2fa/use-recovery-code")]
        [NoCache]
        public async Task<IActionResult> LoginWithRecoveryCode(LoginWithRecoveryCodeViewModel model, [FromForm(Name = "grecaptcha")] string captchaToken)
        {
            // Ensure the user has gone through the username & password screen first
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return RedirectToAction("Login", new { model.ReturnUrl });
            }

            model.RecaptchaSiteKey = _recaptchaService.SiteKey;
            if (!ModelState.IsValid || string.IsNullOrWhiteSpace(captchaToken))
            {
                return View(model);
            }

            var response = await _recaptchaService.CreateAssessment(captchaToken, GoogleRecaptchaService.Actions.RecoveryCode);
            await _recaptchaService.Delay(response);

            var recoveryCode = model.RecoveryCode.Replace(" ", string.Empty);
            var result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

            if (result.Succeeded)
            {
                _logger.LogInformation("User with ID '{UserId}' logged in with a recovery code.", user.Id);
                
                var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

                return await AfterUserSignInAsync(user, context, model.ReturnUrl);
            }

            if (result.IsLockedOut)
            {
                _logger.LogWarning("User with ID '{UserId}' account locked out.", user.Id);
                return RedirectToAction("LockedOut");
            }
            
            _logger.LogWarning("Invalid recovery code entered for user with ID '{UserId}' ", user.Id);
            ModelState.AddModelError(string.Empty, _localizer["Invalid recovery code entered."]);
            
            return View(model);
        }

        [HttpGet]
        [Route("~/locked-out")]
        [NoCache]
        public IActionResult LockedOut()
        {
            return View();
        }

        private async Task<IActionResult> DiscoverHomeRealm(LoginUsernameInputModel model)
        {
            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(model);

            if (vm.IsExternalLoginOnly)
            {
                string prompt = null, upn = null;
                if (Request.Query.ContainsKey("prompt"))
                {
                    prompt = Request.Query["prompt"];
                }
                if (Request.Query.ContainsKey("upn"))
                {
                    upn = Request.Query["upn"];
                }

                // we only have one option for logging in and it's an external provider
                return RedirectToAction("Challenge", "External", new { scheme = vm.ExternalLoginScheme, model.ReturnUrl, loginHint = model.Username, prompt, upn });
            }

            HttpContext.Session.SetString(LoginEmailKey, model.Username);
            return RedirectToAction(nameof(LoginLocally), new { model.ReturnUrl });
        }

        [HttpGet]
        [Route("~/account/logout")]
        [NoCache]
        public IActionResult LogoutRedirects(string logoutId)
        {
            return RedirectToAction(nameof(Logout), new { logoutId });
        }

        /// <summary>
        /// Show logout page
        /// </summary>
        [HttpGet]
        [Route("~/logout")]
        [NoCache]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Route("~/logout")]
        [NoCache]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity?.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await _signInManager.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                var url = Url.Action(nameof(Logout), new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }

        [HttpGet]
        [Route("~/access-denied")]
        [NoCache]
        public IActionResult AccessDenied()
        {
            return View();
        }

        [HttpGet]
        [Route("~/activate-account")]
        [NoCache]
        public IActionResult Activate(string userId, string token, string returnUrl = null)
        {
            return View("ConfirmActivate", new ActivateAccountViewModel
            {
                UserId = userId,
                Token = token,
                ReturnUrl = returnUrl,
                RecaptchaSiteKey = _recaptchaService.SiteKey
            });
        }

        [HttpPost]
        [Route("~/activate-account")]
        [NoCache]
        public async Task<IActionResult> Activate(ActivateAccountViewModel vm, string action, [FromForm(Name = "grecaptcha")] string captchaToken)
        {
            var model = new ActivateViewModel
            {
                ReturnUrl = vm.ReturnUrl
            };

            if (!string.IsNullOrEmpty(captchaToken))
            {
                var response = await _recaptchaService.CreateAssessment(captchaToken, GoogleRecaptchaService.Actions.ActivateAccount);
                await _recaptchaService.Delay(response);
            }

            if (string.IsNullOrEmpty(vm.UserId) || string.IsNullOrEmpty(vm.Token))
            {
                ModelState.AddModelError("", _localizer["MissingRequirements"]);
                return View(model);
            }

            var user = await _userManager.FindByIdAsync(vm.UserId);
            if (user == null)
            {
                await _events.RaiseAsync(new UserAccountActivationFailedEvent(vm.UserId));

                if (!string.IsNullOrWhiteSpace(vm.ReturnUrl))
                {
                    model.LoginLink = Url.Action(nameof(Login), new { vm.ReturnUrl });
                }

                // hide from the potential abuser that something was wrong
                model.IsCompleted = true; 
                return View(model);
            }

            var isEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user);
            if (isEmailConfirmed)
            {
                // Duplicate activation request, don't act twice.
                await _events.RaiseAsync(new UserAccountActivationSuccessEvent(user.UserName, user.Id));

                if (!string.IsNullOrWhiteSpace(vm.ReturnUrl))
                {
                    model.LoginLink = Url.Action(nameof(Login), new { vm.ReturnUrl });
                }

                model.IsCompleted = true;
                return View(model);
            }

            var token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(vm.Token));
            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (!result.Succeeded)
            {
                ModelState.AddModelError("", _localizer["Error activating your account."]);
                return View(model);
            }

            await _events.RaiseAsync(new UserAccountActivationSuccessEvent(user.UserName, user.Id));

            // Send activation confirmation email
            var languageCode = await _userManager.GetPreferredLanguageCodeAsync(user);
            await _emailSender.SendUserAccountActivatedEmailAsync(user.UserName, user.Email, user.FirstName ?? "", Url.Action("ForgotPassword"), languageCode);

            var userHasPassword = await _userManager.HasPasswordAsync(user);
            if (!userHasPassword)
            {
                var passwordResetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
                passwordResetToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(passwordResetToken));
                return RedirectToAction(nameof(ResetPassword), new { token = passwordResetToken, username = user.UserName, vm.ReturnUrl });
            }

            if (!string.IsNullOrWhiteSpace(vm.ReturnUrl))
            {
                model.LoginLink = Url.Action(nameof(Login), new { vm.ReturnUrl });
            }

            model.IsCompleted = true;
            return View(model);
        }

        [HttpGet]
        [Route("~/resend-activation-email")]
        [NoCache]
        public IActionResult ResendActivationEmail([FromQuery] string username = null, [FromQuery(Name = "s")] int? submit = null, [FromQuery] string returnUrl = null)
        {
            TempData["AutoSubmit"] = submit == 1;

            return View(new ResendActivationEmailViewModel
            {
                UserName = username,
                AutoSubmit = submit == 1,
                ReturnUrl = returnUrl,
                RecaptchaSiteKey = _recaptchaService.SiteKey
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Route("~/resend-activation-email")]
        [NoCache]
        public async Task<IActionResult> ResendActivationEmail(ResendActivationEmailViewModel model, [FromForm(Name = "grecaptcha")] string captchaToken = null)
        {
            var autoSubmit = TempData["AutoSubmit"] as bool? ?? false;

            model.RecaptchaSiteKey = _recaptchaService.SiteKey;
            if (!ModelState.IsValid || (string.IsNullOrWhiteSpace(captchaToken) && !autoSubmit))
            {
                return View(model);
            }

            if (autoSubmit != true)
            {
                var response = await _recaptchaService.CreateAssessment(captchaToken, GoogleRecaptchaService.Actions.ResendActivationEmail);
                await _recaptchaService.Delay(response);
            }

            return await HandleResendActivationEmail(model);
        }

        private async Task<IActionResult> HandleResendActivationEmail(ResendActivationEmailViewModel model)
        {
            model.RecaptchaSiteKey = _recaptchaService.SiteKey;

            if (!ModelState.IsValid)
            {
                return View("ResendActivationEmail", model);
            }

            var isEmailConfirmationRequired = _userManager.Options.SignIn.RequireConfirmedEmail;
            if (!isEmailConfirmationRequired)
            {
                model.IsCompleted = true;
                return View("ResendActivationEmail", model);
            }

            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user is null)
            {
                await _events.RaiseAsync(new UserAccountActivationRequestFailedEvent(model.UserName));
            }
            else
            {
                var languageCode = await _userManager.GetPreferredLanguageCodeAsync(user);
                await _userActivationService.SendActivationEmail(user, languageCode, x => _userManager.GenerateEmailConfirmationTokenAsync(x), model.ReturnUrl);
            }
            
            model.IsCompleted = true;
            return View(model);
        }

        [HttpGet]
        [Route("~/confirm-email")]
        [NoCache]
        public async Task<IActionResult> ConfirmEmail(string userId, string token, string returnUrl = null)
        {
            var model = new ConfirmEmailViewModel();

            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                ModelState.AddModelError("", _localizer["MissingRequirements"]);
                return View(model);
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                await _events.RaiseAsync(new UserConfirmEmailFailedEvent(userId, "Invalid User ID."));

                // hide from the potential abuser that something was wrong
                model.IsCompleted = true;
                return View(model);
            }

            token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (!result.Succeeded)
            {
                await _events.RaiseAsync(new UserConfirmEmailFailedEvent(userId, "Invalid token."));

                var link = Url.Action("VerifyEmail", "UserManagement");
                model.Error = _localizer.GetString("Email confirm token expired.", link);

                return View(model);
            }

            await _events.RaiseAsync(new UserConfirmEmailSuccessEvent(user.UserName, user.Id));

            model.IsCompleted = true;
            return View(model);
        }

        [HttpGet]
        [Route("~/confirm-email-change")]
        [NoCache]
        public async Task<IActionResult> ConfirmEmailChange(string userId, string token, string email)
        {
            var model = new ConfirmEmailChangeViewModel();

            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
            {
                ModelState.AddModelError("", _localizer["MissingRequirements"]);
                return View(model);
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                await _events.RaiseAsync(new UserConfirmEmailChangeFailedEvent(userId, "Invalid user ID."));

                // hide from the potential abuser that something was wrong
                return RedirectToAction(nameof(ConfirmEmailChangeSuccess));
            }

            var originalEmail = user.Email;
            var originalEmailConfirmed = user.EmailConfirmed;

            token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
            var result = await _userManager.ChangeEmailAsync(user, email, token);
            if (!result.Succeeded)
            {
                await _events.RaiseAsync(new UserConfirmEmailChangeFailedEvent(userId, "Invalid token."));

                var link = Url.Action("EmailAddress", "UserManagement");
                model.Error = _localizer.GetString("Email change token expired.", link);
                
                return View(model);
            }
            
            // We set username = email for accounts, so when a user updates their email address, we also need to update their username.
            var changeUsernameResult = await _userManager.SetUserNameAsync(user, email);
            if (!changeUsernameResult.Succeeded)
            {
                await _events.RaiseAsync(new UserConfirmEmailChangeFailedEvent(userId, "Email was changed but username is now out of sync! Reverting back to original email address..."));

                await _userManager.SetEmailAsync(user, originalEmail);
                if (originalEmailConfirmed)
                {
                    var confirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    await _userManager.ConfirmEmailAsync(user, confirmationToken);
                }

                ModelState.AddModelError("", _localizer["Error changing user name."]);
                return View(model);
            }

            await _events.RaiseAsync(new UserConfirmEmailChangeSuccessEvent(user.UserName, user.Id));
            await _signInManager.RefreshSignInAsync(user);

            // Use a redirect rather than returning a View in success status, this ensures the cookies are up to date
            // to reflect the username (email) change immediately.
            return RedirectToAction(nameof(ConfirmEmailChangeSuccess));
        }

        [HttpGet]
        [Route("~/email-confirmed")]
        [NoCache]
        public IActionResult ConfirmEmailChangeSuccess()
        {
            return View();
        }

        [HttpGet]
        [Route("~/forgot-password")]
        [NoCache]
        public async Task<IActionResult> ForgotPassword(string returnUrl)
        {
            if (_generalOptions.DisablePasswordManagement)
            {
                return RedirectToAction(nameof(Login), new { returnUrl });
            }

            var email = HttpContext.Session.GetString(LoginEmailKey);
            var vm = await BuildForgotPasswordViewModelAsync(returnUrl, email);
            return View(vm);
        }

        /// <summary>
        /// Handle postback from reset password
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Route("~/forgot-password")]
        [NoCache]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model, string action, [FromForm(Name = "grecaptcha")]string captchaToken)
        {
            // the user clicked the "cancel" button or password reset is not allowed
            if (_generalOptions.DisablePasswordManagement || !string.Equals(action, "confirm", StringComparison.Ordinal))
            {
                return RedirectToAction(nameof(Login), new {returnUrl = model?.ReturnUrl});
            }

            if (ModelState.IsValid && !string.IsNullOrWhiteSpace(captchaToken))
            {
                var response = await _recaptchaService.CreateAssessment(captchaToken, GoogleRecaptchaService.Actions.ForgotPassword);
                await _recaptchaService.Delay(response);

                var user = await _userManager.FindByNameAsync(model.UserName);
                if (user is null)
                {
                    // user not found
                    await _events.RaiseAsync(new UserForgotPasswordFailedEvent(model.UserName));
                }
                else if (await _forgotPasswordService.CanSendResetPasswordEmail(user, _userManager))
                {
                    var languageCode = await _userManager.GetLocaleAsync(user);
                    await _forgotPasswordService.SendResetPasswordEmail(user, languageCode, x => _userManager.GeneratePasswordResetTokenAsync(x));
                }

                // Regardless if we find a user matching the user name or not, show that the flow ended.
                // This prevents enumeration attacks.
                model.IsCompleted = true;
            }

            // something went wrong, show form with error
            model.RecaptchaSiteKey = _recaptchaService.SiteKey;
            return View(model);
        }

        [HttpGet]
        [Route("~/reset-password")]
        [NoCache]
        public async Task<IActionResult> ResetPassword(string token = null, string username = null, string returnUrl = null)
        {
            if (token == null)
            {
                await _events.RaiseAsync(new UserResetPasswordFailedEvent());
                return BadRequest(_localizer["TokenRequiredForPasswordReset"]);
            }

            var vm = await BuildResetPasswordViewModelAsync(token, username, returnUrl);
            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Route("~/reset-password")]
        [NoCache]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model, [FromForm(Name = "grecaptcha")] string captchaToken)
        {
            model.RecaptchaSiteKey = _recaptchaService.SiteKey;

            if (!ModelState.IsValid || string.IsNullOrWhiteSpace(captchaToken))
            {
                model.Password = null;
                model.ConfirmPassword = null;

                return View(model);
            }

            var response = await _recaptchaService.CreateAssessment(captchaToken, GoogleRecaptchaService.Actions.ResetPassword);
            await _recaptchaService.Delay(response);

            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null)
            {
                await _events.RaiseAsync(new UserResetPasswordFailedEvent(model.Username));
                return RedirectToAction(nameof(ResetPasswordConfirmation), new { returnUrl = model.ReturnUrl });
            }
            
            var token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(model.Token));
            var result = await _userManager.ResetPasswordAsync(user, token, model.Password);
            if (result.Succeeded)
            {
                var email = await _userManager.GetEmailAsync(user);
                var languageCode = await _userManager.GetPreferredLanguageCodeAsync(user);
                await _emailSender.SendPasswordChangedMailAsync(user.UserName, email, user.FirstName, languageCode);

                await _events.RaiseAsync(new UserResetPasswordSuccessEvent(user.UserName, user.Id));
                return RedirectToAction(nameof(ResetPasswordConfirmation), new { returnUrl = model.ReturnUrl });
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }

            model.Password = null;
            model.ConfirmPassword = null;
            return View(model);
        }


        [HttpGet]
        [Route("~/password-reset")]
        [NoCache]
        public IActionResult ResetPasswordConfirmation(string returnUrl = null)
        {
            return View();
        }

        [HttpGet]
        [Route("~/register")]
        [NoCache]
        public async Task<IActionResult> Register(string returnUrl = null)
        {
            var vm = await BuildRegisterViewModelAsync(returnUrl);
            if (!vm.EnableRegistration)
            {
                return RedirectToAction("Login", new { returnUrl });
            }

            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Route("~/register")]
        [NoCache]
        public async Task<IActionResult> Register(RegisterViewModel model, [FromForm(Name = "grecaptcha")]string captchaToken)
        {
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);
            model.ReturnUrl ??= Url.Content("~/");

            // If we can discover a realm for the email domain, that means a user can't register locally with that email address.
            var hrdRule = _homeRealmDiscoveryService.DiscoverRealmFromUsername(model.Email);
            if (hrdRule is not null)
            {
                ModelState.AddModelError(nameof(RegisterViewModel.Email), _localizer.GetString("You can not create an account with a '{0}' email address.", hrdRule.MatchedDomain));
            }

            if (ModelState.IsValid && !string.IsNullOrWhiteSpace(captchaToken))
            {
                var response = await _recaptchaService.CreateAssessment(captchaToken, GoogleRecaptchaService.Actions.Register);
                await _recaptchaService.Delay(response);

                var user = new IdentityExpressUser
                {
                    UserName = model.Email,
                    Email = model.Email
                };

                IdentityResult result;
                
                var existingUser = await _userManager.FindByNameAsync(user.Email);
                if (existingUser != null)
                {
                    // Don't attempt to create the user but do validate the password and username/email validity!
                    // If we don't perform the exact same validation as _userManager.CreateAsync does, we'd get a different result which indicates
                    // to a potential abuser that this account (model.Email) exists in the system.
                    result = await _userManager.ValidateUser(user, model.Password);
                    
                    if (result.Succeeded)
                    {
                        // Another user already registered with this email address (or this user forgot they already registered).
                        // Send an email to the user to remind them they already registered but do not display an error to the current user because it might be an abusive action.
                        await _events.RaiseAsync(new UserRegistrationFailedEvent(model.Email, "email address already registered"));

                        var languageCode = await _userManager.GetPreferredLanguageCodeAsync(existingUser);
                        await _emailSender.SendUserAlreadyRegisteredMailAsync(existingUser.UserName, existingUser.Email, existingUser.FirstName, languageCode);

                        return RedirectToAction(nameof(RegisterConfirmation), new { returnUrl = model.ReturnUrl });
                    }
                }
                else
                {
                    result = await _userManager.CreateAsync(user, model.Password);
                    if (result.Succeeded)
                    {
                        await _events.RaiseAsync(new UserRegistrationSuccessEvent(user.UserName, user.Id));

                        if (_userManager.Options.SignIn.RequireConfirmedEmail)
                        {
                            var languageCode = await _userManager.GetPreferredLanguageCodeAsync(user);
                            await _userActivationService.SendActivationEmail(user, languageCode, x => _userManager.GenerateEmailConfirmationTokenAsync(x), model.ReturnUrl);

                            return RedirectToAction(nameof(RegisterConfirmation), new { returnUrl = model.ReturnUrl });
                        }

                        // If a user isn't required to confirm their email address before signing in, let's sign in after registering immediately.
                        await _signInManager.SignInAsync(user, false);
                        return await AfterUserSignInAsync(user, context, model.ReturnUrl);
                    }
                }

                // Creating the user failed, either because the password wasn't strong enough, or because the user already exists
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }

            var vm = await BuildRegisterViewModelAsync(model);
            if (!vm.EnableRegistration)
            {
                return RedirectToAction("Login", new { model.ReturnUrl });
            }

            return View(vm);
        }
        
        [HttpGet]
        [Route("~/registration-complete")]
        [NoCache]
        public async Task<IActionResult> RegisterConfirmation(string returnUrl = null)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            
            var client = context?.Client;
            if (client is not null && client.Properties.Count == 0)
            {
                // Need to load from the store to get properties in case the InitiateLoginUri is stored there.
                client = await _clientStore.FindClientByIdAsync(client.ClientId);
            }
            
            var vm = new RegisterConfirmationViewModel
            {
                ClientLoginUrl = client?.GetInitiateLoginUri(),
                ClientName = client?.ClientName
            };
            
            return View(vm);
        }

        /*****************************************/
        /* helper APIs for the AccountController */
        /*****************************************/
        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl, string username = null, bool autoLogin = false)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            var loginHint = context?.LoginHint;

            if (!string.IsNullOrEmpty(loginHint))
            {
                username = loginHint;
            }
            else 
            {
                loginHint = null;
            }

            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = username,
                    LoginHint = loginHint,
                    RecaptchaSiteKey = _recaptchaService.SiteKey
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null)
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName ?? x.Name,
                    AuthenticationScheme = x.Name,
                }).ToList();

            var allowLocal = true;
            var allowRegistration = true;
            var allowResetPassword = true;

            if (context?.Client.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.Properties.TryGetValue(nameof(GeneralOptions.DisableRegistration), out var disableRegistration))
                    {
                        // Disable registration if the property is set on the client.
                        allowRegistration = !string.Equals(disableRegistration, bool.TrueString, StringComparison.OrdinalIgnoreCase);
                    }
                    if (client.Properties.TryGetValue(nameof(GeneralOptions.DisablePasswordManagement), out var disablePasswordManagement))
                    {
                        // Disable password reset if the property is set on the client.
                        allowResetPassword = !string.Equals(disablePasswordManagement, bool.TrueString, StringComparison.OrdinalIgnoreCase);
                    }

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            if (_generalOptions.DisableRegistration)
            {
                allowRegistration = false;
            }
            if (_generalOptions.DisablePasswordManagement)
            {
                allowResetPassword = false;
            }

            var hrdRule = _homeRealmDiscoveryService.DiscoverRealmFromUsername(username);
            if (hrdRule is not null && providers.Any() && autoLogin)
            {
                // Limit to the discovered realm
                allowLocal = false;
                providers = providers.Where(x => x.AuthenticationScheme == hrdRule.Provider).ToList();
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                EnableRegistration = allowRegistration,
                EnableResetPassword = allowResetPassword,
                ReturnUrl = returnUrl,
                LoginHint = loginHint,
                Username = username,
                ExternalProviders = providers.ToArray(),
                RecaptchaSiteKey = _recaptchaService.SiteKey
            };
        }

        private Task<LoginViewModel> BuildLoginViewModelAsync(LoginUsernameInputModel model)
        {
            return BuildLoginViewModelAsync(model.ReturnUrl, model.Username, false);
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl, model.Username, false);
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel
            {
                LogoutId = logoutId, 
                ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt
            };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }
        
        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };
                        
            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await DoesSchemeSupportSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }

        private async Task<bool> DoesSchemeSupportSignOutAsync(string scheme)
        {
            var provider = HttpContext.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();
            var handler = await provider.GetHandlerAsync(HttpContext, scheme);
            return (handler is IAuthenticationSignOutHandler);
        }

        private Task<ForgotPasswordViewModel> BuildForgotPasswordViewModelAsync(string returnUrl, string email = null)
        {
            return Task.FromResult(new ForgotPasswordViewModel
            {
                UserName = email ?? "",
                ReturnUrl = returnUrl,
                RecaptchaSiteKey = _recaptchaService.SiteKey
            });
        }

        private Task<ResetPasswordViewModel> BuildResetPasswordViewModelAsync(string token, string username = null, string returnUrl = null)
        {
            return Task.FromResult(new ResetPasswordViewModel
            {
                Token = token,
                Username = username,
                ShowEmailField = string.IsNullOrEmpty(username),
                ReturnUrl = returnUrl,
                RecaptchaSiteKey = _recaptchaService.SiteKey
            });
        }

        private async Task<RegisterViewModel> BuildRegisterViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);

            var model = new RegisterViewModel
            {
                ReturnUrl = returnUrl,
                RecaptchaSiteKey = _recaptchaService.SiteKey
            };

            var allowRegistration = true;

            if (context?.Client.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
                if (client != null)
                {
                    if (client.Properties.TryGetValue(nameof(GeneralOptions.DisableRegistration), out var disableRegistration))
                    {
                        // Disable registration if the property is set on the client.
                        allowRegistration = !string.Equals(disableRegistration, bool.TrueString, StringComparison.OrdinalIgnoreCase);
                    }
                }
            }

            if (_generalOptions.DisableRegistration)
            {
                allowRegistration = false;
            }

            model.EnableRegistration = allowRegistration;

            return model;
        }

        private async Task<RegisterViewModel> BuildRegisterViewModelAsync(RegisterViewModel model)
        {
            var vm = await BuildRegisterViewModelAsync(model.ReturnUrl);
            vm.Email = model.Email;

            return vm;
        }

        private async Task<IActionResult> AfterUserSignInAsync(IdentityExpressUser user, AuthorizationRequest context, string returnUrl = null)
        {
            await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.Client.ClientId));
            await SetLanguageAsync(user);
            
            if (context != null)
            {
                if (context.IsNativeClient())
                {
                    // The client is native, so this change in how to
                    // return the response is for better UX for the end user.
                    return this.LoadingPage("Redirect", returnUrl);
                }

                // we can trust returnUrl since GetAuthorizationContextAsync returned non-null
                return Redirect(returnUrl);
            }

            // request for a local page
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            
            if (string.IsNullOrEmpty(returnUrl))
            {
                return Redirect("~/");
            }
            
            // user might have clicked on a malicious link - should be logged
            throw new Exception("invalid return URL");
        }

        private async Task SetLanguageAsync(IdentityExpressUser user)
        {
            var claims = await _userManager.GetClaimsAsync(user);
            var localeClaim = claims?.FirstOrDefault(x => x.Type == JwtClaimTypes.Locale);
            if (localeClaim is null)
            {
                return;
            }

            Response.Cookies.SetCulture(localeClaim.Value);
        }
    }
}