using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Duende.IdentityServer.Services;
using GotSharp.IdSrv.Host.Configuration;
using GotSharp.IdSrv.Host.Controllers.Account;
using GotSharp.IdSrv.Host.Events;
using GotSharp.IdSrv.Host.Internal;
using GotSharp.IdSrv.Host.Services;
using IdentityExpress.Identity;
using IdentityModel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Localization;
using Microsoft.FeatureManagement.Mvc;
using QRCoder;

namespace GotSharp.IdSrv.Host.Controllers.UserManagement
{
    [Route("~/manage")]
    [Authorize]
    [SecurityHeaders]
    public class UserManagementController : Controller
    {
        private readonly Services.UserManager<IdentityExpressUser> _userManager;
        private readonly Services.SignInManager<IdentityExpressUser> _signInManager;
        private readonly IEventService _events;
        private readonly IStringLocalizer<UserManagementController> _localizer;
        private readonly EmailSender _emailSender;
        private readonly HomeRealmDiscoveryService _homeRealmDiscoveryService;
        private readonly UrlEncoder _urlEncoder;
        private readonly IConfiguration _configuration;
        private readonly ILogger<UserManagementController> _logger;

        private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

        public UserManagementController(
            Services.UserManager<IdentityExpressUser> userManager,
            Services.SignInManager<IdentityExpressUser> signInManager,
            IEventService events,
            IStringLocalizer<UserManagementController> localizer,
            EmailSender emailSender,
            HomeRealmDiscoveryService homeRealmDiscoveryService,
            UrlEncoder urlEncoder,
            IConfiguration configuration,
            ILogger<UserManagementController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _events = events;
            _localizer = localizer;
            _emailSender = emailSender;
            _homeRealmDiscoveryService = homeRealmDiscoveryService;
            _urlEncoder = urlEncoder;
            _configuration = configuration;
            _logger = logger;
        }

        [HttpGet(Name = Routes.ManageIndex)]
        public async Task<IActionResult> Index()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            var vm = await BuildProfileViewModel(user);
            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(ProfileViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                if (user is null)
                {
                    return BadRequest();
                }

                var result = await UpsertLocaleClaim(user, JwtClaimTypes.Locale, model.LanguageCode);
                if (result.Succeeded)
                {
                    TempData["StatusMessage"] = "Your preferred language has been changed.";
                                        
                    Response.Cookies.SetCulture(model.LanguageCode);
                    return RedirectToAction("Index");
                }

                // TODO Translate these errors?
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }

            var vm = new ProfileViewModel { LanguageCode = model.LanguageCode };
            return View(vm);
        }

        private async Task<IdentityResult> UpsertLocaleClaim(IdentityExpressUser user, string claimType, string claimValue)
        {
            var newOrUpdatedClaim = new Claim(claimType, claimValue);
            user = await _userManager.FindByIdAsync(user.Id);
            
            var claims = await _userManager.GetClaimsAsync(user);
            var existingClaim = claims.FirstOrDefault(x => x.Type == claimType);
            if (existingClaim is null)
            {
                return await _userManager.AddClaimAsync(user, newOrUpdatedClaim);
            }

            return await _userManager.ReplaceClaimAsync(user, existingClaim, newOrUpdatedClaim);
        }

        [HttpGet]
        [Route("change-password")]
        public async Task<IActionResult> ChangePassword([FromQuery] string returnUrl = null)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (!await CanUserChangePassword(user))
            {
                return RedirectToAction("Index");
            }

            return View(new ChangePasswordViewModel
            {
                ReturnUrl = returnUrl
            });
        }

        [HttpPost]
        [Route("change-password")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (!await CanUserChangePassword(user))
            {
                return RedirectToAction("Index");
            }

            if (ModelState.IsValid)
            {
                var result = await ChangeUserPasswordAsync(_userManager, user.UserName, model.OldPassword, model.NewPassword);
                
                if (result.Succeeded)
                {
                    await _signInManager.RefreshSignInAsync(user);
                    await _events.RaiseAsync(new UserChangePasswordSuccessEvent(user.UserName, user.Id));

                    if (!string.IsNullOrWhiteSpace(model.ReturnUrl))
                    {
                        return View("Redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });
                    }

                    TempData["StatusMessage"] = "Your password has been changed.";
                    return RedirectToAction("Index");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }

            return View(new ChangePasswordViewModel());
        }

        private async Task<IdentityResult> ChangeUserPasswordAsync(Services.UserManager<IdentityExpressUser> userManager, string userName, string oldPassword, string newPassword)
        {
            var user = await userManager.FindByNameAsync(userName);
            if (user is null)
            {
                // Should never happen, but just in case...
                return IdentityResult.Failed(userManager.ErrorDescriber.DefaultError());
            }

            var result = await userManager.ChangePasswordAsync(user, oldPassword, newPassword);
            if (!result.Succeeded)
            {
                return result;
            }

            var email = await userManager.GetEmailAsync(user);
            var languageCode = await userManager.GetPreferredLanguageCodeAsync(user);
            await _emailSender.SendPasswordChangedMailAsync(user.UserName, email, user.FirstName, languageCode);

            return result;
        }

        private async Task<bool> CanUserChangePassword(IdentityExpressUser user)
        {
            return await _userManager.HasPasswordAsync(user);
        }
        
        [HttpGet]
        [Route("email")]
        public async Task<IActionResult> EmailAddress()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (!await CanUserChangeEmailAddress(user))
            {
                return RedirectToAction("Index");
            }

            var vm = await BuildEmailViewModel(user);
            return View(vm);
        }

        [HttpPost]
        [Route("email")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EmailAddress([FromServices] IIssuerNameService issuerNameService, EmailViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (!await CanUserChangeEmailAddress(user))
            {
                return RedirectToAction("Index");
            }

            var currentEmailAddress = await _userManager.GetEmailAsync(user);
            if (string.Equals(currentEmailAddress, model.NewEmail, StringComparison.OrdinalIgnoreCase))
            {
                TempData["StatusMessage"] = "Your email is unchanged.";
                return RedirectToAction("Index");
            }

            if (ModelState.IsValid)
            {
                // If we can discover a realm for the new email's domain, return an error.
                var hrdRule = _homeRealmDiscoveryService.DiscoverRealmFromUsername(model.NewEmail);
                if (hrdRule is not null)
                {
                    ModelState.AddModelError(nameof(EmailViewModel.NewEmail), _localizer.GetString("You can not use a '{0}' email address.", hrdRule.MatchedDomain));
                }
            }

            if (ModelState.IsValid)
            {
                var languageCode = await _userManager.GetPreferredLanguageCodeAsync(user);

                // check if the email is not already in use by someone else: we can't change the email address because that also changes the username!
                if (await EmailAlreadyInUseByAnotherUser(model.NewEmail))
                {
                    // find the "other" user by username, not by email
                    var otherUser = await _userManager.FindByNameAsync(model.NewEmail);
                    if (otherUser != null)
                    {
                        await _emailSender.SendEmailAddressAlreadyInUseMailAsync(otherUser.UserName, model.NewEmail, otherUser.FirstName, languageCode);
                    }

                    await _events.RaiseAsync(new UserChangeEmailFailedEvent(user.Id, "Email address already in use by another user."));
                }
                else 
                {
                    // new email address is not used yet, so we're good. Generate the token and send the confirmation email.
                    var userId = await _userManager.GetUserIdAsync(user);
                    var code = await _userManager.GenerateChangeEmailTokenAsync(user, model.NewEmail);
                    code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

                    var authority = await issuerNameService.GetCurrentAsync();
                    var callbackUrlPath = Url.Action("ConfirmEmailChange", "Account", new { userId, token = code, email = model.NewEmail });
                    var callbackUrl = authority.RemoveTrailingSlash() + callbackUrlPath.EnsureLeadingSlash();
                    
                    await _emailSender.SendConfirmEmailChangeMailAsync(user.UserName, model.NewEmail, user.FirstName, callbackUrl, languageCode);
                    await _events.RaiseAsync(new UserChangeEmailSuccessEvent(user.UserName, user.Id));
                }
                
                // In both cases, act like everything went fine to prevent account/email enumeration.
                TempData["StatusMessage"] = "We've sent a confirmation link to your new email address, please check your inbox.";
                return RedirectToAction("Index");
            }

            var vm = await BuildEmailViewModel(user);
            vm.NewEmail = model.NewEmail;
            return View(vm);
        }

        private async Task<bool> CanUserChangeEmailAddress(IdentityExpressUser user)
        {
            var email = await _userManager.GetEmailAsync(user);
            if (string.IsNullOrEmpty(email))
            {
                return false;
            }
            
            return !user.IsExternalUser();
        }

        private async Task<bool> EmailAlreadyInUseByAnotherUser(string newEmail)
        {
            var userBelongingToNewEmail = await _userManager.FindByNameAsync(newEmail);
            return userBelongingToNewEmail != null;
        }

        [HttpGet]
        [Route("email/verify")]
        public async Task<IActionResult> VerifyEmail()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            var isConfirmed = await _userManager.IsEmailConfirmedAsync(user);
            if (isConfirmed)
            {
                return RedirectToAction("Index");
            }

            var userId = await _userManager.GetUserIdAsync(user);
            var email = await _userManager.GetEmailAsync(user);
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId, token = code });
            var languageCode = await _userManager.GetPreferredLanguageCodeAsync(user);
            await _emailSender.SendConfirmEmailMailAsync(user.UserName, email, user.FirstName, callbackUrl, languageCode);
            await _events.RaiseAsync(new UserConfirmEmailRequestSuccessEvent(user.UserName, user.Id));

            TempData["StatusMessage"] = "Verification email sent, please check your inbox.";
            return RedirectToAction("EmailAddress");
        }
        
        private async Task<ProfileViewModel> BuildProfileViewModel(IdentityExpressUser user)
        {
            var vm = new ProfileViewModel();
            user = await _userManager.FindByIdAsync(user.Id);
            var claims = await _userManager.GetClaimsAsync(user);
            var languageClaim = claims?.FirstOrDefault(x => x.Type == JwtClaimTypes.Locale);
            
            if (languageClaim is null)
            {
                vm.LanguageCode = ProfileViewModel.DefaultLanguageCode;
            }
            else
            {
                var languageCode = languageClaim.Value;
                vm.SetLanguageFromClaim(languageCode);
            }

            return vm;
        }

        private async Task<EmailViewModel> BuildEmailViewModel(IdentityExpressUser user)
        {
            var email = await _userManager.GetEmailAsync(user);
            var isEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user);

            return new EmailViewModel { Email = email, IsEmailConfirmed = isEmailConfirmed, NewEmail = email };
        }

        [HttpGet]
        [Route("mfa")]
        [FeatureGate(FeatureToggles.MFA)]
        public async Task<IActionResult> MultiFactorAuthentication()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (user.IsExternalUser())
            {
                return RedirectToAction("Index");
            }

            var vm = await BuildMultiFactorAuthenticationViewModelAsync(user);
            return View(vm);
        }

        [HttpGet]
        [Route("mfa/enable")]
        [FeatureGate(FeatureToggles.MFA)]
        public async Task<IActionResult> EnableMultiFactorAuthentication()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (user.IsExternalUser())
            {
                return RedirectToAction("Index");
            }

            if (await _userManager.GetTwoFactorEnabledAsync(user))
            {
                return RedirectToAction("MultiFactorAuthentication");
            }

            return View();
        }

        [HttpPost]
        [Route("mfa/enable")]
        [FeatureGate(FeatureToggles.MFA)]
        public async Task<IActionResult> EnableMultiFactorAuthentication(IFormCollection form)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (user.IsExternalUser())
            {
                return RedirectToAction("Index");
            }

            if (await _userManager.GetTwoFactorEnabledAsync(user))
            {
                return RedirectToAction("MultiFactorAuthentication");
            }

            var result = await _userManager.SetTwoFactorEnabledAsync(user, true);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Unexpected error occurred enabling MFA for user with ID '{userId}'.", _userManager.GetUserId(User));
                TempData["StatusMessage"] = "Couldn't enable MFA right now. Try again later.";
            }

            _logger.LogInformation("User with ID '{UserId}' has enabled MFA", _userManager.GetUserId(User));
            TempData["StatusMessage"] = "MFA has been enabled.";
            return RedirectToAction("MultiFactorAuthentication");
        }

        [HttpGet]
        [Route("mfa/disable")]
        [FeatureGate(FeatureToggles.MFA)]
        public async Task<IActionResult> DisableMultiFactorAuthentication()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (user.IsExternalUser())
            {
                return RedirectToAction("Index");
            }

            if (!await _userManager.GetTwoFactorEnabledAsync(user))
            {
                return RedirectToAction("MultiFactorAuthentication");
            }

            var vm = new MinimumMfaViewModel
            {
                HasAuthenticator = await _userManager.GetAuthenticatorKeyAsync(user) != null
            };
            return View(vm);
        }

        [HttpPost]
        [Route("mfa/disable")]
        [FeatureGate(FeatureToggles.MFA)]
        public async Task<IActionResult> DisableMultiFactorAuthentication(IFormCollection form)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (user.IsExternalUser())
            {
                return RedirectToAction("Index");
            }

            var result = await _userManager.SetTwoFactorEnabledAsync(user, false);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Unexpected error occurred disabling MFA for user with ID '{userId}'.", _userManager.GetUserId(User));
                TempData["StatusMessage"] = "Couldn't disable MFA right now. Try again later.";
            }

            _logger.LogInformation("User with ID '{UserId}' has disabled MFA", _userManager.GetUserId(User));
            TempData["StatusMessage"] = "MFA has been disabled. You can reenable MFA at any time.";
            return RedirectToAction("MultiFactorAuthentication");
        }

        [HttpGet]
        [Route("mfa/recovery-codes")]
        [FeatureGate(FeatureToggles.MFA)]
        public async Task<IActionResult> GenerateRecoveryCodes()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (user.IsExternalUser())
            {
                return RedirectToAction("Index");
            }

            if (!await _userManager.GetTwoFactorEnabledAsync(user))
            {
                return RedirectToAction("MultiFactorAuthentication");
            }

            var vm = new MinimumMfaViewModel
            {
                HasAuthenticator = await _userManager.GetAuthenticatorKeyAsync(user) != null
            };
            return View(vm);
        }

        [HttpPost]
        [Route("mfa/recovery-codes")]
        [FeatureGate(FeatureToggles.MFA)]
        public async Task<IActionResult> GenerateRecoveryCodes(IFormCollection form)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (user.IsExternalUser())
            {
                return RedirectToAction("Index");
            }

            if (!await _userManager.GetTwoFactorEnabledAsync(user))
            {
                return RedirectToAction("MultiFactorAuthentication");
            }

            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            _logger.LogInformation("User with ID '{UserId}' has generated new 2FA recovery codes.", user.Id);
            TempData["StatusMessage"] = "You have generated new recovery codes.";

            return View("ShowRecoveryCodes", new RecoveryCodesViewModel
            {
                RecoveryCodes = recoveryCodes.ToArray()
            });
        }

        [HttpGet]
        [Route("mfa/forget-this-device")]
        [FeatureGate(FeatureToggles.MFA)]
        public async Task<IActionResult> ForgetThisDevice()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (user.IsExternalUser())
            {
                return RedirectToAction("Index");
            }

            if (!await _userManager.GetTwoFactorEnabledAsync(user))
            {
                return RedirectToAction("MultiFactorAuthentication");
            }

            return View();
        }

        [HttpPost]
        [Route("mfa/forget-this-device")]
        [FeatureGate(FeatureToggles.MFA)]
        public async Task<IActionResult> ForgetThisDevice(IFormCollection form)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (user.IsExternalUser())
            {
                return RedirectToAction("Index");
            }

            if (!await _userManager.GetTwoFactorEnabledAsync(user))
            {
                return RedirectToAction("MultiFactorAuthentication");
            }

            await _signInManager.ForgetTwoFactorClientAsync();
            TempData["StatusMessage"] = "The current browser has been forgotten. When you login again from this browser you will be prompted for your MFA code.";
            return RedirectToAction("MultiFactorAuthentication");
        }

        [HttpGet]
        [Route("mfa/enable-authenticator-app")]
        [FeatureGate(FeatureToggles.MFA)]
        public async Task<IActionResult> EnableAuthenticator()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (user.IsExternalUser())
            {
                return RedirectToAction("Index");
            }

            if (!await _userManager.GetTwoFactorEnabledAsync(user))
            {
                return RedirectToAction("MultiFactorAuthentication");
            }

            var vm = await BuildSetupAuthenticatorViewModelAsync(user);
            return View(vm);
        }

        [HttpPost]
        [Route("mfa/enable-authenticator-app")]
        [FeatureGate(FeatureToggles.MFA)]
        public async Task<IActionResult> EnableAuthenticator(SetupAuthenticatorViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (user.IsExternalUser())
            {
                return RedirectToAction("Index");
            }

            if (!await _userManager.GetTwoFactorEnabledAsync(user))
            {
                return RedirectToAction("MultiFactorAuthentication");
            }

            if (!ModelState.IsValid)
            {
                var vm = await BuildSetupAuthenticatorViewModelAsync(user);
                return View(vm);
            }

            // Strip spaces and hyphens
            var verificationCode = model.VerificationCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            var isTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

            if (!isTokenValid)
            {
                ModelState.AddModelError(nameof(model.VerificationCode), _localizer["Verification code is invalid."]);
                var vm = await BuildSetupAuthenticatorViewModelAsync(user);
                return View(vm);
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            var userId = await _userManager.GetUserIdAsync(user);
            _logger.LogInformation("User with ID '{UserId}' has enabled MFA with an authenticator app.", userId);

            TempData["StatusMessage"] = "Your authenticator app has been verified.";

            if (await _userManager.CountRecoveryCodesAsync(user) == 0)
            {
                var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                var vm = new RecoveryCodesViewModel
                {
                    RecoveryCodes = recoveryCodes.ToArray()
                };
                return View("ShowRecoveryCodes", vm);
            }
             
            return RedirectToAction("MultiFactorAuthentication");
        }

        [HttpGet]
        [Route("mfa/qrcode.png")]
        [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
        [FeatureGate(FeatureToggles.MFA)]
        public IActionResult GenerateQrCode()
        {
            var authenticatorUri = TempData["AuthenticatorUri"] as string;
            if (string.IsNullOrEmpty(authenticatorUri))
            {
                return NoContent();
            }

            using var qrCodeData = QRCodeGenerator.GenerateQrCode(authenticatorUri, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrCodeData);

            var pngBytes = qrCode.GetGraphic(20);
            return File(pngBytes, "image/png");
        }

        [HttpGet]
        [Route("mfa/reset-authenticator-app")]
        [FeatureGate(FeatureToggles.MFA)]
        public async Task<IActionResult> ResetAuthenticator()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (user.IsExternalUser())
            {
                return RedirectToAction("Index");
            }

            return View();
        }

        [HttpPost]
        [Route("mfa/reset-authenticator-app")]
        [FeatureGate(FeatureToggles.MFA)]
        public async Task<IActionResult> ResetAuthenticator(IFormCollection form)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (user.IsExternalUser())
            {
                return RedirectToAction("Index");
            }

            await _userManager.ResetAuthenticatorKeyAsync(user);
            _logger.LogInformation("User with ID '{UserId}' has reset their authentication app key.", user.Id);

            await _signInManager.RefreshSignInAsync(user);
            TempData["StatusMessage"] = "Your authenticator app key has been reset, you will need to configure your authenticator app using the new key.";

            return RedirectToAction("EnableAuthenticator");
        }

        [HttpGet]
        [Route("mfa/set-preferred-method")]
        [FeatureGate(FeatureToggles.MFA)]
        public async Task<IActionResult> SetPreferredMfaMethod([FromQuery] string type)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
            {
                return BadRequest();
            }

            if (user.IsExternalUser())
            {
                return RedirectToAction("Index");
            }

            if (!await _userManager.GetTwoFactorEnabledAsync(user))
            {
                return RedirectToAction("MultiFactorAuthentication");
            }

            await _userManager.SetPreferredTwoFactorMethod(user, type);
            _logger.LogInformation("User with ID '{UserId}' has set their MFA preference to {method}.", user.Id, type);

            TempData["StatusMessage"] = "Your preferences have been updated.";

            return RedirectToAction("MultiFactorAuthentication");
        }

        private async Task<SetupAuthenticatorViewModel> BuildSetupAuthenticatorViewModelAsync(IdentityExpressUser user)
        {
            // Load the authenticator key & QR code URI to display on the form
            var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            var vm = new SetupAuthenticatorViewModel
            {
                SharedKey = FormatAuthenticatorKey(unformattedKey)
            };

            var email = await _userManager.GetEmailAsync(user);
            TempData["AuthenticatorUri"] = GenerateQrCodeUri(email, unformattedKey);

            return vm;
        }

        private string FormatAuthenticatorKey(string unformattedKey)
        {
            var result = new StringBuilder();
            var currentPosition = 0;
            while (currentPosition + 4 < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition, 4)).Append(' ');
                currentPosition += 4;
            }
            if (currentPosition < unformattedKey.Length)
            {
                result.Append(unformattedKey[currentPosition..]);
            }

            return result.ToString().ToLowerInvariant();
        }

        private string GenerateQrCodeUri(string email, string unformattedKey)
        {
            return string.Format(
                AuthenticatorUriFormat,
                _urlEncoder.Encode(_configuration["AuthenticatorAppName"]),
                _urlEncoder.Encode(email),
                unformattedKey);
        }

        private async Task<MultiFactorAuthenticationViewModel> BuildMultiFactorAuthenticationViewModelAsync(IdentityExpressUser user)
        {
            var vm = new MultiFactorAuthenticationViewModel
            {
                IsMfaEnabled = await _userManager.GetTwoFactorEnabledAsync(user),
                Email = await _userManager.GetEmailAsync(user),
                Phone = await _userManager.GetPhoneNumberAsync(user),
                HasAuthenticator = await _userManager.GetAuthenticatorKeyAsync(user) != null,
                IsMachineRemembered = await _signInManager.IsTwoFactorClientRememberedAsync(user),
                RecoveryCodesLeft = await _userManager.CountRecoveryCodesAsync(user),
                PreferredType = await _userManager.GetPreferredTwoFactorMethod(user)
            };

            return vm;
        }

        private static class Routes
        {
            public const string ManageIndex = nameof(ManageIndex);
        }
    }
}
