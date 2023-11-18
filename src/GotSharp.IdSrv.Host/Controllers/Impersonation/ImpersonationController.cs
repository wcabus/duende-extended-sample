using Duende.IdentityServer.Extensions;
using GotSharp.IdSrv.Host.Configuration;
using GotSharp.IdSrv.Host.Internal;
using GotSharp.IdSrv.Host.Services;
using IdentityExpress.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;

namespace GotSharp.IdSrv.Host.Controllers.Impersonation
{
    [Authorize]
    [SecurityHeaders]
    public class ImpersonationController : Controller
    {
        private readonly UserManager<IdentityExpressUser> _userManager;
        private readonly ImpersonationService _impersonationService;

        private readonly HomeRealmDiscoveryService _homeRealmDiscoveryService;
        private readonly IStringLocalizer<ImpersonationController> _localizer;
        
        public ImpersonationController(
            UserManager<IdentityExpressUser> userManager,
            ImpersonationService impersonationService,
            HomeRealmDiscoveryService homeRealmDiscoveryService,
            IStringLocalizer<ImpersonationController> localizer)
        {
            _userManager = userManager;
            _impersonationService = impersonationService;

            _homeRealmDiscoveryService = homeRealmDiscoveryService;
            _localizer = localizer;
        }

        [Route("~/impersonate")]
        public async Task<IActionResult> Index(string returnUrl = "")
        {
            if (!await _impersonationService.IsCurrentUserAllowedToImpersonateUsers(User))
            {
                return RedirectToAction("Index", "Home");
            }

            if (!User.IsImpersonating())
            {
                return View(new ImpersonateViewModel
                {
                    ReturnUrl = returnUrl
                });
            }

            var model = await BuildImpersonatingModel();
            return View("Impersonating", model);
        }

        [HttpPost]
        [Route("~/impersonate")]
        public async Task<IActionResult> PostIndex(ImpersonateViewModel model)
        {
            if (!await _impersonationService.IsCurrentUserAllowedToImpersonateUsers(User))
            {
                return RedirectToAction("Index", "Home");
            }

            if (User.IsImpersonating())
            {
                return RedirectToAction(nameof(Index));
            }

            IdentityExpressUser userToImpersonate = null;
            if (ModelState.IsValid)
            {
                userToImpersonate = await _userManager.FindByNameAsync(model.Email);
                if (userToImpersonate == null)
                {
                    ModelState.AddModelError(nameof(model.Email), _localizer["No user found."]);
                }

                var realm = _homeRealmDiscoveryService.DiscoverRealmFromUsername(model.Email);
                if (string.Equals(realm?.Provider, AuthProviders.AzureAD, StringComparison.OrdinalIgnoreCase))
                {
                    ModelState.AddModelError(nameof(model.Email), _localizer["Prohibited"]);
                }
            }

            if (!ModelState.IsValid || userToImpersonate is null)
            {
                return View("Index", model);
            }

            await _impersonationService.ImpersonateUser(User, userToImpersonate);

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [Route("~/impersonate/end-session")]
        public async Task<IActionResult> EndSession()
        {
            if (!await _impersonationService.IsCurrentUserAllowedToImpersonateUsers(User))
            {
                return RedirectToAction("Index", "Home");
            }

            if (!User.IsImpersonating())
            {
                return RedirectToAction(nameof(Index));
            }

            if (!await _impersonationService.SwitchBackToActualUser(User))
            {
                return RedirectToAction("Index", "Home");
            }

            return RedirectToAction(nameof(Index));
        }

        private Task<ImpersonateSessionViewModel> BuildImpersonatingModel()
        {
            return Task.FromResult(new ImpersonateSessionViewModel
            {
                Name = User.GetDisplayName()
            });
        }
    }
}
