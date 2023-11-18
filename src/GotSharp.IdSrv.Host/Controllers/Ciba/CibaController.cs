using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using GotSharp.IdSrv.Host.Controllers.Consent;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GotSharp.IdSrv.Host.Controllers.Ciba
{
    [SecurityHeaders]
    [Authorize]
    public class CibaController : Controller
    {
        private readonly IBackchannelAuthenticationInteractionService _backchannelAuthenticationInteractionService;
        private readonly IEventService _events;
        private readonly ILogger<CibaController> _logger;

        public CibaController(
            IBackchannelAuthenticationInteractionService backchannelAuthenticationInteractionService,
            IEventService events,
            ILogger<CibaController> logger)
        {
            _backchannelAuthenticationInteractionService = backchannelAuthenticationInteractionService;
            _events = events;
            _logger = logger;
        }

        [HttpGet]
        [Route("~/ciba")]
        public async Task<IActionResult> Index([FromQuery] string id)
        {
            var loginRequest = await _backchannelAuthenticationInteractionService.GetLoginRequestByInternalIdAsync(id);
            if (loginRequest is null)
            {
                _logger.LogWarning("Invalid backchannel login id {id}.", id);
                return RedirectToAction("Error", "Home");
            }

            return View(loginRequest);
        }

        [HttpGet]
        [Route("~/ciba/consent")]
        public async Task<IActionResult> Consent([FromQuery] string id)
        {
            var model = await BuildConsentViewModelAsync(id);
            if (model is null)
            {
                return RedirectToAction("Error", "Home");
            }

            var inputModel = new CibaConsentInputModel
            {
                Id = id
            };

            model.InputModel = inputModel;
            return View(model);
        }

        [HttpPost]
        [Route("~/ciba/consent")]
        public async Task<IActionResult> Consent([FromForm(Name = "InputModel")] CibaConsentInputModel model)
        {
            if (model is null)
            {
                _logger.LogError("CIBA consent failed, no model.");
                return RedirectToAction("Error", "Home");
            }

            var request = await _backchannelAuthenticationInteractionService.GetLoginRequestByInternalIdAsync(model.Id);
            if (request is null || request.Subject.GetSubjectId() != User.GetSubjectId())
            {
                _logger.LogError("Invalid id {id}", model.Id);
                return RedirectToAction("Error", "Home");
            }

            CompleteBackchannelLoginRequest result = null;

            if (model.Button == "no")
            {
                // access denied
                result = new CompleteBackchannelLoginRequest(model.Id);
                await _events.RaiseAsync(new ConsentDeniedEvent(User.GetSubjectId(), request.Client.ClientId, request.ValidatedResources.RawScopeValues));
            }
            else if (model.Button == "yes")
            {
                if (model.ScopesConsented?.Any() == true)
                {
                    var scopes = model.ScopesConsented;
                    if (!ConsentOptions.EnableOfflineAccess)
                    {
                        scopes = scopes.Where(x => x != IdentityServerConstants.StandardScopes.OfflineAccess);
                    }

                    result = new CompleteBackchannelLoginRequest(model.Id)
                    {
                        ScopesValuesConsented = scopes.ToArray(),
                        Description = model.Description
                    };

                    await _events.RaiseAsync(new ConsentGrantedEvent(User.GetSubjectId(), request.Client.ClientId, request.ValidatedResources.RawScopeValues, result.ScopesValuesConsented, false));
                }
                else
                {
                    // TODO Translate
                    ModelState.AddModelError("", ConsentOptions.MustChooseOneErrorMessage);
                }
            }
            else
            {
                // TODO Translate
                ModelState.AddModelError("", ConsentOptions.InvalidSelectionErrorMessage);
            }

            if (result != null)
            {
                await _backchannelAuthenticationInteractionService.CompleteLoginRequestAsync(result);
                return RedirectToAction("All");
            }

            var vm = await BuildConsentViewModelAsync(model.Id, model);
            return View(vm);
        }

        [HttpGet]
        [Route("~/ciba/all")]
        public async Task<IActionResult> All()
        {
            var logins = await _backchannelAuthenticationInteractionService.GetPendingLoginRequestsForCurrentUserAsync();
            var vm = new CibaPendingLoginsViewModel
            {
                Logins = logins
            };

            return View(vm);
        }

        private async Task<CibaConsentViewModel> BuildConsentViewModelAsync(string id, CibaConsentInputModel inputModel = null)
        {
            var request = await _backchannelAuthenticationInteractionService.GetLoginRequestByInternalIdAsync(id);
            if (request != null && request.Subject.GetSubjectId() == User.GetSubjectId())
            {
                return CreateConsentViewModel(inputModel, request);
            }

            _logger.LogError("No backchannel login request matching id: {id}", id);
            return null;
        }

        private CibaConsentViewModel CreateConsentViewModel(CibaConsentInputModel inputModel, BackchannelUserLoginRequest request)
        {
            var vm = new CibaConsentViewModel
            {
                ClientName = request.Client.ClientName ?? request.Client.ClientId,
                ClientUrl = request.Client.ClientUri,
                ClientLogoUrl = request.Client.LogoUri,
                BindingMessage = request.BindingMessage
            };

            vm.IdentityScopes = request.ValidatedResources.Resources.IdentityResources
                .Select(x => CreateScopeViewModel(x, inputModel?.ScopesConsented == null || inputModel.ScopesConsented?.Contains(x.Name) == true))
                .ToArray();

            var resourceIndicators = request.RequestedResourceIndicators ?? Enumerable.Empty<string>();
            var apiResources = request.ValidatedResources.Resources.ApiResources.Where(x => resourceIndicators.Contains(x.Name));

            var apiScopes = new List<ScopeViewModel>();
            foreach (var parsedScope in request.ValidatedResources.ParsedScopes)
            {
                var apiScope = request.ValidatedResources.Resources.FindApiScope(parsedScope.ParsedName);
                if (apiScope != null)
                {
                    var scopeVm = CreateScopeViewModel(parsedScope, apiScope, inputModel == null || inputModel.ScopesConsented?.Contains(parsedScope.RawValue) == true);
                    scopeVm.Resources = apiResources.Where(x => x.Scopes.Contains(parsedScope.ParsedName))
                        .Select(x => new ResourceViewModel
                        {
                            Name = x.Name,
                            DisplayName = x.DisplayName ?? x.Name,
                        }).ToArray();
                    apiScopes.Add(scopeVm);
                }
            }
            if (ConsentOptions.EnableOfflineAccess && request.ValidatedResources.Resources.OfflineAccess)
            {
                apiScopes.Add(GetOfflineAccessScope(inputModel == null || inputModel.ScopesConsented?.Contains(Duende.IdentityServer.IdentityServerConstants.StandardScopes.OfflineAccess) == true));
            }
            vm.ApiScopes = apiScopes;

            return vm;
        }

        private ScopeViewModel CreateScopeViewModel(IdentityResource identity, bool check)
        {
            return new ScopeViewModel
            {
                Name = identity.Name,
                Value = identity.Name,
                DisplayName = identity.DisplayName ?? identity.Name,
                Description = identity.Description,
                Emphasize = identity.Emphasize,
                Required = identity.Required,
                Checked = check || identity.Required
            };
        }

        public ScopeViewModel CreateScopeViewModel(ParsedScopeValue parsedScopeValue, ApiScope apiScope, bool check)
        {
            var displayName = apiScope.DisplayName ?? apiScope.Name;
            if (!string.IsNullOrWhiteSpace(parsedScopeValue.ParsedParameter))
            {
                displayName += ":" + parsedScopeValue.ParsedParameter;
            }

            return new ScopeViewModel
            {
                Name = parsedScopeValue.ParsedName,
                Value = parsedScopeValue.RawValue,
                DisplayName = displayName,
                Description = apiScope.Description,
                Emphasize = apiScope.Emphasize,
                Required = apiScope.Required,
                Checked = check || apiScope.Required
            };
        }

        private ScopeViewModel GetOfflineAccessScope(bool check)
        {
            return new ScopeViewModel
            {
                Value = Duende.IdentityServer.IdentityServerConstants.StandardScopes.OfflineAccess,
                DisplayName = ConsentOptions.OfflineAccessDisplayName,
                Description = ConsentOptions.OfflineAccessDescription,
                Emphasize = true,
                Checked = check
            };
        }
    }
}
