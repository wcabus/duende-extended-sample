// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using System.Globalization;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GotSharp.IdSrv.Host.Controllers.Grants
{
    /// <summary>
    /// This sample controller allows a user to revoke grants given to clients
    /// </summary>
    [SecurityHeaders]
    [Authorize]
    public class GrantsController : Controller
    {
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clients;
        private readonly IResourceStore _resources;
        private readonly IEventService _events;

        public GrantsController(IIdentityServerInteractionService interaction,
            IClientStore clients,
            IResourceStore resources,
            IEventService events)
        {
            _interaction = interaction;
            _clients = clients;
            _resources = resources;
            _events = events;
        }

        /// <summary>
        /// Show list of grants
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            return View("Index", await BuildViewModelAsync());
        }

        /// <summary>
        /// Handle postback to revoke a client
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Revoke(string clientId)
        {
            await _interaction.RevokeUserConsentAsync(clientId);
            await _events.RaiseAsync(new GrantsRevokedEvent(User.GetSubjectId(), clientId));

            return RedirectToAction("Index");
        }

        private async Task<GrantsViewModel> BuildViewModelAsync()
        {
            var grants = await _interaction.GetAllUserGrantsAsync();

            var list = new List<GrantViewModel>();
            foreach(var grant in grants)
            {
                var client = await _clients.FindClientByIdAsync(grant.ClientId);
                if (client != null)
                {
                    var resources = await _resources.FindResourcesByScopeAsync(grant.Scopes);

                    var item = new GrantViewModel
                    {
                        ClientId = client.ClientId,
                        ClientName = client.ClientName ?? client.ClientId,
                        ClientLogoUrl = client.LogoUri,
                        ClientUrl = client.ClientUri,
                        Description = grant.Description,
                        Created = grant.CreationTime,
                        Expires = grant.Expiration
                    };

                    /*
                     * IdentityGrantNames = resources.IdentityResources.Select(x => x.DisplayName ?? x.Name).ToArray(),
                        ApiGrantNames = resources.ApiScopes.Select(x => x.DisplayName ?? x.Name).ToArray()
                     */

                    var culture = CultureInfo.CurrentUICulture;
                    var resourceNames = new List<string>();
                    foreach (var identityResource in resources.IdentityResources)
                    {
                        var name = identityResource.DisplayName ?? identityResource.Name;
                        var key = $"translation:name:{culture.Name}";
                        if (identityResource.Properties is {Count: > 0} && identityResource.Properties.TryGetValue(key, out var translatedName))
                        {
                            name = translatedName;
                        }
                        resourceNames.Add(name);
                    }

                    item.IdentityGrantNames = resourceNames.ToArray();

                    resourceNames.Clear();
                    foreach (var apiResource in resources.ApiResources)
                    {
                        var name = apiResource.DisplayName ?? apiResource.Name;
                        var key = $"translation:name:{culture.Name}";
                        if (apiResource.Properties is { Count: > 0 } && apiResource.Properties.TryGetValue(key, out var translatedName))
                        {
                            name = translatedName;
                        }
                        resourceNames.Add(name);
                    }

                    item.ApiGrantNames = resourceNames.ToArray();
                    list.Add(item);
                }
            }

            return new GrantsViewModel
            {
                Grants = list
            };
        }
    }
}