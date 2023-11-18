// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using System.Text;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Services;
using GotSharp.IdSrv.Host.Configuration;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace GotSharp.IdSrv.Host.Controllers
{
    public class SecurityHeadersAttribute : ActionFilterAttribute
    {
        public override async Task OnResultExecutionAsync(ResultExecutingContext context, ResultExecutionDelegate next)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (next == null)
            {
                throw new ArgumentNullException(nameof(next));
            }

            await OnResultExecutingAsync(context);
            if (!context.Cancel)
            {
                OnResultExecuted(await next());
            }
        }

        public async Task OnResultExecutingAsync(ResultExecutingContext context)
        {
            var result = context.Result;
            if (result is not ViewResult)
            {
                return;
            }

            // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
            if (!context.HttpContext.Response.Headers.ContainsKey("X-Content-Type-Options"))
            {
                context.HttpContext.Response.Headers.Add("X-Content-Type-Options", "nosniff");
            }

            // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
            if (!context.HttpContext.Response.Headers.ContainsKey("X-Frame-Options"))
            {
                context.HttpContext.Response.Headers.Add("X-Frame-Options", "SAMEORIGIN");
            }
                
            // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
            var referrer_policy = "no-referrer";
            if (!context.HttpContext.Response.Headers.ContainsKey("Referrer-Policy"))
            {
                context.HttpContext.Response.Headers.Add("Referrer-Policy", referrer_policy);
            }

            // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
            // Added for legacy reasons
            if (!context.HttpContext.Response.Headers.ContainsKey("X-XSS-Protection"))
            {
                context.HttpContext.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
            }

            await AddCspHeaderAsync(context);
        }
        
        private async Task AddCspHeaderAsync(ResultExecutingContext context)
        {
            var cspOptions = context.HttpContext.RequestServices.GetService<ContentSecurityPolicyOptions>() ?? new ContentSecurityPolicyOptions();
            
            // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
            var cspBuilder = new StringBuilder();
            cspBuilder.Append("default-src 'self' gotsharp.be *.gotsharp.be; object-src 'none'; sandbox allow-forms allow-same-origin allow-scripts; base-uri 'self';");

            var clientSources = await GetClientSourcesFromContextAsync(context);

            var sources = GetCspSources(cspOptions.ImageSources, includeSelf: true);
            AddCspSources(cspBuilder, "img-src", sources);

            sources = GetCspSources(cspOptions.ScriptSources, includeSelf: true);
            AddCspSources(cspBuilder, "script-src", sources);

            sources = GetCspSources(cspOptions.StyleSources, includeSelf: true);
            AddCspSources(cspBuilder, "style-src", sources);

            sources = GetCspSources(cspOptions.FontSources, includeSelf: false);
            AddCspSources(cspBuilder, "font-src", sources);

            sources = GetCspSources(cspOptions.FrameSources, includeSelf: true);
            AddCspSources(cspBuilder, "frame-src", sources);

            sources = GetCspSources(cspOptions.ConnectSources, includeSelf: false);
            AddCspSources(cspBuilder, "connect-src", sources);

            sources = GetCspSources(cspOptions.FrameAncestors);
            if (sources.Count > 0)
            {
                AddCspSources(cspBuilder, "frame-ancestors", sources);
            }
            else
            {
                cspBuilder.Append(" frame-ancestors 'none';");
            }

            sources = GetCspSources(cspOptions.FormActions, includeSelf: true);
            // Some browsers block form posts when the server returns a 302/307 redirect to an address not in the CSP after POSTing (which is what happens in the login flow)
            sources.AddRange(clientSources);
            AddCspSources(cspBuilder, "form-action", sources);

            cspBuilder.Append(" upgrade-insecure-requests;");
            
            var csp = cspBuilder.ToString();
            // Add once for standards compliant browsers
            if (!context.HttpContext.Response.Headers.ContainsKey("Content-Security-Policy"))
            {
                context.HttpContext.Response.Headers.Add("Content-Security-Policy", csp);
            }
            // and once again for IE
            if (!context.HttpContext.Response.Headers.ContainsKey("X-Content-Security-Policy"))
            {
                context.HttpContext.Response.Headers.Add("X-Content-Security-Policy", csp);
            }
        }

        /// <summary>
        /// Retrieve dynamic CSP (form-action) sources based on the current authorization context, if any.
        /// </summary>
        private async Task<IEnumerable<string>> GetClientSourcesFromContextAsync(ResultExecutingContext context)
        {
            var httpContext = context.HttpContext;
            var interaction = httpContext.RequestServices.GetService<IIdentityServerInteractionService>();
            if (interaction is null)
            {
                return Array.Empty<string>();
            }

            var options = httpContext.RequestServices.GetService<IdentityServerOptions>();
            if (options is null)
            {
                return Array.Empty<string>();
            }

            var returnUrl = httpContext.Request.Query[options.UserInteraction.LoginReturnUrlParameter];
            if (string.IsNullOrEmpty(returnUrl))
            {
                return Array.Empty<string>();
            }

            var authorizationContext = await interaction.GetAuthorizationContextAsync(returnUrl);
            if (authorizationContext is null)
            {
                return Array.Empty<string>();
            }

            var clientOrigins = new List<string>();
            foreach (var clientRedirectUri in authorizationContext.Client.RedirectUris)
            {
                var origin = new Uri(clientRedirectUri).GetLeftPart(UriPartial.Authority); // scheme://authority (includes port if necessary)
                if (!clientOrigins.Contains(origin))
                {
                    clientOrigins.Add(origin);
                }
            }

            return clientOrigins;
        }

        private void AddCspSources(StringBuilder cspBuilder, string directive, IReadOnlyCollection<string> sources)
        {
            if (sources.Count == 0)
            {
                return;
            }

            cspBuilder.Append(' ').Append(directive);
            foreach (var source in sources.Distinct())
            {
                var isHashOrNonceOrSelf = source.StartsWith("sha256-", StringComparison.Ordinal) ||
                                         source.StartsWith("sha384-", StringComparison.Ordinal) ||
                                         source.StartsWith("sha512-", StringComparison.Ordinal) ||
                                         source.StartsWith("nonce-", StringComparison.Ordinal) ||
                                         source.StartsWith("self", StringComparison.Ordinal);

                if (isHashOrNonceOrSelf)
                {
                    cspBuilder.Append(' ').Append('\'').Append(source).Append('\'');
                }
                else
                {
                    cspBuilder.Append(' ').Append(source);
                }
            }

            cspBuilder.Append(';');
        }

        private List<string> GetCspSources(string sourceList, bool includeSelf = false)
        {
            var sources = string.IsNullOrWhiteSpace(sourceList)
                ? new List<string>()
                : sourceList.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).ToList();

            switch (includeSelf)
            {
                case false when sources.Count == 0:
                    return new List<string>();
                case true:
                    sources.Insert(0, "self");
                    break;
            }

            return sources;
        }
    }
}
