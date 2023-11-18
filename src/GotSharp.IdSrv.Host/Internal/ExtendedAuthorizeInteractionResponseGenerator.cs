using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.ResponseHandling;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;

namespace GotSharp.IdSrv.Host.Internal;

internal class ExtendedAuthorizeInteractionResponseGenerator : AuthorizeInteractionResponseGenerator
{
    public ExtendedAuthorizeInteractionResponseGenerator(
        IdentityServerOptions options,
        ISystemClock clock,
        ILogger<AuthorizeInteractionResponseGenerator> logger,
        IConsentService consent,
        IProfileService profile
    ) : base(options, clock, logger, consent, profile)
    {
    }

    protected override async Task<InteractionResponse> ProcessLoginAsync(ValidatedAuthorizeRequest request)
    {
        var promptLoginSet = request.PromptModes.Contains(OidcConstants.PromptModes.Login) ||
                             request.PromptModes.Contains(OidcConstants.PromptModes.SelectAccount);

        var result = await base.ProcessLoginAsync(request);
        if (result.IsLogin && promptLoginSet && request.Subject.IsImpersonating())
        {
            result.IsLogin = false;
        }

        return result;
    }
}