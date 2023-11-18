using GotSharp.IdSrv.Host.Configuration;
using GotSharp.IdSrv.Host.Services.Contracts;
using Microsoft.Extensions.Options;

namespace GotSharp.IdSrv.Host.Internal;

internal class DefaultCallbackUrlGenerator : ICallbackUrlGenerator
{
    private readonly SendGridOptions _sendGridOptions;

    public DefaultCallbackUrlGenerator(IOptionsSnapshot<SendGridOptions> sendGridOptionsSnapshot)
    {
        _sendGridOptions = sendGridOptionsSnapshot.Value;
    }

    public Task<string> GenerateUrl(string localUrl, string username = null)
    {
        // username is unused here
        var baseUrl = _sendGridOptions.CallbackBaseUrl;

        return string.IsNullOrWhiteSpace(localUrl)
            ? Task.FromResult(baseUrl)
            : Task.FromResult(baseUrl.RemoveTrailingSlash() + localUrl.EnsureLeadingSlash());
    }
}