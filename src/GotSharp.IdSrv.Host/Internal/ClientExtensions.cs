using Duende.IdentityServer.Models;

namespace GotSharp.IdSrv.Host.Internal;

internal static class ClientExtensions
{
    public const string MultiFactorBypassedKey = "MultiFactorAuthentication:Bypassed";
    public const string MultiFactorRequiredKey = "MultiFactorAuthentication:Required";

    public static bool BypassMultiFactor(this Client client)
    {
        if (client == null)
        {
            return false;
        }

        if (!client.Properties.ContainsKey(MultiFactorBypassedKey))
        {
            return false;
        }

        return bool.TryParse(client.Properties[MultiFactorBypassedKey], out var bypassed) && bypassed;
    }

    public static bool IsMultiFactorRequired(this Client client)
    {
        if (client == null)
        {
            return false;
        }

        if (!client.Properties.ContainsKey(MultiFactorRequiredKey))
        {
            return false;
        }

        return bool.TryParse(client.Properties[MultiFactorRequiredKey], out var required) && required;
    }

    public static string GetInitiateLoginUri(this Client client)
    {
        if (client is null)
        {
            return null;
        }

        if (!string.IsNullOrEmpty(client.InitiateLoginUri))
        {
            return client.InitiateLoginUri;
        }

        const string key = nameof(Client.InitiateLoginUri);
        return !client.Properties.ContainsKey(key) ? null : client.Properties[key];
    }
}