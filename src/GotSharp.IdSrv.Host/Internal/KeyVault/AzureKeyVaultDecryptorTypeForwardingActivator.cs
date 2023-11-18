using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection.Internal;
using Microsoft.Extensions.Logging.Abstractions;

namespace GotSharp.IdSrv.Host.Internal.KeyVault;

internal class AzureKeyVaultDecryptorTypeForwardingActivator : IActivator
{
    private const string OldNamespace = "Microsoft.AspNet.DataProtection";
    private const string CurrentNamespace = "Microsoft.AspNetCore.DataProtection";
    private const string CurrentCustomNamespace = "GotSharp.IdSrv.Host";

    private const string OldDecryptor = "Microsoft.AspNetCore.DataProtection.XmlEncryption.EncryptedXmlDecryptor";
    private const string OldDecryptorAssembly = "Microsoft.AspNetCore.DataProtection";
    private const string NewDecryptor = "GotSharp.IdSrv.Host.Internal.KeyVault.AzureKeyVaultXmlDecryptor";
    private const string NewDecryptorAssembly = "GotSharp.IdSrv.Host";

    private static readonly Regex VersionPattern = new(@",\s?Version=[0-9]+(\.[0-9]+){0,3}", RegexOptions.Compiled, TimeSpan.FromSeconds(2));
    private static readonly Regex TokenPattern = new(@",\s?PublicKeyToken=[\w\d]+", RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private readonly IServiceProvider _services;
    private readonly ILogger _logger;

    public AzureKeyVaultDecryptorTypeForwardingActivator(IServiceProvider services) : this(services, NullLoggerFactory.Instance)
    {

    }

    public AzureKeyVaultDecryptorTypeForwardingActivator(IServiceProvider services, ILoggerFactory loggerFactory)
    {
        _services = services;
        _logger = loggerFactory.CreateLogger(typeof(AzureKeyVaultDecryptorTypeForwardingActivator));
    }

    public object CreateInstance(Type expectedBaseType, string originalTypeName)
    {
        var forwardedTypeName = originalTypeName;
        var candidate = false;
        if (originalTypeName.Contains(OldNamespace))
        {
            candidate = true;
            forwardedTypeName = originalTypeName.Replace(OldNamespace, CurrentNamespace);
        }

        if (originalTypeName.Contains(OldDecryptor))
        {
            candidate = true;
            forwardedTypeName = originalTypeName
                .Replace(OldDecryptor, NewDecryptor)
                .Replace(OldDecryptorAssembly, NewDecryptorAssembly);
        }

        if (candidate || forwardedTypeName.StartsWith(CurrentNamespace + ".", StringComparison.Ordinal) ||
            forwardedTypeName.StartsWith(CurrentCustomNamespace + ".", StringComparison.Ordinal))
        {
            candidate = true;
            forwardedTypeName = RemoveVersionFromAssemblyName(forwardedTypeName);
            forwardedTypeName = RemovePublicKeyTokenFromAssemblyName(forwardedTypeName);
        }

        if (candidate)
        {
            var type = Type.GetType(forwardedTypeName, false);
            if (type != null)
            {
                _logger.LogDebug("Forwarded activator type request from {FromType} to {ToType}",
                    originalTypeName,
                    forwardedTypeName);

                return CreateInstanceImpl(expectedBaseType, forwardedTypeName);
            }
        }

        return CreateInstanceImpl(expectedBaseType, originalTypeName);
    }

    private static string RemovePublicKeyTokenFromAssemblyName(string forwardedTypeName)
        => TokenPattern.Replace(forwardedTypeName, "");

    internal static string RemoveVersionFromAssemblyName(string forwardedTypeName)
        => VersionPattern.Replace(forwardedTypeName, "");

    private object CreateInstanceImpl(Type expectedBaseType, string implementationTypeName)
    {
        // Would the assignment even work?
        var implementationType = Type.GetType(implementationTypeName, throwOnError: true);

        if (!expectedBaseType.IsAssignableFrom(implementationType))
        {
            // It might seem a bit strange to throw an InvalidCastException explicitly rather than
            // to let the CLR generate one, but searching through NetFX there is indeed precedent
            // for this pattern when the caller knows ahead of time the operation will fail.
            throw new InvalidCastException($"The type '{implementationType.AssemblyQualifiedName}' is not assignable to '{expectedBaseType.AssemblyQualifiedName}'.");
        }

        // If no IServiceProvider was specified, prefer .ctor() [if it exists]
        if (_services == null)
        {
            var ctorParameterless = implementationType.GetConstructor(Type.EmptyTypes);
            if (ctorParameterless != null)
            {
                return Activator.CreateInstance(implementationType);
            }
        }

        // If an IServiceProvider was specified or if .ctor() doesn't exist, prefer .ctor(IServiceProvider) [if it exists]
        var ctorWhichTakesServiceProvider = implementationType.GetConstructor(new Type[] { typeof(IServiceProvider) });
        if (ctorWhichTakesServiceProvider != null)
        {
            return ctorWhichTakesServiceProvider.Invoke(new[] { _services });
        }

        // Finally, prefer .ctor() as an ultimate fallback.
        // This will throw if the ctor cannot be called.
        return Activator.CreateInstance(implementationType);
    }
}