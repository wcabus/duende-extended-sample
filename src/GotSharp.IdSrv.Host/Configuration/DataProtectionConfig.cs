using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

namespace GotSharp.IdSrv.Host.Configuration;

public class DataProtectionConfig
{
    private readonly Dictionary<string, List<X509Certificate2>> _certs = new(StringComparer.Ordinal);

    public string StorageType { get; set; }

    // Azure Blob storage or SQL connection string
    public string ConnectionString { get; set; }

    // Blob config
    public string ContainerName { get; set; }
    public string BlobName { get; set; } = "duende.idsrv.xml";

    public string KeyVaultUri { get; set; }
    public string KeyVaultKeyIdentifier { get; set; }
    public string KeyVaultCertificateName { get; set; }
    public TimeSpan CertificateRefreshingFrequency { get; set; } = TimeSpan.FromMinutes(15);
    public bool RefreshCertificates => !string.IsNullOrWhiteSpace(KeyVaultUri) && !string.IsNullOrWhiteSpace(KeyVaultCertificateName);

    /// <summary>
    /// In case you want to move away from certificates in favor of keys, or have revoked certificates,
    /// this list of old certificates can be used to unprotect data before protecting data with the new certificate or key.
    /// </summary>
    public string[] KeyVaultDeprecatedCertificateNames { get; set; }

    public int KeyDecryptionCertificateCount => _certs.Count;

    public bool TryGetKeyDecryptionCertificates(X509Certificate2 certInfo, [NotNullWhen(true)] out IReadOnlyList<X509Certificate2> keyDecryptionCerts)
    {
        var key = GetKey(certInfo);
        var retVal = _certs.TryGetValue(key, out var keyDecryptionCertsRetVal);
        keyDecryptionCerts = keyDecryptionCertsRetVal;
        return retVal;
    }

    public void SetKeyDecryptionCertificates(IEnumerable<X509Certificate2> certificates)
    {
        _certs.Clear();

        foreach (var certificate in certificates)
        {
            var key = GetKey(certificate);
            if (!_certs.TryGetValue(key, out var certs))
            {
                certs = _certs[key] = new List<X509Certificate2>();
            }

            certs.Add(certificate);
        }
    }

    private static string GetKey(X509Certificate2 cert) => cert.Thumbprint;
}