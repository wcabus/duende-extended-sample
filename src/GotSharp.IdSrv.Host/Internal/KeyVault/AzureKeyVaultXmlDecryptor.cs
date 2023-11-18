using GotSharp.IdSrv.Host.Configuration;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.Options;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml.Linq;
using System.Xml;

namespace GotSharp.IdSrv.Host.Internal.KeyVault;

internal class AzureKeyVaultXmlDecryptor : IXmlDecryptor
{
    private readonly DataProtectionConfig _options;

    public AzureKeyVaultXmlDecryptor(IServiceProvider serviceProvider)
    {
        _options = serviceProvider.GetRequiredService<IOptions<DataProtectionConfig>>().Value;
    }

    public XElement Decrypt(XElement encryptedElement)
    {
        ArgumentNullException.ThrowIfNull(encryptedElement);

        var xmlDocument = new XmlDocument();
        xmlDocument.Load(new XElement("root", encryptedElement).CreateReader());

        // Perform the decryption and update the document in-place.
        var encryptedXml = new EncryptedXmlWithCertificateKeys(_options, xmlDocument);

        encryptedXml.DecryptDocument();

        // Strip the <root /> element back off and convert the XmlDocument to an XElement.
        return XElement.Load(xmlDocument.DocumentElement!.FirstChild!.CreateNavigator()!.ReadSubtree());
    }

    private class EncryptedXmlWithCertificateKeys : EncryptedXml
    {
        private readonly DataProtectionConfig _options;

        public EncryptedXmlWithCertificateKeys(DataProtectionConfig options, XmlDocument xmlDocument) : base(xmlDocument)
        {
            _options = options;
        }

        public override byte[] DecryptEncryptedKey(EncryptedKey encryptedKey)
        {
            var keyInfoEnum = encryptedKey.KeyInfo?.GetEnumerator();
            if (keyInfoEnum == null)
            {
                return null;
            }

            while (keyInfoEnum.MoveNext())
            {
                if (keyInfoEnum.Current is not KeyInfoX509Data kiX509Data)
                {
                    continue;
                }

                var key = GetKeyFromCert(encryptedKey, kiX509Data);
                if (key != null)
                {
                    return key;
                }
            }

            return base.DecryptEncryptedKey(encryptedKey);
        }

        private byte[] GetKeyFromCert(EncryptedKey encryptedKey, KeyInfoX509Data keyInfo)
        {
            var certEnum = keyInfo.Certificates?.GetEnumerator();
            if (certEnum == null)
            {
                return null;
            }

            while (certEnum.MoveNext())
            {
                if (certEnum.Current is not X509Certificate2 certInfo)
                {
                    continue;
                }

                if (_options == null || !_options.TryGetKeyDecryptionCertificates(certInfo, out var keyDecryptionCerts))
                {
                    continue;
                }

                foreach (var keyDecryptionCert in keyDecryptionCerts)
                {
                    if (!keyDecryptionCert.HasPrivateKey)
                    {
                        continue;
                    }

                    using (var privateKey = keyDecryptionCert.GetRSAPrivateKey())
                    {
                        if (privateKey == null)
                        {
                            continue;
                        }

                        var useOAEP = encryptedKey.EncryptionMethod?.KeyAlgorithm == XmlEncRSAOAEPUrl;
                        var result = DecryptKey(encryptedKey.CipherData.CipherValue, privateKey, useOAEP);

                        // Check the result so that we can potentially retry using a different, valid, private key
                        if (result != null)
                        {
                            return result;
                        }
                    }
                }
            }

            return null;
        }
    }
}