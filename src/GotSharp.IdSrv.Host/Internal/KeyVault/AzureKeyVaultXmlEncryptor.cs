using Azure.Security.KeyVault.Certificates;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml.Linq;
using System.Xml;

namespace GotSharp.IdSrv.Host.Internal.KeyVault;

internal class AzureKeyVaultXmlEncryptor : IXmlEncryptor
{
    private readonly string _certificateName;
    private readonly CertificateClient _certificateClient;
    private readonly ILogger<AzureKeyVaultXmlEncryptor> _logger;

    public AzureKeyVaultXmlEncryptor(string certificateName, CertificateClient certificateClient, ILoggerFactory loggerFactory)
    {
        _certificateName = certificateName;
        _certificateClient = certificateClient;
        _logger = loggerFactory.CreateLogger<AzureKeyVaultXmlEncryptor>();
    }

    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        return Task.Run(() => EncryptElementAsync(plaintextElement)).GetAwaiter().GetResult();
    }

    private async Task<EncryptedXmlInfo> EncryptElementAsync(XElement plainTextElement)
    {
        var certInfo = await _certificateClient.GetCertificateAsync(_certificateName);
        var cert = new X509Certificate2(certInfo.Value.Cer); // public key only, but that's enough for encryption purposes.

        return EncryptElement(plainTextElement, cert);
    }

    private EncryptedXmlInfo EncryptElement(XElement plaintextElement, X509Certificate2 cert)
    {
        // EncryptedXml works with XmlDocument, not XLinq. When we perform the conversion
        // we'll wrap the incoming element in a dummy <root /> element since encrypted XML
        // doesn't handle encrypting the root element all that well.
        var xmlDocument = new XmlDocument();
        xmlDocument.Load(new XElement("root", plaintextElement).CreateReader());
        var elementToEncrypt = (XmlElement)xmlDocument.DocumentElement!.FirstChild!;

        // Perform the encryption and update the document in-place.
        var encryptedXml = new EncryptedXml(xmlDocument);
        var encryptedData = PerformEncryption(encryptedXml, elementToEncrypt, cert);
        EncryptedXml.ReplaceElement(elementToEncrypt, encryptedData, content: false);

        // Strip the <root /> element back off and convert the XmlDocument to an XElement.
        var encryptedElement = XElement.Load(xmlDocument.DocumentElement.FirstChild!.CreateNavigator()!.ReadSubtree());

        return new EncryptedXmlInfo(encryptedElement, typeof(AzureKeyVaultXmlDecryptor));
    }

    private EncryptedData PerformEncryption(EncryptedXml encryptedXml, XmlElement elementToEncrypt, X509Certificate2 cert)
    {
        _logger.LogDebug("Encrypting to X.509 certificate with thumbprint '{Thumbprint}'.", cert.Thumbprint);

        try
        {
            return encryptedXml.Encrypt(elementToEncrypt, cert);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while encrypting to X.509 certificate with thumbprint '{Thumbprint}'.", cert.Thumbprint);
            throw;
        }
    }
}