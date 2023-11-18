using Azure.Security.KeyVault.Certificates;
using GotSharp.IdSrv.Host.Configuration;
using Microsoft.Extensions.Options;
using System.Security.Cryptography.X509Certificates;

namespace GotSharp.IdSrv.Host.Internal.KeyVault;

/// <summary>
/// Hosted service that retrieves and refreshes the certificates (and versions) into a DataProtectionConfig instance
/// </summary>
internal class AzureKeyVaultCertificateRefresher : IHostedService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly DataProtectionConfig _options;
    private readonly ILogger<AzureKeyVaultCertificateRefresher> _logger;

    private CancellationTokenSource _tokenSource;

    public AzureKeyVaultCertificateRefresher(IServiceProvider serviceProvider, IOptions<DataProtectionConfig> optionsAccessor, ILogger<AzureKeyVaultCertificateRefresher> logger)
    {
        _serviceProvider = serviceProvider;
        _options = optionsAccessor.Value;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_options.RefreshCertificates)
        {
            if (_tokenSource != null)
            {
                throw new InvalidOperationException("Hosted service has already started.");
            }

            _logger.LogDebug("Starting Azure Key Vault certificate refreshing hosted service...");
            _tokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            Task.Factory.StartNew(() => StartRefresherAsync(_tokenSource.Token), cancellationToken);
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        if (_options.RefreshCertificates)
        {
            if (_tokenSource == null)
            {
                throw new InvalidOperationException("Hosted service has not started.");
            }

            _logger.LogDebug("Stopping Azure Key Vault certificate refreshing hosted service...");

            _tokenSource.Cancel();
            _tokenSource = null;
        }

        return Task.CompletedTask;
    }

    private async Task StartRefresherAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                _logger.LogDebug("Cancellation has been requested. Stopping service...");
                break;
            }

            await RefreshAsync(cancellationToken);

            try
            {
                await Task.Delay(_options.CertificateRefreshingFrequency, cancellationToken);
            }
            catch (TaskCanceledException)
            {
                _logger.LogDebug("TaskCanceledException during Task.Delay. Exiting service...");
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception occurred during a Task.Delay operation. Exiting service...");
                break;
            }

            if (cancellationToken.IsCancellationRequested)
            {
                _logger.LogDebug("Cancellation has been requested. Stopping service...");
                break;
            }
        }
    }

    private async Task RefreshAsync(CancellationToken cancellationToken)
    {
        if (!_options.RefreshCertificates)
        {
            return;
        }

        try
        {
            using (var scope = _serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                var logger = scope.ServiceProvider.GetRequiredService<ILogger<AzureKeyVaultCertificateRefresher>>();
                var options = scope.ServiceProvider.GetRequiredService<IOptions<DataProtectionConfig>>().Value;
                var certificateClient = scope.ServiceProvider.GetRequiredService<CertificateClient>();

                await RefreshCertificatesAsync(options, certificateClient, logger, cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception while refreshing certificates!");
        }
    }

    public static async Task RefreshCertificatesAsync(DataProtectionConfig options, CertificateClient certificateClient, ILogger logger, CancellationToken cancellationToken = default)
    {
        var certificateNames = new List<string>
            {
                options.KeyVaultCertificateName
            };

        if (options.KeyVaultDeprecatedCertificateNames is { Length: > 0 })
        {
            certificateNames.AddRange(options.KeyVaultDeprecatedCertificateNames);
        }

        var certificates = new List<X509Certificate2>();

        foreach (var certificateName in certificateNames)
        {
            await FindAndAddCertificateAsync(certificateClient, certificateName, certificates, logger, cancellationToken);
        }

        logger.LogDebug("Found {CertificateCount} certificates in Key Vault", certificates.Count);

        options.SetKeyDecryptionCertificates(certificates);

        logger.LogDebug("Updated certificates in DataProtectionConfig");
    }

    private static async Task FindAndAddCertificateAsync(CertificateClient certificateClient, string certificateName, IList<X509Certificate2> certificates, ILogger logger, CancellationToken cancellationToken)
    {
        var versionList = certificateClient.GetPropertiesOfCertificateVersionsAsync(certificateName, cancellationToken);
        try
        {
            await foreach (var version in versionList)
            {
                if (version is null || version.Enabled != true)
                {
                    continue;
                }

                var certificate = await certificateClient.DownloadCertificateAsync(new DownloadCertificateOptions(version.Name)
                {
                    Version = version.Version
                }, cancellationToken);

                if (certificate.Value is null)
                {
                    continue;
                }

                certificates.Add(certificate.Value);
            }
        }
        catch (TaskCanceledException)
        {
            logger.LogDebug("TaskCanceledException during FindAndAddCertificateAsync. Keeping old list of certificates...");
        }
    }
}