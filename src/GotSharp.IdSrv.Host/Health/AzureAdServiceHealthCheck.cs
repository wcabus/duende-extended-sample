using GotSharp.IdSrv.Host.Services.AzureAD;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace GotSharp.IdSrv.Host.Health;

internal class AzureAdServiceHealthCheck : IHealthCheck
{
    private readonly IAzureAdService _azureAdService;

    public AzureAdServiceHealthCheck(IAzureAdService azureAdService)
    {
        _azureAdService = azureAdService;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = new CancellationToken())
    {
        try
        {
            await _azureAdService.Ping(cancellationToken);

            return HealthCheckResult.Healthy();
        }
        catch (Exception ex)
        {
            return new HealthCheckResult(context.Registration.FailureStatus, exception: ex);
        }
    }
}