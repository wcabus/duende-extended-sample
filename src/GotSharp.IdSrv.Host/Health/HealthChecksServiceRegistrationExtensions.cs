using GotSharp.IdSrv.Host.Health;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.Extensions.Options;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Diagnostics.HealthChecks;

internal static class HealthChecksServiceRegistrationExtensions
{
    public static IHealthChecksBuilder AddApplicationInsightsPublisher(this IHealthChecksBuilder builder,
        string connectionString,
        bool generateDetailedReports = false,
        bool excludeHealthyReports = false,
        Action<HealthCheckPublisherOptions> configureAction = null)
    {
        if (configureAction != null)
        {
            builder.Services.Configure(configureAction);
        }

        builder.Services.AddSingleton<IHealthCheckPublisher>(sp =>
        {
            var telemetryConfigurationOptions = sp.GetRequiredService<IOptions<TelemetryConfiguration>>();
            return new ApplicationInsightsHealthCheckPublisher(telemetryConfigurationOptions, connectionString, generateDetailedReports, excludeHealthyReports);
        });

        return builder;
    }
}