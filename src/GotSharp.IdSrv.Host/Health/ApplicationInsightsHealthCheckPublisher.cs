using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.ApplicationInsights;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using System.Reflection;

namespace GotSharp.IdSrv.Host.Health;

internal class ApplicationInsightsHealthCheckPublisher : IHealthCheckPublisher
{
    private readonly TelemetryConfiguration _telemetryConfiguration;
    private readonly bool _generateDetailedReports;
    private readonly bool _excludeHealthyReports;

    private static TelemetryClient _telemetryClient;
    private static readonly object StaticLock = new();

    private const string EventName = "HealthCheck";
    private const string StatusMetricName = "HealthCheckStatus";
    private const string DurationMetricName = "HealthCheckDuration";
    private const string HealthCheckName = "HealthCheckName";

    public ApplicationInsightsHealthCheckPublisher(
        IOptions<TelemetryConfiguration> telemetryConfiguration,
        string connectionString,
        bool generateDetailedReports = false,
        bool excludeHealthyReports = false)
    {
        _telemetryConfiguration = telemetryConfiguration.Value;
        if (!string.IsNullOrEmpty(connectionString))
        {
            _telemetryConfiguration.ConnectionString = connectionString;
        }

        _generateDetailedReports = generateDetailedReports;
        _excludeHealthyReports = excludeHealthyReports;
    }

    public Task PublishAsync(HealthReport report, CancellationToken cancellationToken)
    {
        if (report.Status == HealthStatus.Healthy && _excludeHealthyReports)
        {
            return Task.CompletedTask;
        }

        var client = GetTelemetryClientInstance();

        if (_generateDetailedReports)
        {
            GenerateDetailedReport(report, client);
        }
        else
        {
            GenerateStandardReport(report, client);
        }

        return Task.CompletedTask;
    }

    private void GenerateStandardReport(HealthReport report, TelemetryClient client)
    {
        client.TrackEvent(EventName,
            new Dictionary<string, string>
            {
                    { nameof(Environment.MachineName), Environment.MachineName },
                    { nameof(Assembly), Assembly.GetEntryAssembly()?.GetName().Name }
            },
            new Dictionary<string, double>
            {
                    { StatusMetricName, report.Status switch
                    {
                        HealthStatus.Healthy => 1,
                        HealthStatus.Degraded => 0,
                        _ => -1
                    } },
                    { DurationMetricName, report.TotalDuration.TotalMilliseconds }
            });
    }

    private void GenerateDetailedReport(HealthReport report, TelemetryClient client)
    {
        foreach (var reportEntry in report.Entries.Where(entry => !_excludeHealthyReports || entry.Value.Status != HealthStatus.Healthy))
        {
            client.TrackEvent($"{EventName}:{reportEntry.Key}",
                properties: new Dictionary<string, string>()
                {
                        { nameof(Environment.MachineName), Environment.MachineName },
                        { nameof(Assembly), Assembly.GetEntryAssembly()?.GetName().Name },
                        { HealthCheckName, reportEntry.Key }
                },
                metrics: new Dictionary<string, double>()
                {
                        { StatusMetricName, reportEntry.Value.Status switch
                        {
                            HealthStatus.Healthy => 1,
                            HealthStatus.Degraded => 0,
                            _ => -1
                        } },
                        { DurationMetricName, reportEntry.Value.Duration.TotalMilliseconds }
                });
        }

        foreach (var reportEntry in report.Entries.Where(entry => entry.Value.Exception != null))
        {
            client.TrackException(reportEntry.Value.Exception,
                properties: new Dictionary<string, string>()
                {
                        { nameof(Environment.MachineName), Environment.MachineName },
                        { nameof(Assembly), Assembly.GetEntryAssembly()?.GetName().Name },
                        { HealthCheckName, reportEntry.Key }
                },
                metrics: new Dictionary<string, double>()
                {
                        { StatusMetricName, reportEntry.Value.Status switch
                        {
                            HealthStatus.Healthy => 1,
                            HealthStatus.Degraded => 0,
                            _ => -1
                        } },
                        { DurationMetricName, reportEntry.Value.Duration.TotalMilliseconds }
                });
        }
    }

    private TelemetryClient GetTelemetryClientInstance()
    {
        if (_telemetryClient is null)
        {
            lock (StaticLock)
            {
                _telemetryClient ??= new TelemetryClient(_telemetryConfiguration);
            }
        }

        return _telemetryClient;
    }
}