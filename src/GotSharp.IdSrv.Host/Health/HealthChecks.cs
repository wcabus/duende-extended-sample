namespace GotSharp.IdSrv.Host.Health;

internal static class HealthChecks
{
    public const string Initialized = nameof(Initialized);

    public const string IdentityDb = "Identity Database";
    public const string ConfigDb = "Configuration & Operational Database";

    public const string MicrosoftGraph = nameof(MicrosoftGraph);
    public const string SendGrid = nameof(SendGrid);
}