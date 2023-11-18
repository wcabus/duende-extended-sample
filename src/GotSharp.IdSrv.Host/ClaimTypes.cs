namespace GotSharp.IdSrv.Host;

public static class ClaimTypes
{
    /// <summary>
    /// Impersonator's user ID
    /// </summary>
    public const string Impersonator = "impersonator_sub";

    /// <summary>
    /// Impersonator's name
    /// </summary>
    public const string ImpersonatorName = "impersonator_name";
}

public static class Scopes
{
    public const string Role = "role";
    public const string Impersonation = "impersonation";
}