namespace GotSharp.IdSrv.Host.Configuration;

public class ImpersonationOptions
{
    public List<string> Groups { get; set; } = new();

    public bool AllowImpersonationWhenNoGroupsSet { get; set;} = false;
}