namespace GotSharp.IdSrv.Host.Configuration;

public class HomeRealmDiscovery
{
    public List<HomeRealmDiscoveryRule> Rules { get; set; }
}

public class HomeRealmDiscoveryRule
{
    public string Provider { get; set; }
    public List<string> Domains { get; set; } = new();
    public string DomainWildcard { get; set; } = null;
    public List<string> ExcludedDomains { get; set; } = new();

    public string MatchedDomain { get; set; }
}