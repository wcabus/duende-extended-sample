using GotSharp.IdSrv.Host.Configuration;
using Microsoft.Extensions.Options;

namespace GotSharp.IdSrv.Host.Services;

public class HomeRealmDiscoveryService
{
    private readonly IOptions<HomeRealmDiscovery> _homeRealmDiscoveryOptions;

    public HomeRealmDiscoveryService(IOptions<HomeRealmDiscovery> homeRealmDiscoveryOptions)
    {
        _homeRealmDiscoveryOptions = homeRealmDiscoveryOptions;
    }

    public HomeRealmDiscoveryRule DiscoverRealmFromUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username) || !username.Contains('@', StringComparison.Ordinal))
        {
            return null;
        }

        var rules = (ICollection<HomeRealmDiscoveryRule>)_homeRealmDiscoveryOptions.Value?.Rules ?? Array.Empty<HomeRealmDiscoveryRule>();
        var emailDomain = username[(username.LastIndexOf("@", StringComparison.Ordinal) + 1)..];

        var matchedRule = FindConcreteMatch(emailDomain, rules) ??
                          FindWildcardMatch(emailDomain, rules);

        if (matchedRule is not null)
        {
            matchedRule.MatchedDomain = emailDomain;
        }

        return matchedRule;
    }

    private HomeRealmDiscoveryRule FindConcreteMatch(string emailDomain, IEnumerable<HomeRealmDiscoveryRule> rules)
    {
        return rules
            .FirstOrDefault(rule =>
                rule.Domains.Any(domain =>
                    string.Equals(domain, emailDomain, StringComparison.OrdinalIgnoreCase)));
    }

    private HomeRealmDiscoveryRule FindWildcardMatch(string emailDomain, IEnumerable<HomeRealmDiscoveryRule> rules)
    {
        foreach (var rule in rules.Where(x => !string.IsNullOrEmpty(x.DomainWildcard)))
        {
            // We only support *.domain.tld wildcards for now
            var domainWithoutWildcard = rule.DomainWildcard[1..];
            if (emailDomain.EndsWith(domainWithoutWildcard, StringComparison.OrdinalIgnoreCase))
            {
                // Check if this domain is in the exclusion list
                if (!rule.ExcludedDomains.Any(x =>
                        string.Equals(x, emailDomain, StringComparison.OrdinalIgnoreCase)))
                {
                    // This email domain is not excluded and matches the wildcard, we found a match!
                    return rule;
                }
            }
        }

        return null; // no match found
    }
}