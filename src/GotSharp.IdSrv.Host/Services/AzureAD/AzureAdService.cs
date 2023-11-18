using Microsoft.Extensions.Caching.Memory;
using Microsoft.Graph;
using Microsoft.Graph.Users.Item.CheckMemberGroups;

namespace GotSharp.IdSrv.Host.Services.AzureAD;

internal class AzureAdService : IAzureAdService
{
    private readonly GraphServiceClient _graphServiceClient;
    private readonly IMemoryCache _cache;
    private readonly ILogger<AzureAdService> _logger;

    public AzureAdService(
        GraphServiceClient graphServiceClient,
        IMemoryCache cache,
        ILogger<AzureAdService> logger)
    {
        _graphServiceClient = graphServiceClient;
        _cache = cache;
        _logger = logger;
    }

    public async Task<bool> CheckGroupMembership(string intent, string upn, IEnumerable<string> groups)
    {
        ArgumentNullException.ThrowIfNull(upn);
        ArgumentNullException.ThrowIfNull(groups);

        var groupsArray = groups.ToArray();
        var cacheResult = GetFromCache(intent, upn);
        if (cacheResult.Found)
        {
            return cacheResult.Value;
        }

        var index = 0;
        var numberOfGroups = groupsArray.Length;
        const int maxGroupsPerCall = 20;
        do
        {
            var currentGroups = groupsArray.Skip(index).Take(maxGroupsPerCall).ToList();
            index += maxGroupsPerCall;

            // Check if the current user belongs to one of the groups.
            try
            {
                var response = await _graphServiceClient.Users[upn]
                    .CheckMemberGroups
                    .PostAsCheckMemberGroupsPostResponseAsync(new CheckMemberGroupsPostRequestBody
                    {
                        GroupIds = currentGroups
                    });

                if (response?.Value?.Count > 0)
                {
                    AddToCache(intent, upn, true);
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while calling the Graph API to verify a user's membership.");
                throw;
            }
        } while (index < numberOfGroups);

        AddToCache(intent, upn, false);
        return false;
    }

    public async Task<bool> Ping(CancellationToken cancellationToken)
    {
        var response = await _graphServiceClient.Users
            .GetAsync(x => x.QueryParameters.Top = 1, cancellationToken);

        return response != null;
    }

    private (bool Found, bool Value) GetFromCache(string intent, string upn)
    {
        return _cache.TryGetValue(GetKey("CheckGroupMembership", upn, intent), out bool isMember)
            ? (true, isMember)
            : (false, false);
    }

    private void AddToCache(string intent, string upn, bool value)
    {
        var key = GetKey("CheckGroupMembership", upn, intent);
        _cache.Set(key, value, TimeSpan.FromMinutes(5));
    }

    private string GetKey(params string[] keyParts)
    {
        return string.Join(":", keyParts);
    }
}