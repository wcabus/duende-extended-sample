namespace GotSharp.IdSrv.Host.Services.AzureAD;

internal class NullAzureAdService : IAzureAdService
{
    public bool BelongsToGroup { get; set; } = false;

    public bool PingResponse { get; set; } = true;

    public Task<bool> CheckGroupMembership(string intent, string upn, IEnumerable<string> groups)
    {
        return Task.FromResult(BelongsToGroup);
    }

    public Task<bool> Ping(CancellationToken cancellationToken)
    {
        return Task.FromResult(PingResponse);
    }
}