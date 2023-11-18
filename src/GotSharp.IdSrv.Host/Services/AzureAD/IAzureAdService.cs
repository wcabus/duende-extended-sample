namespace GotSharp.IdSrv.Host.Services.AzureAD;

public interface IAzureAdService
{
    /// <summary>
    /// Checks if the user (identified by <paramref name="upn"/>) belongs to at least one of the specified <paramref name="groups"/>.
    /// </summary>
    /// <param name="intent">The intention for checking group membership. Used to cache the result.</param>
    /// <param name="upn">The user identifier in Azure AD, typically their corporate email address.</param>
    /// <param name="groups">List of Azure AD group identifiers.</param>
    /// <returns><c>true</c> if the user belongs to at least one group.</returns>
    Task<bool> CheckGroupMembership(string intent, string upn, IEnumerable<string> groups);

    Task<bool> Ping(CancellationToken cancellationToken);
}