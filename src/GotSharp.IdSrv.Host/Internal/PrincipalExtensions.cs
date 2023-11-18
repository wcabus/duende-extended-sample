using System.Diagnostics;
using System.Security.Claims;
using System.Security.Principal;

namespace GotSharp.IdSrv.Host.Internal;

public static class PrincipalExtensions
{
    /// <summary>
    /// Returns <c>true</c> if the principal is currently impersonating another user.
    /// </summary>
    /// <param name="principal">The principal.</param>
    /// <returns></returns>
    [DebuggerStepThrough]
    public static bool IsImpersonating(this IPrincipal principal)
    {
        return principal is not ClaimsPrincipal cp
            ? principal.Identity.IsImpersonating()
            : cp.Identities.Any(identity => identity.IsImpersonating());
    }

    /// <summary>
    /// Returns <c>true</c> if the identity is currently impersonating another user.
    /// </summary>
    /// <param name="identity">The identity.</param>
    /// <returns></returns>
    [DebuggerStepThrough]
    public static bool IsImpersonating(this IIdentity identity)
    {
        var id = identity as ClaimsIdentity;
        var claim = id?.FindFirst(ClaimTypes.Impersonator);

        return claim != null;
    }
}