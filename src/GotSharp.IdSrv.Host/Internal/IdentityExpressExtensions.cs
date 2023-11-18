using IdentityExpress.Identity;
using IdentityModel;
using System.Security.Claims;

namespace GotSharp.IdSrv.Host.Internal;

internal static class IdentityExpressExtensions
{
    /// <summary>
    /// Returns <c>true</c> if the <paramref name="username"/> indicates an external user 
    /// </summary>
    /// <remarks>An external user's username ends with <c>@gotsharp.be</c></remarks>
    /// <param name="username">The username</param>
    public static bool IsExternalUser(this string username)
    {
        return !string.IsNullOrEmpty(username) &&
               username.EndsWith("@gotsharp.be", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Returns <c>true</c> if the <paramref name="user"/>'s user name ends with "@gotsharp.be".
    /// </summary>
    /// <param name="user">A <see cref="ClaimsPrincipal"/></param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="user"/> is <c>null</c>.</exception>
    public static bool IsExternalUser(this ClaimsPrincipal user)
    {
        ArgumentNullException.ThrowIfNull(user);

        var userName = user.FindFirstValue(JwtClaimTypes.PreferredUserName);
        return userName.IsExternalUser();
    }

    /// <summary>
    /// Returns <c>true</c> if the <paramref name="user"/>'s user name ends with "@gotsharp.be".
    /// </summary>
    /// <param name="user">An <see cref="IdentityExpressUser"/></param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="user"/> is <c>null</c>.</exception>
    public static bool IsExternalUser(this IdentityExpressUser user)
    {
        ArgumentNullException.ThrowIfNull(user);

        return user.UserName.IsExternalUser();
    }
}