using System.Security.Claims;
using Duende.IdentityServer.AspNetIdentity;
using Duende.IdentityServer.Models;
using Microsoft.AspNetCore.Identity;

namespace GotSharp.IdSrv.Host.Internal;

internal class CustomProfileService<TUser> : ProfileService<TUser> where TUser : class
{
    public CustomProfileService(
        UserManager<TUser> userManager,
        IUserClaimsPrincipalFactory<TUser> claimsFactory,
        ILogger<ProfileService<TUser>> logger)
        : base(userManager, claimsFactory, logger) { }

    /// <summary>
    /// Called to get the claims for the user based on the profile request.
    /// </summary>
    protected override async Task GetProfileDataAsync(ProfileDataRequestContext context, TUser user)
    {
        var principal = await GetUserClaimsAsync(context, user);
        context.AddRequestedClaims(principal.Claims);
    }

    /// <summary>
    /// Gets the claims for a user.
    /// </summary>
    protected virtual async Task<ClaimsPrincipal> GetUserClaimsAsync(ProfileDataRequestContext context, TUser user)
    {
        var principal = await ClaimsFactory.CreateAsync(user);
        if (principal == null)
        {
            throw new Exception("ClaimsFactory failed to create a principal");
        }

        if (context?.Subject.IsImpersonating() == true)
        {
            var identity = (ClaimsIdentity)principal.Identity!;
            identity.AddClaims(new[]
            {
                new Claim(ClaimTypes.Impersonator, context.Subject.FindFirstValue(ClaimTypes.Impersonator)!),
                new Claim(ClaimTypes.ImpersonatorName, context.Subject.FindFirstValue(ClaimTypes.ImpersonatorName)!)
            });
        }

        return principal;
    }
}