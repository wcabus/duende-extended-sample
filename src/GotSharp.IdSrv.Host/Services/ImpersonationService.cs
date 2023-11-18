using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Services;
using GotSharp.IdSrv.Host.Services.AzureAD;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using GotSharp.IdSrv.Host.Internal;
using GotSharp.IdSrv.Host.Configuration;
using GotSharp.IdSrv.Host.Events;
using IdentityExpress.Identity;

namespace GotSharp.IdSrv.Host.Services;

public class ImpersonationService
{
    private readonly SignInManager<IdentityExpressUser> _signInManager;
    private readonly UserManager<IdentityExpressUser> _userManager;
    private readonly IAzureAdService _azureAdService;
    private readonly IEventService _events;
    private readonly ImpersonationOptions _impersonationOptions;
    private readonly IMemoryCache _cache;

    public ImpersonationService(
        SignInManager<IdentityExpressUser> signInManager,
        UserManager<IdentityExpressUser> userManager,
        IAzureAdService azureAdService,
        IOptions<ImpersonationOptions> impersonationOptionsAccessor,
        IEventService events,
        IMemoryCache cache)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _azureAdService = azureAdService;
        _events = events;
        _impersonationOptions = impersonationOptionsAccessor.Value;
        _cache = cache;
    }

    public async Task<bool> IsCurrentUserAllowedToImpersonateUsers(ClaimsPrincipal currentUser)
    {
        var userId = currentUser.GetSubjectId();
        if (currentUser.IsImpersonating())
        {
            userId = currentUser.FindFirstValue(ClaimTypes.Impersonator);
        }

        var cacheKey = GetCacheKey("ImpersonationAllowed", userId);
        if (_cache.TryGetValue(cacheKey, out bool value))
        {
            return value;
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            // No user means definitely no access
            _cache.Set(cacheKey, false, TimeSpan.FromMinutes(5));
            return false;
        }

        if (!await HasAzureAdAccount(user))
        {
            // User should have an Azure AD account to be allowed to impersonate people
            _cache.Set(cacheKey, false, TimeSpan.FromMinutes(5));
            return false;
        }

        var result = await UserIsInImpersonationGroup(user);
        _cache.Set(cacheKey, result, TimeSpan.FromMinutes(5));
        return result;
    }

    public async Task ImpersonateUser(ClaimsPrincipal currentUser, IdentityExpressUser userToImpersonate)
    {
        var currentUserClaims = (SubjectId: currentUser.GetSubjectId(), Name: currentUser.GetDisplayName());
        var additionalClaims = new List<Claim>
            {
                new(ClaimTypes.Impersonator, currentUserClaims.SubjectId),
                new(ClaimTypes.ImpersonatorName, currentUserClaims.Name)
            };

        // If the user has external logins, add them as identity providers so that Identity Server knows the correct context during sign in calls
        var externalLogins = await _userManager.GetLoginsAsync(userToImpersonate);
        if (externalLogins.Any())
        {
            additionalClaims.AddRange(externalLogins.Select(externalLogin => new Claim(JwtClaimTypes.IdentityProvider, externalLogin.LoginProvider)));
        }

        // And sign in as the impersonated user
        await _signInManager.SignInWithClaimsAsync(userToImpersonate, new AuthenticationProperties { IsPersistent = false }, additionalClaims);
        await _events.RaiseAsync(new UserImpersonationSessionStartedEvent(currentUserClaims.Name, currentUserClaims.SubjectId, userToImpersonate.UserName, userToImpersonate.Id));
    }

    public async Task<bool> SwitchBackToActualUser(ClaimsPrincipal user)
    {
        var originalUserId = user.FindFirstValue(ClaimTypes.Impersonator);
        var originalUser = await _userManager.FindByIdAsync(originalUserId);
        if (originalUser is null)
        {
            // User was impersonating but their original user no longer exists: sign out and indicate failure to switch back.
            await _signInManager.SignOutAsync();
            return false;
        }

        // And sign in as the original user
        await _signInManager.SignInAsync(originalUser, new AuthenticationProperties { IsPersistent = false });
        await _events.RaiseAsync(new UserImpersonationSessionEndedEvent(originalUser.UserName, originalUser.Id));

        return true;
    }

    private async Task<bool> HasAzureAdAccount(IdentityExpressUser user)
    {
        var logins = await _userManager.GetLoginsAsync(user);
        return logins.Any(x => string.Equals(x.LoginProvider, AuthProviders.AzureAD, StringComparison.OrdinalIgnoreCase));
    }

    private async Task<bool> UserIsInImpersonationGroup(IdentityExpressUser user)
    {
        if (!_impersonationOptions.Groups.Any())
        {
            return _impersonationOptions.AllowImpersonationWhenNoGroupsSet; // If no groups are configured, use the default configuration
        }

        try
        {
            // Check Azure AD group membership to see if the user is in a group that allows impersonation
            return await _azureAdService.CheckGroupMembership("Impersonation", user.UserName, _impersonationOptions.Groups);
        }
        catch (Exception)
        {
            // Failed to query Graph API
        }

        return false;
    }

    private string GetCacheKey(params string[] keyParts)
    {
        return string.Join(":", keyParts);
    }
}