using IdentityModel;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace GotSharp.IdSrv.Host.Services;

public class UserManager<TUser> : Microsoft.AspNetCore.Identity.UserManager<TUser> where TUser : class
{
    public UserManager
    (
        IUserStore<TUser> userStore,
        IOptions<IdentityOptions> optionsAccessor,
        IPasswordHasher<TUser> passwordHasher,
        IEnumerable<IUserValidator<TUser>> userValidators,
        IEnumerable<IPasswordValidator<TUser>> passwordValidators,
        ILookupNormalizer keyNormalizer,
        IdentityErrorDescriber errors,
        IServiceProvider services,
        ILogger<UserManager<TUser>> logger
    )
        : base(
            userStore,
            optionsAccessor,
            passwordHasher,
            userValidators,
            passwordValidators,
            keyNormalizer,
            errors,
            services,
            logger
        )
    { }

    private const string PreferencesProvider = "[Preferences]";
    private const string PreferredMfaMethodTokenName = "DefaultMfaMethod";

    /// <summary>
    /// Validates the given <paramref name="user"/> and <paramref name="newPassword"/> against the registered validations.
    /// </summary>
    /// <param name="user">A <typeparamref name="TUser"/></param>
    /// <param name="newPassword">The new password for the user.</param>
    /// <returns>An <see cref="IdentityResult"/> which either indicates success or failure. When the latter, the result contains validation errors.</returns>
    public async Task<IdentityResult> ValidateUser(TUser user, string newPassword)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(newPassword);

        var validate = await ValidatePasswordAsync(user, newPassword);
        if (!validate.Succeeded)
        {
            return validate;
        }

        validate = await ValidateUserAsync(user);
        if (!validate.Succeeded && validate.Errors.Select(x => x.Code).Contains(nameof(ErrorDescriber.DuplicateUserName)))
        {
            // remove the duplicate username error to prevent enumeration attacks
            if (validate.Errors.Count() == 1)
            {
                // there was only a single error and it says "duplicate username": return <quote>success</unquote> and pretend everything was OK
                return IdentityResult.Success;
            }

            // return a new failed IdentityResult with the remaining validation errors.
            var remainingValidationErrors = validate.Errors
                .Where(x => !string.Equals(x.Code, nameof(ErrorDescriber.DuplicateUserName), StringComparison.Ordinal))
                .ToArray();

            return IdentityResult.Failed(remainingValidationErrors);
        }

        return validate;
    }

    /// <summary>
    /// Returns the locale claim for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <returns>
    /// The locale or the default locale if no locale has been set.
    /// </returns>
    public async Task<string> GetLocaleAsync(TUser user)
    {
        ThrowIfDisposed();

        var claims = await GetClaimsAsync(user);
        var localeClaim = claims?.FirstOrDefault(x => x.Type == JwtClaimTypes.Locale);
        return localeClaim is null ? "nl-BE" : localeClaim.Value;
    }

    /// <summary>
    /// Returns the preferred communication language for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <returns>
    /// The two-letter language code, or the default if no locale claim has been set.
    /// </returns>
    public async Task<string> GetPreferredLanguageCodeAsync(TUser user)
    {
        var locale = await GetLocaleAsync(user);
        return locale switch
        {
            "en-CA" => "en",
            "en-GB" => "en",
            "en-UK" => "en",
            "en-US" => "en",
            "fr-BE" => "fr",
            "fr-CA" => "fr",
            "fr-FR" => "fr",
            _ => "nl"
        };
    }

    /// <summary>
    /// Retrieves the preferred MFA method for a user.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <returns>A string containing the preferred MFA method type, or null if no preference has been set.</returns>
    public async Task<string> GetPreferredTwoFactorMethod(TUser user)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);

        var store = GetAuthenticationTokenStore();

        return await store.GetTokenAsync(user, PreferencesProvider, PreferredMfaMethodTokenName, CancellationToken.None);
    }

    /// <summary>
    /// Saves the preferred MFA method when a user adds multiple MFA methods to their account.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <param name="type">MFA method type, either email, phone or authenticator.</param>
    /// <returns>
    /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
    /// of the operation.
    /// </returns>
    public async Task<IdentityResult> SetPreferredTwoFactorMethod(TUser user, string type)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(type);

        var store = GetAuthenticationTokenStore();

        if (type != MfaTypes.Email && type != MfaTypes.Phone && type != MfaTypes.Authenticator)
        {
            Logger.LogWarning("Invalid MFA type specified: {type}", type);
            return IdentityResult.Failed(new IdentityError
            {
                Code = "Invalid MFA type specified"
            });
        }

        await store.SetTokenAsync(user, PreferencesProvider, PreferredMfaMethodTokenName, type, CancellationToken.None);
        return await UpdateAsync(user);
    }

    private IUserAuthenticationTokenStore<TUser> GetAuthenticationTokenStore()
    {
        if (Store is not IUserAuthenticationTokenStore<TUser> cast)
        {
            throw new NotSupportedException("Store is not an authentication token store");
        }
        return cast;
    }
}