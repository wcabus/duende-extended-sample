using Microsoft.AspNetCore.Localization;

namespace GotSharp.IdSrv.Host.Internal;

internal static class ResponseCookiesExtensions
{
    public static void SetCulture(this IResponseCookies cookies, string languageCode)
    {
        // TODO Replace cookie name!
        cookies.Append(
            CookieRequestCultureProvider.DefaultCookieName,
            CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(languageCode)),
            new CookieOptions
            {
                Expires = DateTimeOffset.UtcNow.AddYears(1)
            });
    }
}