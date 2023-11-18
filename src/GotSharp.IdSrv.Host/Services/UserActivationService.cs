using System.Text;
using Duende.IdentityServer.Services;
using GotSharp.IdSrv.Host.Events;
using GotSharp.IdSrv.Host.Internal;
using IdentityExpress.Identity;
using Microsoft.AspNetCore.WebUtilities;

namespace GotSharp.IdSrv.Host.Services;

public class UserActivationService
{
    private readonly EmailSender _emailSender;
    private readonly IEventService _events;

    public UserActivationService(EmailSender emailSender, IEventService events)
    {
        _emailSender = emailSender;
        _events = events;
    }

    public async Task SendActivationEmail(IdentityExpressUser user, string languageCode, Func<IdentityExpressUser, Task<string>> emailConfirmationTokenGenerator, string returnUrl = null)
    {
        if (user is null || user.EmailConfirmed)
        {
            return;
        }

        var callbackUrl = await GetCallbackUrl(user, emailConfirmationTokenGenerator, returnUrl);
        await _emailSender.SendActivateUserAccountMailAsync(user.UserName, user.Email, user.FirstName ?? "", callbackUrl, languageCode);

        await _events.RaiseAsync(new UserAccountActivationRequestSuccessEvent(user.UserName, user.Id));
    }

    private async Task<string> GetCallbackUrl(IdentityExpressUser user, Func<IdentityExpressUser, Task<string>> emailConfirmationTokenGenerator, string returnUrl = null)
    {
        var token = await emailConfirmationTokenGenerator(user);
        token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

        var localUrl = $"/activate-account?userId={user.Id}&token={token}";
        return !string.IsNullOrEmpty(returnUrl)
            ? localUrl.AddQueryString("returnUrl", returnUrl)
            : localUrl;
    }
}