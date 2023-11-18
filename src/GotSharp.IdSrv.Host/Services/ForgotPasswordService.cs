using System.Text;
using Duende.IdentityServer.Services;
using GotSharp.IdSrv.Host.Events;
using IdentityExpress.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;

namespace GotSharp.IdSrv.Host.Services;

public class ForgotPasswordService
{
    private readonly EmailSender _emailSender;
    private readonly IEventService _events;

    public ForgotPasswordService(EmailSender emailSender, IEventService events)
    {
        _emailSender = emailSender;
        _events = events;
    }

    public async Task<bool> CanSendResetPasswordEmail(IdentityExpressUser user, UserManager<IdentityExpressUser> userManager)
    {
        if (userManager.Options.SignIn.RequireConfirmedEmail)
        {
            if (!await userManager.IsEmailConfirmedAsync(user))
            {
                // email not yet confirmed
                await _events.RaiseAsync(new UserForgotPasswordFailedEvent(user.UserName, true));
                return false;
            }
        }

        // Additional check: if this user only has external logins, don't allow them to reset their password (that only applies to local accounts)
        // We might set a password on that account, making it both a local user and an external one. While there are use cases where this is normal, we're not using that capability at this time.
        var logins = await userManager.GetLoginsAsync(user);
        if (logins?.Any() == true)
        {
            await _events.RaiseAsync(new UserForgotPasswordFailedEvent(user.UserName, externalAccountOnly: true));
            return false;
        }

        return true;
    }

    public async Task SendResetPasswordEmail(IdentityExpressUser user, string languageCode, Func<IdentityExpressUser, Task<string>> passwordResetTokenGenerator)
    {
        if (user is null)
        {
            return;
        }

        var username = user.UserName;
        var email = user.Email;

        var callbackUrl = await GetCallbackUrl(user, passwordResetTokenGenerator);
        await _emailSender.SendResetPasswordMailAsync(username, email, user.FirstName ?? "", callbackUrl, languageCode);

        await _events.RaiseAsync(new UserForgotPasswordSuccessEvent(user.UserName, user.Id));
    }

    private async Task<string> GetCallbackUrl(IdentityExpressUser user, Func<IdentityExpressUser, Task<string>> passwordResetTokenGenerator)
    {
        var token = await passwordResetTokenGenerator(user);
        token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

        var localUrl = $"/reset-password?token={token}";
        return localUrl;
    }
}