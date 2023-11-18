using Microsoft.Extensions.Options;
using SendGrid.Helpers.Mail;
using SendGrid;
using System.Dynamic;
using System.Globalization;
using GotSharp.IdSrv.Host.Configuration;
using GotSharp.IdSrv.Host.Resources;
using GotSharp.IdSrv.Host.Services.Contracts;

namespace GotSharp.IdSrv.Host.Services;

public class EmailSender
{
    private readonly ISendGridClient _sendGrid;
    private readonly ICallbackUrlGenerator _callbackUrlGenerator;
    private readonly ILogger<EmailSender> _logger;
    private readonly SendGridOptions _options;

    private readonly EmailAddress _from;
    private readonly TrackingSettings _doNotTrack;

    public EmailSender(ISendGridClient sendGrid, ICallbackUrlGenerator callbackUrlGenerator, IOptions<SendGridOptions> options, ILogger<EmailSender> logger)
    {
        _sendGrid = sendGrid;
        _callbackUrlGenerator = callbackUrlGenerator;
        _logger = logger;
        _options = options.Value;

        _from = new EmailAddress(_options.Sender.Email, _options.Sender.Name);
        _doNotTrack = new TrackingSettings
        {
            ClickTracking = new ClickTracking
            {
                Enable = false
            },
            Ganalytics = new Ganalytics
            {
                Enable = false
            },
            OpenTracking = new OpenTracking
            {
                Enable = false
            },
            SubscriptionTracking = new SubscriptionTracking
            {
                Enable = false
            }
        };
    }

    public async Task SendActivateUserAccountMailAsync(string username, string email, string firstName, string callbackUrl, string languageCode = null)
    {
        var templateData = CreateTemplateData(email, firstName, languageCode, username);
        templateData.account_activation_link = await _callbackUrlGenerator.GenerateUrl(callbackUrl, username);

        await SendEmail(new EmailAddress(email, firstName), SendGridTemplate.ActivateAccount, templateData, languageCode);
    }

    public async Task SendUserAccountActivatedEmailAsync(string username, string email, string firstName, string callbackUrl, string languageCode = null)
    {
        var templateData = CreateTemplateData(email, firstName, languageCode, username);
        templateData.password_reset_link = await _callbackUrlGenerator.GenerateUrl(callbackUrl, username);

        await SendEmail(new EmailAddress(email, firstName), SendGridTemplate.AccountActivated, templateData, languageCode);
    }

    public async Task SendResetPasswordMailAsync(string username, string email, string firstName, string callbackUrl, string languageCode = null)
    {
        var templateData = CreateTemplateData(email, firstName, languageCode, username);
        templateData.password_reset_link = await _callbackUrlGenerator.GenerateUrl(callbackUrl, username);

        await SendEmail(new EmailAddress(email, firstName), SendGridTemplate.ResetPassword, templateData, languageCode);
    }

    public async Task SendPasswordChangedMailAsync(string username, string email, string firstName, string languageCode = null)
    {
        var templateData = CreateTemplateData(email, firstName, languageCode, username);

        await SendEmail(new EmailAddress(email, firstName), SendGridTemplate.PasswordChanged, templateData, languageCode);
    }

    public async Task SendUserAlreadyRegisteredMailAsync(string username, string email, string firstName, string languageCode = null)
    {
        var templateData = CreateTemplateData(email, firstName, languageCode, username);

        await SendEmail(new EmailAddress(email, firstName), SendGridTemplate.UserAlreadyRegistered, templateData, languageCode);
    }

    public async Task SendConfirmEmailMailAsync(string username, string email, string firstName, string callbackUrl, string languageCode = null)
    {
        var templateData = CreateTemplateData(email, firstName, languageCode, username);
        templateData.confirm_email_link = await _callbackUrlGenerator.GenerateUrl(callbackUrl, username);

        await SendEmail(new EmailAddress(email, firstName), SendGridTemplate.ConfirmEmailAddress, templateData, languageCode);
    }

    public async Task SendConfirmEmailChangeMailAsync(string username, string email, string firstName, string callbackUrl, string languageCode = null)
    {
        var templateData = CreateTemplateData(email, firstName, languageCode, username);
        templateData.confirm_email_link = callbackUrl; // callback URL is an absolute url in this case!

        await SendEmail(new EmailAddress(email, firstName), SendGridTemplate.ConfirmEmailAddressChange, templateData, languageCode);
    }

    public async Task SendEmailAddressAlreadyInUseMailAsync(string username, string email, string firstName, string languageCode = null)
    {
        var templateData = CreateTemplateData(email, firstName, languageCode, username);

        await SendEmail(new EmailAddress(email, firstName), SendGridTemplate.EmailAddressAlreadyInUse, templateData, languageCode);
    }

    public async Task SendEmailAddressChangedMailAsync(string username, string email, string firstName, string oldEmail, string languageCode = null)
    {
        var templateData = CreateTemplateData(email, firstName, languageCode, username);
        templateData.old_email = oldEmail;

        // Send this message to the old and the new address
        await SendEmail(new EmailAddress(oldEmail, firstName), SendGridTemplate.EmailAddressChanged, templateData, languageCode);
        await SendEmail(new EmailAddress(email, firstName), SendGridTemplate.EmailAddressChanged, templateData, languageCode);
    }

    public async Task SendCibaRequestMailAsync(string username, string email, string firstName, string client, string callbackUrl, string languageCode = null)
    {
        var templateData = CreateTemplateData(email, firstName, languageCode, username);
        templateData.client = client;
        templateData.ciba_link = await _callbackUrlGenerator.GenerateUrl(callbackUrl);

        await SendEmail(new EmailAddress(email, firstName), SendGridTemplate.CIBA, templateData, languageCode);
    }

    public async Task SendTwoFactorAuthenticationCodeViaMailAsync(string username, string email, string firstName, string authenticatorCode, string location, string languageCode = null)
    {
        var templateData = CreateTemplateData(email, firstName, languageCode, username);
        templateData.authenticator_code = authenticatorCode;
        templateData.location = location;

        await SendEmail(new EmailAddress(email, firstName), SendGridTemplate.TwoFactorCodeSent, templateData, languageCode);
    }

    private dynamic CreateTemplateData(string email, string firstName, string languageCode = null, string username = null)
    {
        dynamic templateData = new ExpandoObject();
        templateData.firstname = firstName ?? "";
        templateData.email = email;
        templateData.username = username ?? email;

        return templateData;
    }

    private SendGridMessage CreateMessage(EmailAddress to, string templateName, dynamic templateData, string languageCode)
    {
        try
        {
            var subject = EmailSubjects.ResourceManager.GetString(templateName, new CultureInfo(languageCode));
            if (!string.IsNullOrWhiteSpace(subject))
            {
                templateData.subject = subject;
            }
        }
        catch
        {
            // soft fail if no subject data can be found
        }

        var templateId = _options.GetTemplateId(templateName);
        SendGridMessage message = MailHelper.CreateSingleTemplateEmail(_from, to, templateId, templateData);
        message.TrackingSettings = _doNotTrack;

        return message;
    }

    private SendGridMessage CreateMessage(IEnumerable<EmailAddress> tos, string templateName, dynamic templateData, string languageCode)
    {
        try
        {
            var subject = EmailSubjects.ResourceManager.GetString(templateName, new CultureInfo(languageCode));
            if (!string.IsNullOrWhiteSpace(subject))
            {
                templateData.subject = subject;
            }
        }
        catch
        {
            // soft fail if no subject data can be found
        }

        var templateId = _options.GetTemplateId(templateName);
        SendGridMessage message = MailHelper.CreateSingleTemplateEmailToMultipleRecipients(_from, tos.ToList(), templateId, templateData);
        message.TrackingSettings = _doNotTrack;

        return message;
    }

    private async Task SendEmail(EmailAddress to, string templateName, dynamic templateData, string languageCode)
    {
        var message = CreateMessage(to, templateName, templateData, languageCode);

        var response = await _sendGrid.SendEmailAsync(message);
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var reason = "unknown reason";
        try
        {
            reason = await response.Body.ReadAsStringAsync();
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Couldn't read error response.");
        }

        _logger.LogError("Could not send email: {reason}", reason);
    }

    private async Task SendBulkEmail(SendGridMessage message)
    {
        var response = await _sendGrid.SendEmailAsync(message);
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var reason = "unknown reason";
        try
        {
            reason = await response.Body.ReadAsStringAsync();
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Couldn't read error response.");
        }

        _logger.LogError("Could not send email: {reason}", reason);
    }
}