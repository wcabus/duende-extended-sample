namespace GotSharp.IdSrv.Host.Configuration;

public class SendGridOptions
{
    public string ApiKey { get; set; }
    public Sender Sender { get; set; }

    public string CallbackBaseUrl { get; set; }

    public List<SendGridTemplate> Templates { get; set; } = new();

    public SendGridTemplate GetTemplate(string templateName)
    {
        if (Templates is null || Templates.Count == 0)
        {
            return null;
        }

        return Templates.FirstOrDefault(x => string.Equals(x.Name, templateName, StringComparison.OrdinalIgnoreCase));
    }

    public string GetTemplateId(string templateName)
    {
        return GetTemplate(templateName)?.TemplateId;
    }
}

public class Sender
{
    public string Name { get; set; }
    public string Email { get; set; }
}

public class SendGridTemplate
{
    public const string ActivateAccount = nameof(ActivateAccount);
    public const string AccountActivated = nameof(AccountActivated);

    public const string ConfirmEmailAddress = nameof(ConfirmEmailAddress);
    public const string ConfirmEmailAddressChange = nameof(ConfirmEmailAddressChange);
    public const string EmailAddressAlreadyInUse = nameof(EmailAddressAlreadyInUse);
    public const string EmailAddressChanged = nameof(EmailAddressChanged);

    public const string ResetPassword = nameof(ResetPassword);
    public const string PasswordChanged = nameof(PasswordChanged);

    public const string UserAlreadyRegistered = nameof(UserAlreadyRegistered);

    public const string TwoFactorCodeSent = nameof(TwoFactorCodeSent);
    public const string CIBA = nameof(CIBA);

    public string Name { get; set; }
    public string TemplateId { get; set; }
}