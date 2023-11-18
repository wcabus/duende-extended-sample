namespace GotSharp.IdSrv.Host.Recaptcha;

public class RecaptchaViewModel
{
    public string RecaptchaSiteKey { get; set; }

    public string ButtonId { get; set; }
    public string FormId { get; set; }

    public string RecaptchaFieldName { get; set; } = "grecaptcha";

    public string ActionFieldName { get; set; } = "action";
    public string ButtonAction { get; set; }

    public string Action { get; set; }
}