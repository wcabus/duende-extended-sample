namespace GotSharp.IdSrv.Host.Configuration;

public class GeneralOptions
{
    // Warning, do not blindly rename these two properties! They're linked to a property on a client definition as well!
    public bool DisableRegistration { get; set; } = false;
    public bool DisablePasswordManagement { get; set; } = false;
}