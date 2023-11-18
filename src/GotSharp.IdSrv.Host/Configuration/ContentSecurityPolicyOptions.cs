namespace GotSharp.IdSrv.Host.Configuration;

public class ContentSecurityPolicyOptions
{
    public string ScriptSources { get; set; }
    public string StyleSources { get; set; }
    public string ImageSources { get; set; }
    public string FontSources { get; set; }
    public string FrameSources { get; set; }
    public string FrameAncestors { get; set; }
    public string FormActions { get; set; }
    public string ConnectSources { get; set; }
}