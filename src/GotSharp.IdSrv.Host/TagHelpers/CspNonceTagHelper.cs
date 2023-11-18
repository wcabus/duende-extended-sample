using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Razor.TagHelpers;
using System.Security.Cryptography;
using System.Text;

namespace GotSharp.IdSrv.Host.TagHelpers;

[HtmlTargetElement(ScriptTag, Attributes = CspNonceAttributeName)]
[HtmlTargetElement(StyleTag, Attributes = CspNonceAttributeName)]
public class CspNonceTagHelper : TagHelper
{
    private const string ScriptTag = "script";
    private const string StyleTag = "style";
    private const string CspNonceAttributeName = "csp-nonce";

    /// <summary>
    /// Specifies a whether a nonce should be added to the tag and the CSP header.
    /// </summary>
    [HtmlAttributeName(CspNonceAttributeName)]
    public bool UseCspNonce { get; set; }

    [HtmlAttributeNotBound]
    [ViewContext]
    public ViewContext ViewContext { get; set; }

    public override void Process(TagHelperContext context, TagHelperOutput output)
    {
        if (!UseCspNonce)
        {
            return;
        }

        string nonce;
        switch (context.TagName)
        {
            case ScriptTag:
                nonce = GetNonce(ScriptTag);
                break;
            case StyleTag:
                nonce = GetNonce(StyleTag);
                break;
            default:
                throw new Exception($"{CspNonceAttributeName} is not supported for use on the '{context.TagName}' HTML tag.");
        }


        output.Attributes.Add("nonce", nonce);
    }

    private string GetNonce(string tagName)
    {
        var httpContext = ViewContext.HttpContext;
        var key = $"csp-nonce-{tagName}";

        if (httpContext.Items.ContainsKey(key))
        {
            return (string)httpContext.Items[key];
        }

        var nonce = GenerateNonce();
        httpContext.Items[key] = nonce;

        var directive = tagName == ScriptTag ? "script-src" : "style-src";
        AddNonceToCspDirective(httpContext, directive, nonce);

        return nonce;
    }

    private string GenerateNonce()
    {
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        var nonceBytes = new byte[18];
        randomNumberGenerator.GetBytes(nonceBytes);

        return Convert.ToBase64String(nonceBytes);
    }

    private void AddNonceToCspDirective(HttpContext httpContext, string directive, string nonce)
    {
        var csp = "";
        if (httpContext.Response.Headers.ContainsKey("Content-Security-Policy"))
        {
            csp = httpContext.Response.Headers["Content-Security-Policy"];
        }

        var cspBuilder = new StringBuilder(csp);
        var directivePosition = csp.IndexOf(directive, StringComparison.Ordinal);
        if (directivePosition == -1)
        {
            // simple addition of a not-yet existing CSP directive
            cspBuilder.AppendFormat(" {0} 'nonce-{1}';", directive, nonce);
        }
        else
        {
            // find the end of the current directive to insert the nonce
            var insertPos = csp.IndexOf(';', directivePosition);
            cspBuilder.Insert(insertPos, $" 'nonce-{nonce}'");
        }

        csp = cspBuilder.ToString();
        httpContext.Response.Headers["Content-Security-Policy"] = csp;
        httpContext.Response.Headers["X-Content-Security-Policy"] = csp;
    }
}