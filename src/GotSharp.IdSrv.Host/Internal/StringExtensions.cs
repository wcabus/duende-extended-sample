namespace GotSharp.IdSrv.Host.Internal;

internal static class StringExtensions
{
    public static bool IsLocalUrl(this string url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return false;
        }

        if (url[0] == '/' && (url.Length == 1 || url[1] != '/' && url[1] != '\\'))
        {
            return true;
        }

        return url.Length > 1 && url[0] == '~' && url[1] == '/';
    }

    public static string GetOrigin(this string url)
    {
        if (url == null || (!url.StartsWith("http://") && !url.StartsWith("https://")))
        {
            return null;
        }

        var idx = url.IndexOf("//", StringComparison.Ordinal);
        if (idx <= 0)
        {
            return null;
        }

        var length = url.IndexOf("/", idx + 2, StringComparison.Ordinal);
        if (length >= 0)
        {
            url = url[..length];
        }

        return url;
    }

    public static string GetRelativeUrl(this string path, string baseUrl)
    {
        if (!path.IsLocalUrl())
        {
            return null;
        }

        if (path.StartsWith("~/"))
        {
            path = path[1..];
        }

        return baseUrl.EnsureTrailingSlash() + path.RemoveLeadingSlash();
    }

    public static string AddQueryString(this string url, string name, string value) =>
        url.AddQueryString(name + "=" + value);

    public static string AddQueryString(this string url, string query)
    {
        if (!url.Contains('?'))
        {
            return url + "?" + query;
        }

        if (!url.EndsWith("&"))
        {
            url += "&";
        }

        return url + query;
    }

    public static string EnsureLeadingSlash(this string url) => !url.StartsWith("/") ? "/" + url : url;
    public static string EnsureTrailingSlash(this string url) => !url.EndsWith("/") ? url + "/" : url;

    public static string RemoveLeadingSlash(this string url)
    {
        if (url != null && url.StartsWith("/"))
        {
            return url[1..];
        }

        return url;
    }

    public static string RemoveTrailingSlash(this string url)
    {
        if (url != null && url.EndsWith("/"))
        {
            return url[..^1];
        }

        return url;
    }
}