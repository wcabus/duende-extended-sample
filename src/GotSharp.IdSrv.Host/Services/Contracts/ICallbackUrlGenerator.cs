namespace GotSharp.IdSrv.Host.Services.Contracts;

public interface ICallbackUrlGenerator
{
    Task<string> GenerateUrl(string localUrl, string username = null);
}