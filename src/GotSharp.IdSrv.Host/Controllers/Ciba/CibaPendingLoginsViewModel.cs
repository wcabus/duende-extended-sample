using Duende.IdentityServer.Models;

namespace GotSharp.IdSrv.Host.Controllers.Ciba
{
    public class CibaPendingLoginsViewModel
    {
        public IEnumerable<BackchannelUserLoginRequest> Logins { get; set; }
    }
}