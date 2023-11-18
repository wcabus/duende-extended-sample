using GotSharp.IdSrv.Host.Controllers.Consent;

namespace GotSharp.IdSrv.Host.Controllers.Ciba
{
    public class CibaConsentViewModel
    {
        public string ClientName { get; set; }
        public string ClientUrl { get; set; }
        public string ClientLogoUrl { get; set; }

        public string BindingMessage { get; set; }

        public IEnumerable<ScopeViewModel> IdentityScopes { get; set; }
        public IEnumerable<ScopeViewModel> ApiScopes { get; set; }
        public CibaConsentInputModel InputModel { get; set; }
    }
}