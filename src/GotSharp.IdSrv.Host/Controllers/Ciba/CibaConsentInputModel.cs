namespace GotSharp.IdSrv.Host.Controllers.Ciba
{
    public class CibaConsentInputModel
    {
        public string Button { get; set; }
        public IEnumerable<string> ScopesConsented { get; set; }
        public string Id { get; set; }
        public string Description { get; set; }
    }
}