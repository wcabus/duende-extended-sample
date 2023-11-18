namespace GotSharp.IdSrv.Host.Controllers.Account
{
    public class ActivateViewModel
    {
        public bool IsCompleted { get; set; }
        public string LoginLink { get; set; }
        public string ReturnUrl { get; set; }
    }
}