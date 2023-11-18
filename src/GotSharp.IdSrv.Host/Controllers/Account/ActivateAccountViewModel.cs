namespace GotSharp.IdSrv.Host.Controllers.Account
{
    public class ActivateAccountViewModel
    {
        public string UserId { get; set; }
        public string Token { get; set; }
        public string ReturnUrl { get; set; }

        public string RecaptchaSiteKey { get; set; }
    }
}