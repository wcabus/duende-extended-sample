using System.ComponentModel.DataAnnotations;

namespace GotSharp.IdSrv.Host.Controllers.Account
{
    public class LoginWithRecoveryCodeViewModel
    {
        [Required(ErrorMessage = "The field {0} is required.")]
        [Display(Name = "Recovery code")]
        public string RecoveryCode { get; set; }

        public string ReturnUrl { get; set; }
        public string RecaptchaSiteKey { get; set; }
    }
}