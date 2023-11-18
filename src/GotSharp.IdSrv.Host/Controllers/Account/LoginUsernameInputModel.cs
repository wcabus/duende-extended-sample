using System.ComponentModel.DataAnnotations;

namespace GotSharp.IdSrv.Host.Controllers.Account
{
    public class LoginUsernameInputModel
    {
        [Required(ErrorMessage = "The field {0} is required.")]
        [Display(Name = "Username")]
        public string Username { get; set; }

        public string LoginHint { get; set; }

        public string ReturnUrl { get; set; }
        public string RecaptchaSiteKey { get; set; }

        public bool EnableLocalLogin { get; set; } = true;
        public bool EnableRegistration { get; set; }
        public bool EnableResetPassword { get; set; } = true;
    }
}