using System.ComponentModel.DataAnnotations;

namespace GotSharp.IdSrv.Host.Controllers.Account
{
    public class ForgotPasswordViewModel
    {
        [Required(ErrorMessage = "The field {0} is required.")]
        [EmailAddress(ErrorMessage = "The {0} field is not a valid e-mail address.")]
        [Display(Name = "Username")]
        public string UserName { get; set; }

        public string ReturnUrl { get; set; }
        
        public bool IsCompleted { get; set; }
        public string RecaptchaSiteKey { get; set; }
    }
}