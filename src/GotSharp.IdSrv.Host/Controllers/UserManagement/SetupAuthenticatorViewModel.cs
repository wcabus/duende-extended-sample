using System.ComponentModel.DataAnnotations;

namespace GotSharp.IdSrv.Host.Controllers.UserManagement
{
    public class SetupAuthenticatorViewModel
    {
        public string SharedKey { get; set; }

        [Required(ErrorMessage = "The field {0} is required.")]
        [Display(Name = "Authenticator code")]
        public string VerificationCode { get; set; }
    }
}