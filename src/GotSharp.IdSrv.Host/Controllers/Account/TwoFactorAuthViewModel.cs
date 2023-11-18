using System.ComponentModel.DataAnnotations;

namespace GotSharp.IdSrv.Host.Controllers.Account
{
    public class TwoFactorAuthViewModel
    {
        [Required(ErrorMessage = "The field {0} is required.")]
        [StringLength(7, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [Display(Name = "Authenticator code")]
        public string TwoFactorCode { get; set; }

        [Display(Name = "Remember this device")]
        public bool RememberDevice { get; set; }

        public bool RememberMe { get; set; }
        public string ReturnUrl { get; set; }

        public string TokenProvider { get; set; }

        public IReadOnlyCollection<string> OtherTokenProviders { get; set; } = Array.Empty<string>();
        public bool CanSelectOtherTokenProvider => OtherTokenProviders.Count != 0;

        public string RecaptchaSiteKey { get; set; }
    }
}