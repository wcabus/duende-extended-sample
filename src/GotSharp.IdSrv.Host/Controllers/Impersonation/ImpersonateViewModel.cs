using System.ComponentModel.DataAnnotations;

namespace GotSharp.IdSrv.Host.Controllers.Impersonation
{
    public class ImpersonateViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        public string ReturnUrl { get; set; }
    }
}