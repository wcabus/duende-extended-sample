using System.ComponentModel.DataAnnotations;

namespace GotSharp.IdSrv.Host.Controllers.UserManagement
{
    public class EmailViewModel
    {
        [Display(Name = "Email")]
        public string Email { get; set; }
        public bool IsEmailConfirmed { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "New email")]
        public string NewEmail { get; set; }
    }
}