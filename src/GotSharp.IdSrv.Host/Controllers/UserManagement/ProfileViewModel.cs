using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace GotSharp.IdSrv.Host.Controllers.UserManagement
{
    public class ProfileViewModel
    {
        public const string DefaultLanguageCode = "nl-BE";

        [Display(Name = "Preferred language")]
        [Required]
        public string LanguageCode { get; set; }

        public List<SelectListItem> Languages { get; } = new()
        {
            new SelectListItem("Nederlands", "nl-BE"),
            new SelectListItem("Français", "fr-BE"),
            new SelectListItem("English", "en-GB")
        };

        public void SetLanguageFromClaim(string languageCode)
        {
            LanguageCode = string.IsNullOrWhiteSpace(languageCode) ?
                DefaultLanguageCode :
                TranslateLanguageCode(languageCode);
        }

        private string TranslateLanguageCode(string languageCode)
        {
            if (languageCode.StartsWith("en", StringComparison.OrdinalIgnoreCase))
            {
                return "en-GB";
            }

            if (languageCode.StartsWith("fr", StringComparison.OrdinalIgnoreCase))
            {
                return "fr-BE";
            }

            return DefaultLanguageCode;
        }
    }
}