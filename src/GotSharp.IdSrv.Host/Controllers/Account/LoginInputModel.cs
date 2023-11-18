// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using System.ComponentModel.DataAnnotations;

namespace GotSharp.IdSrv.Host.Controllers.Account
{
    public class LoginInputModel : LoginUsernameInputModel
    {
        [Required(ErrorMessage = "The field {0} is required.")]
        [Display(Name = "Password")]
        public string Password { get; set; }
        
        public bool RememberLogin { get; set; }
    }
}