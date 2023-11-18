namespace GotSharp.IdSrv.Host.Controllers.UserManagement
{
    public class MultiFactorAuthenticationViewModel : MinimumMfaViewModel
    {
        public bool IsMfaEnabled { get; set; }

        public string Email { get; set; }
        public string Phone { get; set; }

        public int RecoveryCodesLeft { get; set; }

        public bool IsMachineRemembered { get; set; }

        public bool HasEmail => !string.IsNullOrEmpty(Email);
        public bool HasPhone => !string.IsNullOrEmpty(Phone);
        public bool HasAllMfaTypes => HasAuthenticator && HasEmail /* && HasPhone */;

        public string PreferredType { get; set; }
    }
}