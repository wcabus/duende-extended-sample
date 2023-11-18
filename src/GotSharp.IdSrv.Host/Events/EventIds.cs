namespace GotSharp.IdSrv.Host.Events;

internal static class EventIds
{
    // Let's start our custom event ids in the 9000 range to not interfere with the default event ids
    public const int UserForgotPasswordSuccess = 9000;
    public const int UserForgotPasswordFailed = 9001;
    public const int UserResetPasswordSuccess = 9002;
    public const int UserResetPasswordFailed = 9003;
    public const int UserAccountActivationRequestSuccess = 9004;
    public const int UserAccountActivationRequestFailed = 9005;
    public const int UserAccountActivationSuccess = 9006;
    public const int UserAccountActivationFailed = 9007;
    public const int UserRegistrationSuccess = 9010;
    public const int UserRegistrationFailed = 9011;
    public const int UserConfirmEmailSuccess = 9012;
    public const int UserConfirmEmailFailed = 9013;
    public const int UserConfirmEmailChangeSuccess = 9014;
    public const int UserConfirmEmailChangeFailed = 9015;
    public const int UserChangePasswordSuccess = 9016;
    public const int UserChangePasswordFailed = 9017;
    public const int UserChangeEmailSuccess = 9018;
    public const int UserChangeEmailFailed = 9019;
    public const int UserChangeEmailRequestSuccess = 9020;
    public const int UserChangeEmailRequestFailed = 9021;

    public const int UserImpersonationSessionStarted = 9100;
    public const int UserImpersonationSessionEnded = 9101;
}