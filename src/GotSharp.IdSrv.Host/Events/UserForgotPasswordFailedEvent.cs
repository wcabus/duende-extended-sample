using Duende.IdentityServer.Events;
using GotSharp.IdSrv.Host.Events.Contracts;

namespace GotSharp.IdSrv.Host.Events;

public class UserForgotPasswordFailedEvent : Event, IUserEvent
{
    public UserForgotPasswordFailedEvent(string email, bool emailNotConfirmed = false, bool externalAccountOnly = false) : this()
    {
        Email = email;
        EmailNotConfirmed = emailNotConfirmed;
        ExternalAccountOnly = externalAccountOnly;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="UserForgotPasswordFailedEvent"/> class.
    /// </summary>
    protected UserForgotPasswordFailedEvent()
        : base(EventCategories.UserManagement,
            "User Forgot Password Failed",
            EventTypes.Failure,
            EventIds.UserForgotPasswordFailed)
    {
    }

    /// <summary>
    /// Gets or sets the email.
    /// </summary>
    /// <returns>
    /// The email.
    /// </returns>
    public string Email { get; set; }

    /// <summary>
    /// Gets or sets "email not confirmed".
    /// </summary>
    /// <returns>
    /// "email not confirmed".
    /// </returns>
    public bool EmailNotConfirmed { get; set; }

    /// <summary>
    /// Gets or sets "external account only".
    /// </summary>
    /// <returns>
    /// "external account only".
    /// </returns>
    public bool ExternalAccountOnly { get; set; }

    string IUserEvent.UserId => "";
    string IUserEvent.UserNameOrEmail => Email;
}