using Duende.IdentityServer.Events;
using GotSharp.IdSrv.Host.Events.Contracts;

namespace GotSharp.IdSrv.Host.Events;

public class UserResetPasswordFailedEvent : Event, IUserEvent
{
    public UserResetPasswordFailedEvent(string email = null) : this()
    {
        Email = email;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="UserResetPasswordFailedEvent"/> class.
    /// </summary>
    protected UserResetPasswordFailedEvent()
        : base(EventCategories.UserManagement,
            "User Forgot Password Failed",
            EventTypes.Failure,
            EventIds.UserResetPasswordFailed)
    {
    }

    /// <summary>
    /// Gets or sets the email.
    /// </summary>
    /// <returns>
    /// The email.
    /// </returns>
    public string Email { get; set; }

    string IUserEvent.UserId => "";
    string IUserEvent.UserNameOrEmail => Email;
}