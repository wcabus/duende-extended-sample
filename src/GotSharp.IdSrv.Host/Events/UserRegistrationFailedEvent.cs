using Duende.IdentityServer.Events;
using GotSharp.IdSrv.Host.Events.Contracts;

namespace GotSharp.IdSrv.Host.Events;

public class UserRegistrationFailedEvent : Event, IUserEvent
{
    public UserRegistrationFailedEvent(string email = null, string reason = null) : this()
    {
        Email = email;
        Reason = reason;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="UserRegistrationFailedEvent"/> class.
    /// </summary>
    protected UserRegistrationFailedEvent()
        : base(EventCategories.UserManagement,
            "User Registration Failed",
            EventTypes.Failure,
            EventIds.UserRegistrationFailed)
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
    /// Gets or sets the reason.
    /// </summary>
    /// <returns>
    /// The reason.
    /// </returns>
    public string Reason { get; set; }

    string IUserEvent.UserId => "";
    string IUserEvent.UserNameOrEmail => Email;
}