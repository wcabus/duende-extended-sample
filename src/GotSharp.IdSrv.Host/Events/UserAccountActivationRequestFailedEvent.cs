using Duende.IdentityServer.Events;
using GotSharp.IdSrv.Host.Events.Contracts;

namespace GotSharp.IdSrv.Host.Events;

public class UserAccountActivationRequestFailedEvent : Event, IUserEvent
{
    public UserAccountActivationRequestFailedEvent(string email) : this()
    {
        Email = email;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="UserAccountActivationRequestFailedEvent"/> class.
    /// </summary>
    protected UserAccountActivationRequestFailedEvent()
        : base(EventCategories.UserManagement,
            "User Account Activation Request Failed",
            EventTypes.Failure,
            EventIds.UserAccountActivationRequestFailed)
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