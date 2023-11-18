using Duende.IdentityServer.Events;
using GotSharp.IdSrv.Host.Events.Contracts;

namespace GotSharp.IdSrv.Host.Events;

public class UserAccountActivationFailedEvent : Event, IUserEvent
{
    public UserAccountActivationFailedEvent(string userId) : this()
    {
        UserId = userId;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="UserAccountActivationFailedEvent"/> class.
    /// </summary>
    protected UserAccountActivationFailedEvent()
        : base(EventCategories.UserManagement,
            "User Account Activation Failed",
            EventTypes.Failure,
            EventIds.UserAccountActivationFailed)
    {
    }

    /// <summary>
    /// Gets or sets the user id.
    /// </summary>
    /// <returns>
    /// The email.
    /// </returns>
    public string UserId { get; set; }

    string IUserEvent.UserNameOrEmail => "";
}