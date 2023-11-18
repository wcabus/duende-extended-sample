using Duende.IdentityServer.Events;
using GotSharp.IdSrv.Host.Events.Contracts;

namespace GotSharp.IdSrv.Host.Events;

public class UserConfirmEmailFailedEvent : Event, IUserEvent
{
    public UserConfirmEmailFailedEvent(string userId, string failure) : this()
    {
        UserId = userId;
        Failure = failure;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="UserConfirmEmailFailedEvent"/> class.
    /// </summary>
    protected UserConfirmEmailFailedEvent()
        : base(EventCategories.UserManagement,
            "User Confirm Email Failed",
            EventTypes.Failure,
            EventIds.UserConfirmEmailFailed)
    {
    }

    /// <summary>
    /// Gets or sets the user id.
    /// </summary>
    /// <returns>
    /// The user id.
    /// </returns>
    public string UserId { get; set; }

    /// <summary>
    /// Gets or sets the failure message.
    /// </summary>
    public string Failure { get; set; }

    string IUserEvent.UserNameOrEmail => "";
}