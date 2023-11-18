using Duende.IdentityServer.Events;
using GotSharp.IdSrv.Host.Events.Contracts;

namespace GotSharp.IdSrv.Host.Events;

public class UserConfirmEmailChangeFailedEvent : Event, IUserEvent
{
    public UserConfirmEmailChangeFailedEvent(string userId, string failure) : this()
    {
        UserId = userId;
        Failure = failure;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="UserConfirmEmailChangeFailedEvent"/> class.
    /// </summary>
    protected UserConfirmEmailChangeFailedEvent()
        : base(EventCategories.UserManagement,
            "User Confirm Email Change Failed",
            EventTypes.Failure,
            EventIds.UserConfirmEmailChangeFailed)
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
    /// Gets or sets the actual failure.
    /// </summary>
    /// <returns>
    /// The failure reason.
    /// </returns>
    public string Failure { get; set; }

    string IUserEvent.UserNameOrEmail => "";
}