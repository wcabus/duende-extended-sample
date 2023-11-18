using Duende.IdentityServer.Events;
using GotSharp.IdSrv.Host.Events.Contracts;

namespace GotSharp.IdSrv.Host.Events;

public class UserChangeEmailFailedEvent : Event, IUserEvent
{
    public UserChangeEmailFailedEvent(string userId, string failure) : this()
    {
        UserId = userId;
        Failure = failure;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="UserChangeEmailFailedEvent"/> class.
    /// </summary>
    protected UserChangeEmailFailedEvent()
        : base(EventCategories.UserManagement,
            "User Change Email Failed",
            EventTypes.Failure,
            EventIds.UserChangeEmailFailed)
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