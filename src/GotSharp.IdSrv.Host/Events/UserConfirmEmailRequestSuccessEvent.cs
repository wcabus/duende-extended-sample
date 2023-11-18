using Duende.IdentityServer.Events;
using GotSharp.IdSrv.Host.Events.Contracts;

namespace GotSharp.IdSrv.Host.Events;

public class UserConfirmEmailRequestSuccessEvent : Event, IUserEvent
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UserConfirmEmailRequestSuccessEvent"/> class.
    /// </summary>
    /// <param name="username">The username.</param>
    /// <param name="subjectId">The subject identifier.</param>
    public UserConfirmEmailRequestSuccessEvent(string username, string subjectId)
        : this()
    {
        Username = username;
        SubjectId = subjectId;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="UserConfirmEmailRequestSuccessEvent"/> class.
    /// </summary>
    protected UserConfirmEmailRequestSuccessEvent()
        : base(EventCategories.UserManagement,
            "User Change Email Request Success",
            EventTypes.Success,
            EventIds.UserChangeEmailRequestSuccess)
    {
    }

    /// <summary>
    /// Gets or sets the username.
    /// </summary>
    /// <value>
    /// The username.
    /// </value>
    public string Username { get; set; }

    /// <summary>
    /// Gets or sets the subject identifier.
    /// </summary>
    /// <value>
    /// The subject identifier.
    /// </value>
    public string SubjectId { get; set; }

    string IUserEvent.UserId => SubjectId;
    string IUserEvent.UserNameOrEmail => Username;
}