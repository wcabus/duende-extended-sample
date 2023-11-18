using Duende.IdentityServer.Events;
using GotSharp.IdSrv.Host.Events.Contracts;

namespace GotSharp.IdSrv.Host.Events;

public class UserImpersonationSessionEndedEvent : Event, IUserEvent
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UserImpersonationSessionEndedEvent"/> class.
    /// </summary>
    public UserImpersonationSessionEndedEvent(string username, string subjectId)
        : this()
    {
        Username = username;
        SubjectId = subjectId;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="UserImpersonationSessionEndedEvent"/> class.
    /// </summary>
    protected UserImpersonationSessionEndedEvent()
        : base(EventCategories.Impersonation,
            "User Account Impersonation Session Ended",
            EventTypes.Success,
            EventIds.UserImpersonationSessionEnded)
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