using Duende.IdentityServer.Events;
using GotSharp.IdSrv.Host.Events.Contracts;

namespace GotSharp.IdSrv.Host.Events;

public class UserImpersonationSessionStartedEvent : Event, IUserEvent
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UserImpersonationSessionStartedEvent"/> class.
    /// </summary>
    public UserImpersonationSessionStartedEvent(string username, string subjectId, string impersonatedUsername, string impersonatedSubjectId)
        : this()
    {
        Username = username;
        SubjectId = subjectId;
        ImpersonatedUsername = impersonatedUsername;
        ImpersonatedSubjectId = impersonatedSubjectId;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="UserImpersonationSessionStartedEvent"/> class.
    /// </summary>
    protected UserImpersonationSessionStartedEvent()
        : base(EventCategories.Impersonation,
            "User Account Impersonation Session Started",
            EventTypes.Success,
            EventIds.UserImpersonationSessionStarted)
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

    /// <summary>
    /// Gets or sets the username of the impersonated user.
    /// </summary>
    /// <value>
    /// The username.
    /// </value>
    public string ImpersonatedUsername { get; set; }

    /// <summary>
    /// Gets or sets the subject identifier of the impersonated user.
    /// </summary>
    /// <value>
    /// The subject identifier.
    /// </value>
    public string ImpersonatedSubjectId { get; set; }

    string IUserEvent.UserId => SubjectId;
    string IUserEvent.UserNameOrEmail => Username;
}