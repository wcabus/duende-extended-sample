using Duende.IdentityServer.Events;
using GotSharp.IdSrv.Host.Events.Contracts;

namespace GotSharp.IdSrv.Host.Events;

public class UserResetPasswordSuccessEvent : Event, IUserEvent
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UserResetPasswordSuccessEvent"/> class.
    /// </summary>
    /// <param name="username">The username.</param>
    /// <param name="subjectId">The subject identifier.</param>
    public UserResetPasswordSuccessEvent(string username, string subjectId)
        : this()
    {
        Username = username;
        SubjectId = subjectId;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="UserResetPasswordSuccessEvent"/> class.
    /// </summary>
    protected UserResetPasswordSuccessEvent()
        : base(EventCategories.UserManagement,
            "User Reset Password Success",
            EventTypes.Success,
            EventIds.UserResetPasswordSuccess)
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