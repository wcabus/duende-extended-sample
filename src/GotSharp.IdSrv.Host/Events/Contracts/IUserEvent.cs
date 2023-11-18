namespace GotSharp.IdSrv.Host.Events.Contracts;

public interface IUserEvent : IEvent
{
    /// <summary>
    /// Gets or sets the user name or email.
    /// </summary>
    /// <returns>
    /// The email.
    /// </returns>
    string UserNameOrEmail { get; }

    /// <summary>
    /// Gets or sets the user id.
    /// </summary>
    /// <returns>
    /// The email.
    /// </returns>
    string UserId { get; }
}