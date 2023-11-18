using Duende.IdentityServer.Events;

namespace GotSharp.IdSrv.Host.Events.Contracts;

public interface IEvent
{
    /// <summary>
    /// Gets or sets the category.
    /// </summary>
    /// <value>
    /// The category.
    /// </value>
    string Category { get; }

    /// <summary>
    /// Gets or sets the name.
    /// </summary>
    /// <value>
    /// The name.
    /// </value>
    string Name { get; }

    /// <summary>
    /// Gets or sets the event type.
    /// </summary>
    /// <value>
    /// The type of the event.
    /// </value>
    EventTypes EventType { get; }

    /// <summary>
    /// Gets or sets the identifier.
    /// </summary>
    /// <value>
    /// The identifier.
    /// </value>
    int Id { get; }

    /// <summary>
    /// Gets or sets the event message.
    /// </summary>
    /// <value>
    /// The message.
    /// </value>
    string Message { get; }

    /// <summary>
    /// Gets or sets the per-request activity identifier.
    /// </summary>
    /// <value>
    /// The activity identifier.
    /// </value>
    string ActivityId { get; }

    /// <summary>
    /// Gets or sets the time stamp when the event was raised.
    /// </summary>
    /// <value>
    /// The time stamp.
    /// </value>
    DateTime TimeStamp { get; }

    /// <summary>
    /// Gets or sets the server process identifier.
    /// </summary>
    /// <value>
    /// The process identifier.
    /// </value>
    int ProcessId { get; }

    /// <summary>
    /// Gets or sets the local ip address of the current request.
    /// </summary>
    /// <value>
    /// The local ip address.
    /// </value>
    string LocalIpAddress { get; }

    /// <summary>
    /// Gets or sets the remote ip address of the current request.
    /// </summary>
    /// <value>
    /// The remote ip address.
    /// </value>
    string RemoteIpAddress { get; }
}