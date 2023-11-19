using GotSharp.IdSrv.Host.Events.Contracts;
using RSK.Audit;
using Rsk.DuendeIdentityServer.AuditEventSink;

namespace GotSharp.IdSrv.Host.Events;

public class UserEventAdapter : IAuditEventArguments
{
    private readonly IUserEvent _evt;

    public UserEventAdapter(IUserEvent evt)
    {
        _evt = evt ?? throw new ArgumentNullException(nameof(evt));
    }

    public ResourceActor Actor => new UserResourceActor(_evt.UserId ?? "<unknown user ID>", _evt.UserNameOrEmail ?? "<unknown username / email>");
    public string Action => _evt.Name;
    public AuditableResource Resource => new("IdentityServer");
    public FormattedString Description => _evt.ToString().SafeForFormatted();
}