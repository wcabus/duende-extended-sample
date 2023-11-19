using Duende.IdentityServer.Events;
using Duende.IdentityServer.Services;
using GotSharp.IdSrv.Host.Events.Contracts;
using RSK.Audit;
using Rsk.DuendeIdentityServer.AuditEventSink.Adapters;

namespace GotSharp.IdSrv.Host.Events;

public class AuditSink : IEventSink
{
    private readonly IRecordAuditableActions _auditRecorder;

    public AuditSink(IRecordAuditableActions auditRecorder)
    {
        _auditRecorder = auditRecorder;
    }

    public Task PersistAsync(Event evt)
    {
        var eventArgs = ConvertEventIntoArgs(evt);
        if (eventArgs == null)
        {
            return Task.CompletedTask;
        }

        return evt.EventType is EventTypes.Success or EventTypes.Information
            ? _auditRecorder.RecordSuccess(eventArgs)
            : _auditRecorder.RecordFailure(eventArgs);
    }

    private IAuditEventArguments ConvertEventIntoArgs(Event evt)
    {
        switch (evt)
        {
            case TokenIssuedSuccessEvent evt1:
                return new TokenIssuedSuccessEventAdapter(evt1);
            case UserLoginSuccessEvent evt2:
                return new UserLoginSuccessEventAdapter(evt2);
            case UserLoginFailureEvent evt3:
                return new UserLoginFailureEventAdapter(evt3);
            case UserLogoutSuccessEvent evt4:
                return new UserLogoutSuccessEventAdapter(evt4);
            case ConsentGrantedEvent evt5:
                return new ConsentGrantedEventAdapter(evt5);
            case ConsentDeniedEvent evt6:
                return new ConsentDeniedEventAdapter(evt6);
            case TokenIssuedFailureEvent evt7:
                return new TokenIssuedFailureEventAdapter(evt7);
            case GrantsRevokedEvent evt8:
                return new GrantsRevokedEventAdapter(evt8);
            case IUserEvent userEvt:
                return new UserEventAdapter(userEvt);
            default:
                return null;
        }
    }
}