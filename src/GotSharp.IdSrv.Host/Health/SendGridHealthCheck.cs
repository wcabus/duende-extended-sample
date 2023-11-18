using Microsoft.Extensions.Diagnostics.HealthChecks;
using SendGrid.Helpers.Mail;
using SendGrid;

namespace GotSharp.IdSrv.Host.Health;

internal class SendGridHealthCheck : IHealthCheck
{
    private readonly ISendGridClient _sendGridClient;

    public SendGridHealthCheck(ISendGridClient sendGridClient)
    {
        _sendGridClient = sendGridClient;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = new())
    {
        var msg = new SendGridMessage
        {
            From = new EmailAddress("test.sender@gotsharp.be"),
            Subject = "Test mail",
            MailSettings = new MailSettings
            {
                SandboxMode = new SandboxMode
                {
                    Enable = true // prevents an actual email from being sent, just verifies that we can reach SendGrids API.
                }
            }
        };

        msg.AddTo("test.recipient@gotsharp.be");
        msg.PlainTextContent = "Just a small test.";

        try
        {
            var response = await _sendGridClient.SendEmailAsync(msg, cancellationToken);
            return response.IsSuccessStatusCode
                ? HealthCheckResult.Healthy()
                : new HealthCheckResult(context.Registration.FailureStatus, $"Unexpected response from SendGrid API. Expected 200 OK, received {response.StatusCode}.");
        }
        catch (Exception ex)
        {
            return new HealthCheckResult(context.Registration.FailureStatus, exception: ex);
        }
    }
}