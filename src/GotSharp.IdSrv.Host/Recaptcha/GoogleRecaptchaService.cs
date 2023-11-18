using Google.Api.Gax.ResourceNames;
using Google.Cloud.RecaptchaEnterprise.V1;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace GotSharp.IdSrv.Host.Recaptcha;

public class GoogleRecaptchaService
{
    private readonly RecaptchaEnterpriseServiceClient _client;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<GoogleRecaptchaService> _logger;
    private readonly RecaptchaOptions _options;
    private readonly ProjectName _projectName;

    public GoogleRecaptchaService(
        RecaptchaEnterpriseServiceClient client,
        IOptionsMonitor<RecaptchaOptions> options,
        IHttpContextAccessor httpContextAccessor,
        ILogger<GoogleRecaptchaService> logger)
    {
        _client = client;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
        _options = options.CurrentValue;
        _projectName = new ProjectName(_options.ProjectId);
    }

    public static class Actions
    {
        public const string Login = "login";
        public const string Register = "register";
        public const string ActivateAccount = "activate_account";
        public const string ForgotPassword = "forgot_password";
        public const string ResetPassword = "reset_password";
        public const string ResendActivationEmail = "resend_activation_email";
        public const string MFA = "mfa";
        public const string RecoveryCode = "recovery_code";
    }

    public string SiteKey => _options.SiteKey;

    public async Task<RecaptchaResponse> CreateAssessment(string token, string action)
    {
        _logger.LogTrace("Creating Google Recaptcha assessment...");

        try
        {
            var httpContext = _httpContextAccessor.HttpContext;
            string userAgent = null;
            string userIpAddress = null;

            if (httpContext is not null)
            {
                userAgent = httpContext.Request.Headers[HeaderNames.UserAgent];
                _logger.LogDebug("User-Agent: {useragent}", userAgent);

                userIpAddress = httpContext.Connection.RemoteIpAddress?.ToString();
                _logger.LogDebug("Client IP: {remoteIpAddress}", userIpAddress);
            }

            var assessmentRequest = new CreateAssessmentRequest
            {
                Assessment = new Assessment
                {
                    Event = new Event
                    {
                        SiteKey = _options.SiteKey,
                        Token = token,
                        ExpectedAction = action,
                        UserAgent = userAgent,
                        UserIpAddress = userIpAddress
                    }
                },
                ParentAsProjectName = _projectName
            };

            var response = await _client.CreateAssessmentAsync(assessmentRequest);
            if (!response.TokenProperties.Valid)
            {
                _logger.LogWarning("The response was deemed invalid, reason: {reason}",
                    response.TokenProperties.InvalidReason.ToString());
                return RecaptchaResponse.Invalid();
            }

            if (response.TokenProperties.Action != action)
            {
                _logger.LogWarning("The response action is a mismatch. Expected {expectedAction}, got {action}",
                    action, response.TokenProperties.Action);
                return RecaptchaResponse.ActionMismatch();
            }


            if (_logger.IsEnabled(LogLevel.Trace))
            {
                _logger.LogTrace("Valid response and matching action, score = {score}. Reasons:",
                    response.RiskAnalysis.Score);
                foreach (var reason in response.RiskAnalysis.Reasons)
                {
                    _logger.LogTrace(reason.ToString());
                }
            }

            return RecaptchaResponse.Valid(response.RiskAnalysis.Score, response.RiskAnalysis.Reasons.Select(x => x.ToString()));
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Unhandled error during Recaptcha Assessment.");
        }

        // benefit of doubt in this case
        return RecaptchaResponse.Valid(1, Array.Empty<string>());
    }

    public async Task Delay(RecaptchaResponse response)
    {
        if (response.Score >= 0.7)
        {
            // most likely just fine
            return;
        }

        if (response.Score >= 0.5)
        {
            // introduce a slight delay
            await Task.Delay(TimeSpan.FromSeconds(1));
            return;
        }

        // hard delay
        await Task.Delay(TimeSpan.FromSeconds(5));
    }
}