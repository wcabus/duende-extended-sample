namespace GotSharp.IdSrv.Host.Recaptcha;

public class RecaptchaResponse
{
    private RecaptchaResponse() { }

    public static RecaptchaResponse Invalid()
    {
        return new RecaptchaResponse
        {
            Reasons = new[] { "Invalid" }
        };
    }

    public static RecaptchaResponse ActionMismatch()
    {
        return new RecaptchaResponse
        {
            Reasons = new[] { "ActionMismatch" }
        };
    }

    public static RecaptchaResponse Valid(float score, IEnumerable<string> reasons)
    {
        return new RecaptchaResponse
        {
            Score = score,
            Reasons = reasons.ToArray()
        };
    }

    public float Score { get; init; }
    public IEnumerable<string> Reasons { get; init; } = Array.Empty<string>();
}