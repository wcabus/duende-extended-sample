using GotSharp.IdSrv.Host.Configuration;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;
using Microsoft.FeatureManagement.Mvc;

namespace GotSharp.IdSrv.Host.Internal;

/// <summary>
/// Depending on the feature, we want to redirect to a different page or status code.
/// </summary>
internal class RedirectDisabledFeaturesHandler : IDisabledFeaturesHandler
{
    public Task HandleDisabledFeatures(IEnumerable<string> features, ActionExecutingContext context)
    {
        if (features.Contains(FeatureToggles.MFA))
        {
            // Redirect to the home page
            context.Result = new RedirectToActionResult("Index", "Home", null);
            return Task.CompletedTask;
        }

        // Default behavior: show a 404 page
        context.Result = (IActionResult)new StatusCodeResult(404);
        return Task.CompletedTask;
    }

}