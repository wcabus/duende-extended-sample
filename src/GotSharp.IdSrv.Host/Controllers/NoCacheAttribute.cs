using Duende.IdentityServer.Extensions;
using Microsoft.AspNetCore.Mvc.Filters;

namespace GotSharp.IdSrv.Host.Controllers;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class NoCacheAttribute : Attribute, IActionFilter
{
    public void OnActionExecuting(ActionExecutingContext context)
    {

    }

    public void OnActionExecuted(ActionExecutedContext context)
    {
        context.HttpContext.Response.SetNoCache();
    }
}