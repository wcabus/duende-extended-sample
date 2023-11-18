using IdentityExpress.Identity;
using Microsoft.AspNetCore.Identity;

namespace GotSharp.IdSrv.Host.Internal.IdentityExpress;

internal class AutoSavingIdentityExpressRoleStore : IdentityExpressRoleStore
{
    public AutoSavingIdentityExpressRoleStore(IdentityExpressDbContext context, IdentityErrorDescriber describer = null) : base(context, describer)
    {
        // IdentityExpressRoleStore disables auto saving
        AutoSaveChanges = true;
    }
}