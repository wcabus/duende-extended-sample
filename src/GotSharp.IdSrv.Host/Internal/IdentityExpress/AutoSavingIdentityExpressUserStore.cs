using IdentityExpress.Identity;
using Microsoft.AspNetCore.Identity;

namespace GotSharp.IdSrv.Host.Internal.IdentityExpress;

internal class AutoSavingIdentityExpressUserStore : IdentityExpressUserStore<IdentityExpressUser>
{
    public AutoSavingIdentityExpressUserStore(IdentityExpressDbContext<IdentityExpressUser> context, IdentityErrorDescriber describer = null) : base(context, describer)
    {
        // IdentityExpressUserStore disables auto saving
        AutoSaveChanges = true;
    }

    public override async Task<IdentityResult> DeleteAsync(IdentityExpressUser user, CancellationToken cancellationToken = new())
    {
        ThrowIfCancelledOrDisposed(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);

        return await HardDeleteAsync(user, cancellationToken);
    }

    protected void ThrowIfCancelledOrDisposed(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
    }
}