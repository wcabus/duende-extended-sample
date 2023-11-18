// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

namespace GotSharp.IdSrv.Host.Controllers.Account
{
    public class AccountOptions
    {
        public static bool AllowLocalLogin = true;
        public static bool AllowRememberLogin = true;
        public static TimeSpan RememberMeLoginDuration = TimeSpan.FromDays(30);

        public static bool ShowLogoutPrompt = true;
        public static bool AutomaticRedirectAfterSignOut = true; // Disable to make sure the user is logged out everywhere
    }
}
