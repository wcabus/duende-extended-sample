// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using GotSharp.IdSrv.Host.Controllers.Consent;

namespace GotSharp.IdSrv.Host.Controllers.Device
{
    public class DeviceAuthorizationViewModel : ConsentViewModel
    {
        public string UserCode { get; set; }
        public bool ConfirmUserCode { get; set; }
    }
}