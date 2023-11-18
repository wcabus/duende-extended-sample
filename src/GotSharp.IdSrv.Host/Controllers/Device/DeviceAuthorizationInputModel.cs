// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using GotSharp.IdSrv.Host.Controllers.Consent;

namespace GotSharp.IdSrv.Host.Controllers.Device
{
    public class DeviceAuthorizationInputModel : ConsentInputModel
    {
        public string UserCode { get; set; }
    }
}