// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using GotSharp.IdSrv.Host.Controllers.Ciba;

namespace GotSharp.IdSrv.Host.Controllers.Consent
{
    public class ScopeViewModel
    {
        public string Name { get; set; }
        public string Value { get; set; }
        public string DisplayName { get; set; }
        public string Description { get; set; }
        public bool Emphasize { get; set; }
        public bool Required { get; set; }
        public bool Checked { get; set; }
        public IEnumerable<ResourceViewModel> Resources { get; set; }
    }
}
