﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace GotSharp.IdSrv.Host.Resources {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "17.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class EmailSubjects {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal EmailSubjects() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("GotSharp.IdSrv.Host.Resources.EmailSubjects", typeof(EmailSubjects).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to GotSharp - Your account has been activated.
        /// </summary>
        internal static string AccountActivated {
            get {
                return ResourceManager.GetString("AccountActivated", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to GotSharp - Activate your account.
        /// </summary>
        internal static string ActivateAccount {
            get {
                return ResourceManager.GetString("ActivateAccount", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to GotSharp - An application requests you to sign in.
        /// </summary>
        internal static string CIBA {
            get {
                return ResourceManager.GetString("CIBA", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to GotSharp - Confirm your email address.
        /// </summary>
        internal static string ConfirmEmailAddress {
            get {
                return ResourceManager.GetString("ConfirmEmailAddress", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to GotSharp - Change your email address.
        /// </summary>
        internal static string ConfirmEmailAddressChange {
            get {
                return ResourceManager.GetString("ConfirmEmailAddressChange", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to GotSharp - Email address change requested.
        /// </summary>
        internal static string EmailAddressAlreadyInUse {
            get {
                return ResourceManager.GetString("EmailAddressAlreadyInUse", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to GotSharp - Email address changed.
        /// </summary>
        internal static string EmailAddressChanged {
            get {
                return ResourceManager.GetString("EmailAddressChanged", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to GotSharp - Your password has been changed.
        /// </summary>
        internal static string PasswordChanged {
            get {
                return ResourceManager.GetString("PasswordChanged", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to GotSharp - Change password.
        /// </summary>
        internal static string ResetPassword {
            get {
                return ResourceManager.GetString("ResetPassword", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to GotSharp - Code to sign in.
        /// </summary>
        internal static string TwoFactorCodeSent {
            get {
                return ResourceManager.GetString("TwoFactorCodeSent", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to GotSharp - Suspicious activitity detected.
        /// </summary>
        internal static string UserAlreadyRegistered {
            get {
                return ResourceManager.GetString("UserAlreadyRegistered", resourceCulture);
            }
        }
    }
}
