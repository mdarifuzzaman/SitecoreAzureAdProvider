using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Identity;
using Sitecore.Owin.Authentication.Services;
using Sitecore.Security.Accounts;
using Sitecore.SecurityModel.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AzureAdProviderApp.Helpers
{
    public class UserBuilderOkta : DefaultExternalUserBuilder
    {
        public UserBuilderOkta(ApplicationUserFactory applicationUserFactory, IHashEncryption hashEncryption) : base(applicationUserFactory, hashEncryption)
        {
        }


        public override ApplicationUser BuildUser(UserManager<ApplicationUser> userManager, ExternalLoginInfo externalLoginInfo)
        {
            Assert.ArgumentNotNull((object)externalLoginInfo, nameof(externalLoginInfo));
            ApplicationUser user = this.ApplicationUserFactory.CreateUser(this.CreateUniqueUserName(userManager, externalLoginInfo));

            user.IsVirtual = !this.IsPersistentUser;
            user.Email = externalLoginInfo.Email;
            return user;

        }
        protected override string CreateUniqueUserName(Microsoft.AspNet.Identity.UserManager<ApplicationUser> userManager, Microsoft.AspNet.Identity.Owin.ExternalLoginInfo externalLoginInfo)
        {
            Assert.ArgumentNotNull((object)userManager, nameof(userManager));
            Assert.ArgumentNotNull((object)externalLoginInfo, nameof(externalLoginInfo));
            IdentityProvider identityProvider = this.FederatedAuthenticationConfiguration.GetIdentityProvider(externalLoginInfo.ExternalIdentity);
            if (identityProvider == null)
                throw new InvalidOperationException("Unable to retrieve identity provider for given identity");
            string domain = identityProvider.Domain;
            string email = externalLoginInfo.DefaultUserName;

            // return email and domain
            return $"{domain}\\\\\\\\{email}";
        }
    }
}