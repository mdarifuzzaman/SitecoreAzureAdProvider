﻿using Sitecore;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Collections;
using Sitecore.Owin.Authentication.Services;
using Sitecore.Security.Accounts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AzureAdProviderApp.Helpers
{
    public class UserPropertyInitializer: PropertyInitializer
    {
        private const string AzureAdClaimName = "AzureAd";
        private const string OktaClaimName = "Okta";
        protected override void MapCore(User user, ClaimCollection claimCollection)
        {
            Assert.ArgumentNotNull((object)user, nameof(user));
            Assert.ArgumentNotNull((object)claimCollection, nameof(claimCollection));

            base.MapCore(user, claimCollection);

            var isAdminGroup = claimCollection.Any(e => e.Value.Contains("2ea20d7b-4cd3-4a36-b760-39208ef50290"));
            var isOktaAdminGroup = claimCollection.Any(e => e.Value.Contains("OktaAdmins"));
            var claim = claimCollection.Single(e => e.Type == "idp");
            var isAzureAd = claim.Value == AzureAdClaimName;
            var isOkta = claim.Value == OktaClaimName;

            if (isAzureAd)
            {
                if (!user.RuntimeSettings.IsVirtual && (isAdminGroup))
                {
                    if (MainUtil.GetBool(user.Profile.GetCustomProperty("IsAdminMapped"), false))
                    {
                        user.Profile.RemoveCustomProperty("IsAdminMapped");
                    }

                    user.Profile.IsAdministrator = true;
                    user.Profile.SetCustomProperty("IsAdminMapped", "True");
                }
            }
            else if (isOkta)
            {
                if (isOktaAdminGroup)
                {
                    if (MainUtil.GetBool(user.Profile.GetCustomProperty("IsAdminMapped"), false))
                    {
                        user.Profile.RemoveCustomProperty("IsAdminMapped");
                    }

                    user.Profile.IsAdministrator = true;
                    user.Profile.SetCustomProperty("IsAdminMapped", "True");
                }
            }
            
                
            user.Profile.Save();
        }
    }
}