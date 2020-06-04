using Microsoft.IdentityModel.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Sitecore.Abstractions;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web;

namespace AzureAdProviderApp.Pipelines.AzureAd
{
    public class AzureADIdentityProviderProcessor : IdentityProvidersProcessor
    {
        public AzureADIdentityProviderProcessor(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration, Microsoft.Owin.Infrastructure.ICookieManager cookieManager, BaseSettings settings) : 
            base(federatedAuthenticationConfiguration, cookieManager, settings)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            IdentityModelEventSource.ShowPII = true;
        }

        protected override string IdentityProviderName => "AzureAd";

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, nameof(args));

            var identityProvider = this.GetIdentityProvider();
            var authenticationType = this.GetAuthenticationType();

            string aadInstance = Settings.GetSetting("AADInstance");
            string tenant = Settings.GetSetting("Tenant");
            string clientId = Settings.GetSetting("ClientId");
            string postLogoutRedirectURI = Settings.GetSetting("PostLogoutRedirectURI");
            string redirectURI = Settings.GetSetting("RedirectURI");
            string authority = string.Format(CultureInfo.InvariantCulture, aadInstance, tenant);

            args.App.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Caption = identityProvider.Caption,
                AuthenticationType = authenticationType,
                AuthenticationMode = AuthenticationMode.Passive,
                ClientId = clientId,
                Authority = authority,
                PostLogoutRedirectUri = postLogoutRedirectURI,
                RedirectUri = redirectURI,
                Scope = "offline_access",

                // Watch for Events
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    // When everything is passed
                    SecurityTokenValidated = async notification =>
                    {
                        // Get the Ident object from Ticket
                        var identity = notification.AuthenticationTicket.Identity;

                        // Use Sitecore Claim Transformation Service to generate additional claims like role or admin
                        foreach (var claimTransformationService in identityProvider.Transformations)
                        {
                            claimTransformationService.Transform(identity,
                                new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
                        }

                        // Create new Auth Ticket
                        notification.AuthenticationTicket = new AuthenticationTicket(identity, notification.AuthenticationTicket.Properties);

                        //Returns blank task
                        return;
                    }

                }
            });
        }
    }
}