using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using Okta.AspNet;
using Owin;
using Sitecore.Abstractions;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using System.Configuration;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Security.Claims;

namespace AzureAdProviderApp.Pipelines.Okta
{
    public class OktaIdentityProviderProcessor : IdentityProvidersProcessor
    {
        public OktaIdentityProviderProcessor(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration, Microsoft.Owin.Infrastructure.ICookieManager cookieManager, BaseSettings settings) :
            base(federatedAuthenticationConfiguration, cookieManager, settings)
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
        }

        protected override string IdentityProviderName => "Okta";

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, nameof(args));

            var identityProvider = this.GetIdentityProvider();
            var authenticationType = this.GetAuthenticationType();

            string orgUri = Settings.GetSetting("OrgUri");
            string clientSecret = Settings.GetSetting("ClientSecret");
            string clientId = Settings.GetSetting("ClientId");
            string postLogoutRedirectURI = Settings.GetSetting("PostLogoutRedirectURI");
            string redirectURI = Settings.GetSetting("RedirectURI");

            args.App.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Caption = identityProvider.Caption,
                AuthenticationType = authenticationType,
                AuthenticationMode = AuthenticationMode.Passive,
                ClientId = clientId,
                ClientSecret = clientSecret,
                Authority = orgUri,
                RedirectUri = redirectURI,
                ResponseType = Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectResponseType.CodeIdToken,
                Scope = Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectScope.OpenIdProfile,
                TokenValidationParameters = new TokenValidationParameters { NameClaimType = "name" },

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
                    },
                    AuthorizationCodeReceived =  async n =>
                    {
                        foreach (var group in n.AuthenticationTicket.Identity.Claims.Where(x => x.Type == "groups"))
                        {
                            n.AuthenticationTicket.Identity.AddClaim(new Claim(ClaimTypes.Role, group.Value));
                        }
                    }
                }
            });
        }
    }
}