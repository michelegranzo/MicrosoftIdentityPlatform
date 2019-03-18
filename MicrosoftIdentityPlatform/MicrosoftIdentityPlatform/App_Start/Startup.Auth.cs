using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Claims;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;
using MicrosoftIdentityPlatform.Utils;
using MicrosoftIdentityPlatform.Models;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
//using Microsoft.AspNet.Identity;
//using Microsoft.AspNet.Identity.Owin;
//using Microsoft.Owin;
// using Microsoft.Owin.Security.Google;


namespace MicrosoftIdentityPlatform
{
    public partial class Startup
    {
        // da https://github.com/Azure-Samples/active-directory-dotnet-webapp-openidconnect-v2
        public static string clientId = CustomConfigurationManager.AppSettings["ClientId"];
        private static string appKey = CustomConfigurationManager.AppSettings["ClientSecret"];
        public static string aadInstance = ConfigurationManager.AppSettings["AADInstance"];
        private static string redirectUri = ConfigurationManager.AppSettings["RedirectUri"];

        // da https://docs.microsoft.com/en-us/azure/active-directory/develop/tutorial-v2-asp-webapp
        //// The Client ID is used by the application to uniquely identify itself to Azure AD.
        //string clientId = CustomConfigurationManager.AppSettings["ClientId"];
        //// RedirectUri is the URL where the user will be redirected to after they sign in.
        //string redirectUri = System.Configuration.ConfigurationManager.AppSettings["RedirectUri"];
        //// Tenant is the tenant ID (e.g. contoso.onmicrosoft.com, or 'common' for multi-tenant)
        //static string tenant = System.Configuration.ConfigurationManager.AppSettings["Tenant"];
        //// Authority is the URL for authority, composed by Azure Active Directory v2.0 endpoint and the tenant name (e.g. https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0)
        //string authority = String.Format(System.Globalization.CultureInfo.InvariantCulture, System.Configuration.ConfigurationManager.AppSettings["Authority"], tenant);


        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            // Custom middleware initialization
            app.UseOAuth2CodeRedeemer(
                new OAuth2CodeRedeemerOptions
                {
                    ClientId = clientId,
                    ClientSecret = appKey,
                    RedirectUri = redirectUri
                }
                );

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    // The `Authority` represents the v2.0 endpoint - https://login.microsoftonline.com/common/v2.0
                    // The `Scope` describes the initial permissions that your app will need.  See https://azure.microsoft.com/documentation/articles/active-directory-v2-scopes/
                    ClientId = clientId,
                    // Authority = authority,
                    Authority = String.Format(CultureInfo.InvariantCulture, aadInstance, "common", "/v2.0"),
                    RedirectUri = redirectUri,
                    Scope = "openid profile offline_access Mail.Read",
                    PostLogoutRedirectUri = redirectUri,
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        // In a real application you would use IssuerValidator for additional checks, like making sure the user's organization has signed up for your app.
                        //     IssuerValidator = (issuer, token, tvp) =>
                        //     {
                        //        //if(MyCustomTenantValidation(issuer))
                        //        return issuer;
                        //        //else
                        //        //    throw new SecurityTokenInvalidIssuerException("Invalid issuer");
                        //    },
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        AuthorizationCodeReceived = OnAuthorization,
                        AuthenticationFailed = OnAuthenticationFailed
                    }
                });
        }

        private async Task OnAuthorization(AuthorizationCodeReceivedNotification context)
        {
            var code = context.Code;
            string signedInUserID = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;
            TokenCache userTokenCache = new MSALSessionCache(signedInUserID, context.OwinContext.Environment["System.Web.HttpContextBase"] as HttpContextBase).GetMsalCacheInstance();
            ConfidentialClientApplication cca = new ConfidentialClientApplication(clientId, redirectUri, new ClientCredential(appKey), userTokenCache, null);
            string[] scopes = { "Mail.Read" };

            try
            {
                AuthenticationResult result = await cca.AcquireTokenByAuthorizationCodeAsync(code, scopes);
            }
            catch (Exception ex)
            {
                context.Response.Write(ex.Message);
            }
        }

        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            // If there is a code in the OpenID Connect response, redeem it for an access token and refresh token, and store those away.
            {
                notification.HandleResponse();
                notification.Response.Redirect("/Error?message=" + notification.Exception.Message);
                return Task.FromResult(0);
            }
        }
    }
}