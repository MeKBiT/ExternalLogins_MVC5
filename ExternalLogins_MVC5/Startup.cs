using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Facebook;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.MicrosoftAccount;
using Microsoft.Owin.Security.Twitter;
using Owin;
using Owin.Security.Providers.GitHub;
using Owin.Security.Providers.LinkedIn;
using System.Configuration;

[assembly: OwinStartupAttribute(typeof(ExternalLogins_MVC5.Startup))]
namespace ExternalLogins_MVC5
{
    public class Startup
    {
        public Startup()
        {
        }

        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }

        //This method is inside App_Start/Startup.Auth.cs
        public void ConfigureAuth(IAppBuilder app)
        {
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            #region Microsoft

            var microsoftAuthenticationOptions = new MicrosoftAccountAuthenticationOptions()
            {
                ClientId = ConfigurationManager.AppSettings["MsI"],
                ClientSecret = ConfigurationManager.AppSettings["MsS"],
                Provider = new MicrosoftAccountAuthenticationProvider()
                {
                    OnAuthenticated = async context =>
                    {
                        context.Identity.AddClaim(new System.Security.Claims.Claim("MicrosoftAccessToken", context.AccessToken));
                        foreach (var claim in context.User)
                        {
                            var claimType = string.Format("urn:microsoft:{0}", claim.Key);
                            string claimValue = claim.Value.ToString();
                            if (!context.Identity.HasClaim(claimType, claimValue))
                                context.Identity.AddClaim(new System.Security.Claims.Claim(claimType, claimValue, "XmlSchemaString", "Microsoft"));
                        }
                    }
                }
            };
            microsoftAuthenticationOptions.Scope.Add("wl.basic");
            microsoftAuthenticationOptions.Scope.Add("wl.emails");
            microsoftAuthenticationOptions.Scope.Add("wl.birthday");
            app.UseMicrosoftAccountAuthentication(microsoftAuthenticationOptions);

            #endregion Microsoft

            #region Twitter
            var twitterAuthenticationOptions = new TwitterAuthenticationOptions()
            {
                ConsumerKey = ConfigurationManager.AppSettings["TwtI"],
                ConsumerSecret = ConfigurationManager.AppSettings["TwtS"],
                BackchannelCertificateValidator = new CertificateSubjectKeyIdentifierValidator(
                new[]
                {
                    "A5EF0B11CEC04103A34A659048B21CE0572D7D47", // VeriSign Class 3 Secure Server CA - G2
                "0D445C165344C1827E1D20AB25F40163D8BE79A5", // VeriSign Class 3 Secure Server CA - G3
                "7FD365A7C2DDECBBF03009F34339FA02AF333133", // VeriSign Class 3 Public Primary Certification Authority - G5
                "39A55D933676616E73A761DFA16A7E59CDE66FAD", // Symantec Class 3 Secure Server CA - G4
                "4eb6d578499b1ccf5f581ead56be3d9b6744a5e5", // VeriSign Class 3 Primary CA - G5
                "5168FF90AF0207753CCCD9656462A212B859723B", // DigiCert SHA2 High Assurance Server C‎A 
                "B13EC36903F8BF4701D498261A0802EF63642BC3" // DigiCert High Assurance EV Root CA
                }),
                Provider = new TwitterAuthenticationProvider()
                {
                    OnAuthenticated = async context =>
                    {
                        context.Identity.AddClaim(new System.Security.Claims.Claim("TwitterAccessToken", context.AccessToken));
                        foreach (var claim in context.UserId)
                        {
                            var claimType = string.Format("urn:twitter:{0}", claim);
                            string claimValue = claim.ToString();
                            if (!context.Identity.HasClaim(claimType, claimValue))
                                context.Identity.AddClaim(new System.Security.Claims.Claim(claimType, claimValue, "XmlSchemaString", "Twitter"));
                        }
                    }
                }
            };
            app.UseTwitterAuthentication(twitterAuthenticationOptions);

            #endregion Twitter

            #region Facebook

            var facebookAuthenticationOptions = new FacebookAuthenticationOptions()
            {
                AppId = ConfigurationManager.AppSettings["FaceI"],
                AppSecret = ConfigurationManager.AppSettings["FaceS"],
                Provider = new FacebookAuthenticationProvider()
                {
                    OnAuthenticated = async context =>
                    {
                        context.Identity.AddClaim(new System.Security.Claims.Claim("FacebookAccessToken", context.AccessToken));
                        foreach (var claim in context.User)
                        {
                            var claimType = string.Format("urn:facebook:{0}", claim.Key);
                            string claimValue = claim.Value.ToString();
                            if (!context.Identity.HasClaim(claimType, claimValue))
                                context.Identity.AddClaim(new System.Security.Claims.Claim(claimType, claimValue, "XmlSchemaString", "Facebook"));
                        }
                    }
                }
            };
            facebookAuthenticationOptions.Scope.Add("public_profile");
            facebookAuthenticationOptions.Scope.Add("email");
            facebookAuthenticationOptions.Scope.Add("user_birthday");
            app.UseFacebookAuthentication(facebookAuthenticationOptions);

            #endregion Facebook

            #region Google

            var googleAuthenticationOptions = new GoogleOAuth2AuthenticationOptions()
            {
                ClientId = ConfigurationManager.AppSettings["GglI"],
                ClientSecret = ConfigurationManager.AppSettings["GglS"],
                Provider = new GoogleOAuth2AuthenticationProvider()
                {
                    OnAuthenticated = async context =>
                    {
                        context.Identity.AddClaim(new System.Security.Claims.Claim("GoogleAccessToken", context.AccessToken));
                        foreach (var claim in context.User)
                        {
                            var claimType = string.Format("urn:google:{0}", claim.Key);
                            string claimValue = claim.Value.ToString();
                            if (!context.Identity.HasClaim(claimType, claimValue))
                                context.Identity.AddClaim(new System.Security.Claims.Claim(claimType, claimValue, "XmlSchemaString", "Google"));
                        }
                    }
                }
            };
            googleAuthenticationOptions.Scope.Add("https://www.googleapis.com/auth/plus.login email");
            app.UseGoogleAuthentication(googleAuthenticationOptions);

            #endregion Google

            #region LinkedIn

            var linkedinAuthenticationOptions = new LinkedInAuthenticationOptions()
            {
                ClientId = ConfigurationManager.AppSettings["LinkI"],
                ClientSecret = ConfigurationManager.AppSettings["LinkS"],
                Provider = new LinkedInAuthenticationProvider()
                {
                    OnAuthenticated = async context =>
                    {
                        context.Identity.AddClaim(new System.Security.Claims.Claim("LinkedInAccessToken", context.AccessToken));
                        foreach (var claim in context.User)
                        {
                            var claimType = string.Format("urn:linkedin:{0}", claim.Key);
                            string claimValue = claim.Value.ToString();
                            if (!context.Identity.HasClaim(claimType, claimValue))
                                context.Identity.AddClaim(new System.Security.Claims.Claim(claimType, claimValue, "XmlSchemaString", "LinkedIn"));
                        }
                    }
                }
            };
            app.UseLinkedInAuthentication(linkedinAuthenticationOptions);

            #endregion LinkedIn

            #region GitHub

            var gitAuthanticationOptions = new GitHubAuthenticationOptions()
            {
                ClientId = ConfigurationManager.AppSettings["GitI"],
                ClientSecret = ConfigurationManager.AppSettings["GitS"],
                Provider = new GitHubAuthenticationProvider()
                {
                    OnAuthenticated = async context =>
                    {
                        context.Identity.AddClaim(new System.Security.Claims.Claim("GitHubAccessToken", context.AccessToken));
                        foreach (var claim in context.User)
                        {
                            var claimType = string.Format("urn:github:{0}", claim.Key);
                            string claimValue = claim.Value.ToString();
                            if (!context.Identity.HasClaim(claimType, claimValue))
                                context.Identity.AddClaim(new System.Security.Claims.Claim(claimType, claimValue, "XmlSchemaString", "GitHub"));
                        }
                    }
                }
            };
            app.UseGitHubAuthentication(gitAuthanticationOptions);

            #endregion GitHub

        }

    }
}