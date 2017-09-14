// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Microsoft.AspNetCore.Authentication.WsFederation
{
    public class WsFederationTest
    {
        [Fact]
        public async Task EndToEnd()
        {
            var builder = new WebHostBuilder()
                .ConfigureServices(ConfigureAppServices)
                .Configure(ConfigureApp);
            var server = new TestServer(builder);

            var httpClient = server.CreateClient();

            // Set the right metadata document in the server cache
            var kvps = new List<KeyValuePair<string, string>>();
            kvps.Add(new KeyValuePair<string, string>("metadata", File.ReadAllText(@"federationmetadata.xml")));
            await httpClient.PostAsync("/metadata", new FormUrlEncodedContent(kvps));

            // Verify if the request is redirected to STS with right parameters
            var response = await httpClient.GetAsync("/");
            Assert.Equal("https://login.windows.net/4afbc689-805b-48cf-a24c-d4aa3248a248/wsfed", response.Headers.Location.GetLeftPart(System.UriPartial.Path));
            var queryItems = QueryHelpers.ParseQuery(response.Headers.Location.Query);

            Assert.Equal("http://Automation1", queryItems["wtrealm"]);
            Assert.True(queryItems["wctx"].ToString().StartsWith("WsFedAppState="), "wctx does not start with a WsFedAppState=");
            Assert.True(queryItems["mystate"].ToString().EndsWith("customValue"), "wctx does not end with a &mystate=customValue");
            Assert.Equal<string>(server.BaseAddress + "signin-wsfed", queryItems["wreply"]);
            Assert.Equal<string>("wsignin1.0", queryItems["wa"]);
        }

        [Fact]
        public async Task InvalidTokenIsRjected()
        {
            var builder = new WebHostBuilder()
                .ConfigureServices(ConfigureAppServices)
                .Configure(ConfigureApp);
            var server = new TestServer(builder);

            var httpClient = server.CreateClient();

            // Set the right metadata document in the server cache
            var kvps = new List<KeyValuePair<string, string>>();
            kvps.Add(new KeyValuePair<string, string>("metadata", File.ReadAllText(@"federationmetadata.xml")));
            await httpClient.PostAsync("/metadata", new FormUrlEncodedContent(kvps));

            // Verify if the request is redirected to STS with right parameters
            var response = await httpClient.GetAsync("/");
            var queryItems = QueryHelpers.ParseQuery(response.Headers.Location.Query);

            // Send an invalid token and verify that the token is not honored
            kvps = new List<KeyValuePair<string, string>>();
            kvps.Add(new KeyValuePair<string, string>("wa", "wsignin1.0"));
            kvps.Add(new KeyValuePair<string, string>("wresult", File.ReadAllText(@"InvalidToken.xml")));
            kvps.Add(new KeyValuePair<string, string>("wctx", queryItems["wctx"]));
            response = await httpClient.PostAsync(queryItems["wreply"], new FormUrlEncodedContent(kvps));

            // Did the request end in the actual resource requested for
            Assert.Equal("AuthenticationFailed", await response.Content.ReadAsStringAsync());
        }

        private void ConfigureAppServices(IServiceCollection services)
        {
            services.AddAuthentication(sharedOptions =>
            {
                sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                sharedOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                sharedOptions.DefaultChallengeScheme = WsFederationDefaults.AuthenticationScheme;
            })
            .AddWsFederation(options =>
            {
                options.Wtrealm = "http://Automation1";
                options.MetadataAddress = "https://login.windows.net/4afbc689-805b-48cf-a24c-d4aa3248a248/federationmetadata/2007-06/federationmetadata.xml";
                options.BackchannelHttpHandler = new WaadMetadataDocumentHandler();
                options.StateDataFormat = new CustomStateDataFormat();
                // options.CallbackPath = "/";
                // options.SkipUnrecognizedRequests = true;
                options.Events = new WsFederationEvents()
                {
                    MessageReceived = context =>
                    {
                        Assert.True(context.ProtocolMessage.Wctx.EndsWith("&mystate=customValue"), "wctx is not ending with &mystate=customValue");
                        context.ProtocolMessage.Wctx = context.ProtocolMessage.Wctx.Replace("&mystate=customValue", string.Empty);
                        context.HttpContext.Items["MessageReceived"] = true;
                        return Task.FromResult(0);
                    },
                    RedirectToIdentityProvider = context =>
                    {
                        if (context.ProtocolMessage.IsSignInMessage)
                        {
                            //Sign in message
                            context.ProtocolMessage.Wctx += "&mystate=customValue";
                        }

                        return Task.FromResult(0);
                    },
                    SecurityTokenReceived = context =>
                    {
                        context.HttpContext.Items["SecurityTokenReceived"] = true;
                        return Task.FromResult(0);
                    },
                    SecurityTokenValidated = context =>
                    {
                        Assert.True((bool)context.HttpContext.Items["MessageReceived"], "MessageReceived notification not invoked");
                        Assert.True((bool)context.HttpContext.Items["SecurityTokenReceived"], "SecurityTokenReceived notification not invoked");

                        if (context.Principal != null)
                        {
                            var identity = context.Principal.Identities.Single();
                            identity.AddClaim(new Claim("ReturnEndpoint", "true"));
                            identity.AddClaim(new Claim("Authenticated", "true"));
                            identity.AddClaim(new Claim(identity.RoleClaimType, "Guest", ClaimValueTypes.String));
                        }

                        return Task.FromResult(0);
                    },
                    AuthenticationFailed = context =>
                    {
                        context.HttpContext.Items["AuthenticationFailed"] = true;
                        //Change the request url to something different and skip Wsfed. This new url will handle the request and let us know if this notification was invoked.
                        context.HttpContext.Request.Path = new PathString("/AuthenticationFailed");
                        context.SkipHandler();
                        return Task.FromResult(0);
                    }
                };
            })
            .AddCookie();
        }

        // Store the metadata once and reuse the same
        private static string metadataXml;
        private void ConfigureApp(IApplicationBuilder app)
        {
            app.Map("/Logout", subApp =>
                {
                    subApp.Run(async context =>
                        {
                            if (context.User.Identity.IsAuthenticated)
                            {
                                var authProperties = new AuthenticationProperties() { RedirectUri = context.Request.GetEncodedUrl() };
                                await context.SignOutAsync(WsFederationDefaults.AuthenticationScheme, authProperties);
                                await context.Response.WriteAsync("Signing out...");
                            }
                            else
                            {
                                await context.Response.WriteAsync("SignedOut");
                            }
                        });
                });

            app.Map("/AuthenticationFailed", subApp =>
            {
                subApp.Run(async context =>
                {
                    await context.Response.WriteAsync("AuthenticationFailed");
                });
            });

            app.Map("/signout-wsfed", subApp =>
            {
                subApp.Run(async context =>
                {
                    await context.Response.WriteAsync("signout-wsfed");
                });
            });
            
            app.Map("/metadata", subApp =>
            {
                subApp.Run(async context =>
                {
                    if (context.Request.Method == "POST")
                    {
                        var formParameters = await context.Request.ReadFormAsync();
                        metadataXml = formParameters["metadata"];
                        await context.Response.WriteAsync("Received metadata");
                    }
                    else
                    {
                        context.Response.ContentType = "text/xml";
                        await context.Response.WriteAsync(metadataXml);
                    }
                });
            });

            app.Run(async context =>
            {
                if (context.User == null || !context.User.Identity.IsAuthenticated)
                {
                    await context.ChallengeAsync(WsFederationDefaults.AuthenticationScheme);
                    await context.Response.WriteAsync("Unauthorized");
                }
                else
                {
                    var identity = context.User.Identities.Single();
                    if (identity.NameClaimType == "Name_Failed" && identity.RoleClaimType == "Role_Failed")
                    {
                        context.Response.StatusCode = 500;
                        await context.Response.WriteAsync("SignIn_Failed");
                    }
                    else if (!identity.HasClaim("Authenticated", "true") || !identity.HasClaim("ReturnEndpoint", "true") || !identity.HasClaim(identity.RoleClaimType, "Guest"))
                    {
                        await context.Response.WriteAsync("Provider not invoked");
                        return;
                    }
                    else
                    {
                        await context.Response.WriteAsync(WsFederationDefaults.AuthenticationScheme);
                    }
                }
            });
        }

        private class WaadMetadataDocumentHandler : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var newResponse = new HttpResponseMessage() { Content = new StringContent(WsFederationTest.metadataXml, Encoding.UTF8, "text/xml") };
                return Task.FromResult<HttpResponseMessage>(newResponse);
            }
        }
    }
}