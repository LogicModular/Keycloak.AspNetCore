using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace Keycloak.AspNetCore
{
    public static class KeycloakExtensions
    {

        public static AuthenticationBuilder AddKeycloak(this AuthenticationBuilder builder)
            => builder.AddKeycloak(KeycloakDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddKeycloak(this AuthenticationBuilder builder, Action<KeycloakOptions> configureOptions)
            => builder.AddKeycloak(KeycloakDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddKeycloak(this AuthenticationBuilder builder, string authenticationScheme, Action<KeycloakOptions> configureOptions)
        {

            builder.Services.AddHttpClient();

            builder.Services.AddTransient<IClaimsTransformation, KeycloakClaimsTransformer>();

            var keycloakOptions = new KeycloakOptions();
            configureOptions(keycloakOptions);
            builder.Services.AddSingleton(keycloakOptions);

            return builder.AddOpenIdConnect(authenticationScheme, options => {

                options.Authority = $"{keycloakOptions.Host}/auth/realms/{keycloakOptions.Realm}";
                options.ClientId = keycloakOptions.ClientId;
                options.ClientSecret = keycloakOptions.ClientSecret;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.RequireHttpsMetadata = keycloakOptions.RequireHttpsMetadata;

                options.ResponseType = keycloakOptions.ResponseType;
                options.SignInScheme = keycloakOptions.SignInScheme;

                options.SaveTokens = keycloakOptions.SaveTokens;

                options.UsePkce = keycloakOptions.UsePkce;

                options.Scope.Clear();
                foreach (var scope in keycloakOptions.Scope)
                {
                    options.Scope.Add(scope);
                }

                options.TokenValidationParameters = keycloakOptions.TokenValidationParameters;

                options.Events = new OpenIdConnectEvents
                {
                    
                    OnTokenValidated = ctx =>
                    {
                        Console.WriteLine("OnTokenValidated Called.");
                        if (ctx.Properties.Items.ContainsKey(".Token.expires_at"))
                        {
                            var expire = DateTime.Parse(ctx.Properties.Items[".Token.expires_at"]);
                            if (expire > DateTime.Now)
                            {
                            }
                        }
                        return Task.CompletedTask;
                    }
                };

            });
        }
    }
}
