using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Keycloak.AspNetCore;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.Cookies;
using IdentityModel.Client;
using System.Net.Http;

namespace KeycloakMvc
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = KeycloakDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = KeycloakDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddKeycloak(options => {
                options.Host = Configuration["Keycloak:Host"];
                options.Realm = Configuration["Keycloak:Realm"];
                options.ClientId = Configuration["Keycloak:ClientId"];
                options.ClientSecret = Configuration["Keycloak:ClientSecret"];
                options.RequireHttpsMetadata = false;
                options.SaveTokens = true;
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.UsePkce = true;

                options.Scope.Add("openid");
                options.Scope.Add("profile");
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
