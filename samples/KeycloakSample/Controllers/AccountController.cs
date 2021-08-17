using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Keycloak.AspNetCore;
using KeycloakMvc.Models;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Newtonsoft.Json;
using System.Web;
using System.Net.Http;
using IdentityModel.Client;
using System.Globalization;

namespace KeycloakMvc.Controllers
{
    [Authorize(AuthenticationSchemes = KeycloakDefaults.AuthenticationScheme)]
    public class AccountController : Controller
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IDiscoveryCache _discoveryCache;
        public AccountController(IHttpClientFactory httpClientFactory, IDiscoveryCache discoveryCache)
        {
            _httpClientFactory = httpClientFactory;
            _discoveryCache = discoveryCache;
        }
        
        public async Task<IActionResult> Login(string returnUrl)
        {
            await HttpContext.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignOutAsync(KeycloakDefaults.AuthenticationScheme);

            var homeUrl = Url.Action("Index", "Home");
            return new SignOutResult(KeycloakDefaults.AuthenticationScheme, new AuthenticationProperties { RedirectUri = homeUrl });
        }

        [Authorize]
        public async Task<IActionResult> Refresh()
        {
            var disco = await _discoveryCache.GetAsync();
            if (disco.IsError) throw new Exception(disco.Error);

            string refresh_token = await HttpContext.GetTokenAsync("refresh_token");
            var tokenClient = _httpClientFactory.CreateClient();

            var tokenResult = await tokenClient.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = disco.TokenEndpoint,
                ClientId = "mvc",
                ClientSecret = "ac7c1953-73c1-49d1-9d12-3d351ba8faaf",
                RefreshToken = refresh_token,
                GrantType = "refresh_token",
                Method = HttpMethod.Post,
                ClientCredentialStyle = ClientCredentialStyle.PostBody
            });

            if(!tokenResult.IsError)
            {
                var old_id_token = await HttpContext.GetTokenAsync("id_token");
                var new_id_token = tokenResult.IdentityToken;
                var new_access_token = tokenResult.AccessToken;
                var new_refresh_token = tokenResult.RefreshToken;
                var expiresAt = DateTime.UtcNow + TimeSpan.FromSeconds(tokenResult.ExpiresIn);

                var info = await HttpContext.AuthenticateAsync("Cookies");

                info.Properties.UpdateTokenValue("id_token", new_id_token);
                info.Properties.UpdateTokenValue("refresh_token", new_refresh_token);
                info.Properties.UpdateTokenValue("access_token", new_access_token);
                info.Properties.UpdateTokenValue("expires_at", expiresAt.ToString("o", CultureInfo.InvariantCulture));

                await HttpContext.SignInAsync("Cookies", info.Principal, info.Properties);
                return Redirect("~/Home/Index");
            }
            Console.WriteLine(tokenResult.Error);
            //ViewData["Error"] = ;
            return View("Error");
        }

        [Authorize]
        public async Task<IActionResult> IdToken()
        {
            string id_token = await HttpContext.GetTokenAsync("id_token");
            string id_token_json = new JwtSecurityTokenHandler().ReadJwtToken(id_token).Payload.SerializeToJson();
            return View(new AccountViewModel { IdToken = id_token, IdTokenJson = id_token_json });
        }

        [Authorize]
        public async Task<IActionResult> AccessToken()
        {
            string access_token = await HttpContext.GetTokenAsync("access_token");
            string access_token_json = new JwtSecurityTokenHandler().ReadJwtToken(access_token).Payload.SerializeToJson();
            return View(new AccountViewModel { AccessToken = access_token, AccessTokenJson = access_token_json });
        }

        [Authorize]
        public async Task<IActionResult> RefreshToken()
        {
            string refresh_token = await HttpContext.GetTokenAsync("refresh_token");
            string refresh_token_json = new JwtSecurityTokenHandler().ReadJwtToken(refresh_token).Payload.SerializeToJson();
            return View(new AccountViewModel { RefreshToken = refresh_token, RefreshTokenJson = refresh_token_json });
        }

        [Authorize]
        public IActionResult Claims()
        {
            return View(new AccountViewModel { Claims = User.Claims });
        }

        [Authorize]
        public async Task<IActionResult> Api()
        {
            string refresh_token = await HttpContext.GetTokenAsync("refresh_token");
            string refresh_token_json = new JwtSecurityTokenHandler().ReadJwtToken(refresh_token).Payload.SerializeToJson();
            return View(new AccountViewModel { RefreshToken = refresh_token, RefreshTokenJson = refresh_token_json });
        }
    }
}
