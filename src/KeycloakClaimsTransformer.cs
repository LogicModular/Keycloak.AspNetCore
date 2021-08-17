using Microsoft.AspNetCore.Authentication;
using Newtonsoft.Json.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Keycloak.AspNetCore
{
    public class KeycloakClaimsTransformer : IClaimsTransformation
    {
        private readonly KeycloakOptions _keycloakOptions;

        public KeycloakClaimsTransformer(KeycloakOptions keycloakOptions)
        {
            _keycloakOptions = keycloakOptions;
        }

        public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            var claimsIdenity = principal.Identity as ClaimsIdentity;

            var realmAccess = principal.FindFirstValue("realm_access");
            if (realmAccess != null)
            {
                var realmAccessObj = JObject.Parse(realmAccess);
                var realmRoles = realmAccessObj["roles"];
                foreach (var realmRole in realmRoles)
                {
                    claimsIdenity.AddClaim(new Claim(ClaimTypes.Role, realmRole.ToString()));
                }
            }

            var resourceAccess = principal.FindFirstValue("resource_access");
            if (resourceAccess != null)
            {
                var resourceAccessObj = JObject.Parse(resourceAccess);
                var clientResource = resourceAccessObj[_keycloakOptions.ClientId];
                var clientRoles = clientResource["roles"];
                foreach (var clientRole in clientRoles)
                {
                    claimsIdenity.AddClaim(new Claim(ClaimTypes.Role, clientRole.ToString()));
                }
            }
            return Task.FromResult(principal);
        }
    }
}
