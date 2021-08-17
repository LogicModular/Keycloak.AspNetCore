using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;

#nullable enable

namespace Keycloak.AspNetCore
{
    public class KeycloakOptions : RemoteAuthenticationOptions
    { 
        /// <summary>
        /// Gets or set the Host to use when making KeycloakConnect calls.
        /// </summary>
        public string? Host { get; set; }

        /// <summary>
        /// Gets or set the KeycloakConnect realm.
        /// </summary>
        public string? Realm { get; set; }

        /// <summary>
        /// Gets or sets the 'client_id'
        /// </summary>
        public string? ClientId { get; set; }

        /// <summary>
        /// Gets or sets the 'client_secret'
        /// </summary>
        public string? ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets if HTTPS is required for the metadata address or authority.
        /// The default is true. This should be disabled only in development environments.
        /// </summary>
        public bool RequireHttpsMetadata { get; set; } = true;

        /// <summary>
        /// Gets or sets the 'response_type'.
        /// </summary>
        public string ResponseType { get; set; } = OpenIdConnectResponseType.IdToken;

        /// <summary>
        /// Gets the list of permissions to request.
        /// </summary>
        public ICollection<string> Scope { get; } = new HashSet<string>();

        /// <summary>
        /// Enables or disables the use of the Proof Key for Code Exchange (PKCE) standard.
        /// This only applies when the <see cref="ResponseType"/> is set to <see cref="OpenIdConnectResponseType.Code"/>.
        /// See https://tools.ietf.org/html/rfc7636.
        /// The default value is `true`.
        /// </summary>
        public bool UsePkce { get; set; } = true;

        /// <summary>
        /// Gets or sets the parameters used to validate identity tokens.
        /// </summary>
        /// <remarks>Contains the types and definitions required for validating a token.</remarks>
        public TokenValidationParameters TokenValidationParameters { get; set; } = new TokenValidationParameters
        {
            NameClaimType = "name"
        };

    }
}
