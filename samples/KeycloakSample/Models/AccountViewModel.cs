using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace KeycloakMvc.Models
{
    public class AccountViewModel
    {
        public string IdToken { get; set; }

        public string IdTokenJson { get; set; }

        public string AccessToken { get; set; }

        public string AccessTokenJson { get; set; }

        public string RefreshToken { get; set; }

        public string RefreshTokenJson { get; set; }

        public IEnumerable<Claim> Claims { get; set; }
    }
}
