using System.IdentityModel.Tokens;

namespace AuthBearer.Models
{
    public class TokenAuthOptions
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public SigningCredentials SigningCredentials { get; set; }
    }
}
