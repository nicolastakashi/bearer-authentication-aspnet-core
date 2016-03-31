using System;
using Microsoft.AspNet.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.AspNet.Authorization;
using AuthBearer.Models;

namespace AuthBearer.Controllers
{
    [Route("api/accounts")]
    public class AccountController : Controller
    {
        private readonly TokenAuthOptions _tokenOptions;

        public AccountController(TokenAuthOptions tokenOptions)
        {
            _tokenOptions = tokenOptions;
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public dynamic Login([FromBody]User value)
        {
            //Defini uma data de expiração do Token
            var expires = DateTime.UtcNow.AddMinutes(5);

            //Cria uma instancia da classe que gera o token
            var handler = new JwtSecurityTokenHandler();

            //Criar as claims do usuário
            var identity = new ClaimsIdentity(new GenericIdentity(value.UserName, "TokenAuth"), new[] { new Claim("UserId", "1", ClaimValueTypes.Integer), new Claim(ClaimTypes.Role, "Admin") });

            // Gera as infos que iram constar token de segurança
            var securityToken = handler.CreateToken(
                issuer: _tokenOptions.Issuer,
                audience: _tokenOptions.Audience,
                signingCredentials: _tokenOptions.SigningCredentials,
                subject: identity,
                expires: expires);

            // Escreve o token de segurança
            var token = handler.WriteToken(securityToken);

            // retorna o token com as informações desejadas.
            return new { authenticated = true, entityId = 1, token = token, tokenExpires = expires };

        }

        [Authorize]
        [HttpGet]
        public string Get() => "Ok Authorized";
    }
}
