using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace TestOAuth2.Services {
    public class JwtService {
        //private const string KEY = "SUPER_SECRET_KEY_123";
        private readonly byte[] key = new byte[32]
{ 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
  17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 }; //Encoding.UTF8.GetBytes(KEY);

        public string Generate (string email) {
            var creds = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256
            );

            var token = new JwtSecurityToken(
                claims: new[] { new Claim(ClaimTypes.Email, email) },
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
