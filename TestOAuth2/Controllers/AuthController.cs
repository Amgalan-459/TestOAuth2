using Google.Apis.Auth;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Text.Json;
using TestOAuth2.Models;
using TestOAuth2.Services;

namespace TestOAuth2.Controllers {
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase {
        private static readonly List<User> Users = new();

        private readonly JwtService _jwt;
        private readonly GoogleTokenValidator _google;
        private readonly ILogger<AuthController> _logger;

        public AuthController (JwtService jwt, GoogleTokenValidator google, ILogger<AuthController> logger) {
            _jwt = jwt;
            _google = google;
            _logger = logger;
        }

        // ---------------- JWT EMAIL/PASSWORD ----------------

        [HttpPost("register")]
        public IActionResult Register (RegisterRequest req) {
            if (Users.Any(u => u.Email == req.Email))
                return BadRequest("User exists");

            var hash = BCrypt.Net.BCrypt.HashPassword(req.Password);

            Users.Add(new User {
                Email = req.Email,
                PasswordHash = hash
            });

            return Ok();
        }

        [HttpPost("login")]
        public IActionResult Login (LoginRequest req) {
            var user = Users.FirstOrDefault(u => u.Email == req.Email);
            if (user == null) return Unauthorized("not_found");

            if (!BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash))
                return Unauthorized("wrong_password");

            var token = _jwt.Generate(req.Email);

            return Ok(new { token });
        }


        // ---------------- GOOGLE OAuth2 ----------------

        [HttpPost("google-test")]
        public IActionResult TestGoogle ([FromBody] JsonElement body) {
            var google = HttpContext.RequestServices.GetRequiredService<IOptions<GoogleOptions>>().Value;

            Console.WriteLine("CLIENT ID: " + google.ClientId);
            Console.WriteLine("CLIENT SECRET: " + google.ClientSecret);

            return Ok(new { clientId = google.ClientId });
        }

        [HttpPost("google")]
        public async Task<IActionResult> GoogleLogin ([FromBody] JsonElement body) {
            _logger.LogInformation("google login");
            string code = body.GetProperty("code").GetString()!;
            string redirectUri = body.GetProperty("redirectUri").GetString()!;

            Console.WriteLine($"code: {code}");

            var google = HttpContext.RequestServices.GetRequiredService<IOptions<GoogleOptions>>().Value;

            var data = new Dictionary<string, string>
            {
                { "code", code },
                { "client_id", google.ClientId },
                { "client_secret", google.ClientSecret },
                { "redirect_uri", redirectUri },
                { "grant_type", "authorization_code" }
            };

            using var http = new HttpClient();
            var response = await http.PostAsync(
                "https://oauth2.googleapis.com/token",
                new FormUrlEncodedContent(data));

            var rawGoogleResponse = await response.Content.ReadAsStringAsync();
            Console.WriteLine("GOOGLE RESPONSE: " + rawGoogleResponse);

            if (!response.IsSuccessStatusCode)
                return Unauthorized("token_exchange_failed");

            var json = await response.Content.ReadAsStringAsync();
            var tokenData = JsonSerializer.Deserialize<JsonElement>(json);

            string idToken = tokenData.GetProperty("id_token").GetString()!;

            // Валидация id_token
            var payload = await GoogleJsonWebSignature.ValidateAsync(idToken);
            string email = payload.Email;

            // создаём пользователя
            if (!Users.Any(u => u.Email == email))
                Users.Add(new User { Email = email, PasswordHash = "" });

            var token = _jwt.Generate(email);

            return Ok(new { token });
        }



        // ---------------- VK OAuth2 ----------------

        [HttpPost("vk")]
        public async Task<IActionResult> VkLogin ([FromBody] JsonElement body) {
            string code = body.GetProperty("code").GetString()!;
            string redirect = body.GetProperty("redirectUri").GetString()!;

            //string clientId = Environment.GetEnvironmentVariable("VK_CLIENT_ID")!;
            //string clientSecret = Environment.GetEnvironmentVariable("VK_CLIENT_SECRET")!;
            string clientId = "jAxr6JKlVX4Eghp2ANz7";
            string clientSecret = "46ee238f46ee238f46ee238fbb45d2c7ab446ee46ee238f2ff97c73e55767bad3d40ce8";

            var url =
                $"https://oauth.vk.com/access_token?client_id={clientId}&client_secret={clientSecret}&redirect_uri={redirect}&code={code}";

            using var http = new HttpClient();
            var json = await http.GetStringAsync(url);

            var data = JsonSerializer.Deserialize<JsonElement>(json);

            if (!data.TryGetProperty("email", out var emailProp))
                return Unauthorized("no_email");

            string email = emailProp.GetString()!;

            if (!Users.Any(u => u.Email == email))
                Users.Add(new User { Email = email, PasswordHash = "" });

            var token = _jwt.Generate(email);

            return Ok(new { token });
        }
    }
}
