using Google.Apis.Auth;

namespace TestOAuth2.Services {
    public class GoogleTokenValidator {
        public async Task<GoogleJsonWebSignature.Payload?> Validate (string idToken) {
            try {
                return await GoogleJsonWebSignature.ValidateAsync(idToken);
            }
            catch {
                return null;
            }
        }
    }
}
