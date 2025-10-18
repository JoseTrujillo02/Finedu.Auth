using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using FirebaseAdmin.Auth;

public class FirebaseAuthenticationOptions : AuthenticationSchemeOptions
{
}

public class FirebaseAuthHandler : AuthenticationHandler<FirebaseAuthenticationOptions>
{
    public const string SchemeName = "Firebase";
    public FirebaseAuthHandler(IOptionsMonitor<FirebaseAuthenticationOptions> options,
                               ILoggerFactory logger,
                               UrlEncoder encoder,
                               ISystemClock clock)
        : base(options, logger, encoder, clock) { }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Esperamos header: Authorization: Bearer <idToken>
        if (!Request.Headers.ContainsKey("Authorization"))
            return AuthenticateResult.NoResult();

        var authHeader = Request.Headers["Authorization"].ToString();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            return AuthenticateResult.Fail("No Bearer token.");

        var token = authHeader.Substring("Bearer ".Length).Trim();

        try
        {
            FirebaseToken decoded = await FirebaseAuth.DefaultInstance.VerifyIdTokenAsync(token);
            var uid = decoded.Uid;

            // Construimos claims desde decoded.Claims (puedes mapear lo que necesites)
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, uid)
            };

            // Si el token trae email o name, agrégalos
            if (decoded.Claims.TryGetValue("email", out var emailObj) && emailObj != null)
                claims.Add(new Claim(ClaimTypes.Email, emailObj.ToString()));

            if (decoded.Claims.TryGetValue("name", out var nameObj) && nameObj != null)
                claims.Add(new Claim(ClaimTypes.Name, nameObj.ToString()));

            var identity = new ClaimsIdentity(claims, SchemeName);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, SchemeName);

            return AuthenticateResult.Success(ticket);
        }
        catch (Exception ex)
        {
            Logger.LogWarning(ex, "Firebase token validation failed.");
            return AuthenticateResult.Fail("Invalid Firebase token.");
        }
    }
}
