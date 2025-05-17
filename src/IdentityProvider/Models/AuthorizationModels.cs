namespace IdentityProvider.Models;

public class RefreshToken
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string UserId { get; set; } = default!;
    public string ClientId { get; set; } = default!;
    public string Token { get; set; } = default!;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public bool IsRevoked { get; set; } = false;
    public string? ReplacedByToken { get; set; }
    public string? ReasonRevoked { get; set; }
}

public class AuthorizationCode
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Code { get; set; } = default!;
    public string UserId { get; set; } = default!;
    public string ClientId { get; set; } = default!;
    public string RedirectUri { get; set; } = default!;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public bool IsUsed { get; set; } = false;
    public string CodeChallenge { get; set; } = default!;
    public string CodeChallengeMethod { get; set; } = default!;
    public List<string> RequestedScopes { get; set; } = new();
}

public class OAuth2Request
{
    public string ClientId { get; set; } = default!;
    public string? RedirectUri { get; set; }
    public string ResponseType { get; set; } = default!;
    public string State { get; set; } = default!;
    public string Scope { get; set; } = default!;
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
    public string? Nonce { get; set; }
    public string? Prompt { get; set; }
}

public class TokenRequest
{
    public string GrantType { get; set; } = default!;
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    public string? Code { get; set; }
    public string? RefreshToken { get; set; }
    public string? RedirectUri { get; set; }
    public string? CodeVerifier { get; set; }
}