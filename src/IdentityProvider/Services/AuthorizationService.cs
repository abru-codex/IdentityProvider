using System.Security.Cryptography;
using System.Text;
using IdentityProvider.Database;
using IdentityProvider.Models;
using IdentityProvider.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IdentityProvider.Services;

public class AuthorizationService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly IOAuthClientService _oauthClientService;
    private readonly TokenService _tokenService;
    private readonly UserManager<IdentityUser> _userManager;

    public AuthorizationService(
        ApplicationDbContext dbContext,
        IOAuthClientService oauthClientService,
        TokenService tokenService,
        UserManager<IdentityUser> userManager)
    {
        _dbContext = dbContext;
        _oauthClientService = oauthClientService;
        _tokenService = tokenService;
        _userManager = userManager;
    }

    public async Task<AuthorizationCode> CreateAuthorizationCodeAsync(
        string userId,
        string clientId,
        string redirectUri,
        string codeChallenge,
        string codeChallengeMethod,
        IEnumerable<string> requestedScopes)
    {
        var code = GenerateAuthorizationCode();

        var authCode = new AuthorizationCode
        {
            Code = code,
            UserId = userId,
            ClientId = clientId,
            RedirectUri = redirectUri,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            RequestedScopes = requestedScopes.ToList(),
            ExpiresAt = DateTime.UtcNow.AddMinutes(5)
        };

        _dbContext.AuthorizationCodes.Add(authCode);
        await _dbContext.SaveChangesAsync();

        return authCode;
    }

    public async Task<AuthorizationCode?> ValidateAuthorizationCodeAsync(
        string code,
        string clientId,
        string redirectUri,
        string? codeVerifier = null)
    {
        var authCode = await _dbContext.AuthorizationCodes
            .FirstOrDefaultAsync(a => a.Code == code && a.ClientId == clientId && !a.IsUsed);

        if (authCode == null || authCode.ExpiresAt < DateTime.UtcNow)
        {
            return null;
        }

        if (authCode.RedirectUri != redirectUri)
        {
            return null;
        }

        if (!string.IsNullOrEmpty(authCode.CodeChallenge) && !string.IsNullOrEmpty(codeVerifier))
        {
            if (!VerifyCodeChallenge(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod))
            {
                return null;
            }
        }

        authCode.IsUsed = true;
        await _dbContext.SaveChangesAsync();

        return authCode;
    }

    public async Task<bool> ValidateClientAsync(string clientId, string? clientSecret = null)
    {
        return await _oauthClientService.ValidateClientAsync(clientId, clientSecret);
    }

    public async Task<bool> ValidateRedirectUriAsync(string clientId, string redirectUri)
    {
        var client = await _oauthClientService.GetClientAsync(clientId);
        if (client == null)
        {
            return false;
        }

        return client.GetRedirectUris().Contains(redirectUri, StringComparer.OrdinalIgnoreCase);
    }

    public async Task<(string accessToken, string? idToken, string? refreshToken)> GenerateTokensAsync(
        IdentityUser user,
        string clientId,
        IEnumerable<string> requestedScopes,
        string? nonce = null)
    {
        var roles = await _userManager.GetRolesAsync(user);
        var scopes = CleanScopes(requestedScopes);

        var accessToken = _tokenService.GenerateAccessToken(user, roles, clientId, scopes);

        string? idToken = null;
        if (scopes.Contains("openid"))
        {
            idToken = _tokenService.GenerateIdToken(user, clientId, nonce);
        }

        string? refreshToken = null;
        if (scopes.Contains("offline_access"))
        {
            var refreshTokenEntity = await _tokenService.GenerateRefreshTokenAsync(user.Id, clientId);
            refreshToken = refreshTokenEntity.Token;
        }

        return (accessToken, idToken, refreshToken);
    }

    private string GenerateAuthorizationCode()
    {
        var randomBytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private bool VerifyCodeChallenge(string codeVerifier, string codeChallenge, string codeChallengeMethod)
    {
        switch (codeChallengeMethod.ToLower())
        {
            case "plain":
                return codeVerifier == codeChallenge;

            case "s256":
                using (var sha256 = SHA256.Create())
                {
                    var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                    var computedChallenge = Convert.ToBase64String(challengeBytes)
                        .TrimEnd('=')
                        .Replace('+', '-')
                        .Replace('/', '_');

                    return computedChallenge == codeChallenge;
                }

            default:
                return false;
        }
    }

    private IEnumerable<string> CleanScopes(IEnumerable<string> scopes)
    {
        return scopes
            .SelectMany(s => s.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Distinct();
    }
}