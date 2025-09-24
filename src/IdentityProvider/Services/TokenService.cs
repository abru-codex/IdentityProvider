using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using IdentityProvider.Database;
using IdentityProvider.Models;
using IdentityProvider.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace IdentityProvider.Services;

public class TokenService
{
    private readonly JwtOption _jwtOption;
    private readonly ApplicationDbContext _dbContext;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IOptions<OpenIdConnectOptions> _oidcOptions;
    private readonly JwksService _jwksService;

    public TokenService(
        IOptions<JwtOption> jwtOption,
        ApplicationDbContext dbContext,
        UserManager<IdentityUser> userManager,
        IOptions<OpenIdConnectOptions> oidcOptions,
        JwksService jwksService)
    {
        _jwtOption = jwtOption.Value;
        _dbContext = dbContext;
        _userManager = userManager;
        _oidcOptions = oidcOptions;
        _jwksService = jwksService;
    }

    public string GenerateJwtToken(string username, string userId, IList<string> roles)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId),
            new Claim(JwtRegisteredClaimNames.Email, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var signingCredentials = _jwksService.GetSigningCredentials();

        var token = new JwtSecurityToken(
            issuer: _jwtOption.Issuer,
            audience: _jwtOption.Audience,
            claims: claims,
            expires: DateTime.Now.AddHours(1),
            signingCredentials: signingCredentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public string GenerateIdToken(
        IdentityUser user,
        string clientId,
        string? nonce = null,
        TimeSpan? lifetime = null)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("preferred_username", user.UserName ?? string.Empty),
            new Claim("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
        };

        if (!string.IsNullOrEmpty(user.PhoneNumber))
        {
            claims.Add(new Claim("phone_number", user.PhoneNumber));
        }

        if (!string.IsNullOrEmpty(nonce))
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));
        }

        claims.Add(new Claim(JwtRegisteredClaimNames.Aud, clientId));

        var signingCredentials = _jwksService.GetSigningCredentials();

        var tokenLifetime = lifetime ?? TimeSpan.FromMinutes(10);

        var token = new JwtSecurityToken(
            issuer: _jwtOption.Issuer,
            claims: claims,
            expires: DateTime.UtcNow.Add(tokenLifetime),
            signingCredentials: signingCredentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public string GenerateAccessToken(
        IdentityUser user,
        IList<string> roles,
        string clientId,
        IEnumerable<string> scopes,
        TimeSpan? lifetime = null)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("client_id", clientId)
        };

        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        claims.AddRange(scopes.Select(scope => new Claim("scope", scope)));

        var signingCredentials = _jwksService.GetSigningCredentials();

        var clientConfig = _oidcOptions.Value.Clients.FirstOrDefault(c => c.ClientId == clientId);
        var tokenLifetime = lifetime ?? TimeSpan.FromMinutes(clientConfig?.AccessTokenLifetimeMinutes ?? 60);

        var token = new JwtSecurityToken(
            issuer: _jwtOption.Issuer,
            audience: _jwtOption.Issuer,
            claims: claims,
            expires: DateTime.UtcNow.Add(tokenLifetime),
            signingCredentials: signingCredentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<RefreshToken> GenerateRefreshTokenAsync(string userId, string clientId)
    {
        var clientConfig = _oidcOptions.Value.Clients.FirstOrDefault(c => c.ClientId == clientId);
        int refreshTokenLifetimeDays = clientConfig?.RefreshTokenLifetimeDays ?? 30;

        var refreshToken = new RefreshToken
        {
            UserId = userId,
            ClientId = clientId,
            Token = GenerateRandomToken(),
            ExpiresAt = DateTime.UtcNow.AddDays(refreshTokenLifetimeDays)
        };

        _dbContext.RefreshTokens.Add(refreshToken);
        await _dbContext.SaveChangesAsync();

        return refreshToken;
    }

    public async Task<(RefreshToken?, IdentityUser?)> ValidateRefreshTokenAsync(string token)
    {
        var refreshToken = await _dbContext.RefreshTokens
            .SingleOrDefaultAsync(rt => rt.Token == token && !rt.IsRevoked);

        if (refreshToken == null || refreshToken.ExpiresAt < DateTime.UtcNow)
        {
            return (null, null);
        }

        var user = await _userManager.FindByIdAsync(refreshToken.UserId);
        if (user == null)
        {
            return (refreshToken, null);
        }

        return (refreshToken, user);
    }

    public async Task RevokeRefreshTokenAsync(RefreshToken refreshToken, string? reason = null, string? replacedByToken = null)
    {
        refreshToken.IsRevoked = true;
        refreshToken.ReasonRevoked = reason;
        refreshToken.ReplacedByToken = replacedByToken;

        await _dbContext.SaveChangesAsync();
    }

    private string GenerateRandomToken()
    {
        var randomBytes = new byte[40];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
