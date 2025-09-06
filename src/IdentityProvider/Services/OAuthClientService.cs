using IdentityProvider.Database;
using IdentityProvider.Models;
using Microsoft.EntityFrameworkCore;

namespace IdentityProvider.Services;

public interface IOAuthClientService
{
    Task<OAuthClient?> GetClientAsync(string clientId);
    Task<List<OAuthClient>> GetAllClientsAsync();
    Task<List<string>> GetAllowedCorsOriginsAsync();
    Task<bool> ValidateClientAsync(string clientId, string? clientSecret = null);
}

public class OAuthClientService : IOAuthClientService
{
    private readonly ApplicationDbContext _context;

    public OAuthClientService(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<OAuthClient?> GetClientAsync(string clientId)
    {
        return await _context.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == clientId);
    }

    public async Task<List<OAuthClient>> GetAllClientsAsync()
    {
        return await _context.OAuthClients.ToListAsync();
    }

    public async Task<List<string>> GetAllowedCorsOriginsAsync()
    {
        var clients = await _context.OAuthClients.ToListAsync();
        return clients.SelectMany(c => c.GetAllowedCorsOrigins()).Distinct().ToList();
    }

    public async Task<bool> ValidateClientAsync(string clientId, string? clientSecret = null)
    {
        var client = await GetClientAsync(clientId);
        if (client == null) return false;

        if (clientSecret != null)
        {
            return client.ClientSecret == clientSecret;
        }

        return true;
    }
}
