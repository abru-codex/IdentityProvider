using Microsoft.Extensions.Caching.Distributed;
using System.Text.Json;

namespace IdentityProvider.Services
{
    public interface IPermissionCacheService
    {
        Task<List<string>?> GetUserPermissionsAsync(string userId);
        Task SetUserPermissionsAsync(string userId, List<string> permissions, TimeSpan? expiry = null);
        Task InvalidateUserPermissionsAsync(string userId);
        Task InvalidateAllUserPermissionsAsync();
        Task InvalidateUsersByRoleAsync(string roleId);
        Task<List<string>?> GetRolePermissionsAsync(string roleId);
        Task SetRolePermissionsAsync(string roleId, List<string> permissions, TimeSpan? expiry = null);
        Task InvalidateRolePermissionsAsync(string roleId);
    }

    public class PermissionCacheService : IPermissionCacheService
    {
        private readonly IDistributedCache _cache;
        private readonly ILogger<PermissionCacheService> _logger;
        private const string UserPermissionsPrefix = "user_permissions:";
        private const string RolePermissionsPrefix = "role_permissions:";
        private readonly TimeSpan _defaultExpiry = TimeSpan.FromMinutes(30);

        public PermissionCacheService(IDistributedCache cache, ILogger<PermissionCacheService> logger)
        {
            _cache = cache;
            _logger = logger;
        }

        public async Task<List<string>?> GetUserPermissionsAsync(string userId)
        {
            try
            {
                var cacheKey = $"{UserPermissionsPrefix}{userId}";
                var cachedValue = await _cache.GetStringAsync(cacheKey);
                
                if (cachedValue != null)
                {
                    _logger.LogDebug("Cache hit for user permissions: {UserId}", userId);
                    return JsonSerializer.Deserialize<List<string>>(cachedValue);
                }
                
                _logger.LogDebug("Cache miss for user permissions: {UserId}", userId);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user permissions from cache for user: {UserId}", userId);
                return null;
            }
        }

        public async Task SetUserPermissionsAsync(string userId, List<string> permissions, TimeSpan? expiry = null)
        {
            try
            {
                var cacheKey = $"{UserPermissionsPrefix}{userId}";
                var serializedPermissions = JsonSerializer.Serialize(permissions);
                var options = new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = expiry ?? _defaultExpiry
                };
                
                await _cache.SetStringAsync(cacheKey, serializedPermissions, options);
                _logger.LogDebug("Cached user permissions for user: {UserId}", userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting user permissions cache for user: {UserId}", userId);
            }
        }

        public async Task InvalidateUserPermissionsAsync(string userId)
        {
            try
            {
                var cacheKey = $"{UserPermissionsPrefix}{userId}";
                await _cache.RemoveAsync(cacheKey);
                _logger.LogDebug("Invalidated user permissions cache for user: {UserId}", userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error invalidating user permissions cache for user: {UserId}", userId);
            }
        }

        public Task InvalidateAllUserPermissionsAsync()
        {
            try
            {
                _logger.LogWarning("InvalidateAllUserPermissionsAsync called - this might not clear all keys efficiently");
                return Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error invalidating all user permissions cache");
                return Task.CompletedTask;
            }
        }

        public Task InvalidateUsersByRoleAsync(string roleId)
        {
            try
            {
                _logger.LogInformation("Role {RoleId} permissions changed - consider clearing related user caches", roleId);
                return Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error invalidating users cache for role: {RoleId}", roleId);
                return Task.CompletedTask;
            }
        }

        public async Task<List<string>?> GetRolePermissionsAsync(string roleId)
        {
            try
            {
                var cacheKey = $"{RolePermissionsPrefix}{roleId}";
                var cachedValue = await _cache.GetStringAsync(cacheKey);
                
                if (cachedValue != null)
                {
                    _logger.LogDebug("Cache hit for role permissions: {RoleId}", roleId);
                    return JsonSerializer.Deserialize<List<string>>(cachedValue);
                }
                
                _logger.LogDebug("Cache miss for role permissions: {RoleId}", roleId);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting role permissions from cache for role: {RoleId}", roleId);
                return null;
            }
        }

        public async Task SetRolePermissionsAsync(string roleId, List<string> permissions, TimeSpan? expiry = null)
        {
            try
            {
                var cacheKey = $"{RolePermissionsPrefix}{roleId}";
                var serializedPermissions = JsonSerializer.Serialize(permissions);
                var options = new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = expiry ?? _defaultExpiry
                };
                
                await _cache.SetStringAsync(cacheKey, serializedPermissions, options);
                _logger.LogDebug("Cached role permissions for role: {RoleId}", roleId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting role permissions cache for role: {RoleId}", roleId);
            }
        }

        public async Task InvalidateRolePermissionsAsync(string roleId)
        {
            try
            {
                var cacheKey = $"{RolePermissionsPrefix}{roleId}";
                await _cache.RemoveAsync(cacheKey);
                _logger.LogDebug("Invalidated role permissions cache for role: {RoleId}", roleId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error invalidating role permissions cache for role: {RoleId}", roleId);
            }
        }
    }
}
