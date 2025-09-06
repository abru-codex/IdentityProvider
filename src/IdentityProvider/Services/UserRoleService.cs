using Microsoft.AspNetCore.Identity;

namespace IdentityProvider.Services
{
    public interface IUserRoleService
    {
        Task<bool> AddUserToRoleAsync(string userId, string roleName);
        Task<bool> RemoveUserFromRoleAsync(string userId, string roleName);
        Task<bool> UpdateUserRolesAsync(string userId, IList<string> roles);
    }

    public class UserRoleService : IUserRoleService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IPermissionCacheService _cacheService;
        private readonly ILogger<UserRoleService> _logger;

        public UserRoleService(
            UserManager<IdentityUser> userManager,
            IPermissionCacheService cacheService,
            ILogger<UserRoleService> logger)
        {
            _userManager = userManager;
            _cacheService = cacheService;
            _logger = logger;
        }

        public async Task<bool> AddUserToRoleAsync(string userId, string roleName)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    _logger.LogWarning("User not found: {UserId}", userId);
                    return false;
                }

                var result = await _userManager.AddToRoleAsync(user, roleName);
                
                if (result.Succeeded)
                {
                    // Invalidate user's permission cache
                    await _cacheService.InvalidateUserPermissionsAsync(userId);
                    _logger.LogInformation("Added user {UserId} to role {RoleName} and invalidated cache", userId, roleName);
                    return true;
                }
                else
                {
                    _logger.LogWarning("Failed to add user {UserId} to role {RoleName}: {Errors}", 
                        userId, roleName, string.Join(", ", result.Errors.Select(e => e.Description)));
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error adding user {UserId} to role {RoleName}", userId, roleName);
                return false;
            }
        }

        public async Task<bool> RemoveUserFromRoleAsync(string userId, string roleName)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    _logger.LogWarning("User not found: {UserId}", userId);
                    return false;
                }

                var result = await _userManager.RemoveFromRoleAsync(user, roleName);
                
                if (result.Succeeded)
                {
                    // Invalidate user's permission cache
                    await _cacheService.InvalidateUserPermissionsAsync(userId);
                    _logger.LogInformation("Removed user {UserId} from role {RoleName} and invalidated cache", userId, roleName);
                    return true;
                }
                else
                {
                    _logger.LogWarning("Failed to remove user {UserId} from role {RoleName}: {Errors}", 
                        userId, roleName, string.Join(", ", result.Errors.Select(e => e.Description)));
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error removing user {UserId} from role {RoleName}", userId, roleName);
                return false;
            }
        }

        public async Task<bool> UpdateUserRolesAsync(string userId, IList<string> roles)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    _logger.LogWarning("User not found: {UserId}", userId);
                    return false;
                }

                // Get current roles
                var currentRoles = await _userManager.GetRolesAsync(user);
                
                // Remove from current roles
                var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);
                if (!removeResult.Succeeded)
                {
                    _logger.LogWarning("Failed to remove current roles for user {UserId}: {Errors}", 
                        userId, string.Join(", ", removeResult.Errors.Select(e => e.Description)));
                    return false;
                }

                // Add to new roles
                var addResult = await _userManager.AddToRolesAsync(user, roles);
                if (!addResult.Succeeded)
                {
                    _logger.LogWarning("Failed to add new roles for user {UserId}: {Errors}", 
                        userId, string.Join(", ", addResult.Errors.Select(e => e.Description)));
                    return false;
                }

                // Invalidate user's permission cache
                await _cacheService.InvalidateUserPermissionsAsync(userId);
                _logger.LogInformation("Updated roles for user {UserId} and invalidated cache", userId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating roles for user {UserId}", userId);
                return false;
            }
        }
    }
}
