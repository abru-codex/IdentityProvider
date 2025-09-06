using IdentityProvider.Database;
using IdentityProvider.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using IdentityProvider.Services;

namespace IdentityProvider.Services
{
    public interface IRolePermissionService
    {
        Task<List<string>> GetRolePermissionsAsync(string roleId);
        Task<bool> HasPermissionAsync(string roleId, string permission);
        Task<bool> AddPermissionAsync(string roleId, string permission, string? roleName = null);
        Task<bool> RemovePermissionAsync(string roleId, string permission);
        Task<bool> SetRolePermissionsAsync(string roleId, List<string> permissions, string? roleName = null);
        Task<List<string>> GetUserPermissionsAsync(string userId);
        Task<bool> UserHasPermissionAsync(string userId, string permission);
        Task<List<string>> GetUserPermissionsByRolesAsync(IList<string> userRoles);
    }

    public class RolePermissionService : IRolePermissionService
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IPermissionCacheService _cacheService;
        private readonly ILogger<RolePermissionService> _logger;

        public RolePermissionService(
            ApplicationDbContext context, 
            UserManager<IdentityUser> userManager,
            IPermissionCacheService cacheService,
            ILogger<RolePermissionService> logger)
        {
            _context = context;
            _userManager = userManager;
            _cacheService = cacheService;
            _logger = logger;
        }

        public async Task<List<string>> GetRolePermissionsAsync(string roleId)
        {
            // Try to get from cache first
            var cachedPermissions = await _cacheService.GetRolePermissionsAsync(roleId);
            if (cachedPermissions != null)
            {
                return cachedPermissions;
            }

            // Get from database
            var permissions = await _context.RolePermissions
                .Where(rp => rp.RoleId == roleId)
                .Select(rp => rp.Permission)
                .ToListAsync();

            // Cache the result
            await _cacheService.SetRolePermissionsAsync(roleId, permissions);

            return permissions;
        }

        public async Task<bool> HasPermissionAsync(string roleId, string permission)
        {
            var permissions = await GetRolePermissionsAsync(roleId);
            return permissions.Contains(permission);
        }

        public async Task<bool> AddPermissionAsync(string roleId, string permission, string? roleName = null)
        {
            // Check if permission already exists
            var exists = await _context.RolePermissions
                .AnyAsync(rp => rp.RoleId == roleId && rp.Permission == permission);
            
            if (exists)
                return false;

            var rolePermission = new RolePermission
            {
                RoleId = roleId,
                Permission = permission,
                RoleName = roleName,
                CreatedAt = DateTime.UtcNow
            };

            _context.RolePermissions.Add(rolePermission);
            await _context.SaveChangesAsync();

            // Invalidate cache for this role
            await _cacheService.InvalidateRolePermissionsAsync(roleId);
            
            // Invalidate user caches for users with this role
            await InvalidateUserCachesForRoleAsync(roleId);

            return true;
        }

        public async Task<bool> RemovePermissionAsync(string roleId, string permission)
        {
            var rolePermission = await _context.RolePermissions
                .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.Permission == permission);

            if (rolePermission == null)
                return false;

            _context.RolePermissions.Remove(rolePermission);
            await _context.SaveChangesAsync();

            // Invalidate cache for this role
            await _cacheService.InvalidateRolePermissionsAsync(roleId);
            
            // Invalidate user caches for users with this role
            await InvalidateUserCachesForRoleAsync(roleId);

            return true;
        }

        public async Task<bool> SetRolePermissionsAsync(string roleId, List<string> permissions, string? roleName = null)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();
            
            try
            {
                // Remove existing permissions
                var existingPermissions = await _context.RolePermissions
                    .Where(rp => rp.RoleId == roleId)
                    .ToListAsync();

                _context.RolePermissions.RemoveRange(existingPermissions);

                // Add new permissions
                if (permissions.Any())
                {
                    var newPermissions = permissions.Select(permission => new RolePermission
                    {
                        RoleId = roleId,
                        Permission = permission,
                        RoleName = roleName,
                        CreatedAt = DateTime.UtcNow
                    }).ToList();

                    await _context.RolePermissions.AddRangeAsync(newPermissions);
                }

                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                // Invalidate cache for this role
                await _cacheService.InvalidateRolePermissionsAsync(roleId);
                
                // Invalidate user caches for users with this role
                await InvalidateUserCachesForRoleAsync(roleId);

                return true;
            }
            catch
            {
                await transaction.RollbackAsync();
                return false;
            }
        }

        public async Task<List<string>> GetUserPermissionsAsync(string userId)
        {
            // Try to get from cache first
            var cachedPermissions = await _cacheService.GetUserPermissionsAsync(userId);
            if (cachedPermissions != null)
            {
                return cachedPermissions;
            }

            // Get from database
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return new List<string>();

            var userRoles = await _userManager.GetRolesAsync(user);
            var permissions = await GetUserPermissionsByRolesAsync(userRoles);

            // Cache the result
            await _cacheService.SetUserPermissionsAsync(userId, permissions);

            return permissions;
        }

        public async Task<bool> UserHasPermissionAsync(string userId, string permission)
        {
            var userPermissions = await GetUserPermissionsAsync(userId);
            return userPermissions.Contains(permission);
        }

        public async Task<List<string>> GetUserPermissionsByRolesAsync(IList<string> userRoles)
        {
            if (!userRoles.Any())
                return new List<string>();

            // Get role IDs from role names
            var roleIds = await _context.Roles
                .Where(r => userRoles.Contains(r.Name!))
                .Select(r => r.Id)
                .ToListAsync();

            if (!roleIds.Any())
                return new List<string>();

            var permissions = await _context.RolePermissions
                .Where(rp => roleIds.Contains(rp.RoleId))
                .Select(rp => rp.Permission)
                .Distinct()
                .ToListAsync();

            return permissions;
        }

        private async Task InvalidateUserCachesForRoleAsync(string roleId)
        {
            try
            {
                // Get role name from roleId
                var role = await _context.Roles.FindAsync(roleId);
                if (role?.Name == null) return;

                // Get all users with this role
                var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name);
                
                // Invalidate cache for each user
                foreach (var user in usersInRole)
                {
                    await _cacheService.InvalidateUserPermissionsAsync(user.Id);
                }

                _logger.LogInformation("Invalidated permission cache for {UserCount} users in role {RoleId}", 
                    usersInRole.Count, roleId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error invalidating user caches for role {RoleId}", roleId);
            }
        }
    }
}
