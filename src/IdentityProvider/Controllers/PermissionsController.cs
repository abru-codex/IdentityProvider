using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using IdentityProvider.Services;
using System.Security.Claims;

namespace IdentityProvider.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class PermissionsController : ControllerBase
    {
        private readonly IRolePermissionService _rolePermissionService;
        private readonly IUserRoleService _userRoleService;
        private readonly ILogger<PermissionsController> _logger;

        public PermissionsController(
            IRolePermissionService rolePermissionService,
            IUserRoleService userRoleService,
            ILogger<PermissionsController> logger)
        {
            _rolePermissionService = rolePermissionService;
            _userRoleService = userRoleService;
            _logger = logger;
        }

        /// <summary>
        /// Get current user's permissions (cached)
        /// </summary>
        [HttpGet("my-permissions")]
        public async Task<IActionResult> GetMyPermissions()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized();
            }

            var permissions = await _rolePermissionService.GetUserPermissionsAsync(userId);
            return Ok(new { UserId = userId, Permissions = permissions });
        }

        /// <summary>
        /// Check if current user has a specific permission (cached)
        /// </summary>
        [HttpGet("check/{permission}")]
        public async Task<IActionResult> CheckPermission(string permission)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized();
            }

            var hasPermission = await _rolePermissionService.UserHasPermissionAsync(userId, permission);
            return Ok(new { UserId = userId, Permission = permission, HasPermission = hasPermission });
        }

        /// <summary>
        /// Get permissions for a specific role (cached)
        /// </summary>
        [HttpGet("role/{roleId}")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> GetRolePermissions(string roleId)
        {
            var permissions = await _rolePermissionService.GetRolePermissionsAsync(roleId);
            return Ok(new { RoleId = roleId, Permissions = permissions });
        }

        /// <summary>
        /// Add permission to role (invalidates cache)
        /// </summary>
        [HttpPost("role/{roleId}/permission")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> AddPermissionToRole(string roleId, [FromBody] AddPermissionRequest request)
        {
            var result = await _rolePermissionService.AddPermissionAsync(roleId, request.Permission, request.RoleName);
            if (result)
            {
                _logger.LogInformation("Permission {Permission} added to role {RoleId}", request.Permission, roleId);
                return Ok(new { Message = "Permission added successfully" });
            }
            
            return BadRequest(new { Message = "Failed to add permission or permission already exists" });
        }

        /// <summary>
        /// Remove permission from role (invalidates cache)
        /// </summary>
        [HttpDelete("role/{roleId}/permission/{permission}")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> RemovePermissionFromRole(string roleId, string permission)
        {
            var result = await _rolePermissionService.RemovePermissionAsync(roleId, permission);
            if (result)
            {
                _logger.LogInformation("Permission {Permission} removed from role {RoleId}", permission, roleId);
                return Ok(new { Message = "Permission removed successfully" });
            }
            
            return BadRequest(new { Message = "Failed to remove permission or permission not found" });
        }

        /// <summary>
        /// Add user to role (invalidates user's permission cache)
        /// </summary>
        [HttpPost("user/{userId}/role")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> AddUserToRole(string userId, [FromBody] AddRoleRequest request)
        {
            var result = await _userRoleService.AddUserToRoleAsync(userId, request.RoleName);
            if (result)
            {
                _logger.LogInformation("User {UserId} added to role {RoleName}", userId, request.RoleName);
                return Ok(new { Message = "User added to role successfully" });
            }
            
            return BadRequest(new { Message = "Failed to add user to role" });
        }

        /// <summary>
        /// Remove user from role (invalidates user's permission cache)
        /// </summary>
        [HttpDelete("user/{userId}/role/{roleName}")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> RemoveUserFromRole(string userId, string roleName)
        {
            var result = await _userRoleService.RemoveUserFromRoleAsync(userId, roleName);
            if (result)
            {
                _logger.LogInformation("User {UserId} removed from role {RoleName}", userId, roleName);
                return Ok(new { Message = "User removed from role successfully" });
            }
            
            return BadRequest(new { Message = "Failed to remove user from role" });
        }
    }

    public class AddPermissionRequest
    {
        public string Permission { get; set; } = string.Empty;
        public string? RoleName { get; set; }
    }

    public class AddRoleRequest
    {
        public string RoleName { get; set; } = string.Empty;
    }
}
