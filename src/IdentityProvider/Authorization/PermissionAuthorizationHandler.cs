using Microsoft.AspNetCore.Authorization;
using IdentityProvider.Services;
using System.Security.Claims;

namespace IdentityProvider.Authorization
{
    public class PermissionRequirement : IAuthorizationRequirement
    {
        public string Permission { get; }

        public PermissionRequirement(string permission)
        {
            Permission = permission;
        }
    }

    public class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
    {
        private readonly IRolePermissionService _rolePermissionService;

        public PermissionAuthorizationHandler(IRolePermissionService rolePermissionService)
        {
            _rolePermissionService = rolePermissionService;
        }

        protected override async Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            PermissionRequirement requirement)
        {
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            
            if (string.IsNullOrEmpty(userId))
            {
                context.Fail();
                return;
            }

            var hasPermission = await _rolePermissionService.UserHasPermissionAsync(userId, requirement.Permission);
            
            if (hasPermission)
            {
                context.Succeed(requirement);
            }
            else
            {
                context.Fail();
            }
        }
    }
}
