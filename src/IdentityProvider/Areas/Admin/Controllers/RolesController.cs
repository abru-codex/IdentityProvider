using IdentityProvider.Areas.Admin.Models.ViewModels;
using IdentityProvider.Authorization;
using IdentityProvider.Database;
using IdentityProvider.Models;
using IdentityProvider.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityProvider.Areas.Admin.Controllers
{
    [Authorize(Policy = "AdminOnly")]
    [Route("Admin/[controller]")]
    public class RolesController(
        UserManager<IdentityUser> userManager,
        RoleManager<IdentityRole> roleManager,
        ILogger<AdminBaseController> logger,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration, 
        ApplicationDbContext context,
        IRolePermissionService rolePermissionService)
        : AdminBaseController(logger, httpClientFactory, configuration)
    {
        [HttpGet]
        [RequirePermission(IdentityProvider.Models.Permissions.RoleRead)]
        public async Task<IActionResult> Index()
        {
            var roles = await roleManager.Roles.ToListAsync();

            var roleIds = roles.Select(r => r.Id).ToList();
            var rolePermissions = await context.RolePermissions
                .Where(rp => roleIds.Contains(rp.RoleId))
                .GroupBy(rp => rp.RoleId)
                .Select(g => new { 
                    RoleId = g.Key, 
                    Permissions = g.Select(rp => rp.Permission).ToList() 
                })
                .ToListAsync();
            var permissionLookup = rolePermissions.ToDictionary(
                rp => rp.RoleId, 
                rp => rp.Permissions
            );
            var roleViewModels = new List<RoleListViewModel>();
            
            foreach (var role in roles)
            {
                var usersInRole = await userManager.GetUsersInRoleAsync(role.Name!);
                var permissions = permissionLookup.GetValueOrDefault(role.Id, new List<string>());
                
                roleViewModels.Add(new RoleListViewModel
                {
                    Id = role.Id,
                    Name = role.Name!,
                    NormalizedName = role.NormalizedName,
                    UserCount = usersInRole.Count,
                    AssignedUsers = usersInRole.Select(u => u.UserName!).ToList(),
                    Permissions = permissions,
                    PermissionCount = permissions.Count
                });
            }

            return View(roleViewModels);
        }

        [HttpGet("Details/{id}")]
        [RequirePermission(IdentityProvider.Models.Permissions.RoleRead)]
        public async Task<IActionResult> Details(string id)
        {
            var role = await roleManager.FindByIdAsync(id);
            if (role == null)
            {
                SetErrorMessage("Role not found.");
                return RedirectToAction(nameof(Index));
            }

            var usersInRole = await userManager.GetUsersInRoleAsync(role.Name!);
            var assignedUsers = new List<UserRoleAssignmentViewModel>();

            foreach (var user in usersInRole)
            {
                var otherRoles = await userManager.GetRolesAsync(user);
                assignedUsers.Add(new UserRoleAssignmentViewModel
                {
                    UserId = user.Id,
                    UserName = user.UserName!,
                    Email = user.Email,
                    IsAssigned = true,
                    OtherRoles = otherRoles.Where(r => r != role.Name).ToList()
                });
            }

            var viewModel = new RoleDetailsViewModel
            {
                Id = role.Id,
                Name = role.Name!,
                NormalizedName = role.NormalizedName,
                UserCount = usersInRole.Count,
                AssignedUsers = assignedUsers
            };

            return View(viewModel);
        }

        [HttpGet("Create")]
        [RequirePermission(IdentityProvider.Models.Permissions.RoleCreate)]
        public IActionResult Create()
        {
            return View(new CreateRoleViewModel());
        }

        [HttpPost("Create")]
        [RequirePermission(IdentityProvider.Models.Permissions.RoleCreate)]
        public async Task<IActionResult> Create(CreateRoleViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var existingRole = await roleManager.FindByNameAsync(model.Name);
            if (existingRole != null)
            {
                ModelState.AddModelError("Name", "A role with this name already exists.");
                return View(model);
            }

            var role = new IdentityRole(model.Name);
            var result = await roleManager.CreateAsync(role);

            if (result.Succeeded)
            {
                SetSuccessMessage($"Role '{model.Name}' created successfully!");
                return RedirectToAction(nameof(Index));
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        [HttpGet("Edit/{id}")]
        [RequirePermission(IdentityProvider.Models.Permissions.RoleUpdate)]
        public async Task<IActionResult> Edit(string id)
        {
            var role = await roleManager.FindByIdAsync(id);
            if (role == null)
            {
                SetErrorMessage("Role not found.");
                return RedirectToAction(nameof(Index));
            }

            var usersInRole = await userManager.GetUsersInRoleAsync(role.Name!);
            var allUsers = await userManager.Users.ToListAsync();
            
            var assignedUsers = new List<UserRoleAssignmentViewModel>();
            var availableUsers = new List<UserRoleAssignmentViewModel>();

            foreach (var user in allUsers)
            {
                var userRoles = await userManager.GetRolesAsync(user);
                var isAssigned = usersInRole.Any(u => u.Id == user.Id);
                
                var userViewModel = new UserRoleAssignmentViewModel
                {
                    UserId = user.Id,
                    UserName = user.UserName!,
                    Email = user.Email,
                    IsAssigned = isAssigned,
                    OtherRoles = userRoles.Where(r => r != role.Name).ToList()
                };

                if (isAssigned)
                {
                    assignedUsers.Add(userViewModel);
                }
                else
                {
                    availableUsers.Add(userViewModel);
                }
            }

            var viewModel = new EditRoleViewModel
            {
                Id = role.Id,
                Name = role.Name!,
                NormalizedName = role.NormalizedName,
                AssignedUsers = assignedUsers,
                AvailableUsers = availableUsers
            };

            return View(viewModel);
        }

        [HttpPost("Edit/{id}")]
        [RequirePermission(IdentityProvider.Models.Permissions.RoleUpdate)]
        public async Task<IActionResult> Edit(string id, EditRoleViewModel model)
        {
            if (id != model.Id)
            {
                return BadRequest();
            }

            var role = await roleManager.FindByIdAsync(id);
            if (role == null)
            {
                SetErrorMessage("Role not found.");
                return RedirectToAction(nameof(Index));
            }

            if (!ModelState.IsValid)
            {
                await LoadEditRoleViewModelData(model, role);
                return View(model);
            }

            if (role.Name != model.Name)
            {
                var existingRole = await roleManager.FindByNameAsync(model.Name);
                if (existingRole != null && existingRole.Id != role.Id)
                {
                    ModelState.AddModelError("Name", "A role with this name already exists.");
                    await LoadEditRoleViewModelData(model, role);
                    return View(model);
                }

                role.Name = model.Name;
                role.NormalizedName = model.Name.ToUpper();
            }

            var result = await roleManager.UpdateAsync(role);

            if (result.Succeeded)
            {
                SetSuccessMessage($"Role '{model.Name}' updated successfully!");
                return RedirectToAction(nameof(Index));
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            await LoadEditRoleViewModelData(model, role);
            return View(model);
        }

        [HttpPost("Delete/{id}")]
        [RequirePermission(IdentityProvider.Models.Permissions.RoleDelete)]
        public async Task<IActionResult> Delete(string id)
        {
            var role = await roleManager.FindByIdAsync(id);
            if (role == null)
            {
                SetErrorMessage("Role not found.");
                return RedirectToAction(nameof(Index));
            }

            var usersInRole = await userManager.GetUsersInRoleAsync(role.Name!);
            if (usersInRole.Any())
            {
                SetErrorMessage($"Cannot delete role '{role.Name}' because it has {usersInRole.Count} assigned user(s). Please remove all users from this role first.");
                return RedirectToAction(nameof(Details), new { id });
            }

            var result = await roleManager.DeleteAsync(role);

            if (result.Succeeded)
            {
                SetSuccessMessage($"Role '{role.Name}' deleted successfully!");
            }
            else
            {
                SetErrorMessage($"Failed to delete role '{role.Name}'.");
            }

            return RedirectToAction(nameof(Index));
        }

        [HttpPost("AssignUser/{roleId}")]
        public async Task<IActionResult> AssignUser(string roleId, string userId)
        {
            var role = await roleManager.FindByIdAsync(roleId);
            var user = await userManager.FindByIdAsync(userId);

            if (role == null || user == null)
            {
                return Json(new { success = false, message = "Role or user not found." });
            }

            var isInRole = await userManager.IsInRoleAsync(user, role.Name!);
            if (isInRole)
            {
                return Json(new { success = false, message = "User is already assigned to this role." });
            }

            var result = await userManager.AddToRoleAsync(user, role.Name!);

            if (result.Succeeded)
            {
                return Json(new { success = true, message = $"User '{user.UserName}' assigned to role '{role.Name}' successfully!" });
            }

            return Json(new { success = false, message = "Failed to assign user to role." });
        }

        [HttpPost("RemoveUser/{roleId}")]
        public async Task<IActionResult> RemoveUser(string roleId, string userId)
        {
            var role = await roleManager.FindByIdAsync(roleId);
            var user = await userManager.FindByIdAsync(userId);

            if (role == null || user == null)
            {
                return Json(new { success = false, message = "Role or user not found." });
            }

            var isInRole = await userManager.IsInRoleAsync(user, role.Name!);
            if (!isInRole)
            {
                return Json(new { success = false, message = "User is not assigned to this role." });
            }

            var result = await userManager.RemoveFromRoleAsync(user, role.Name!);

            if (result.Succeeded)
            {
                return Json(new { success = true, message = $"User '{user.UserName}' removed from role '{role.Name}' successfully!" });
            }

            return Json(new { success = false, message = "Failed to remove user from role." });
        }

        [HttpPost("ManageUsers/{roleId}")]
        public async Task<IActionResult> ManageUsers(string roleId, List<string> selectedUserIds)
        {
            var role = await roleManager.FindByIdAsync(roleId);
            if (role == null)
            {
                SetErrorMessage("Role not found.");
                return RedirectToAction(nameof(Index));
            }

            selectedUserIds ??= new List<string>();

            var currentUsersInRole = await userManager.GetUsersInRoleAsync(role.Name!);
            var currentUserIds = currentUsersInRole.Select(u => u.Id).ToList();

            var usersToRemove = currentUserIds.Except(selectedUserIds).ToList();
            foreach (var userId in usersToRemove)
            {
                var user = await userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    await userManager.RemoveFromRoleAsync(user, role.Name!);
                }
            }

            var usersToAdd = selectedUserIds.Except(currentUserIds).ToList();
            foreach (var userId in usersToAdd)
            {
                var user = await userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    await userManager.AddToRoleAsync(user, role.Name!);
                }
            }

            SetSuccessMessage($"User assignments for role '{role.Name}' updated successfully!");
            return RedirectToAction(nameof(Details), new { id = roleId });
        }
        
        [HttpGet("Permissions/{id}")]
        [RequirePermission(IdentityProvider.Models.Permissions.RoleManagePermissions)]
        public async Task<IActionResult> Permissions(string id)
        {
            var role = await roleManager.FindByIdAsync(id);
            if (role == null)
            {
                SetErrorMessage("Role not found.");
                return RedirectToAction(nameof(Index));
            }

            var assignedPermissions = await context.RolePermissions
                .Where(rp => rp.RoleId == id)
                .Select(rp => rp.Permission)
                .ToListAsync();

            var permissionCategories = new Dictionary<string, List<PermissionViewModel>>();

            foreach (var category in IdentityProvider.Models.Permissions.GetCategories())
            {
                var categoryPermissions = IdentityProvider.Models.Permissions.GetPermissionsByCategory(category);
                var permissionViewModels = categoryPermissions.Select(permission => new PermissionViewModel
                {
                    Permission = permission,
                    Description = IdentityProvider.Models.Permissions.GetPermissionDescription(permission),
                    IsAssigned = assignedPermissions.Contains(permission)
                }).ToList();

                permissionCategories[category] = permissionViewModels;
            }

            var viewModel = new RolePermissionsViewModel
            {
                RoleId = role.Id,
                RoleName = role.Name!,
                PermissionCategories = permissionCategories,
                AssignedPermissions = assignedPermissions
            };

            return View(viewModel);
        }

        [HttpGet("AssignPermissions/{id}")]
        [RequirePermission(IdentityProvider.Models.Permissions.RoleManagePermissions)]
        public async Task<IActionResult> AssignPermissions(string id)
        {
            var role = await roleManager.FindByIdAsync(id);
            if (role == null)
            {
                SetErrorMessage("Role not found.");
                return RedirectToAction(nameof(Index));
            }

            var assignedPermissions = await context.RolePermissions
                .Where(rp => rp.RoleId == id)
                .Select(rp => rp.Permission)
                .ToListAsync();

            var viewModel = new AssignPermissionsViewModel
            {
                RoleId = role.Id,
                RoleName = role.Name!,
                SelectedPermissions = assignedPermissions
            };

            return View(viewModel);
        }

        [HttpPost("AssignPermissions/{id}")]
        [RequirePermission(IdentityProvider.Models.Permissions.RoleManagePermissions)]
        public async Task<IActionResult> AssignPermissions(string id, AssignPermissionsViewModel model)
        {
            if (id != model.RoleId)
            {
                return BadRequest();
            }

            var role = await roleManager.FindByIdAsync(id);
            if (role == null)
            {
                SetErrorMessage("Role not found.");
                return RedirectToAction(nameof(Index));
            }

            try
            {
                await using var transaction = await context.Database.BeginTransactionAsync();

                var existingPermissions = await context.RolePermissions
                    .Where(rp => rp.RoleId == id)
                    .ToListAsync();

                context.RolePermissions.RemoveRange(existingPermissions);

                if (model.SelectedPermissions?.Any() == true)
                {
                    var newPermissions = model.SelectedPermissions.Select(permission => new RolePermission
                    {
                        RoleId = id,
                        Permission = permission,
                        RoleName = role.Name,
                        CreatedAt = DateTime.UtcNow
                    }).ToList();

                    await context.RolePermissions.AddRangeAsync(newPermissions);
                }

                await context.SaveChangesAsync();
                await transaction.CommitAsync();

                SetSuccessMessage($"Permissions for role '{role.Name}' updated successfully!");
                return RedirectToAction(nameof(Permissions), new { id });
            }
            catch (Exception ex)
            {
                SetErrorMessage($"Failed to update permissions: {ex.Message}");
                return RedirectToAction(nameof(AssignPermissions), new { id });
            }
        }

        [HttpPost("AddPermission/{roleId}")]
        [RequirePermission(IdentityProvider.Models.Permissions.RoleManagePermissions)]
        public async Task<IActionResult> AddPermission(string roleId, string permission)
        {
            var role = await roleManager.FindByIdAsync(roleId);
            if (role == null)
            {
                return Json(new { success = false, message = "Role not found." });
            }

            if (!IdentityProvider.Models.Permissions.GetAllPermissions().Contains(permission))
            {
                return Json(new { success = false, message = "Invalid permission." });
            }

            var existingPermission = await context.RolePermissions
                .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.Permission == permission);

            if (existingPermission != null)
            {
                return Json(new { success = false, message = "Permission is already assigned to this role." });
            }

            try
            {
                var rolePermission = new RolePermission
                {
                    RoleId = roleId,
                    Permission = permission,
                    RoleName = role.Name,
                    CreatedAt = DateTime.UtcNow
                };

                context.RolePermissions.Add(rolePermission);
                await context.SaveChangesAsync();

                return Json(new { success = true, message = $"Permission '{permission}' added to role '{role.Name}' successfully!" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = $"Failed to add permission: {ex.Message}" });
            }
        }

        [HttpPost("RemovePermission/{roleId}")]
        [RequirePermission(IdentityProvider.Models.Permissions.RoleManagePermissions)]
        public async Task<IActionResult> RemovePermission(string roleId, string permission)
        {
            var role = await roleManager.FindByIdAsync(roleId);
            if (role == null)
            {
                return Json(new { success = false, message = "Role not found." });
            }

            var existingPermission = await context.RolePermissions
                .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.Permission == permission);

            if (existingPermission == null)
            {
                return Json(new { success = false, message = "Permission is not assigned to this role." });
            }

            try
            {
                context.RolePermissions.Remove(existingPermission);
                await context.SaveChangesAsync();

                return Json(new { success = true, message = $"Permission '{permission}' removed from role '{role.Name}' successfully!" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = $"Failed to remove permission: {ex.Message}" });
            }
        }

        [HttpGet("GetRolePermissions/{roleId}")]
        public async Task<IActionResult> GetRolePermissions(string roleId)
        {
            var permissions = await context.RolePermissions
                .Where(rp => rp.RoleId == roleId)
                .Select(rp => new { rp.Permission, Description = IdentityProvider.Models.Permissions.GetPermissionDescription(rp.Permission) })
                .ToListAsync();

            return Json(permissions);
        }

        private async Task LoadEditRoleViewModelData(EditRoleViewModel model, IdentityRole role)
        {
            var usersInRole = await userManager.GetUsersInRoleAsync(role.Name!);
            var allUsers = await userManager.Users.ToListAsync();
            
            var assignedUsers = new List<UserRoleAssignmentViewModel>();
            var availableUsers = new List<UserRoleAssignmentViewModel>();

            foreach (var user in allUsers)
            {
                var userRoles = await userManager.GetRolesAsync(user);
                var isAssigned = usersInRole.Any(u => u.Id == user.Id);
                
                var userViewModel = new UserRoleAssignmentViewModel
                {
                    UserId = user.Id,
                    UserName = user.UserName!,
                    Email = user.Email,
                    IsAssigned = isAssigned,
                    OtherRoles = userRoles.Where(r => r != role.Name).ToList()
                };

                if (isAssigned)
                {
                    assignedUsers.Add(userViewModel);
                }
                else
                {
                    availableUsers.Add(userViewModel);
                }
            }

            model.AssignedUsers = assignedUsers;
            model.AvailableUsers = availableUsers;
        }
    }
}

