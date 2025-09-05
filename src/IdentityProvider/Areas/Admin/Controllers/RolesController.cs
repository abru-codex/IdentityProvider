using IdentityProvider.Models.ViewModels;
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
        IConfiguration configuration)
        : AdminBaseController(logger, httpClientFactory, configuration)
    {
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var roles = await roleManager.Roles.ToListAsync();
            var roleViewModels = new List<RoleListViewModel>();

            foreach (var role in roles)
            {
                var usersInRole = await userManager.GetUsersInRoleAsync(role.Name!);
                roleViewModels.Add(new RoleListViewModel
                {
                    Id = role.Id,
                    Name = role.Name!,
                    NormalizedName = role.NormalizedName,
                    UserCount = usersInRole.Count,
                    AssignedUsers = usersInRole.Select(u => u.UserName!).ToList()
                });
            }

            return View(roleViewModels);
        }

        [HttpGet("Details/{id}")]
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
        public IActionResult Create()
        {
            return View(new CreateRoleViewModel());
        }

        [HttpPost("Create")]
        public async Task<IActionResult> Create(CreateRoleViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Check if role already exists
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
                // Reload user data for the view
                await LoadEditRoleViewModelData(model, role);
                return View(model);
            }

            // Check if the new name conflicts with an existing role (excluding current role)
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
        public async Task<IActionResult> Delete(string id)
        {
            var role = await roleManager.FindByIdAsync(id);
            if (role == null)
            {
                SetErrorMessage("Role not found.");
                return RedirectToAction(nameof(Index));
            }

            // Check if any users are assigned to this role
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

            // Get current users in role
            var currentUsersInRole = await userManager.GetUsersInRoleAsync(role.Name!);
            var currentUserIds = currentUsersInRole.Select(u => u.Id).ToList();

            // Remove users that are no longer selected
            var usersToRemove = currentUserIds.Except(selectedUserIds).ToList();
            foreach (var userId in usersToRemove)
            {
                var user = await userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    await userManager.RemoveFromRoleAsync(user, role.Name!);
                }
            }

            // Add newly selected users
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