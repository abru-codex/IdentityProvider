using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using IdentityProvider.Validation;
using FluentValidation;
using IdentityProvider.Models;

namespace IdentityProvider.Controllers
{
    [Authorize(Policy = "AdminOnly")]
    public class RoleManagementController : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ILogger<RoleManagementController> _logger;

        public RoleManagementController(
            RoleManager<IdentityRole> roleManager,
            UserManager<IdentityUser> userManager,
            ILogger<RoleManagementController> logger)
        {
            _roleManager = roleManager;
            _userManager = userManager;
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var roles = await _roleManager.Roles
                .Select(r => new Models.ViewModels.RoleListViewModel
                {
                    Id = r.Id,
                    Name = r.Name,
                    NormalizedName = r.NormalizedName
                })
                .ToListAsync();

            return View(roles);
        }

        [HttpGet]
        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Models.ViewModels.CreateRoleViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            if (await _roleManager.RoleExistsAsync(model.Name))
            {
                ModelState.AddModelError(string.Empty, "Role already exists");
                return View(model);
            }

            var role = new IdentityRole { Name = model.Name };
            var result = await _roleManager.CreateAsync(role);

            if (result.Succeeded)
            {
                _logger.LogInformation("Role created: {RoleName}", model.Name);
                TempData["SuccessMessage"] = "Role created successfully!";
                return RedirectToAction(nameof(Index));
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> Details(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);

            if (role == null || string.IsNullOrWhiteSpace(role.Name))
            {
                return NotFound();
            }

            // Get users in this role
            var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name);
            var assignedUsers = usersInRole?.Select(u => new Models.ViewModels.UserRoleAssignmentViewModel
            {
                UserId = u.Id,
                UserName = u.UserName ?? "",
                Email = u.Email,
                IsAssigned = true,
                OtherRoles = new List<string>() // We could populate this if needed
            }).ToList() ?? new List<Models.ViewModels.UserRoleAssignmentViewModel>();

            var viewModel = new Models.ViewModels.RoleDetailsViewModel
            {
                Id = role.Id,
                Name = role.Name,
                NormalizedName = role.NormalizedName,
                UserCount = assignedUsers.Count,
                AssignedUsers = assignedUsers
            };

            return View(viewModel);
        }

        [HttpGet]
        public async Task<IActionResult> Edit(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);

            if (role == null)
            {
                return NotFound();
            }

            var viewModel = new Models.ViewModels.EditRoleViewModel
            {
                Id = role.Id,
                Name = role.Name
            };

            return View(viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string id, Models.ViewModels.EditRoleViewModel model)
        {
            if (id != model.Id)
            {
                return BadRequest();
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var role = await _roleManager.FindByIdAsync(id);

            if (role == null)
            {
                return NotFound();
            }

            if (!string.IsNullOrEmpty(model.Name) && role.Name != model.Name)
            {
                // Check if new name already exists
                if (await _roleManager.RoleExistsAsync(model.Name))
                {
                    ModelState.AddModelError(string.Empty, "Role name already exists");
                    return View(model);
                }

                role.Name = model.Name;
                var result = await _roleManager.UpdateAsync(role);

                if (result.Succeeded)
                {
                    _logger.LogInformation("Role updated: {RoleName}", model.Name);
                    TempData["SuccessMessage"] = "Role updated successfully!";
                    return RedirectToAction(nameof(Index));
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);

            if (role == null)
            {
                return NotFound();
            }

            // Check if this is a system role
            if (IsSystemRole(role.Name))
            {
                TempData["ErrorMessage"] = "Cannot delete system role";
                return RedirectToAction(nameof(Index));
            }

            var result = await _roleManager.DeleteAsync(role);

            if (result.Succeeded)
            {
                _logger.LogInformation("Role deleted: {RoleName}", role.Name);
                TempData["SuccessMessage"] = "Role deleted successfully!";
            }
            else
            {
                TempData["ErrorMessage"] = "Failed to delete role.";
            }

            return RedirectToAction(nameof(Index));
        }

        private static bool IsSystemRole(string? roleName)
        {
            if (string.IsNullOrEmpty(roleName))
                return false;

            // Define your system roles here
            var systemRoles = new[] { "Admin", "User" };
            return systemRoles.Contains(roleName, StringComparer.OrdinalIgnoreCase);
        }
    }

}