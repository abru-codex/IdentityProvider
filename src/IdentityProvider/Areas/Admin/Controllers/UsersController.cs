using IdentityProvider.Areas.Admin.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityProvider.Areas.Admin.Controllers
{
    [Authorize(Policy = "AdminOnly")]
    [Route("Admin/[controller]")]
    public class UsersController(
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
            var users = await userManager.Users.ToListAsync();
            var userViewModels = new List<UserListViewModel>();

            foreach (var user in users)
            {
                var roles = await userManager.GetRolesAsync(user);
                userViewModels.Add(new UserListViewModel
                {
                    Id = user.Id,
                    UserName = user.UserName,
                    Email = user.Email,
                    EmailConfirmed = user.EmailConfirmed,
                    PhoneNumber = user.PhoneNumber,
                    LockoutEnd = user.LockoutEnd,
                    Roles = roles.ToList()
                });
            }

            return View(userViewModels);
        }

        [HttpGet("Details/{id}")]
        public async Task<IActionResult> Details(string id)
        {
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            var roles = await userManager.GetRolesAsync(user);
            var viewModel = new UserDetailsViewModel
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                EmailConfirmed = user.EmailConfirmed,
                PhoneNumber = user.PhoneNumber,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                TwoFactorEnabled = user.TwoFactorEnabled,
                LockoutEnd = user.LockoutEnd,
                LockoutEnabled = user.LockoutEnabled,
                AccessFailedCount = user.AccessFailedCount,
                Roles = roles.ToList()
            };

            return View(viewModel);
        }

        [HttpGet("Create")]
        public async Task<IActionResult> Create()
        {
            var viewModel = new CreateUserViewModel
            {
                AvailableRoles = await roleManager.Roles.Select(r => r.Name).ToListAsync()
            };
            return View(viewModel);
        }

        [HttpPost("Create")]
        public async Task<IActionResult> Create(CreateUserViewModel model)
        {
            if (!ModelState.IsValid)
            {
                model.AvailableRoles = await roleManager.Roles.Select(r => r.Name).ToListAsync();
                return View(model);
            }

            var user = new IdentityUser
            {
                UserName = model.UserName,
                Email = model.Email,
                EmailConfirmed = model.EmailConfirmed,
                PhoneNumber = model.PhoneNumber
            };

            var result = await userManager.CreateAsync(user, model.Password);
            
            if (result.Succeeded)
            {
                if (model.SelectedRoles != null && model.SelectedRoles.Any())
                {
                    await userManager.AddToRolesAsync(user, model.SelectedRoles);
                }
                
                TempData["Success"] = "User created successfully!";
                return RedirectToAction(nameof(Index));
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            model.AvailableRoles = await roleManager.Roles.Select(r => r.Name).ToListAsync();
            return View(model);
        }

        [HttpGet("Edit/{id}")]
        public async Task<IActionResult> Edit(string id)
        {
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            var userRoles = await userManager.GetRolesAsync(user);
            var allRoles = await roleManager.Roles.Select(r => r.Name).ToListAsync();

            var viewModel = new EditUserViewModel
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                EmailConfirmed = user.EmailConfirmed,
                PhoneNumber = user.PhoneNumber,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                TwoFactorEnabled = user.TwoFactorEnabled,
                LockoutEnabled = user.LockoutEnabled,
                SelectedRoles = userRoles.ToList(),
                AvailableRoles = allRoles
            };

            return View(viewModel);
        }

        [HttpPost("Edit/{id}")]
        public async Task<IActionResult> Edit(string id, EditUserViewModel model)
        {
            if (id != model.Id)
            {
                return BadRequest();
            }

            if (!ModelState.IsValid)
            {
                model.AvailableRoles = await roleManager.Roles.Select(r => r.Name).ToListAsync();
                return View(model);
            }

            var user = await userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            user.UserName = model.UserName;
            user.Email = model.Email;
            user.EmailConfirmed = model.EmailConfirmed;
            user.PhoneNumber = model.PhoneNumber;
            user.PhoneNumberConfirmed = model.PhoneNumberConfirmed;
            user.TwoFactorEnabled = model.TwoFactorEnabled;
            user.LockoutEnabled = model.LockoutEnabled;

            var result = await userManager.UpdateAsync(user);
            
            if (result.Succeeded)
            {
                var currentRoles = await userManager.GetRolesAsync(user);
                await userManager.RemoveFromRolesAsync(user, currentRoles);
                
                if (model.SelectedRoles != null && model.SelectedRoles.Any())
                {
                    await userManager.AddToRolesAsync(user, model.SelectedRoles);
                }
                
                TempData["Success"] = "User updated successfully!";
                return RedirectToAction(nameof(Index));
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            model.AvailableRoles = await roleManager.Roles.Select(r => r.Name).ToListAsync();
            return View(model);
        }

        [HttpPost("Delete/{id}")]
        public async Task<IActionResult> Delete(string id)
        {
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            var result = await userManager.DeleteAsync(user);
            
            if (result.Succeeded)
            {
                TempData["Success"] = "User deleted successfully!";
            }
            else
            {
                TempData["Error"] = "Failed to delete user.";
            }

            return RedirectToAction(nameof(Index));
        }

        [HttpPost("ResetPassword/{id}")]
        public async Task<IActionResult> ResetPassword(string id, string newPassword)
        {
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            var token = await userManager.GeneratePasswordResetTokenAsync(user);
            var result = await userManager.ResetPasswordAsync(user, token, newPassword);
            
            if (result.Succeeded)
            {
                return Json(new { success = true, message = "Password reset successfully!" });
            }

            return Json(new { success = false, errors = result.Errors.Select(e => e.Description) });
        }

        [HttpPost("ToggleLockout/{id}")]
        public async Task<IActionResult> ToggleLockout(string id)
        {
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            if (user.LockoutEnd != null && user.LockoutEnd > DateTimeOffset.UtcNow)
            {
                await userManager.SetLockoutEndDateAsync(user, null);
                TempData["Success"] = "User unlocked successfully!";
            }
            else
            {
                await userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddDays(30));
                TempData["Success"] = "User locked for 30 days!";
            }

            return RedirectToAction(nameof(Details), new { id });
        }
    }
}