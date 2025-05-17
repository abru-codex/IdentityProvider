using IdentityWebClient.Models;
using IdentityWebClient.Models.Users;
using IdentityWebClient.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityWebClient.Controllers
{
    [Authorize(Roles = "Admin")]
    public class UsersController : Controller
    {
        private readonly IUserService _userService;
        private readonly IRoleService _roleService;
        private readonly ILogger<UsersController> _logger;

        public UsersController(
            IUserService userService,
            IRoleService roleService,
            ILogger<UsersController> logger)
        {
            _userService = userService;
            _roleService = roleService;
            _logger = logger;
        }

        // GET: Users
        public async Task<IActionResult> Index(int page = 1, int pageSize = 10)
        {
            var skip = (page - 1) * pageSize;
            var result = await _userService.GetUsersAsync(skip, pageSize);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Failed to retrieve users: {StatusCode}", result.StatusCode);
                return View("Error", new ErrorViewModel { RequestId = HttpContext.TraceIdentifier, ErrorMessage = "Failed to retrieve users" });
            }

            return View(result.Data);
        }

        // GET: Users/Details/5
        public async Task<IActionResult> Details(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest();
            }

            var result = await _userService.GetUserAsync(id);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Failed to retrieve user details: {StatusCode}", result.StatusCode);
                return View("Error", new ErrorViewModel { RequestId = HttpContext.TraceIdentifier, ErrorMessage = "Failed to retrieve user details" });
            }

            return View(result.Data);
        }

        // GET: Users/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Users/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(RegisterUserDto model)
        {
            if (ModelState.IsValid)
            {
                var result = await _userService.CreateUserAsync(model);

                if (result.IsSuccess)
                {
                    _logger.LogInformation("User created successfully: {Email}", model.Email);
                    return RedirectToAction(nameof(Index));
                }

                _logger.LogWarning("Failed to create user: {ErrorMessage}", result.ErrorMessage);
                ModelState.AddModelError(string.Empty, result.ErrorMessage ?? "Failed to create user");
            }

            return View(model);
        }

        // GET: Users/Edit/5
        public async Task<IActionResult> Edit(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest();
            }

            var result = await _userService.GetUserAsync(id);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Failed to retrieve user for editing: {StatusCode}", result.StatusCode);
                return View("Error", new ErrorViewModel { RequestId = HttpContext.TraceIdentifier, ErrorMessage = "Failed to retrieve user" });
            }

            var model = new UpdateUserDto
            {
                Email = result.Data?.Email,
                PhoneNumber = result.Data?.PhoneNumber
            };

            return View(model);
        }

        // POST: Users/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string id, UpdateUserDto model)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest();
            }

            if (ModelState.IsValid)
            {
                var result = await _userService.UpdateUserAsync(id, model);

                if (result.IsSuccess)
                {
                    _logger.LogInformation("User updated successfully: {Id}", id);
                    return RedirectToAction(nameof(Details), new { id });
                }

                _logger.LogWarning("Failed to update user: {ErrorMessage}", result.ErrorMessage);
                ModelState.AddModelError(string.Empty, result.ErrorMessage ?? "Failed to update user");
            }

            return View(model);
        }

        // GET: Users/Delete/5
        public async Task<IActionResult> Delete(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest();
            }

            var result = await _userService.GetUserAsync(id);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Failed to retrieve user for deletion: {StatusCode}", result.StatusCode);
                return View("Error", new ErrorViewModel { RequestId = HttpContext.TraceIdentifier, ErrorMessage = "Failed to retrieve user" });
            }

            return View(result.Data);
        }

        // POST: Users/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest();
            }

            var result = await _userService.DeleteUserAsync(id);

            if (result.IsSuccess)
            {
                _logger.LogInformation("User deleted successfully: {Id}", id);
                return RedirectToAction(nameof(Index));
            }

            _logger.LogWarning("Failed to delete user: {ErrorMessage}", result.ErrorMessage);
            return View("Error", new ErrorViewModel { RequestId = HttpContext.TraceIdentifier, ErrorMessage = "Failed to delete user" });
        }

        // GET: Users/ChangePassword/5
        public IActionResult ChangePassword(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest();
            }

            ViewBag.UserId = id;
            return View(new ChangePasswordDto());
        }

        // POST: Users/ChangePassword/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(string id, ChangePasswordDto model)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest();
            }

            if (ModelState.IsValid)
            {
                if (model.NewPassword != model.ConfirmNewPassword)
                {
                    ModelState.AddModelError(nameof(model.ConfirmNewPassword), "The new password and confirmation password do not match.");
                    return View(model);
                }

                var result = await _userService.ChangePasswordAsync(id, model);

                if (result.IsSuccess)
                {
                    _logger.LogInformation("Password changed successfully for user: {Id}", id);
                    TempData["SuccessMessage"] = "Password changed successfully.";
                    return RedirectToAction(nameof(Details), new { id });
                }

                _logger.LogWarning("Failed to change password: {ErrorMessage}", result.ErrorMessage);
                ModelState.AddModelError(string.Empty, result.ErrorMessage ?? "Failed to change password");
            }

            ViewBag.UserId = id;
            return View(model);
        }

        // GET: Users/ManageRoles/5
        public async Task<IActionResult> ManageRoles(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest();
            }

            var userResult = await _userService.GetUserAsync(id);
            var rolesResult = await _roleService.GetRolesAsync();

            if (!userResult.IsSuccess || !rolesResult.IsSuccess)
            {
                _logger.LogWarning("Failed to retrieve user or roles: {UserStatus}, {RolesStatus}",
                    userResult.StatusCode, rolesResult.StatusCode);
                return View("Error", new ErrorViewModel { RequestId = HttpContext.TraceIdentifier, ErrorMessage = "Failed to retrieve user or roles" });
            }

            var user = userResult.Data;
            ViewBag.AllRoles = rolesResult.Data;
            ViewBag.UserId = id;

            return View(user);
        }

        // POST: Users/AddToRole
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> AddToRole(string userId, string roleName)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(roleName))
            {
                return BadRequest();
            }

            var result = await _userService.AddRoleToUserAsync(userId, roleName);

            if (result.IsSuccess)
            {
                _logger.LogInformation("Role {Role} added to user {UserId}", roleName, userId);
                TempData["SuccessMessage"] = $"Role '{roleName}' added successfully.";
            }
            else
            {
                _logger.LogWarning("Failed to add role: {ErrorMessage}", result.ErrorMessage);
                TempData["ErrorMessage"] = $"Failed to add role: {result.ErrorMessage}";
            }

            return RedirectToAction(nameof(ManageRoles), new { id = userId });
        }

        // POST: Users/RemoveFromRole
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RemoveFromRole(string userId, string roleName)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(roleName))
            {
                return BadRequest();
            }

            var result = await _userService.RemoveRoleFromUserAsync(userId, roleName);

            if (result.IsSuccess)
            {
                _logger.LogInformation("Role {Role} removed from user {UserId}", roleName, userId);
                TempData["SuccessMessage"] = $"Role '{roleName}' removed successfully.";
            }
            else
            {
                _logger.LogWarning("Failed to remove role: {ErrorMessage}", result.ErrorMessage);
                TempData["ErrorMessage"] = $"Failed to remove role: {result.ErrorMessage}";
            }

            return RedirectToAction(nameof(ManageRoles), new { id = userId });
        }
    }
}