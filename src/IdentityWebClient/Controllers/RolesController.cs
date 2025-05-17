using IdentityWebClient.Models;
using IdentityWebClient.Models.Roles;
using IdentityWebClient.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityWebClient.Controllers
{
    [Authorize(Roles = "Admin")]
    public class RolesController : Controller
    {
        private readonly IRoleService _roleService;
        private readonly ILogger<RolesController> _logger;

        public RolesController(
            IRoleService roleService,
            ILogger<RolesController> logger)
        {
            _roleService = roleService;
            _logger = logger;
        }

        // GET: Roles
        public async Task<IActionResult> Index()
        {
            var result = await _roleService.GetRolesAsync();

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Failed to retrieve roles: {StatusCode}", result.StatusCode);
                return View("Error", new ErrorViewModel { RequestId = HttpContext.TraceIdentifier, ErrorMessage = "Failed to retrieve roles" });
            }

            return View(new RoleListViewModel { Roles = result.Data ?? new List<RoleDto>() });
        }

        // GET: Roles/Details/5
        public async Task<IActionResult> Details(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest();
            }

            var result = await _roleService.GetRoleAsync(id);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Failed to retrieve role details: {StatusCode}", result.StatusCode);
                return View("Error", new ErrorViewModel { RequestId = HttpContext.TraceIdentifier, ErrorMessage = "Failed to retrieve role details" });
            }

            return View(result.Data);
        }

        // GET: Roles/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Roles/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(CreateRoleDto model)
        {
            if (ModelState.IsValid)
            {
                var result = await _roleService.CreateRoleAsync(model);

                if (result.IsSuccess)
                {
                    _logger.LogInformation("Role created successfully: {Name}", model.Name);
                    return RedirectToAction(nameof(Index));
                }

                _logger.LogWarning("Failed to create role: {ErrorMessage}", result.ErrorMessage);
                ModelState.AddModelError(string.Empty, result.ErrorMessage ?? "Failed to create role");
            }

            return View(model);
        }

        // GET: Roles/Edit/5
        public async Task<IActionResult> Edit(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest();
            }

            var result = await _roleService.GetRoleAsync(id);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Failed to retrieve role for editing: {StatusCode}", result.StatusCode);
                return View("Error", new ErrorViewModel { RequestId = HttpContext.TraceIdentifier, ErrorMessage = "Failed to retrieve role" });
            }

            var model = new UpdateRoleDto
            {
                Name = result.Data?.Name
            };

            return View(model);
        }

        // POST: Roles/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string id, UpdateRoleDto model)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest();
            }

            if (ModelState.IsValid)
            {
                var result = await _roleService.UpdateRoleAsync(id, model);

                if (result.IsSuccess)
                {
                    _logger.LogInformation("Role updated successfully: {Id}", id);
                    return RedirectToAction(nameof(Details), new { id });
                }

                _logger.LogWarning("Failed to update role: {ErrorMessage}", result.ErrorMessage);
                ModelState.AddModelError(string.Empty, result.ErrorMessage ?? "Failed to update role");
            }

            return View(model);
        }

        // GET: Roles/Delete/5
        public async Task<IActionResult> Delete(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest();
            }

            var result = await _roleService.GetRoleAsync(id);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Failed to retrieve role for deletion: {StatusCode}", result.StatusCode);
                return View("Error", new ErrorViewModel { RequestId = HttpContext.TraceIdentifier, ErrorMessage = "Failed to retrieve role" });
            }

            return View(result.Data);
        }

        // POST: Roles/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest();
            }

            var result = await _roleService.DeleteRoleAsync(id);

            if (result.IsSuccess)
            {
                _logger.LogInformation("Role deleted successfully: {Id}", id);
                return RedirectToAction(nameof(Index));
            }

            _logger.LogWarning("Failed to delete role: {ErrorMessage}", result.ErrorMessage);
            return View("Error", new ErrorViewModel { RequestId = HttpContext.TraceIdentifier, ErrorMessage = "Failed to delete role" });
        }
    }
}