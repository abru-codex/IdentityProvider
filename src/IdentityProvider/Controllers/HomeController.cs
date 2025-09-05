using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace IdentityProvider.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                var userRoles = User.Claims
                    .Where(c => c.Type == ClaimTypes.Role)
                    .Select(c => c.Value)
                    .ToList();

                var viewModel = new
                {
                    UserName = User.Identity.Name,
                    Roles = userRoles,
                    IsAdmin = User.IsInRole("Admin")
                };

                return View(viewModel);
            }

            return View();
        }

        [Authorize]
        public IActionResult Profile()
        {
            var userRoles = User.Claims
                .Where(c => c.Type == ClaimTypes.Role)
                .Select(c => c.Value)
                .ToList();

            var viewModel = new
            {
                UserId = User.FindFirstValue(ClaimTypes.NameIdentifier),
                UserName = User.Identity?.Name,
                Email = User.FindFirstValue(ClaimTypes.Email),
                Roles = userRoles
            };

            return View(viewModel);
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View();
        }
    }
}