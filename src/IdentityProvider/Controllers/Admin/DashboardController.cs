using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using IdentityProvider.DbContext;
using IdentityProvider.Models.ViewModels;

namespace IdentityProvider.Controllers.Admin
{
    public class DashboardController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;

        public DashboardController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            ApplicationDbContext context,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _context = context;
            _configuration = configuration;
        }

        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> Index()
        {
            var viewModel = new DashboardViewModel
            {
                TotalUsers = await _userManager.Users.CountAsync(),
                TotalRoles = await _roleManager.Roles.CountAsync(),
                ActiveSessions = await _context.RefreshTokens.Where(rt => !rt.IsRevoked && rt.ExpiresAt > DateTime.UtcNow).CountAsync(),
                TotalClients = _configuration.GetSection("OpenIdConnect:Clients").Get<List<object>>()?.Count ?? 0,
                RecentUsers = await _userManager.Users
                    .OrderByDescending(u => u.Id)
                    .Take(5)
                    .Select(u => new RecentUserViewModel
                    {
                        Id = u.Id,
                        Email = u.Email,
                        UserName = u.UserName,
                        EmailConfirmed = u.EmailConfirmed
                    })
                    .ToListAsync(),
                UserGrowth = await GetUserGrowthData(),
                TokensIssued = await _context.RefreshTokens.CountAsync()
            };

            return View(viewModel);
        }

        private async Task<List<UserGrowthData>> GetUserGrowthData()
        {
            // Get user registration data for the last 7 days
            var sevenDaysAgo = DateTime.UtcNow.AddDays(-7);
            var users = await _userManager.Users.ToListAsync();
            
            var growthData = new List<UserGrowthData>();
            for (int i = 6; i >= 0; i--)
            {
                var date = DateTime.UtcNow.AddDays(-i).Date;
                growthData.Add(new UserGrowthData
                {
                    Date = date.ToString("MMM dd"),
                    Count = users.Count(u => u.Id != null) // Simplified for now
                });
            }
            
            return growthData;
        }
    }
}