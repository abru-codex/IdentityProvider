using IdentityProvider.DbContext;
using IdentityProvider.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityProvider.Areas.Admin.Controllers
{
    public class DashboardController(
        UserManager<IdentityUser> userManager,
        RoleManager<IdentityRole> roleManager,
        ApplicationDbContext context,
        IConfiguration configuration,
        ILogger<AdminBaseController> logger,
        IHttpClientFactory httpClientFactory)
        : AdminBaseController(logger, httpClientFactory, configuration)
    {
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> Index()
        {
            var viewModel = new DashboardViewModel
            {
                TotalUsers = await userManager.Users.CountAsync(),
                TotalRoles = await roleManager.Roles.CountAsync(),
                ActiveSessions = await context.RefreshTokens.Where(rt => !rt.IsRevoked && rt.ExpiresAt > DateTime.UtcNow).CountAsync(),
                TotalClients = Configuration.GetSection("OpenIdConnect:Clients").Get<List<object>>()?.Count ?? 0,
                RecentUsers = await userManager.Users
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
                TokensIssued = await context.RefreshTokens.CountAsync()
            };

            return View(viewModel);
        }

        private async Task<List<UserGrowthData>> GetUserGrowthData()
        {
            // Get user registration data for the last 7 days
            var sevenDaysAgo = DateTime.UtcNow.AddDays(-7);
            var users = await userManager.Users.ToListAsync();

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