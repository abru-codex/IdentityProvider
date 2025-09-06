using IdentityProvider.Areas.Admin.Models.ViewModels;
using IdentityProvider.Database;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using IdentityProvider.Models;

namespace IdentityProvider.Areas.Admin.Controllers
{
    [Authorize(Policy = "AdminOnly")]
    [Route("Admin/[controller]")]
    public class ClientsController(
        IConfiguration configuration,
        ILogger<AdminBaseController> logger,
        IHttpClientFactory httpClientFactory,
        ApplicationDbContext context)
        : AdminBaseController(logger, httpClientFactory, configuration)
    {
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var clients = await context.OAuthClients.ToListAsync();
            var viewModels = clients.Select(c => new ClientListViewModel
            {
                ClientId = c.ClientId,
                ClientName = c.ClientName,
                RedirectUris = c.GetRedirectUris(),
                AllowedScopes = c.GetAllowedScopes(),
                RequirePkce = c.RequirePkce,
                AllowOfflineAccess = c.AllowOfflineAccess,
                AccessTokenLifetimeMinutes = c.AccessTokenLifetimeMinutes
            }).ToList();

            return View(viewModels);
        }

        [HttpGet("Details/{clientId}")]
        public async Task<IActionResult> Details(string clientId)
        {
            var client = await context.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == clientId);
            if (client == null)
            {
                return NotFound();
            }

            var viewModel = new ClientDetailsViewModel
            {
                ClientId = client.ClientId,
                ClientName = client.ClientName,
                ClientSecret = client.ClientSecret,
                RedirectUris = client.GetRedirectUris(),
                PostLogoutRedirectUris = client.GetPostLogoutRedirectUris(),
                AllowedCorsOrigins = client.GetAllowedCorsOrigins(),
                AllowedScopes = client.GetAllowedScopes(),
                RequirePkce = client.RequirePkce,
                AllowOfflineAccess = client.AllowOfflineAccess,
                AccessTokenLifetimeMinutes = client.AccessTokenLifetimeMinutes,
                RefreshTokenLifetimeDays = client.RefreshTokenLifetimeDays
            };

            return View(viewModel);
        }

        [HttpGet("Create")]
        public IActionResult Create()
        {
            var viewModel = new CreateClientViewModel
            {
                ClientSecret = GenerateClientSecret(),
                RequirePkce = true,
                AllowOfflineAccess = true,
                AccessTokenLifetimeMinutes = 60,
                RefreshTokenLifetimeDays = 30
            };
            return View(viewModel);
        }

        [HttpPost("Create")]
        public async Task<IActionResult> Create(CreateClientViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Check if client ID already exists
            var existingClient = await context.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == model.ClientId);
            if (existingClient != null)
            {
                ModelState.AddModelError("ClientId", "A client with this ID already exists.");
                return View(model);
            }

            var newClient = new OAuthClient
            {
                ClientId = model.ClientId,
                ClientName = model.ClientName,
                ClientSecret = model.ClientSecret,
                RequirePkce = model.RequirePkce,
                AllowOfflineAccess = model.AllowOfflineAccess,
                AccessTokenLifetimeMinutes = model.AccessTokenLifetimeMinutes,
                RefreshTokenLifetimeDays = model.RefreshTokenLifetimeDays,
                CreatedAt = DateTime.UtcNow
            };

            newClient.SetRedirectUris(ParseUris(model.RedirectUris));
            newClient.SetPostLogoutRedirectUris(ParseUris(model.PostLogoutRedirectUris));
            newClient.SetAllowedCorsOrigins(ParseUris(model.AllowedCorsOrigins));
            newClient.SetAllowedScopes(model.AllowedScopes);

            context.OAuthClients.Add(newClient);
            await context.SaveChangesAsync();

            TempData["Success"] = "Client created successfully!";
            return RedirectToAction(nameof(Index));
        }

        [HttpGet("Edit/{clientId}")]
        public async Task<IActionResult> Edit(string clientId)
        {
            var client = await context.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == clientId);
            if (client == null)
            {
                return NotFound();
            }

            var viewModel = new EditClientViewModel
            {
                ClientId = client.ClientId,
                ClientName = client.ClientName,
                ClientSecret = string.Empty, // Don't show existing secret
                RedirectUris = string.Join("\n", client.GetRedirectUris()),
                PostLogoutRedirectUris = string.Join("\n", client.GetPostLogoutRedirectUris()),
                AllowedCorsOrigins = string.Join("\n", client.GetAllowedCorsOrigins()),
                AllowedScopes = client.GetAllowedScopes(),
                RequirePkce = client.RequirePkce,
                AllowOfflineAccess = client.AllowOfflineAccess,
                AccessTokenLifetimeMinutes = client.AccessTokenLifetimeMinutes,
                RefreshTokenLifetimeDays = client.RefreshTokenLifetimeDays,
                OriginalClientId = client.ClientId
            };

            return View(viewModel);
        }

        [HttpPost("Edit/{clientId}")]
        public async Task<IActionResult> Edit(string clientId, EditClientViewModel model)
        {
            if (clientId != model.OriginalClientId)
            {
                return BadRequest();
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var client = await context.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == clientId);
            if (client == null)
            {
                return NotFound();
            }

            // Update client properties
            client.ClientName = model.ClientName;
            
            // Only update secret if a new one is provided
            if (!string.IsNullOrWhiteSpace(model.ClientSecret))
            {
                client.ClientSecret = model.ClientSecret;
            }
            
            client.SetRedirectUris(ParseUris(model.RedirectUris));
            client.SetPostLogoutRedirectUris(ParseUris(model.PostLogoutRedirectUris));
            client.SetAllowedCorsOrigins(ParseUris(model.AllowedCorsOrigins));
            client.SetAllowedScopes(model.AllowedScopes);
            client.RequirePkce = model.RequirePkce;
            client.AllowOfflineAccess = model.AllowOfflineAccess;
            client.AccessTokenLifetimeMinutes = model.AccessTokenLifetimeMinutes;
            client.RefreshTokenLifetimeDays = model.RefreshTokenLifetimeDays;
            client.UpdatedAt = DateTime.UtcNow;

            await context.SaveChangesAsync();

            TempData["Success"] = "Client updated successfully!";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost("Delete/{clientId}")]
        public async Task<IActionResult> Delete(string clientId)
        {
            var client = await context.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == clientId);
            if (client == null)
            {
                return NotFound();
            }

            context.OAuthClients.Remove(client);
            await context.SaveChangesAsync();

            TempData["Success"] = "Client deleted successfully!";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost("RegenerateSecret/{clientId}")]
        public async Task<IActionResult> RegenerateSecret(string clientId)
        {
            var client = await context.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == clientId);
            if (client == null)
            {
                return NotFound();
            }

            client.ClientSecret = GenerateClientSecret();
            client.UpdatedAt = DateTime.UtcNow;
            await context.SaveChangesAsync();

            TempData["Success"] = $"New client secret: {client.ClientSecret}";
            TempData["Warning"] = "Please save this secret securely. It won't be shown again.";
            
            return RedirectToAction(nameof(Details), new { clientId });
        }


        private List<string> ParseUris(string uris)
        {
            if (string.IsNullOrWhiteSpace(uris))
                return new List<string>();

            return uris.Split(new[] { '\n', '\r', ',' }, StringSplitOptions.RemoveEmptyEntries)
                      .Select(u => u.Trim())
                      .Where(u => !string.IsNullOrEmpty(u))
                      .ToList();
        }

        private string GenerateClientSecret()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, 32)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }
}
