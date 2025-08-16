using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using IdentityProvider.Models.ViewModels;
using IdentityProvider.Options;
using System.Text.Json;

namespace IdentityProvider.Controllers.Admin
{
    [Authorize(Policy = "AdminOnly")]
    [Route("Admin/[controller]")]
    public class ClientsController : AdminBaseController
    {
        private readonly string _configPath;

        public ClientsController(
            IConfiguration configuration,
            ILogger<AdminBaseController> logger,
            IHttpClientFactory httpClientFactory)
            : base(logger, httpClientFactory, configuration)
        {
            _configPath = Path.Combine(Directory.GetCurrentDirectory(), "appsettings.json");
        }

        [HttpGet]
        public IActionResult Index()
        {
            var clients = GetClients();
            var viewModels = clients.Select(c => new ClientListViewModel
            {
                ClientId = c.ClientId,
                ClientName = c.ClientName,
                RedirectUris = c.RedirectUris,
                AllowedScopes = c.AllowedScopes,
                RequirePkce = c.RequirePkce,
                AllowOfflineAccess = c.AllowOfflineAccess,
                AccessTokenLifetimeMinutes = c.AccessTokenLifetimeMinutes
            }).ToList();

            return View(viewModels);
        }

        [HttpGet("Details/{clientId}")]
        public IActionResult Details(string clientId)
        {
            var client = GetClient(clientId);
            if (client == null)
            {
                return NotFound();
            }

            var viewModel = new ClientDetailsViewModel
            {
                ClientId = client.ClientId,
                ClientName = client.ClientName,
                ClientSecret = client.ClientSecret,
                RedirectUris = client.RedirectUris,
                PostLogoutRedirectUris = client.PostLogoutRedirectUris,
                AllowedCorsOrigins = client.AllowedCorsOrigins,
                AllowedScopes = client.AllowedScopes,
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
        public IActionResult Create(CreateClientViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var clients = GetClients();
            
            // Check if client ID already exists
            if (clients.Any(c => c.ClientId.Equals(model.ClientId, StringComparison.OrdinalIgnoreCase)))
            {
                ModelState.AddModelError("ClientId", "A client with this ID already exists.");
                return View(model);
            }

            var newClient = new OpenIdConnectClientOptions
            {
                ClientId = model.ClientId,
                ClientName = model.ClientName,
                ClientSecret = model.ClientSecret,
                RedirectUris = ParseUris(model.RedirectUris),
                PostLogoutRedirectUris = ParseUris(model.PostLogoutRedirectUris),
                AllowedCorsOrigins = ParseUris(model.AllowedCorsOrigins),
                AllowedScopes = model.AllowedScopes ?? new List<string>(),
                RequirePkce = model.RequirePkce,
                AllowOfflineAccess = model.AllowOfflineAccess,
                AccessTokenLifetimeMinutes = model.AccessTokenLifetimeMinutes,
                RefreshTokenLifetimeDays = model.RefreshTokenLifetimeDays
            };

            clients.Add(newClient);
            SaveClients(clients);

            TempData["Success"] = "Client created successfully!";
            return RedirectToAction(nameof(Index));
        }

        [HttpGet("Edit/{clientId}")]
        public IActionResult Edit(string clientId)
        {
            var client = GetClient(clientId);
            if (client == null)
            {
                return NotFound();
            }

            var viewModel = new EditClientViewModel
            {
                ClientId = client.ClientId,
                ClientName = client.ClientName,
                ClientSecret = string.Empty, // Don't show existing secret
                RedirectUris = string.Join("\n", client.RedirectUris),
                PostLogoutRedirectUris = string.Join("\n", client.PostLogoutRedirectUris),
                AllowedCorsOrigins = string.Join("\n", client.AllowedCorsOrigins),
                AllowedScopes = client.AllowedScopes,
                RequirePkce = client.RequirePkce,
                AllowOfflineAccess = client.AllowOfflineAccess,
                AccessTokenLifetimeMinutes = client.AccessTokenLifetimeMinutes,
                RefreshTokenLifetimeDays = client.RefreshTokenLifetimeDays,
                OriginalClientId = client.ClientId
            };

            return View(viewModel);
        }

        [HttpPost("Edit/{clientId}")]
        public IActionResult Edit(string clientId, EditClientViewModel model)
        {
            if (clientId != model.OriginalClientId)
            {
                return BadRequest();
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var clients = GetClients();
            var clientIndex = clients.FindIndex(c => c.ClientId == clientId);
            
            if (clientIndex == -1)
            {
                return NotFound();
            }

            var existingClient = clients[clientIndex];
            
            // Update client properties
            existingClient.ClientName = model.ClientName;
            
            // Only update secret if a new one is provided
            if (!string.IsNullOrWhiteSpace(model.ClientSecret))
            {
                existingClient.ClientSecret = model.ClientSecret;
            }
            
            existingClient.RedirectUris = ParseUris(model.RedirectUris);
            existingClient.PostLogoutRedirectUris = ParseUris(model.PostLogoutRedirectUris);
            existingClient.AllowedCorsOrigins = ParseUris(model.AllowedCorsOrigins);
            existingClient.AllowedScopes = model.AllowedScopes ?? new List<string>();
            existingClient.RequirePkce = model.RequirePkce;
            existingClient.AllowOfflineAccess = model.AllowOfflineAccess;
            existingClient.AccessTokenLifetimeMinutes = model.AccessTokenLifetimeMinutes;
            existingClient.RefreshTokenLifetimeDays = model.RefreshTokenLifetimeDays;

            SaveClients(clients);

            TempData["Success"] = "Client updated successfully!";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost("Delete/{clientId}")]
        public IActionResult Delete(string clientId)
        {
            var clients = GetClients();
            var client = clients.FirstOrDefault(c => c.ClientId == clientId);
            
            if (client == null)
            {
                return NotFound();
            }

            clients.Remove(client);
            SaveClients(clients);

            TempData["Success"] = "Client deleted successfully!";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost("RegenerateSecret/{clientId}")]
        public IActionResult RegenerateSecret(string clientId)
        {
            var clients = GetClients();
            var client = clients.FirstOrDefault(c => c.ClientId == clientId);
            
            if (client == null)
            {
                return NotFound();
            }

            client.ClientSecret = GenerateClientSecret();
            SaveClients(clients);

            TempData["Success"] = $"New client secret: {client.ClientSecret}";
            TempData["Warning"] = "Please save this secret securely. It won't be shown again.";
            
            return RedirectToAction(nameof(Details), new { clientId });
        }

        private List<OpenIdConnectClientOptions> GetClients()
        {
            var clientsSection = _configuration.GetSection("OpenIdConnect:Clients");
            var clients = clientsSection.Get<List<OpenIdConnectClientOptions>>() ?? new List<OpenIdConnectClientOptions>();
            return clients;
        }

        private OpenIdConnectClientOptions? GetClient(string clientId)
        {
            return GetClients().FirstOrDefault(c => c.ClientId == clientId);
        }

        private void SaveClients(List<OpenIdConnectClientOptions> clients)
        {
            try
            {
                var json = System.IO.File.ReadAllText(_configPath);
                var jsonObj = JsonSerializer.Deserialize<Dictionary<string, object>>(json);
                
                if (jsonObj != null)
                {
                    var openIdConnectSection = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonObj["OpenIdConnect"].ToString()!);
                    openIdConnectSection!["Clients"] = clients;
                    jsonObj["OpenIdConnect"] = openIdConnectSection;

                    var options = new JsonSerializerOptions
                    {
                        WriteIndented = true
                    };

                    var updatedJson = JsonSerializer.Serialize(jsonObj, options);
                    System.IO.File.WriteAllText(_configPath, updatedJson);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save clients to configuration");
                throw;
            }
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