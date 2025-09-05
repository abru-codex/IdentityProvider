using IdentityProvider.Options;
using IdentityProvider.Models;
using IdentityProvider.DbContext;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore;

namespace IdentityProvider.Services;

public class DbSeeder
{
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<DbSeeder> _logger;
    private readonly DefaultAdminOption _defaultAdminOption;
    private readonly OpenIdConnectOptions _openIdConnectOptions;
    private readonly IRolePermissionService _rolePermissionService;

    public DbSeeder(
        RoleManager<IdentityRole> roleManager,
        UserManager<IdentityUser> userManager,
        ApplicationDbContext context,
        ILogger<DbSeeder> logger,
        IOptions<DefaultAdminOption> defaultAdminOption,
        IOptions<OpenIdConnectOptions> openIdConnectOptions,
        IRolePermissionService rolePermissionService)
    {
        _roleManager = roleManager;
        _userManager = userManager;
        _context = context;
        _logger = logger;
        _defaultAdminOption = defaultAdminOption.Value;
        _openIdConnectOptions = openIdConnectOptions.Value;
        _rolePermissionService = rolePermissionService;
    }

    public async Task SeedAsync()
    {
        try
        {
            // Create default roles if they don't exist
            await SeedRolesAsync();

            // Seed role permissions
            await SeedRolePermissionsAsync();

            // Create default admin user if not exists
            await SeedAdminUserAsync();

            // Seed OAuth clients from configuration and create default clients
            await SeedOAuthClientsAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while seeding the database");
        }
    }

    private async Task SeedRolesAsync()
    {
        string[] roleNames = { "Admin", "User", "Manager" };
        foreach (var roleName in roleNames)
        {
            if (!await _roleManager.RoleExistsAsync(roleName))
            {
                await _roleManager.CreateAsync(new IdentityRole(roleName));
                _logger.LogInformation("Created role: {Role}", roleName);
            }
        }
    }

    private async Task SeedRolePermissionsAsync()
    {
        // Get roles
        var adminRole = await _roleManager.FindByNameAsync("Admin");
        var userRole = await _roleManager.FindByNameAsync("User");
        var managerRole = await _roleManager.FindByNameAsync("Manager");

        if (adminRole != null)
        {
            await SeedAdminPermissionsAsync(adminRole);
        }

        if (userRole != null)
        {
            await SeedUserPermissionsAsync(userRole);
        }

        if (managerRole != null)
        {
            await SeedManagerPermissionsAsync(managerRole);
        }
    }

    private async Task SeedAdminPermissionsAsync(IdentityRole adminRole)
    {
        // Admin gets all permissions
        var allPermissions = new List<string>
        {
            // User Management Permissions
            Permissions.UserRead,
            Permissions.UserCreate,
            Permissions.UserUpdate,
            Permissions.UserDelete,
            Permissions.UserManageRoles,

            // Role Management Permissions
            Permissions.RoleRead,
            Permissions.RoleCreate,
            Permissions.RoleUpdate,
            Permissions.RoleDelete,
            Permissions.RoleManagePermissions,

            // Client Management Permissions
            Permissions.ClientRead,
            Permissions.ClientCreate,
            Permissions.ClientUpdate,
            Permissions.ClientDelete,

            // Dashboard Permissions
            Permissions.DashboardView,
            Permissions.DashboardManage,

            // System Permissions
            Permissions.SystemSettings,
            Permissions.SystemLogs,

            // Authentication Permissions
            Permissions.AuthorizeClients,
            Permissions.IssueTokens
        };

        var existingPermissions = await _rolePermissionService.GetRolePermissionsAsync(adminRole.Id);
        var newPermissions = allPermissions.Except(existingPermissions).ToList();

        if (newPermissions.Any())
        {
            foreach (var permission in newPermissions)
            {
                await _rolePermissionService.AddPermissionAsync(adminRole.Id, permission, adminRole.Name);
            }
            _logger.LogInformation("Added {Count} permissions to Admin role", newPermissions.Count);
        }
    }

    private async Task SeedUserPermissionsAsync(IdentityRole userRole)
    {
        // Regular users get basic read permissions
        var userPermissions = new List<string>
        {
            Permissions.DashboardView
        };

        var existingPermissions = await _rolePermissionService.GetRolePermissionsAsync(userRole.Id);
        var newPermissions = userPermissions.Except(existingPermissions).ToList();

        if (newPermissions.Any())
        {
            foreach (var permission in newPermissions)
            {
                await _rolePermissionService.AddPermissionAsync(userRole.Id, permission, userRole.Name);
            }
            _logger.LogInformation("Added {Count} permissions to User role", newPermissions.Count);
        }
    }

    private async Task SeedManagerPermissionsAsync(IdentityRole managerRole)
    {
        // Managers get moderate permissions (user management but not system-level)
        var managerPermissions = new List<string>
        {
            // User Management Permissions (except delete)
            Permissions.UserRead,
            Permissions.UserCreate,
            Permissions.UserUpdate,
            Permissions.UserManageRoles,

            // Role Management Permissions (read only)
            Permissions.RoleRead,

            // Client Management Permissions (read only)
            Permissions.ClientRead,

            // Dashboard Permissions
            Permissions.DashboardView,
            Permissions.DashboardManage,

            // Authentication Permissions
            Permissions.AuthorizeClients,
            Permissions.IssueTokens
        };

        var existingPermissions = await _rolePermissionService.GetRolePermissionsAsync(managerRole.Id);
        var newPermissions = managerPermissions.Except(existingPermissions).ToList();

        if (newPermissions.Any())
        {
            foreach (var permission in newPermissions)
            {
                await _rolePermissionService.AddPermissionAsync(managerRole.Id, permission, managerRole.Name);
            }
            _logger.LogInformation("Added {Count} permissions to Manager role", newPermissions.Count);
        }
    }

    private async Task SeedAdminUserAsync()
    {
        var adminEmail = _defaultAdminOption.Email ?? "admin@example.com";
        var adminPassword = _defaultAdminOption.Password ?? "Admin@123456";

        var adminUser = await _userManager.FindByEmailAsync(adminEmail);
        if (adminUser == null)
        {
            adminUser = new IdentityUser
            {
                UserName = adminEmail,
                Email = adminEmail,
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(adminUser, adminPassword);
            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(adminUser, "Admin");
                _logger.LogInformation("Created admin user: {Email}", adminEmail);
            }
            else
            {
                foreach (var error in result.Errors)
                {
                    _logger.LogError("Error creating admin user: {Error}", error.Description);
                }
            }
        }
    }

    private async Task SeedOAuthClientsAsync()
    {
        // First, migrate existing clients from configuration to database
        if (_openIdConnectOptions.Clients?.Any() == true)
        {
            foreach (var configClient in _openIdConnectOptions.Clients)
            {
                var existingClient = await _context.OAuthClients
                    .FirstOrDefaultAsync(c => c.ClientId == configClient.ClientId);

                if (existingClient == null)
                {
                    var oauthClient = new OAuthClient
                    {
                        ClientId = configClient.ClientId,
                        ClientName = configClient.ClientName,
                        ClientSecret = configClient.ClientSecret,
                        RequirePkce = configClient.RequirePkce,
                        AllowOfflineAccess = configClient.AllowOfflineAccess,
                        AccessTokenLifetimeMinutes = configClient.AccessTokenLifetimeMinutes,
                        RefreshTokenLifetimeDays = configClient.RefreshTokenLifetimeDays,
                        CreatedAt = DateTime.UtcNow
                    };

                    oauthClient.SetRedirectUris(configClient.RedirectUris);
                    oauthClient.SetPostLogoutRedirectUris(configClient.PostLogoutRedirectUris);
                    oauthClient.SetAllowedCorsOrigins(configClient.AllowedCorsOrigins);
                    oauthClient.SetAllowedScopes(configClient.AllowedScopes);

                    _context.OAuthClients.Add(oauthClient);
                    _logger.LogInformation("Migrated client from config: {ClientId}", configClient.ClientId);
                }
            }
        }
        else
        {
            await CreateDefaultClientsAsync();
        }
        
        await _context.SaveChangesAsync();
    }

    private async Task CreateDefaultClientsAsync()
    {
        var defaultClients = new[]
        {
            new OAuthClient
            {
                ClientId = "spa-client",
                ClientName = "SPA Test Client",
                ClientSecret = "spa-client-secret-key-2024",
                RequirePkce = true,
                AllowOfflineAccess = true,
                AccessTokenLifetimeMinutes = 60,
                RefreshTokenLifetimeDays = 30,
                CreatedAt = DateTime.UtcNow
            },
            new OAuthClient
            {
                ClientId = "web-client",
                ClientName = "Web Application Client",
                ClientSecret = "web-client-secret-key-2024",
                RequirePkce = false,
                AllowOfflineAccess = true,
                AccessTokenLifetimeMinutes = 30,
                RefreshTokenLifetimeDays = 7,
                CreatedAt = DateTime.UtcNow
            },
            new OAuthClient
            {
                ClientId = "mobile-client",
                ClientName = "Mobile Application Client",
                ClientSecret = "mobile-client-secret-key-2024",
                RequirePkce = true,
                AllowOfflineAccess = true,
                AccessTokenLifetimeMinutes = 120,
                RefreshTokenLifetimeDays = 90,
                CreatedAt = DateTime.UtcNow
            }
        };

        // Configure default redirect URIs and scopes
        defaultClients[0].SetRedirectUris(new List<string> { "http://localhost:3000/callback", "https://localhost:3001/callback" });
        defaultClients[0].SetPostLogoutRedirectUris(new List<string> { "http://localhost:3000", "https://localhost:3001" });
        defaultClients[0].SetAllowedCorsOrigins(new List<string> { "http://localhost:3000", "https://localhost:3001" });
        defaultClients[0].SetAllowedScopes(new List<string> { "openid", "profile", "email", "api", "offline_access" });

        defaultClients[1].SetRedirectUris(new List<string> { "https://localhost:5001/signin-oidc", "https://localhost:7001/signin-oidc" });
        defaultClients[1].SetPostLogoutRedirectUris(new List<string> { "https://localhost:5001/signout-callback-oidc", "https://localhost:7001/signout-callback-oidc" });
        defaultClients[1].SetAllowedCorsOrigins(new List<string> { "https://localhost:5001", "https://localhost:7001" });
        defaultClients[1].SetAllowedScopes(new List<string> { "openid", "profile", "email" });

        defaultClients[2].SetRedirectUris(new List<string> { "com.example.app://callback" });
        defaultClients[2].SetPostLogoutRedirectUris(new List<string> { "com.example.app://logout" });
        defaultClients[2].SetAllowedCorsOrigins(new List<string>());
        defaultClients[2].SetAllowedScopes(new List<string> { "openid", "profile", "email", "offline_access" });

        foreach (var client in defaultClients)
        {
            _context.OAuthClients.Add(client);
            _logger.LogInformation("Created default client: {ClientId}", client.ClientId);
        }
    }
}

public static class DbSeederExtensions
{
    public static async Task SeedDatabaseAsync(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        var seeder = scope.ServiceProvider.GetRequiredService<DbSeeder>();
        await seeder.SeedAsync();
    }
}