using IdentityProvider.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace IdentityProvider.Services;

public class DbSeeder
{
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<DbSeeder> _logger;
    private readonly DefaultAdminOption _defaultAdminOption;

    public DbSeeder(
        RoleManager<IdentityRole> roleManager,
        UserManager<IdentityUser> userManager,
        ILogger<DbSeeder> logger,
        IOptions<DefaultAdminOption> defaultAdminOption)
    {
        _roleManager = roleManager;
        _userManager = userManager;
        _logger = logger;
        _defaultAdminOption = defaultAdminOption.Value;
    }

    public async Task SeedAsync()
    {
        try
        {
            // Create default roles if they don't exist
            await SeedRolesAsync();

            // Create default admin user if not exists
            await SeedAdminUserAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while seeding the database");
        }
    }

    private async Task SeedRolesAsync()
    {
        string[] roleNames = { "Admin", "User" };
        foreach (var roleName in roleNames)
        {
            if (!await _roleManager.RoleExistsAsync(roleName))
            {
                await _roleManager.CreateAsync(new IdentityRole(roleName));
                _logger.LogInformation("Created role: {Role}", roleName);
            }
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