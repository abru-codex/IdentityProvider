using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using FluentValidation;
using IdentityProvider.Validation;
using Microsoft.EntityFrameworkCore;

namespace IdentityProvider.Endpoints;

public static class RoleManagementEndpoint
{
    public static void MapRoleManagementEndpoint(this IEndpointRouteBuilder route)
    {
        var roleGroup = route.MapGroup("api/roles").WithTags("Roles").RequireAuthorization("AdminOnly");

        // Get all roles
        roleGroup.MapGet("/", async (RoleManager<IdentityRole> roleManager) =>
        {
            var roles = await roleManager.Roles
                .Select(r => new RoleDto
                {
                    Id = r.Id,
                    Name = r.Name,
                    NormalizedName = r.NormalizedName
                })
                .ToListAsync();

            return Results.Ok(roles);
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "Get all roles";
            return operation;
        })
        .Produces<List<RoleDto>>(StatusCodes.Status200OK);

        // Create a new role
        roleGroup.MapPost("/", async (
            [FromBody] CreateRoleDto model,
            RoleManager<IdentityRole> roleManager,
            IValidator<CreateRoleDto> validator,
            HttpContext httpContext) =>
        {
            // Validate the model using FluentValidation
            var validationResult = await validator.ValidateAsync(model, httpContext);
            if (!validationResult.IsValid)
            {
                return Results.ValidationProblem(validationResult.GetValidationErrorsDictionary());
            }

            if (await roleManager.RoleExistsAsync(model.Name))
            {
                return Results.BadRequest(new { error = "Role already exists" });
            }

            var role = new IdentityRole { Name = model.Name };
            var result = await roleManager.CreateAsync(role);

            if (!result.Succeeded)
            {
                return Results.ValidationProblem(result.Errors.ToDictionary(e => e.Code, e => new[] { e.Description }));
            }

            return Results.Created($"/api/roles/{role.Id}", new RoleDto
            {
                Id = role.Id,
                Name = role.Name,
                NormalizedName = role.NormalizedName
            });
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "Create a new role";
            return operation;
        })
        .Produces<RoleDto>(StatusCodes.Status201Created)
        .Produces(StatusCodes.Status400BadRequest);

        // Get role by ID
        roleGroup.MapGet("/{id}", async (string id, UserManager<IdentityUser> userManager,
        RoleManager<IdentityRole> roleManager) =>
        {
            var role = await roleManager.FindByIdAsync(id);

            if (role == null || string.IsNullOrWhiteSpace(role.Name))
            {
                return Results.NotFound();
            }

            // Get users in this role
            var usersInRole = (await userManager.GetUsersInRoleAsync(role.Name))?.Select(u => u.UserName).ToList();

            return Results.Ok(new RoleDetailsDto
            {
                Id = role.Id,
                Name = role.Name,
                NormalizedName = role.NormalizedName,
                Users = usersInRole
            });
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "Get role by ID";
            return operation;
        })
        .Produces<RoleDetailsDto>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status404NotFound);

        // Update role
        roleGroup.MapPut("/{id}", async (
            string id,
            [FromBody] UpdateRoleDto model,
            RoleManager<IdentityRole> roleManager,
            IValidator<UpdateRoleDto> validator,
            HttpContext httpContext) =>
        {
            // Validate the model using FluentValidation
            var validationResult = await validator.ValidateAsync(model, httpContext);
            if (!validationResult.IsValid)
            {
                return Results.ValidationProblem(validationResult.GetValidationErrorsDictionary());
            }

            var role = await roleManager.FindByIdAsync(id);

            if (role == null)
            {
                return Results.NotFound();
            }

            if (!string.IsNullOrEmpty(model.Name) && role.Name != model.Name)
            {
                // Check if new name already exists
                if (await roleManager.RoleExistsAsync(model.Name))
                {
                    return Results.BadRequest(new { error = "Role name already exists" });
                }

                role.Name = model.Name;
                var result = await roleManager.UpdateAsync(role);

                if (!result.Succeeded)
                {
                    return Results.ValidationProblem(result.Errors.ToDictionary(e => e.Code, e => new[] { e.Description }));
                }
            }

            return Results.Ok(new RoleDto
            {
                Id = role.Id,
                Name = role.Name,
                NormalizedName = role.NormalizedName
            });
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "Update role";
            return operation;
        })
        .Produces<RoleDto>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status404NotFound)
        .Produces(StatusCodes.Status400BadRequest);

        // Delete role
        roleGroup.MapDelete("/{id}", async (string id, RoleManager<IdentityRole> roleManager) =>
        {
            var role = await roleManager.FindByIdAsync(id);

            if (role == null)
            {
                return Results.NotFound();
            }

            // Check if this is a system role
            if (IsSystemRole(role.Name))
            {
                return Results.BadRequest(new { error = "Cannot delete system role" });
            }

            var result = await roleManager.DeleteAsync(role);

            if (!result.Succeeded)
            {
                return Results.ValidationProblem(result.Errors.ToDictionary(e => e.Code, e => new[] { e.Description }));
            }

            return Results.NoContent();
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "Delete role";
            return operation;
        })
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status404NotFound)
        .Produces(StatusCodes.Status400BadRequest);
    }

    private static bool IsSystemRole(string? roleName)
    {
        if (string.IsNullOrEmpty(roleName))
            return false;

        // Define your system roles here
        var systemRoles = new[] { "Admin", "User" };
        return systemRoles.Contains(roleName, StringComparer.OrdinalIgnoreCase);
    }
}

// DTOs for Role management
public class CreateRoleDto
{
    public string Name { get; set; } = default!;
}

public class UpdateRoleDto
{
    public string? Name { get; set; }
}

public class RoleDto
{
    public string Id { get; set; } = default!;
    public string? Name { get; set; }
    public string? NormalizedName { get; set; }
}

public class RoleDetailsDto : RoleDto
{
    public List<string> Users { get; set; } = new();
}