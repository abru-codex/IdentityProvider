using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using IdentityProvider.Validation;
using FluentValidation;
using Microsoft.EntityFrameworkCore;

namespace IdentityProvider.Endpoints;

public static class UserManagementEndpoint
{
    public static void MapUserManagementEndpoint(this IEndpointRouteBuilder route)
    {
        var userGroup = route.MapGroup("api/users").WithTags("Users");

        // Create new user (register)
        userGroup.MapPost("/", async (
            [FromBody] RegisterUserDto model,
            UserManager<IdentityUser> userManager,
            ILogger<Program> logger,
            IValidator<RegisterUserDto> validator,
            HttpContext httpContext) =>
        {
            // Validate the model using FluentValidation
            var validationResult = await validator.ValidateAsync(model, httpContext);
            if (!validationResult.IsValid)
            {
                return Results.ValidationProblem(validationResult.GetValidationErrorsDictionary());
            }

            var user = new IdentityUser
            {
                UserName = model.Email,
                Email = model.Email,
                PhoneNumber = model.PhoneNumber
            };

            var result = await userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                return Results.ValidationProblem(result.Errors.ToDictionary(e => e.Code, e => new[] { e.Description }));
            }

            // Add user to default role if specified
            if (!string.IsNullOrEmpty(model.Role))
            {
                await userManager.AddToRoleAsync(user, model.Role);
            }

            logger.LogInformation("User created: {Email}", model.Email);

            return Results.Created($"/api/users/{user.Id}", new UserDto
            {
                Id = user.Id,
                Email = user.Email,
                PhoneNumber = user.PhoneNumber,
                UserName = user.UserName
            });
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "Register new user";
            return operation;
        })
        .Produces<UserDto>(StatusCodes.Status201Created)
        .Produces(StatusCodes.Status400BadRequest);

        // Get all users (admin only)
        userGroup.MapGet("/", async (
            UserManager<IdentityUser> userManager,
            [AsParameters] PaginationParams pagination,
            IValidator<PaginationParams> validator,
            HttpContext httpContext) =>
        {
            // Validate pagination parameters
            var validationResult = await validator.ValidateAsync(pagination, httpContext);
            if (!validationResult.IsValid)
            {
                return Results.ValidationProblem(validationResult.GetValidationErrorsDictionary());
            }

            var users = userManager.Users
                .Skip(pagination.Skip)
                .Take(pagination.Take)
                .Select(u => new UserDto
                {
                    Id = u.Id,
                    Email = u.Email,
                    UserName = u.UserName,
                    PhoneNumber = u.PhoneNumber,
                    EmailConfirmed = u.EmailConfirmed
                });

            return Results.Ok(new
            {
                Users = await users.ToListAsync(),
                Pagination = new
                {
                    Skip = pagination.Skip,
                    Take = pagination.Take,
                    Total = await userManager.Users.CountAsync()
                }
            });
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "Get all users (admin only)";
            return operation;
        })
        .RequireAuthorization("AdminOnly")
        .Produces<List<UserDto>>(StatusCodes.Status200OK);

        // Get user by ID
        userGroup.MapGet("/{id}", async (
            string id,
            UserManager<IdentityUser> userManager,
            ClaimsPrincipal user) =>
        {
            // Only allow admins or the user themselves to view user details
            if (!user.IsInRole("Admin") && user.FindFirstValue(ClaimTypes.NameIdentifier) != id)
            {
                return Results.Forbid();
            }

            var identityUser = await userManager.FindByIdAsync(id);

            if (identityUser == null)
            {
                return Results.NotFound();
            }

            var userRoles = await userManager.GetRolesAsync(identityUser);

            return Results.Ok(new UserDetailsDto
            {
                Id = identityUser.Id,
                Email = identityUser.Email,
                UserName = identityUser.UserName,
                PhoneNumber = identityUser.PhoneNumber,
                EmailConfirmed = identityUser.EmailConfirmed,
                PhoneNumberConfirmed = identityUser.PhoneNumberConfirmed,
                TwoFactorEnabled = identityUser.TwoFactorEnabled,
                LockoutEnabled = identityUser.LockoutEnabled,
                LockoutEnd = identityUser.LockoutEnd,
                AccessFailedCount = identityUser.AccessFailedCount,
                Roles = userRoles.ToList()
            });
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "Get user by ID";
            return operation;
        })
        .RequireAuthorization()
        .Produces<UserDetailsDto>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status404NotFound)
        .Produces(StatusCodes.Status403Forbidden);

        // Update user details
        userGroup.MapPut("/{id}", async (
            string id,
            [FromBody] UpdateUserDto model,
            UserManager<IdentityUser> userManager,
            ClaimsPrincipal user,
            IValidator<UpdateUserDto> validator,
            HttpContext httpContext) =>
        {
            // Validate the model
            var validationResult = await validator.ValidateAsync(model, httpContext);
            if (!validationResult.IsValid)
            {
                return Results.ValidationProblem(validationResult.GetValidationErrorsDictionary());
            }

            // Only allow admins or the user themselves to update user details
            if (!user.IsInRole("Admin") && user.FindFirstValue(ClaimTypes.NameIdentifier) != id)
            {
                return Results.Forbid();
            }

            var identityUser = await userManager.FindByIdAsync(id);

            if (identityUser == null)
            {
                return Results.NotFound();
            }

            // Update user properties
            if (!string.IsNullOrEmpty(model.Email) && identityUser.Email != model.Email)
            {
                identityUser.Email = model.Email;
                identityUser.UserName = model.Email; // Username is typically the email
                identityUser.EmailConfirmed = false; // Require reconfirmation
            }

            if (!string.IsNullOrEmpty(model.PhoneNumber) && identityUser.PhoneNumber != model.PhoneNumber)
            {
                identityUser.PhoneNumber = model.PhoneNumber;
                identityUser.PhoneNumberConfirmed = false; // Require reconfirmation
            }

            var result = await userManager.UpdateAsync(identityUser);

            if (!result.Succeeded)
            {
                return Results.ValidationProblem(result.Errors.ToDictionary(e => e.Code, e => new[] { e.Description }));
            }

            // Update password if provided
            if (!string.IsNullOrEmpty(model.NewPassword))
            {
                // Check if the current password is provided and correct
                if (string.IsNullOrEmpty(model.CurrentPassword) ||
                    !await userManager.CheckPasswordAsync(identityUser, model.CurrentPassword))
                {
                    // If admin, allow password reset without current password
                    if (!user.IsInRole("Admin"))
                    {
                        return Results.ValidationProblem(new Dictionary<string, string[]>
                        {
                            { "CurrentPassword", new[] { "Current password is incorrect" } }
                        });
                    }
                }

                var passwordResult = await userManager.ChangePasswordAsync(
                    identityUser,
                    model.CurrentPassword ?? "AdminOverride", // Bypass for admin
                    model.NewPassword);

                if (!passwordResult.Succeeded)
                {
                    return Results.ValidationProblem(passwordResult.Errors.ToDictionary(
                        e => e.Code,
                        e => new[] { e.Description }));
                }
            }

            return Results.Ok(new UserDto
            {
                Id = identityUser.Id,
                Email = identityUser.Email,
                UserName = identityUser.UserName,
                PhoneNumber = identityUser.PhoneNumber
            });
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "Update user";
            return operation;
        })
        .RequireAuthorization()
        .Produces<UserDto>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status404NotFound)
        .Produces(StatusCodes.Status403Forbidden)
        .Produces(StatusCodes.Status400BadRequest);

        // Delete user
        userGroup.MapDelete("/{id}", async (
            string id,
            UserManager<IdentityUser> userManager,
            ClaimsPrincipal user) =>
        {
            // Only allow admins or the user themselves to delete their account
            if (!user.IsInRole("Admin") && user.FindFirstValue(ClaimTypes.NameIdentifier) != id)
            {
                return Results.Forbid();
            }

            var identityUser = await userManager.FindByIdAsync(id);

            if (identityUser == null)
            {
                return Results.NotFound();
            }

            var result = await userManager.DeleteAsync(identityUser);

            if (!result.Succeeded)
            {
                return Results.ValidationProblem(result.Errors.ToDictionary(e => e.Code, e => new[] { e.Description }));
            }

            return Results.NoContent();
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "Delete user";
            return operation;
        })
        .RequireAuthorization()
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status404NotFound)
        .Produces(StatusCodes.Status403Forbidden);

        // Change password
        userGroup.MapPost("/{id}/change-password", async (
            string id,
            [FromBody] ChangePasswordDto model,
            UserManager<IdentityUser> userManager,
            ClaimsPrincipal user,
            IValidator<ChangePasswordDto> validator,
            HttpContext httpContext) =>
        {
            // Validate the model
            var validationResult = await validator.ValidateAsync(model, httpContext);
            if (!validationResult.IsValid)
            {
                return Results.ValidationProblem(validationResult.GetValidationErrorsDictionary());
            }

            // Only allow the user themselves or an admin to change password
            if (!user.IsInRole("Admin") && user.FindFirstValue(ClaimTypes.NameIdentifier) != id)
            {
                return Results.Forbid();
            }

            var identityUser = await userManager.FindByIdAsync(id);

            if (identityUser == null)
            {
                return Results.NotFound();
            }

            // If it's an admin and they're changing someone else's password
            if (user.IsInRole("Admin") && user.FindFirstValue(ClaimTypes.NameIdentifier) != id)
            {
                var resetToken = await userManager.GeneratePasswordResetTokenAsync(identityUser);
                var result = await userManager.ResetPasswordAsync(identityUser, resetToken, model.NewPassword);

                if (!result.Succeeded)
                {
                    return Results.ValidationProblem(result.Errors.ToDictionary(e => e.Code, e => new[] { e.Description }));
                }

                return Results.Ok(new { message = "Password changed successfully" });
            }

            // Regular user changing their own password
            var passwordResult = await userManager.ChangePasswordAsync(identityUser, model.CurrentPassword, model.NewPassword);

            if (!passwordResult.Succeeded)
            {
                return Results.ValidationProblem(passwordResult.Errors.ToDictionary(e => e.Code, e => new[] { e.Description }));
            }

            return Results.Ok(new { message = "Password changed successfully" });
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "Change password";
            return operation;
        })
        .RequireAuthorization()
        .Produces(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status404NotFound)
        .Produces(StatusCodes.Status403Forbidden)
        .Produces(StatusCodes.Status400BadRequest);

        // User roles management
        var rolesGroup = userGroup.MapGroup("{id}/roles").RequireAuthorization("AdminOnly");

        // Add role to user
        rolesGroup.MapPost("/{role}", async (
            string id,
            string role,
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager) =>
        {
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
                return Results.NotFound("User not found");

            // Check if role exists
            if (!await roleManager.RoleExistsAsync(role))
                return Results.NotFound("Role not found");

            // Check if user already has the role
            if (await userManager.IsInRoleAsync(user, role))
                return Results.BadRequest("User already has this role");

            var result = await userManager.AddToRoleAsync(user, role);
            if (!result.Succeeded)
                return Results.BadRequest(result.Errors.Select(e => e.Description));

            return Results.Ok(new { message = $"Role '{role}' added to user" });
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "Add role to user";
            return operation;
        });

        // Remove role from user
        rolesGroup.MapDelete("/{role}", async (
            string id,
            string role,
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager) =>
        {
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
                return Results.NotFound("User not found");

            // Check if role exists
            if (!await roleManager.RoleExistsAsync(role))
                return Results.NotFound("Role not found");

            // Check if user has the role
            if (!await userManager.IsInRoleAsync(user, role))
                return Results.BadRequest("User doesn't have this role");

            var result = await userManager.RemoveFromRoleAsync(user, role);
            if (!result.Succeeded)
                return Results.BadRequest(result.Errors.Select(e => e.Description));

            return Results.Ok(new { message = $"Role '{role}' removed from user" });
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "Remove role from user";
            return operation;
        });
    }
}

// DTOs for User management
public class RegisterUserDto
{
    public string Email { get; set; } = default!;
    public string Password { get; set; } = default!;
    public string? PhoneNumber { get; set; }
    public string? Role { get; set; }
}

public class UpdateUserDto
{
    public string? Email { get; set; }
    public string? PhoneNumber { get; set; }
    public string? CurrentPassword { get; set; }
    public string? NewPassword { get; set; }
}

public class ChangePasswordDto
{
    public string CurrentPassword { get; set; } = default!;
    public string NewPassword { get; set; } = default!;
}

public class UserDto
{
    public string Id { get; set; } = default!;
    public string? Email { get; set; }
    public string? UserName { get; set; }
    public string? PhoneNumber { get; set; }
    public bool EmailConfirmed { get; set; }
}

public class UserDetailsDto : UserDto
{
    public bool PhoneNumberConfirmed { get; set; }
    public bool TwoFactorEnabled { get; set; }
    public bool LockoutEnabled { get; set; }
    public DateTimeOffset? LockoutEnd { get; set; }
    public int AccessFailedCount { get; set; }
    public List<string> Roles { get; set; } = new();
}

// Pagination parameters
public class PaginationParams
{
    public int Skip { get; set; } = 0;
    public int Take { get; set; } = 10;
}