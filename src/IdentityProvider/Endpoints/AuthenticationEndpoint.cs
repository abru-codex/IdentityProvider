using FluentValidation;
using IdentityProvider.Services;
using IdentityProvider.Validation;
using Microsoft.AspNetCore.Identity;

namespace IdentityProvider.Endpoints;

public static class AuthenticationEndpoint
{
    public static void MapAuthenticationEndpoint(this IEndpointRouteBuilder route)
    {
        var authGroup = route.MapGroup("api/auth").WithTags("Authentication");

        // Login endpoint with JSON request
        authGroup.MapPost("/login", async (
            LoginRequest request,
            UserManager<IdentityUser> userManager,
            TokenService tokenService,
            IValidator<LoginRequest> validator,
            HttpContext httpContext,
            ILogger<Program> logger) =>
        {
            // Validate the model using FluentValidation
            var validationResult = await validator.ValidateAsync(request, httpContext);
            if (!validationResult.IsValid)
            {
                return Results.ValidationProblem(validationResult.GetValidationErrorsDictionary());
            }

            var user = await userManager.FindByNameAsync(request.Username);
            if (user == null || !await userManager.CheckPasswordAsync(user, request.Password))
            {
                return Results.Unauthorized();
            }

            try
            {
                var roles = await userManager.GetRolesAsync(user);
                var token = tokenService.GenerateJwtToken(request.Username, user.Id, roles);

                return Results.Ok(new AuthenticationResponse
                {
                    AccessToken = token,
                    TokenType = "Bearer",
                    ExpiresIn = 3600,
                    UserId = user.Id
                });
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error generating token");
                return Results.StatusCode(500);
            }
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "Login with username and password";
            operation.Description = "Authenticates a user and returns a JWT token for API access";
            return operation;
        })
        .Produces<AuthenticationResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .Produces(StatusCodes.Status500InternalServerError);

        // Form-based token endpoint (OAuth2 password grant compatibility)
        authGroup.MapPost("/token", async (
            HttpContext context,
            UserManager<IdentityUser> userManager,
            TokenService tokenService,
            ILogger<Program> logger) =>
        {
            if (!context.Request.HasFormContentType)
                return Results.BadRequest("Invalid content type");

            var form = await context.Request.ReadFormAsync();
            var grantType = form["grant_type"].ToString();
            var username = form["username"].ToString();
            var password = form["password"].ToString();

            if (string.IsNullOrEmpty(grantType) || grantType != "password")
                return Results.BadRequest("Unsupported or missing grant type");

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                return Results.BadRequest("Username or password missing");

            var user = await userManager.FindByNameAsync(username);
            if (user == null || !await userManager.CheckPasswordAsync(user, password))
                return Results.Unauthorized();

            try
            {
                var roles = await userManager.GetRolesAsync(user);
                var token = tokenService.GenerateJwtToken(username, user.Id, roles);

                return Results.Ok(new
                {
                    access_token = token,
                    token_type = "Bearer",
                    expires_in = 3600,
                    user_id = user.Id
                });
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error generating token");
                return Results.StatusCode(500);
            }
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "OAuth2 token endpoint";
            operation.Description = "OAuth2 compatible token endpoint supporting password grant type";
            return operation;
        })
        .Produces(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .Produces(StatusCodes.Status500InternalServerError);

        // Refresh token endpoint
        authGroup.MapPost("/refresh", (TokenService tokenService) =>
        {
            // TODO: Implement refresh token functionality
            return Results.StatusCode(StatusCodes.Status501NotImplemented);
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "Refresh access token";
            operation.Description = "Obtain a new access token using a refresh token";
            return operation;
        });

        // OIDC configuration endpoint
        authGroup.MapGet("/.well-known/openid-configuration", (IConfiguration configuration) =>
        {
            var baseUrl = configuration["BaseUrl"] ?? configuration["Jwt:Issuer"];
            var issuer = configuration["Jwt:Issuer"];

            var oidcConfig = new
            {
                issuer,
                jwks_uri = $"{baseUrl}/api/auth/.well-known/jwks.json",
                authorization_endpoint = $"{baseUrl}/api/auth/authorize",
                token_endpoint = $"{baseUrl}/api/auth/token",
                userinfo_endpoint = $"{baseUrl}/api/auth/userinfo",
                end_session_endpoint = $"{baseUrl}/api/auth/logout",
                response_types_supported = new[] { "code", "id_token", "token" },
                grant_types_supported = new[] { "authorization_code", "client_credentials", "password", "refresh_token" },
                subject_types_supported = new[] { "public" },
                id_token_signing_alg_values_supported = new[] { "RS256" },
                scopes_supported = new[] { "openid", "profile", "email", "api" },
                token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post" },
                claims_supported = new[] { "sub", "name", "email", "role" }
            };

            return Results.Ok(oidcConfig);
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "OpenID Connect configuration";
            operation.Description = "Returns the OpenID Connect discovery document";
            return operation;
        })
        .Produces(StatusCodes.Status200OK);
    }
}

// Request and response models
public class LoginRequest
{
    public string Username { get; set; } = default!;
    public string Password { get; set; } = default!;
}

public class AuthenticationResponse
{
    public string AccessToken { get; set; } = default!;
    public string TokenType { get; set; } = default!;
    public int ExpiresIn { get; set; }
    public string UserId { get; set; } = default!;
}