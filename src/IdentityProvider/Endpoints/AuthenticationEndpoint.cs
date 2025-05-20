using System.Security.Claims;
using IdentityProvider.Models;
using IdentityProvider.Services;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityProvider.Endpoints;

public static class AuthenticationEndpoint
{
    public static void MapAuthenticationEndpoint(this IEndpointRouteBuilder route)
    {
        var authGroup = route.MapGroup("api/auth").WithTags("Authentication");

        // OAuth2/OpenID Connect authorization endpoint
        authGroup.MapGet("/authorize", async (
            HttpContext context,
            UserManager<IdentityUser> userManager,
            AuthorizationService authorizationService,
            ILogger<Program> logger) =>
        {
            var query = context.Request.Query;

            // Parse the request
            var request = new OAuth2Request
            {
                ClientId = query["client_id"].ToString(),
                RedirectUri = query["redirect_uri"].ToString(),
                ResponseType = query["response_type"].ToString(),
                State = query["state"].ToString(),
                Scope = query["scope"].ToString(),
                CodeChallenge = query["code_challenge"].ToString(),
                CodeChallengeMethod = query["code_challenge_method"].ToString() ?? "plain",
                Nonce = query["nonce"].ToString(),
                Prompt = query["prompt"].ToString()
            };

            // Validate the client
            if (!await authorizationService.ValidateClientAsync(request.ClientId))
            {
                return Results.BadRequest(new { error = "invalid_client", error_description = "Invalid client ID" });
            }

            // Validate redirect URI
            if (!authorizationService.ValidateRedirectUri(request.ClientId, request.RedirectUri!))
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "Invalid redirect URI" });
            }

            // Validate response type (we only support 'code' flow for now)
            if (request.ResponseType != "code")
            {
                var redirectWithError = QueryHelpers.AddQueryString(request.RedirectUri, new Dictionary<string, string>
                {
                    ["error"] = "unsupported_response_type",
                    ["error_description"] = "Only 'code' response type is supported",
                    ["state"] = request.State
                });

                return Results.Redirect(redirectWithError);
            }

            // Check if the user is authenticated
            if (!context.User.Identity?.IsAuthenticated ?? true)
            {
                // User is not authenticated, redirect to login
                var loginUrl = $"/api/auth/login?returnUrl={Uri.EscapeDataString(context.Request.GetEncodedUrl())}";
                return Results.Redirect(loginUrl);
            }

            // User is authenticated, generate authorization code
            var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await userManager.FindByIdAsync(userId!);

            if (user == null)
            {
                return Results.Unauthorized();
            }

            try
            {
                var requestedScopes = request.Scope?.Split(' ') ?? Array.Empty<string>();

                // Create authorization code
                var authCode = await authorizationService.CreateAuthorizationCodeAsync(
                    userId!,
                    request.ClientId,
                    request.RedirectUri!,
                    request.CodeChallenge ?? "",
                    request.CodeChallengeMethod ?? "plain",
                    requestedScopes);

                // Redirect back to client with code
                var redirectUrl = QueryHelpers.AddQueryString(request.RedirectUri!, new Dictionary<string, string>
                {
                    ["code"] = authCode.Code,
                    ["state"] = request.State
                });

                return Results.Redirect(redirectUrl);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error generating authorization code");
                var redirectWithError = QueryHelpers.AddQueryString(request.RedirectUri!, new Dictionary<string, string>
                {
                    ["error"] = "server_error",
                    ["error_description"] = "An error occurred processing the request",
                    ["state"] = request.State
                });

                return Results.Redirect(redirectWithError);
            }
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "OAuth2/OpenID Connect Authorization Endpoint";
            operation.Description = "Initiates the authorization flow";
            return operation;
        });

        // Login page route (will typically render a UI, but we'll return a form for testing)
        authGroup.MapGet("/login", (string? returnUrl) =>
        {
            var loginForm = $@"
                <html>
                <head>
                    <title>Login</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
                        form {{ max-width: 400px; margin: 0 auto; }}
                        .form-group {{ margin-bottom: 15px; }}
                        label {{ display: block; margin-bottom: 5px; }}
                        input {{ width: 100%; padding: 8px; box-sizing: border-box; }}
                        button {{ padding: 10px 15px; background: #007bff; color: white; border: none; cursor: pointer; }}
                    </style>
                </head>
                <body>
                    <form method='post' action='/api/auth/login'>
                        <h2>Sign In</h2>
                        <div class='form-group'>
                            <label for='username'>Email:</label>
                            <input type='email' id='username' name='username' required />
                        </div>
                        <div class='form-group'>
                            <label for='password'>Password:</label>
                            <input type='password' id='password' name='password' required />
                        </div>
                        <input type='hidden' name='returnUrl' value='{returnUrl}' />
                        <button type='submit'>Sign In</button>
                    </form>
                </body>
                </html>
            ";

            return Results.Content(loginForm, "text/html");
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "Login page";
            operation.Description = "Returns the login form";
            return operation;
        });

        // Login form submission
        authGroup.MapPost("/login", async (
            HttpContext context,
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            ILogger<Program> logger) =>
        {
            var form = await context.Request.ReadFormAsync();
            var username = form["username"].ToString();
            var password = form["password"].ToString();
            var returnUrl = form["returnUrl"].ToString();

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                return Results.BadRequest(new { error = "Username and password are required" });
            }

            var user = await userManager.FindByNameAsync(username);
            if (user == null)
            {
                return Results.BadRequest(new { error = "Invalid username or password" });
            }

            var result = await signInManager.PasswordSignInAsync(username, password, true, lockoutOnFailure: true);

            if (!result.Succeeded)
            {
                return Results.BadRequest(new { error = "Invalid username or password" });
            }

            // If there's a return URL, redirect to it
            if (!string.IsNullOrEmpty(returnUrl))
            {
                return Results.Redirect(returnUrl);
            }

            return Results.Ok(new { message = "Login successful" });
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "Login endpoint";
            operation.Description = "Processes the login form submission";
            return operation;
        });

        // Form-based token endpoint (OAuth2 token endpoint)
        authGroup.MapPost("/token", async (
            HttpContext context,
            UserManager<IdentityUser> userManager,
            AuthorizationService authorizationService,
            TokenService tokenService,
            ILogger<Program> logger) =>
        {
            if (!context.Request.HasFormContentType && !context.Request.HasJsonContentType())
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "Invalid content type" });
            }

            TokenRequest request;
            if (context.Request.HasFormContentType)
            {
                var form = await context.Request.ReadFormAsync();
                request = new TokenRequest
                {
                    GrantType = form["grant_type"].ToString(),
                    ClientId = form["client_id"].ToString(),
                    ClientSecret = form["client_secret"].ToString(),
                    Code = form["code"].ToString(),
                    RefreshToken = form["refresh_token"].ToString(),
                    RedirectUri = form["redirect_uri"].ToString(),
                    CodeVerifier = form["code_verifier"].ToString()
                };
            }
            else
            {
                try
                {
                    request = await context.Request.ReadFromJsonAsync<TokenRequest>() ?? new TokenRequest();
                }
                catch
                {
                    return Results.BadRequest(new { error = "invalid_request", error_description = "Invalid request format" });
                }
            }

            // Validate client
            if (!await authorizationService.ValidateClientAsync(request.ClientId!, request.ClientSecret))
            {
                return Results.BadRequest(new { error = "invalid_client", error_description = "Invalid client authentication" });
            }

            try
            {
                switch (request.GrantType)
                {
                    case "authorization_code":
                        return await HandleAuthorizationCodeGrantAsync(request, authorizationService, userManager);

                    case "refresh_token":
                        return await HandleRefreshTokenGrantAsync(request, tokenService, userManager);

                    case "password":
                        return await HandlePasswordGrantAsync(request, tokenService, userManager);

                    default:
                        return Results.BadRequest(new { error = "unsupported_grant_type", error_description = "The grant type is not supported" });
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error processing token request");
                return Results.BadRequest(new { error = "server_error", error_description = "An error occurred processing the request" });
            }
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "OAuth2/OpenID Connect Token Endpoint";
            operation.Description = "Exchanges authorization code or refresh token for access token";
            return operation;
        })
        .Produces(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized);

        // Userinfo endpoint
        authGroup.MapGet("/userinfo", async (
            ClaimsPrincipal user,
            UserManager<IdentityUser> userManager) =>
        {
            var userId = user.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                return Results.Unauthorized();
            }

            var identityUser = await userManager.FindByIdAsync(userId);
            if (identityUser == null)
            {
                return Results.Unauthorized();
            }

            var userRoles = await userManager.GetRolesAsync(identityUser);

            var userInfo = new
            {
                sub = userId,
                email = identityUser.Email,
                email_verified = identityUser.EmailConfirmed,
                preferred_username = identityUser.UserName,
                phone_number = identityUser.PhoneNumber,
                phone_number_verified = identityUser.PhoneNumberConfirmed,
                roles = userRoles
            };

            return Results.Ok(userInfo);
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "OpenID Connect Userinfo Endpoint";
            operation.Description = "Returns claims about the authenticated end-user";
            return operation;
        });

        // JWKS endpoint for key discovery
        authGroup.MapGet("/.well-known/jwks.json", (JwksService jwksService) =>
        {
            // Return the JSON Web Key Set with our RSA public key
            return Results.Ok(new
            {
                keys = jwksService.GetJsonWebKeys()
            });
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "JSON Web Key Set";
            operation.Description = "Returns the JSON Web Key Set containing the public keys used to verify signatures";
            return operation;
        });

        // OpenID Connect discovery document
        authGroup.MapGet("/.well-known/openid-configuration", (IConfiguration configuration) =>
        {
            var baseUrl = configuration["OpenIdConnect:IssuerUri"] ?? configuration["Jwt:Issuer"];

            var oidcConfig = new
            {
                issuer = baseUrl,
                jwks_uri = $"{baseUrl}/api/auth/.well-known/jwks.json",
                authorization_endpoint = $"{baseUrl}/api/auth/authorize",
                token_endpoint = $"{baseUrl}/api/auth/token",
                userinfo_endpoint = $"{baseUrl}/api/auth/userinfo",
                end_session_endpoint = $"{baseUrl}/api/auth/logout",
                response_types_supported = new[] { "code", "id_token", "token", "id_token token", "code id_token", "code token", "code id_token token" },
                grant_types_supported = new[] { "authorization_code", "client_credentials", "password", "refresh_token" },
                subject_types_supported = new[] { "public" },
                id_token_signing_alg_values_supported = new[] { "RS256" },
                scopes_supported = new[] { "openid", "profile", "email", "api", "offline_access" },
                token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post" },
                claims_supported = new[] { "sub", "name", "email", "email_verified", "role", "preferred_username" },
                code_challenge_methods_supported = new[] { "plain", "S256" }
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

        // Logout endpoint
        authGroup.MapGet("/logout", async (
            HttpContext context,
            SignInManager<IdentityUser> signInManager,
            string? post_logout_redirect_uri,
            string? id_token_hint,
            string? state) =>
        {
            await signInManager.SignOutAsync();

            if (!string.IsNullOrEmpty(post_logout_redirect_uri))
            {
                var redirectUrl = post_logout_redirect_uri;

                if (!string.IsNullOrEmpty(state))
                {
                    redirectUrl = QueryHelpers.AddQueryString(redirectUrl, "state", state);
                }

                return Results.Redirect(redirectUrl);
            }

            return Results.Ok(new { message = "Successfully logged out" });
        })
        .WithOpenApi(operation =>
        {
            operation.Summary = "OpenID Connect Logout Endpoint";
            operation.Description = "Logs the user out and optionally redirects back to client";
            return operation;
        });
    }

    private static async Task<IResult> HandleAuthorizationCodeGrantAsync(
        TokenRequest request,
        AuthorizationService authorizationService,
        UserManager<IdentityUser> userManager)
    {
        if (string.IsNullOrEmpty(request.Code) || string.IsNullOrEmpty(request.RedirectUri))
        {
            return Results.BadRequest(new { error = "invalid_request", error_description = "Code and redirect_uri are required" });
        }

        // Validate the authorization code
        var authCode = await authorizationService.ValidateAuthorizationCodeAsync(
            request.Code,
            request.ClientId!,
            request.RedirectUri,
            request.CodeVerifier);

        if (authCode == null)
        {
            return Results.BadRequest(new { error = "invalid_grant", error_description = "Invalid authorization code" });
        }

        // Get the user
        var user = await userManager.FindByIdAsync(authCode.UserId);
        if (user == null)
        {
            return Results.BadRequest(new { error = "invalid_grant", error_description = "Invalid authorization code" });
        }

        // Generate tokens
        var (accessToken, idToken, refreshToken) = await authorizationService.GenerateTokensAsync(
            user,
            authCode.ClientId,
            authCode.RequestedScopes);

        var response = new
        {
            access_token = accessToken,
            token_type = "Bearer",
            expires_in = 3600 // 1 hour
        };

        // Add ID token if requested
        if (!string.IsNullOrEmpty(idToken))
        {
            return Results.Ok(new
            {
                access_token = accessToken,
                id_token = idToken,
                token_type = "Bearer",
                expires_in = 3600, // 1 hour
                refresh_token = refreshToken
            });
        }

        // Add refresh token if it was generated
        if (!string.IsNullOrEmpty(refreshToken))
        {
            return Results.Ok(new
            {
                access_token = accessToken,
                token_type = "Bearer",
                expires_in = 3600, // 1 hour
                refresh_token = refreshToken
            });
        }

        return Results.Ok(response);
    }

    private static async Task<IResult> HandleRefreshTokenGrantAsync(
        TokenRequest request,
        TokenService tokenService,
        UserManager<IdentityUser> userManager)
    {
        if (string.IsNullOrEmpty(request.RefreshToken))
        {
            return Results.BadRequest(new { error = "invalid_request", error_description = "Refresh token is required" });
        }

        // Validate refresh token
        var (refreshToken, user) = await tokenService.ValidateRefreshTokenAsync(request.RefreshToken);

        if (refreshToken == null || user == null)
        {
            return Results.BadRequest(new { error = "invalid_grant", error_description = "Invalid refresh token" });
        }

        // Revoke old refresh token and generate new one
        var newRefreshTokenEntity = await tokenService.GenerateRefreshTokenAsync(user.Id, refreshToken.ClientId);
        await tokenService.RevokeRefreshTokenAsync(refreshToken, "Replaced by new token", newRefreshTokenEntity.Token);

        // Generate new access token
        var roles = await userManager.GetRolesAsync(user);
        var accessToken = tokenService.GenerateAccessToken(user, roles, refreshToken.ClientId, new[] { "api" });

        return Results.Ok(new
        {
            access_token = accessToken,
            token_type = "Bearer",
            expires_in = 3600, // 1 hour
            refresh_token = newRefreshTokenEntity.Token
        });
    }

    private static async Task<IResult> HandlePasswordGrantAsync(
        TokenRequest request,
        TokenService tokenService,
        UserManager<IdentityUser> userManager)
    {
        var form = await new HttpContextAccessor().HttpContext!.Request.ReadFormAsync();
        var username = form["username"].ToString();
        var password = form["password"].ToString();

        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            return Results.BadRequest(new { error = "invalid_request", error_description = "Username and password are required" });
        }

        // Validate user credentials
        var user = await userManager.FindByNameAsync(username);
        if (user == null || !await userManager.CheckPasswordAsync(user, password))
        {
            return Results.BadRequest(new { error = "invalid_grant", error_description = "Invalid username or password" });
        }

        // Generate tokens
        var roles = await userManager.GetRolesAsync(user);
        var accessToken = tokenService.GenerateJwtToken(username, user.Id, roles);
        var refreshTokenEntity = await tokenService.GenerateRefreshTokenAsync(user.Id, request.ClientId!);

        return Results.Ok(new
        {
            access_token = accessToken,
            token_type = "Bearer",
            expires_in = 3600, // 1 hour
            refresh_token = refreshTokenEntity.Token
        });
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