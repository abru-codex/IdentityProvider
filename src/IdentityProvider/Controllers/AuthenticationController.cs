using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using IdentityProvider.Models;
using IdentityProvider.Services;
using System.Security.Claims;
using IdentityProvider.Areas.Admin.Models.ViewModels;
using IdentityProvider.Models.ViewModels;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Authorization;

namespace IdentityProvider.Controllers
{
    public class AuthenticationController(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        AuthorizationService authorizationService,
        ILogger<AuthenticationController> logger)
        : Controller
    {
        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await userManager.FindByNameAsync(model.Username);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid username or password");
                return View(model);
            }

            var result = await signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                logger.LogInformation("User {UserName} logged in", model.Username);

                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                {
                    return Redirect(returnUrl);
                }

                return RedirectToAction("Index", "Home");
            }

            if (result.IsLockedOut)
            {
                logger.LogWarning("User {UserName} account locked out", model.Username);
                ModelState.AddModelError(string.Empty, "Account is locked out. Please try again later.");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid username or password");
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await signInManager.SignOutAsync();
            logger.LogInformation("User logged out");
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public IActionResult Authorize(string? client_id, string? redirect_uri, string? response_type,
            string? state, string? scope, string? code_challenge, string? code_challenge_method,
            string? nonce, string? prompt)
        {
            var model = new OAuth2Request
            {
                ClientId = client_id,
                RedirectUri = redirect_uri,
                ResponseType = response_type,
                State = state,
                Scope = scope,
                CodeChallenge = code_challenge,
                CodeChallengeMethod = code_challenge_method ?? "plain",
                Nonce = nonce,
                Prompt = prompt
            };

            return View(model);
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Authorize(OAuth2Request model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            if (!await authorizationService.ValidateClientAsync(model.ClientId))
            {
                ModelState.AddModelError(string.Empty, "Invalid client ID");
                return View(model);
            }

            if (!await authorizationService.ValidateRedirectUriAsync(model.ClientId, model.RedirectUri!))
            {
                ModelState.AddModelError(string.Empty, "Invalid redirect URI");
                return View(model);
            }

            if (model.ResponseType != "code")
            {
                var redirectWithError = QueryHelpers.AddQueryString(model.RedirectUri!, new Dictionary<string, string>
                {
                    ["error"] = "unsupported_response_type",
                    ["error_description"] = "Only 'code' response type is supported",
                    ["state"] = model.State
                });

                return Redirect(redirectWithError);
            }

            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                var user = await userManager.FindByIdAsync(userId!);

                if (user == null)
                {
                    return Unauthorized();
                }

                var requestedScopes = model.Scope?.Split(' ') ?? Array.Empty<string>();

                var authCode = await authorizationService.CreateAuthorizationCodeAsync(
                    userId!,
                    model.ClientId,
                    model.RedirectUri!,
                    model.CodeChallenge ?? "",
                    model.CodeChallengeMethod ?? "plain",
                    requestedScopes);

                var redirectUrl = QueryHelpers.AddQueryString(model.RedirectUri!, new Dictionary<string, string>
                {
                    ["code"] = authCode.Code,
                    ["state"] = model.State,
                });

                return Redirect(redirectUrl);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error generating authorization code");
                var redirectWithError = QueryHelpers.AddQueryString(model.RedirectUri!, new Dictionary<string, string>
                {
                    ["error"] = "server_error",
                    ["error_description"] = "An error occurred processing the request",
                    ["state"] = model.State
                });

                return Redirect(redirectWithError);
            }
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> UserInfo()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub");

            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized();
            }

            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return Unauthorized();
            }

            var userRoles = await userManager.GetRolesAsync(user);

            var userInfo = new
            {
                sub = userId,
                email = user.Email,
                email_verified = user.EmailConfirmed,
                preferred_username = user.UserName,
                phone_number = user.PhoneNumber,
                phone_number_verified = user.PhoneNumberConfirmed,
                roles = userRoles
            };

            return Json(userInfo);
        }

        [HttpGet]
        public IActionResult Jwks(JwksService jwksService)
        {
            return Json(new
            {
                keys = jwksService.GetJsonWebKeys()
            });
        }

        [HttpGet]
        public IActionResult OpenIdConfiguration(IConfiguration configuration)
        {
            var baseUrl = configuration["OpenIdConnect:IssuerUri"] ?? configuration["Jwt:Issuer"];

            var oidcConfig = new
            {
                issuer = baseUrl,
                jwks_uri = $"{baseUrl}/Authentication/Jwks",
                authorization_endpoint = $"{baseUrl}/Authentication/Authorize",
                token_endpoint = $"{baseUrl}/Authentication/Token",
                userinfo_endpoint = $"{baseUrl}/Authentication/UserInfo",
                end_session_endpoint = $"{baseUrl}/Authentication/Logout",
                response_types_supported = new[] { "code", "id_token", "token", "id_token token", "code id_token", "code token", "code id_token token" },
                grant_types_supported = new[] { "authorization_code", "client_credentials", "password", "refresh_token" },
                subject_types_supported = new[] { "public" },
                id_token_signing_alg_values_supported = new[] { "RS256" },
                scopes_supported = new[] { "openid", "profile", "email", "api", "offline_access" },
                token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post" },
                claims_supported = new[] { "sub", "name", "email", "email_verified", "role", "preferred_username" },
                code_challenge_methods_supported = new[] { "plain", "S256" }
            };

            return Json(oidcConfig);
        }
    }

}