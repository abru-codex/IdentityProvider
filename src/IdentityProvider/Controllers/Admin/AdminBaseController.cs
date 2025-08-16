using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityProvider.Controllers.Admin
{
    [Authorize(Policy = "AdminOnly")]
    [Area("Admin")]
    public abstract class AdminBaseController : Controller
    {
        protected readonly ILogger<AdminBaseController> _logger;
        protected readonly IHttpClientFactory _httpClientFactory;
        protected readonly IConfiguration _configuration;

        protected AdminBaseController(
            ILogger<AdminBaseController> logger,
            IHttpClientFactory httpClientFactory,
            IConfiguration configuration)
        {
            _logger = logger;
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
        }

        protected string GetApiBaseUrl()
        {
            return _configuration["Jwt:Issuer"] ?? "https://localhost:5001";
        }

        protected async Task<HttpClient> GetAuthenticatedHttpClient()
        {
            var client = _httpClientFactory.CreateClient();
            client.BaseAddress = new Uri(GetApiBaseUrl());
            
            // Get the current user's JWT token from the request
            var token = HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            if (!string.IsNullOrEmpty(token))
            {
                client.DefaultRequestHeaders.Authorization = 
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            }
            
            return client;
        }

        protected void SetSuccessMessage(string message)
        {
            TempData["SuccessMessage"] = message;
        }

        protected void SetErrorMessage(string message)
        {
            TempData["ErrorMessage"] = message;
        }
    }
}