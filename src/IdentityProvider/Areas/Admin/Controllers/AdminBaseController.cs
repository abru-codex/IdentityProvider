using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityProvider.Areas.Admin.Controllers
{
    [Authorize(Policy = "AdminOnly")]
    [Area("Admin")]
    public abstract class AdminBaseController(
        ILogger<AdminBaseController> logger,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration)
        : Controller
    {
        protected readonly ILogger<AdminBaseController> Logger = logger;
        protected readonly IHttpClientFactory HttpClientFactory = httpClientFactory;
        protected readonly IConfiguration Configuration = configuration;

        protected string GetApiBaseUrl()
        {
            return Configuration["Jwt:Issuer"] ?? "https://localhost:5001";
        }

        protected Task<HttpClient> GetAuthenticatedHttpClient()
        {
            var client = HttpClientFactory.CreateClient();
            client.BaseAddress = new Uri(GetApiBaseUrl());

            var token = HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            if (!string.IsNullOrEmpty(token))
            {
                client.DefaultRequestHeaders.Authorization = 
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            }
            
            return Task.FromResult(client);
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