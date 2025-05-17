using Microsoft.AspNetCore.Authentication;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace IdentityWebClient.Services
{
    public class ApiServiceBase
    {
        protected readonly IHttpClientFactory _httpClientFactory;
        protected readonly IHttpContextAccessor _httpContextAccessor;
        protected readonly JsonSerializerOptions _jsonOptions;

        public ApiServiceBase(IHttpClientFactory httpClientFactory, IHttpContextAccessor httpContextAccessor)
        {
            _httpClientFactory = httpClientFactory;
            _httpContextAccessor = httpContextAccessor;
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };
        }

        protected async Task<HttpClient> CreateClientWithAuthAsync()
        {
            var httpClient = _httpClientFactory.CreateClient("IdentityProviderAPI");

            if (_httpContextAccessor.HttpContext != null)
            {
                var accessToken = await _httpContextAccessor.HttpContext.GetTokenAsync("access_token");
                if (!string.IsNullOrEmpty(accessToken))
                {
                    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                }
            }

            return httpClient;
        }

        protected StringContent CreateJsonContent<T>(T data)
        {
            var json = JsonSerializer.Serialize(data, _jsonOptions);
            return new StringContent(json, Encoding.UTF8, "application/json");
        }

        protected async Task<T?> ReadJsonResponseAsync<T>(HttpResponseMessage response)
        {
            if (!response.IsSuccessStatusCode)
                return default;

            var content = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<T>(content, _jsonOptions);
        }

        protected async Task<ApiResult<T>> GetApiResultAsync<T>(HttpResponseMessage response)
        {
            var result = new ApiResult<T>();
            result.StatusCode = response.StatusCode;
            result.IsSuccess = response.IsSuccessStatusCode;

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                if (!string.IsNullOrEmpty(content))
                {
                    result.Data = JsonSerializer.Deserialize<T>(content, _jsonOptions);
                }
            }
            else
            {
                result.ErrorMessage = await response.Content.ReadAsStringAsync();
            }

            return result;
        }
    }

    public class ApiResult<T>
    {
        public bool IsSuccess { get; set; }
        public System.Net.HttpStatusCode StatusCode { get; set; }
        public T? Data { get; set; }
        public string? ErrorMessage { get; set; }
    }
}