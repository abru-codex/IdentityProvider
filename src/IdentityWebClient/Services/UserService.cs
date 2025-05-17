using IdentityWebClient.Models.Users;
using System.Text.Json;

namespace IdentityWebClient.Services
{
    public class UserService : ApiServiceBase, IUserService
    {
        public UserService(IHttpClientFactory httpClientFactory, IHttpContextAccessor httpContextAccessor)
            : base(httpClientFactory, httpContextAccessor)
        {
        }

        public async Task<ApiResult<UserListViewModel>> GetUsersAsync(int skip = 0, int take = 10)
        {
            var client = await CreateClientWithAuthAsync();
            var response = await client.GetAsync($"/api/users?skip={skip}&take={take}");

            if (!response.IsSuccessStatusCode)
                return await GetApiResultAsync<UserListViewModel>(response);

            var content = await response.Content.ReadAsStringAsync();
            var responseObject = JsonSerializer.Deserialize<dynamic>(content, _jsonOptions);

            var viewModel = new UserListViewModel
            {
                Users = JsonSerializer.Deserialize<List<UserDto>>(responseObject.GetProperty("users").GetRawText(), _jsonOptions) ?? new List<UserDto>(),
                Pagination = new PaginationInfo
                {
                    Skip = skip,
                    Take = take,
                    Total = responseObject.GetProperty("pagination").GetProperty("total").GetInt32()
                }
            };

            return new ApiResult<UserListViewModel>
            {
                IsSuccess = true,
                StatusCode = response.StatusCode,
                Data = viewModel
            };
        }

        public async Task<ApiResult<UserDetailsDto>> GetUserAsync(string id)
        {
            var client = await CreateClientWithAuthAsync();
            var response = await client.GetAsync($"/api/users/{id}");
            return await GetApiResultAsync<UserDetailsDto>(response);
        }

        public async Task<ApiResult<UserDto>> CreateUserAsync(RegisterUserDto model)
        {
            var client = await CreateClientWithAuthAsync();
            var content = CreateJsonContent(model);
            var response = await client.PostAsync("/api/users", content);
            return await GetApiResultAsync<UserDto>(response);
        }

        public async Task<ApiResult<UserDto>> UpdateUserAsync(string id, UpdateUserDto model)
        {
            var client = await CreateClientWithAuthAsync();
            var content = CreateJsonContent(model);
            var response = await client.PutAsync($"/api/users/{id}", content);
            return await GetApiResultAsync<UserDto>(response);
        }

        public async Task<ApiResult<object>> DeleteUserAsync(string id)
        {
            var client = await CreateClientWithAuthAsync();
            var response = await client.DeleteAsync($"/api/users/{id}");
            return await GetApiResultAsync<object>(response);
        }

        public async Task<ApiResult<object>> ChangePasswordAsync(string id, ChangePasswordDto model)
        {
            // Create a DTO that matches what the API expects (without confirm password)
            var apiModel = new
            {
                CurrentPassword = model.CurrentPassword,
                NewPassword = model.NewPassword
            };

            var client = await CreateClientWithAuthAsync();
            var content = CreateJsonContent(apiModel);
            var response = await client.PostAsync($"/api/users/{id}/change-password", content);
            return await GetApiResultAsync<object>(response);
        }

        public async Task<ApiResult<object>> AddRoleToUserAsync(string userId, string role)
        {
            var client = await CreateClientWithAuthAsync();
            var response = await client.PostAsync($"/api/users/{userId}/roles/{role}", null);
            return await GetApiResultAsync<object>(response);
        }

        public async Task<ApiResult<object>> RemoveRoleFromUserAsync(string userId, string role)
        {
            var client = await CreateClientWithAuthAsync();
            var response = await client.DeleteAsync($"/api/users/{userId}/roles/{role}");
            return await GetApiResultAsync<object>(response);
        }
    }
}