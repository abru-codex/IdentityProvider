using IdentityWebClient.Models.Roles;

namespace IdentityWebClient.Services
{
    public class RoleService : ApiServiceBase, IRoleService
    {
        public RoleService(IHttpClientFactory httpClientFactory, IHttpContextAccessor httpContextAccessor)
            : base(httpClientFactory, httpContextAccessor)
        {
        }

        public async Task<ApiResult<List<RoleDto>>> GetRolesAsync()
        {
            var client = await CreateClientWithAuthAsync();
            var response = await client.GetAsync("/api/roles");
            return await GetApiResultAsync<List<RoleDto>>(response);
        }

        public async Task<ApiResult<RoleDetailsDto>> GetRoleAsync(string id)
        {
            var client = await CreateClientWithAuthAsync();
            var response = await client.GetAsync($"/api/roles/{id}");
            return await GetApiResultAsync<RoleDetailsDto>(response);
        }

        public async Task<ApiResult<RoleDto>> CreateRoleAsync(CreateRoleDto model)
        {
            var client = await CreateClientWithAuthAsync();
            var content = CreateJsonContent(model);
            var response = await client.PostAsync("/api/roles", content);
            return await GetApiResultAsync<RoleDto>(response);
        }

        public async Task<ApiResult<RoleDto>> UpdateRoleAsync(string id, UpdateRoleDto model)
        {
            var client = await CreateClientWithAuthAsync();
            var content = CreateJsonContent(model);
            var response = await client.PutAsync($"/api/roles/{id}", content);
            return await GetApiResultAsync<RoleDto>(response);
        }

        public async Task<ApiResult<object>> DeleteRoleAsync(string id)
        {
            var client = await CreateClientWithAuthAsync();
            var response = await client.DeleteAsync($"/api/roles/{id}");
            return await GetApiResultAsync<object>(response);
        }
    }
}