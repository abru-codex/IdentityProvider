using IdentityWebClient.Models.Roles;

namespace IdentityWebClient.Services
{
    public interface IRoleService
    {
        Task<ApiResult<List<RoleDto>>> GetRolesAsync();
        Task<ApiResult<RoleDetailsDto>> GetRoleAsync(string id);
        Task<ApiResult<RoleDto>> CreateRoleAsync(CreateRoleDto model);
        Task<ApiResult<RoleDto>> UpdateRoleAsync(string id, UpdateRoleDto model);
        Task<ApiResult<object>> DeleteRoleAsync(string id);
    }
}