using IdentityWebClient.Models.Users;

namespace IdentityWebClient.Services
{
    public interface IUserService
    {
        Task<ApiResult<UserListViewModel>> GetUsersAsync(int skip = 0, int take = 10);
        Task<ApiResult<UserDetailsDto>> GetUserAsync(string id);
        Task<ApiResult<UserDto>> CreateUserAsync(RegisterUserDto model);
        Task<ApiResult<UserDto>> UpdateUserAsync(string id, UpdateUserDto model);
        Task<ApiResult<object>> DeleteUserAsync(string id);
        Task<ApiResult<object>> ChangePasswordAsync(string id, ChangePasswordDto model);
        Task<ApiResult<object>> AddRoleToUserAsync(string userId, string role);
        Task<ApiResult<object>> RemoveRoleFromUserAsync(string userId, string role);
    }
}