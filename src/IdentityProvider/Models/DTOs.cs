namespace IdentityProvider.Models
{
    public class RegisterUserDto
    {
        public string Email { get; set; } = default!;
        public string Password { get; set; } = default!;
        public string? PhoneNumber { get; set; }
        public string? Role { get; set; }
    }

    public class UpdateUserDto
    {
        public string? Email { get; set; }
        public string? PhoneNumber { get; set; }
        public string? CurrentPassword { get; set; }
        public string? NewPassword { get; set; }
    }

    public class ChangePasswordDto
    {
        public string CurrentPassword { get; set; } = default!;
        public string NewPassword { get; set; } = default!;
    }

    public class UserDto
    {
        public string Id { get; set; } = default!;
        public string? Email { get; set; }
        public string? UserName { get; set; }
        public string? PhoneNumber { get; set; }
        public bool EmailConfirmed { get; set; }
    }

    public class UserDetailsDto : UserDto
    {
        public bool PhoneNumberConfirmed { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public bool LockoutEnabled { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }
        public int AccessFailedCount { get; set; }
        public List<string> Roles { get; set; } = new();
    }

    public class CreateRoleDto
    {
        public string Name { get; set; } = default!;
    }

    public class UpdateRoleDto
    {
        public string? Name { get; set; }
    }

    public class RoleDto
    {
        public string Id { get; set; } = default!;
        public string? Name { get; set; }
        public string? NormalizedName { get; set; }
    }

    public class RoleDetailsDto : RoleDto
    {
        public List<string> Users { get; set; } = new();
    }

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

    public class PaginationParams
    {
        public int Skip { get; set; } = 0;
        public int Take { get; set; } = 10;
    }
}