namespace IdentityWebClient.Models.Roles
{
    public class RoleListViewModel
    {
        public List<RoleDto> Roles { get; set; } = new();
    }

    public class RoleDto
    {
        public string Id { get; set; } = string.Empty;
        public string? Name { get; set; }
        public string? NormalizedName { get; set; }
    }

    public class RoleDetailsDto : RoleDto
    {
        public List<string> Users { get; set; } = new();
    }

    public class CreateRoleDto
    {
        public string Name { get; set; } = string.Empty;
    }

    public class UpdateRoleDto
    {
        public string? Name { get; set; }
    }
}