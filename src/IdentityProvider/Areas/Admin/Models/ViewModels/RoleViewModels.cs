using System.ComponentModel.DataAnnotations;

namespace IdentityProvider.Models.ViewModels
{
    public class RoleListViewModel
    {
        public string Id { get; set; } = default!;
        public string Name { get; set; } = default!;
        public string? NormalizedName { get; set; }
        public int UserCount { get; set; }
        public List<string> AssignedUsers { get; set; } = new();
        public string? Description { get; set; }
        public List<string> Permissions { get; set; } = new();
        public int PermissionCount { get; set; }
    }

    public class RoleDetailsViewModel
    {
        public string Id { get; set; } = default!;
        public string Name { get; set; } = default!;
        public string? NormalizedName { get; set; }
        public int UserCount { get; set; }
        public List<UserRoleAssignmentViewModel> AssignedUsers { get; set; } = new();
    }

    public class CreateRoleViewModel
    {
        [Required]
        [StringLength(256, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 2)]
        [Display(Name = "Role Name")]
        public string Name { get; set; } = default!;

        [Display(Name = "Description")]
        [StringLength(500, ErrorMessage = "The {0} must be at max {1} characters long.")]
        public string? Description { get; set; }
    }

    public class EditRoleViewModel
    {
        public string Id { get; set; } = default!;

        [Required]
        [StringLength(256, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 2)]
        [Display(Name = "Role Name")]
        public string Name { get; set; } = default!;

        [Display(Name = "Description")]
        [StringLength(500, ErrorMessage = "The {0} must be at max {1} characters long.")]
        public string? Description { get; set; }

        [Display(Name = "Normalized Name")]
        public string? NormalizedName { get; set; }

        public List<UserRoleAssignmentViewModel> AssignedUsers { get; set; } = new();
        public List<UserRoleAssignmentViewModel> AvailableUsers { get; set; } = new();
    }

    public class UserRoleAssignmentViewModel
    {
        public string UserId { get; set; } = default!;
        public string UserName { get; set; } = default!;
        public string? Email { get; set; }
        public bool IsAssigned { get; set; }
        public List<string> OtherRoles { get; set; } = new();
    }

    public class RoleUsersViewModel
    {
        public string RoleId { get; set; } = default!;
        public string RoleName { get; set; } = default!;
        public List<UserRoleAssignmentViewModel> Users { get; set; } = new();
        public List<string> SelectedUserIds { get; set; } = new();
    }

    // Permission-related ViewModels
    public class PermissionViewModel
    {
        public string Permission { get; set; } = default!;
        public string Description { get; set; } = default!;
        public bool IsAssigned { get; set; }
        public string Category { get; set; } = default!;
    }

    public class RolePermissionsViewModel
    {
        public string RoleId { get; set; } = default!;
        public string RoleName { get; set; } = default!;
        public Dictionary<string, List<PermissionViewModel>> PermissionCategories { get; set; } = new();
        public List<string> AssignedPermissions { get; set; } = new();
        public int TotalPermissions { get; set; }
        public int AssignedPermissionsCount { get; set; }
    }

    public class AssignPermissionsViewModel
    {
        public string RoleId { get; set; } = default!;
        public string RoleName { get; set; } = default!;
        public List<string> SelectedPermissions { get; set; } = new();
        public Dictionary<string, List<string>> AvailablePermissions { get; set; } = new();
    }

    public class PermissionCategoryViewModel
    {
        public string Category { get; set; } = default!;
        public List<PermissionViewModel> Permissions { get; set; } = new();
        public int AssignedCount { get; set; }
        public int TotalCount { get; set; }
    }
}