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
}