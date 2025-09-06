using System.ComponentModel.DataAnnotations;

namespace IdentityProvider.Areas.Admin.Models.ViewModels
{
    public class UserListViewModel
    {
        public string Id { get; set; } = default!;
        public string? Email { get; set; }
        public string? UserName { get; set; }
        public string? PhoneNumber { get; set; }
        public bool EmailConfirmed { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }
        public List<string> Roles { get; set; } = new();
    }

    public class UserDetailsViewModel
    {
        public string Id { get; set; } = default!;
        public string? Email { get; set; }
        public string? UserName { get; set; }
        public string? PhoneNumber { get; set; }
        public bool EmailConfirmed { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public bool LockoutEnabled { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }
        public int AccessFailedCount { get; set; }
        public List<string> Roles { get; set; } = new();
    }

    public class CreateUserViewModel
    {
        [Required]
        [Display(Name = "Username")]
        public string UserName { get; set; } = default!;

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; } = default!;

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 8)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; } = default!;

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; } = default!;

        [Phone]
        [Display(Name = "Phone Number")]
        public string? PhoneNumber { get; set; }

        [Display(Name = "Email Confirmed")]
        public bool EmailConfirmed { get; set; }

        [Display(Name = "Selected Roles")]
        public List<string> SelectedRoles { get; set; } = new();

        public List<string> AvailableRoles { get; set; } = new();
    }

    public class EditUserViewModel
    {
        public string Id { get; set; } = default!;

        [Required]
        [Display(Name = "Username")]
        public string UserName { get; set; } = default!;

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; } = default!;

        [Phone]
        [Display(Name = "Phone Number")]
        public string? PhoneNumber { get; set; }

        [Display(Name = "Email Confirmed")]
        public bool EmailConfirmed { get; set; }

        [Display(Name = "Phone Number Confirmed")]
        public bool PhoneNumberConfirmed { get; set; }

        [Display(Name = "Two Factor Enabled")]
        public bool TwoFactorEnabled { get; set; }

        [Display(Name = "Lockout Enabled")]
        public bool LockoutEnabled { get; set; }

        [Display(Name = "Lockout End Date")]
        public DateTimeOffset? LockoutEnd { get; set; }

        [Display(Name = "Access Failed Count")]
        public int AccessFailedCount { get; set; }

        [Display(Name = "Selected Roles")]
        public List<string> SelectedRoles { get; set; } = new();

        public List<string> AvailableRoles { get; set; } = new();
    }

    public class ChangePasswordViewModel
    {
        public string UserId { get; set; } = default!;
        public string UserEmail { get; set; } = default!;

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 8)]
        [DataType(DataType.Password)]
        [Display(Name = "New Password")]
        public string NewPassword { get; set; } = default!;

        [DataType(DataType.Password)]
        [Display(Name = "Confirm New Password")]
        [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; } = default!;
    }

    public class UserListPageViewModel
    {
        public List<UserListViewModel> Users { get; set; } = new();
        public int CurrentPage { get; set; }
        public int PageSize { get; set; }
        public int TotalCount { get; set; }
        public string? Search { get; set; }
        public int TotalPages => (int)Math.Ceiling((double)TotalCount / PageSize);
    }
}