using System.ComponentModel.DataAnnotations;

namespace IdentityProvider.Models.ViewModels;

public class LoginViewModel
{
    [Required]
    [EmailAddress]
    [Display(Name = "Email")]
    public string Username { get; set; } = default!;

    [Required]
    [DataType(DataType.Password)]
    [Display(Name = "Password")]
    public string Password { get; set; } = default!;

    [Display(Name = "Remember me")]
    public bool RememberMe { get; set; }
}