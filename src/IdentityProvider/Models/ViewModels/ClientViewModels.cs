using System.ComponentModel.DataAnnotations;

namespace IdentityProvider.Models.ViewModels
{
    public class ClientListViewModel
    {
        public string ClientId { get; set; } = default!;
        public string ClientName { get; set; } = default!;
        public List<string> RedirectUris { get; set; } = new();
        public List<string> AllowedScopes { get; set; } = new();
        public bool RequirePkce { get; set; }
        public bool AllowOfflineAccess { get; set; }
        public int AccessTokenLifetimeMinutes { get; set; }
    }

    public class ClientDetailsViewModel
    {
        public string ClientId { get; set; } = default!;
        public string ClientName { get; set; } = default!;
        public string ClientSecret { get; set; } = default!;
        public List<string> RedirectUris { get; set; } = new();
        public List<string> PostLogoutRedirectUris { get; set; } = new();
        public List<string> AllowedCorsOrigins { get; set; } = new();
        public List<string> AllowedScopes { get; set; } = new();
        public bool RequirePkce { get; set; }
        public bool AllowOfflineAccess { get; set; }
        public int AccessTokenLifetimeMinutes { get; set; }
        public int RefreshTokenLifetimeDays { get; set; }
    }

    public class CreateClientViewModel
    {
        [Required]
        [Display(Name = "Client ID")]
        [RegularExpression(@"^[a-z0-9-_]+$", ErrorMessage = "Client ID can only contain lowercase letters, numbers, hyphens, and underscores")]
        public string ClientId { get; set; } = default!;

        [Required]
        [Display(Name = "Client Name")]
        public string ClientName { get; set; } = default!;

        [Required]
        [Display(Name = "Client Secret")]
        [MinLength(12, ErrorMessage = "Client secret must be at least 12 characters long")]
        public string ClientSecret { get; set; } = default!;

        [Display(Name = "Redirect URIs")]
        public string RedirectUris { get; set; } = string.Empty;

        [Display(Name = "Post Logout Redirect URIs")]
        public string PostLogoutRedirectUris { get; set; } = string.Empty;

        [Display(Name = "Allowed CORS Origins")]
        public string AllowedCorsOrigins { get; set; } = string.Empty;

        [Display(Name = "Allowed Scopes")]
        public List<string> AllowedScopes { get; set; } = new();

        [Display(Name = "Require PKCE")]
        public bool RequirePkce { get; set; } = true;

        [Display(Name = "Allow Offline Access (Refresh Tokens)")]
        public bool AllowOfflineAccess { get; set; } = true;

        [Required]
        [Display(Name = "Access Token Lifetime (minutes)")]
        [Range(1, 1440, ErrorMessage = "Access token lifetime must be between 1 and 1440 minutes")]
        public int AccessTokenLifetimeMinutes { get; set; } = 60;

        [Required]
        [Display(Name = "Refresh Token Lifetime (days)")]
        [Range(1, 365, ErrorMessage = "Refresh token lifetime must be between 1 and 365 days")]
        public int RefreshTokenLifetimeDays { get; set; } = 30;

        public List<string> AvailableScopes { get; set; } = new() { "openid", "profile", "email", "api", "offline_access" };
    }

    public class EditClientViewModel
    {
        [Required]
        [Display(Name = "Client ID")]
        public string ClientId { get; set; } = default!;

        [Required]
        [Display(Name = "Client Name")]
        public string ClientName { get; set; } = default!;

        [Display(Name = "Client Secret")]
        [MinLength(12, ErrorMessage = "Client secret must be at least 12 characters long")]
        public string? ClientSecret { get; set; }

        [Display(Name = "Redirect URIs")]
        public string RedirectUris { get; set; } = string.Empty;

        [Display(Name = "Post Logout Redirect URIs")]
        public string PostLogoutRedirectUris { get; set; } = string.Empty;

        [Display(Name = "Allowed CORS Origins")]
        public string AllowedCorsOrigins { get; set; } = string.Empty;

        [Display(Name = "Allowed Scopes")]
        public List<string> AllowedScopes { get; set; } = new();

        [Display(Name = "Require PKCE")]
        public bool RequirePkce { get; set; }

        [Display(Name = "Allow Offline Access (Refresh Tokens)")]
        public bool AllowOfflineAccess { get; set; }

        [Required]
        [Display(Name = "Access Token Lifetime (minutes)")]
        [Range(1, 1440, ErrorMessage = "Access token lifetime must be between 1 and 1440 minutes")]
        public int AccessTokenLifetimeMinutes { get; set; }

        [Required]
        [Display(Name = "Refresh Token Lifetime (days)")]
        [Range(1, 365, ErrorMessage = "Refresh token lifetime must be between 1 and 365 days")]
        public int RefreshTokenLifetimeDays { get; set; }

        public List<string> AvailableScopes { get; set; } = new() { "openid", "profile", "email", "api", "offline_access" };

        public string OriginalClientId { get; set; } = default!;
    }
}