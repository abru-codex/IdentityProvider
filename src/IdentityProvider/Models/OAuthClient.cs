using System.ComponentModel.DataAnnotations;

namespace IdentityProvider.Models;

public class OAuthClient
{
    [Key]
    public int Id { get; set; }
    
    [Required]
    [MaxLength(100)]
    public string ClientId { get; set; } = default!;
    
    [Required]
    [MaxLength(200)]
    public string ClientName { get; set; } = default!;
    
    [Required]
    public string ClientSecret { get; set; } = default!;
    
    public string RedirectUris { get; set; } = string.Empty;
    public string PostLogoutRedirectUris { get; set; } = string.Empty;
    public string AllowedCorsOrigins { get; set; } = string.Empty;
    public string AllowedScopes { get; set; } = string.Empty;
    
    public bool RequirePkce { get; set; } = true;
    public bool AllowOfflineAccess { get; set; } = true;
    public int AccessTokenLifetimeMinutes { get; set; } = 60;
    public int RefreshTokenLifetimeDays { get; set; } = 30;
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }

    public List<string> GetRedirectUris()
    {
        return string.IsNullOrWhiteSpace(RedirectUris) 
            ? new List<string>() 
            : RedirectUris.Split('|', StringSplitOptions.RemoveEmptyEntries).ToList();
    }
    
    public void SetRedirectUris(List<string> uris)
    {
        RedirectUris = string.Join("|", uris);
    }
    
    public List<string> GetPostLogoutRedirectUris()
    {
        return string.IsNullOrWhiteSpace(PostLogoutRedirectUris) 
            ? new List<string>() 
            : PostLogoutRedirectUris.Split('|', StringSplitOptions.RemoveEmptyEntries).ToList();
    }
    
    public void SetPostLogoutRedirectUris(List<string> uris)
    {
        PostLogoutRedirectUris = string.Join("|", uris);
    }
    
    public List<string> GetAllowedCorsOrigins()
    {
        return string.IsNullOrWhiteSpace(AllowedCorsOrigins) 
            ? new List<string>() 
            : AllowedCorsOrigins.Split('|', StringSplitOptions.RemoveEmptyEntries).ToList();
    }
    
    public void SetAllowedCorsOrigins(List<string> origins)
    {
        AllowedCorsOrigins = string.Join("|", origins);
    }
    
    public List<string> GetAllowedScopes()
    {
        return string.IsNullOrWhiteSpace(AllowedScopes) 
            ? new List<string>() 
            : AllowedScopes.Split('|', StringSplitOptions.RemoveEmptyEntries).ToList();
    }
    
    public void SetAllowedScopes(List<string> scopes)
    {
        AllowedScopes = string.Join("|", scopes);
    }
}
