namespace IdentityProvider.Options;

public class OpenIdConnectClientOptions
{
    public string ClientId { get; set; } = default!;
    public string ClientName { get; set; } = default!;
    public string ClientSecret { get; set; } = default!;
    public List<string> RedirectUris { get; set; } = new List<string>();
    public List<string> PostLogoutRedirectUris { get; set; } = new List<string>();
    public List<string> AllowedCorsOrigins { get; set; } = new List<string>();
    public List<string> AllowedScopes { get; set; } = new List<string>();
    public bool RequirePkce { get; set; } = true;
    public bool AllowOfflineAccess { get; set; } = true;
    public int AccessTokenLifetimeMinutes { get; set; } = 60;
    public int RefreshTokenLifetimeDays { get; set; } = 30;
}

public class OpenIdConnectOptions
{
    public List<OpenIdConnectClientOptions> Clients { get; set; } = new List<OpenIdConnectClientOptions>();
    public string IssuerUri { get; set; } = default!;
    public bool RequireHttpsMetadata { get; set; } = true;
}