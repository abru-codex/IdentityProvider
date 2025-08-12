using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Configure authentication
// JwtSecurityTokenHandler.DefaultMapInboundClaims = false;
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie()
.AddOpenIdConnect(options =>
{
    options.RequireHttpsMetadata = true;
    options.MetadataAddress = builder.Configuration["IdentityProvider:MetadataAddress"];
    options.Authority = builder.Configuration["IdentityProvider:Authority"];
    options.ClientId = builder.Configuration["IdentityProvider:ClientId"];
    options.ClientSecret = builder.Configuration["IdentityProvider:ClientSecret"];

    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.ResponseType = OpenIdConnectResponseType.Code;

    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.UseTokenLifetime = true;

    options.ProtocolValidator.RequireNonce = false;

    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    // options.Scope.Add("email");
    // options.Scope.Add("api");
    // options.Scope.Add("offline_access");

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidIssuer = builder.Configuration["IdentityProvider:Authority"],
        ValidateIssuer = true,
    };

    // Map claims
    options.ClaimActions.MapJsonKey("sub", "sub");
    options.ClaimActions.MapJsonKey("email", "email");
});

// Register IHttpContextAccessor
builder.Services.AddHttpContextAccessor();

// Register HTTP client for API calls
builder.Services.AddHttpClient("IdentityProviderAPI", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["IdentityProvider:Authority"] ?? "https://localhost:5001");
    client.DefaultRequestHeaders.Add("Accept", "application/json");
});

// Add services for API calls
builder.Services.AddScoped<IdentityWebClient.Services.IUserService, IdentityWebClient.Services.UserService>();
builder.Services.AddScoped<IdentityWebClient.Services.IRoleService, IdentityWebClient.Services.RoleService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
