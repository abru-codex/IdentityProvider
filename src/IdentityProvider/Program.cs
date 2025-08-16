using System.Security.Claims;
using System.Text;
using IdentityProvider.DbContext;
using IdentityProvider.Endpoints;
using IdentityProvider.Options;
using IdentityProvider.Services;
using IdentityProvider.Validation;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// Configure Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
    {
        // Password settings
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequiredLength = 8;

        // Lockout settings
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        options.Lockout.MaxFailedAccessAttempts = 5;

        // User settings
        options.User.RequireUniqueEmail = true;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Configure Cookies
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.SlidingExpiration = true;
});

// Configure FluentValidation
builder.Services.AddFluentValidation();

// Register options
builder.Services.Configure<JwtOption>(builder.Configuration.GetSection("Jwt"));
builder.Services.Configure<DefaultAdminOption>(builder.Configuration.GetSection("DefaultAdmin"));
builder.Services.Configure<OpenIdConnectOptions>(builder.Configuration.GetSection("OpenIdConnect"));

// Register services
builder.Services.AddSingleton<JwksService>();
builder.Services.AddScoped<TokenService>(); // Changed from Singleton to Scoped
builder.Services.AddScoped<DbSeeder>();
builder.Services.AddScoped<AuthorizationService>();
builder.Services.AddHttpContextAccessor();

// Configure Authentication
builder.Services.AddAuthentication()
    .AddCookie()
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            // Accept both Issuer and Audience values to match token generation
            ValidAudiences = new[]
            {
                builder.Configuration["Jwt:Issuer"],
                builder.Configuration["Jwt:Audience"]
            }
        };

        // Enable using the access token from the query string for SignalR and other non-header based protocols
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var accessToken = context.Request.Query["access_token"];
                var path = context.HttpContext.Request.Path;

                if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/hubs"))
                {
                    context.Token = accessToken;
                }

                return Task.CompletedTask;
            }
        };
    });

// Provide signing key via options pattern (avoids using service provider inside AddJwtBearer)
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<JwksService>((options, jwksService) =>
    {
        options.TokenValidationParameters.IssuerSigningKey = jwksService.GetSecurityKey();
    });

// Add authorization policies
builder.Services.AddAuthorization(options =>
{
    // Admin policy - requires the Admin role
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole("Admin"));

    // Authenticated users policy
    options.AddPolicy("AuthenticatedUsers", policy =>
        policy.RequireAuthenticatedUser());

    // Scope-based policies for API access
    options.AddPolicy("ApiScope", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme);
        policy.RequireClaim("scope", "api");
    });

    // UserInfo endpoint should authorize via Bearer token with at least 'openid' scope
    options.AddPolicy("UserInfoScope", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme);
        policy.RequireClaim("scope", "openid");
    });
});

// Add CORS for SPA clients
builder.Services.AddCors(options =>
{
    options.AddPolicy("DefaultCorsPolicy", policy =>
    {
        policy.WithOrigins(builder.Configuration.GetSection("OpenIdConnect:Clients")
                .Get<List<OpenIdConnectClientOptions>>()
                ?.SelectMany(c => c.AllowedCorsOrigins)
                .ToArray() ?? Array.Empty<string>())
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

builder.Services.AddRazorPages();
builder.Services.AddControllersWithViews();

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();
builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.MapOpenApi();
}

app.UseHttpsRedirection();

// Enable CORS
app.UseCors("DefaultCorsPolicy");

// Authentication & Authorization middleware
app.UseAuthentication();
app.UseAuthorization();

// Map Razor Pages
app.MapRazorPages();

// Map MVC Controllers
app.MapControllerRoute(
    name: "admin",
    pattern: "Admin/{controller=Dashboard}/{action=Index}/{id?}");

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// Map endpoints
app.MapAuthenticationEndpoint();
app.MapUserManagementEndpoint();
app.MapRoleManagementEndpoint();

app.MapGet("/", (ClaimsPrincipal user) =>
{
    return Results.Ok(new
    {
        Message = "Welcome to the Identity Provider API!",
        User = user.Identity?.Name,
        Roles = user.Claims.Select(c => new { c.Type, c.Value })
    });
});

// Seed the database
await app.SeedDatabaseAsync();

app.Run();


