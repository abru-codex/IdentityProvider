using IdentityProvider.Authorization;
using IdentityProvider.DbContext;
using IdentityProvider.Options;
using IdentityProvider.Services;
using IdentityProvider.Validation;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
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
    options.LoginPath = "/Authentication/Login";
    options.LogoutPath = "/Authentication/Logout";
    options.AccessDeniedPath = "/Home/AccessDenied";

});
// Configure FluentValidation
builder.Services.AddFluentValidation();

// Register options
builder.Services.Configure<JwtOption>(builder.Configuration.GetSection("Jwt"));
builder.Services.Configure<DefaultAdminOption>(builder.Configuration.GetSection("DefaultAdmin"));

builder.Services.AddSingleton<JwksService>();
builder.Services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();
builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped<DbSeeder>();
builder.Services.AddScoped<AuthorizationService>();
builder.Services.AddScoped<IOAuthClientService, OAuthClientService>();
builder.Services.AddScoped<IRolePermissionService, RolePermissionService>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddHttpClient();

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

    // Permission-based policies - dynamically create policies for each permission
    foreach (var permission in typeof(IdentityProvider.Models.Permissions).GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
        .Where(f => f.IsLiteral && !f.IsInitOnly && f.FieldType == typeof(string))
        .Select(f => f.GetValue(null)?.ToString())
        .Where(value => !string.IsNullOrEmpty(value)))
    {
        options.AddPolicy($"Permission:{permission}", policy =>
            policy.Requirements.Add(new IdentityProvider.Authorization.PermissionRequirement(permission!)));
    }

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

builder.Services.AddCors(options =>
{
    options.AddPolicy("DefaultCorsPolicy", policy =>
    {
        // Start with localhost for development, will be updated dynamically
        policy.WithOrigins("http://localhost:3000", "https://localhost:3001")
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();

// Enable CORS
app.UseCors("DefaultCorsPolicy");

// Authentication & Authorization middleware
app.UseAuthentication();
app.UseAuthorization();

// Map MVC Controllers
app.MapControllerRoute(
    name: "Admin",
    pattern: "{area:exists}/{controller=Home}/{action=Index}/{id?}");

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// Seed the database
await app.SeedDatabaseAsync();
app.Run();