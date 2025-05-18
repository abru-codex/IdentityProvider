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
builder.Services.AddScoped<TokenService>(); // Changed from Singleton to Scoped
builder.Services.AddScoped<DbSeeder>();
builder.Services.AddScoped<AuthorizationService>();
builder.Services.AddHttpContextAccessor();

// Configure Authentication
builder.Services.AddAuthentication()
// .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
// {
//     options.LoginPath = "/api/auth/login";
//     options.LogoutPath = "/api/auth/logout";
// })
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
    };

    // Enable using the access token from the query string for SignalR and other non-header based protocols
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            var accessToken = context.Request.Query["access_token"];
            var path = context.HttpContext.Request.Path;

            if (!string.IsNullOrEmpty(accessToken) &&
                path.StartsWithSegments("/hubs"))
            {
                context.Token = accessToken;
            }

            return Task.CompletedTask;
        }
    };
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
        policy.RequireClaim("scope", "api");
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

// Map endpoints
app.MapAuthenticationEndpoint();
app.MapUserManagementEndpoint();
app.MapRoleManagementEndpoint();

// Seed the database
await app.SeedDatabaseAsync();

app.Run();


