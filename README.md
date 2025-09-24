# Identity Provider

A comprehensive OAuth 2.0 and OpenID Connect identity provider built with ASP.NET Core 9.0, featuring user management, role-based permissions, and Redis caching for high-performance authentication services.

## Features

### Core Authentication
- **OAuth 2.0 & OpenID Connect**: Full implementation of OAuth 2.0 authorization framework and OpenID Connect authentication layer
- **JWT Token Support**: Secure token generation and validation using JSON Web Tokens
- **PKCE Support**: Proof Key for Code Exchange for enhanced security in public clients
- **Refresh Tokens**: Long-lived refresh token support for seamless user experience

### User & Access Management
- **User Management**: Complete user registration, login, and profile management
- **Role-Based Access Control (RBAC)**: Granular role and permission management system
- **Multi-Factor Authentication**: Enhanced security with two-factor authentication support
- **Password Policies**: Configurable password complexity requirements and lockout policies

### Performance & Scalability
- **Redis Caching**: High-performance caching layer for user permissions and session data
- **Database Support**: PostgreSQL integration with Entity Framework Core
- **Distributed Sessions**: Redis-backed session storage for horizontal scaling

### Administration
- **Admin Dashboard**: Comprehensive administration interface for managing users, roles, and clients
- **Client Management**: OAuth client registration and configuration management
- **Audit Logging**: Detailed logging of authentication events and administrative actions
- **Real-time Monitoring**: Dashboard with authentication metrics and system health indicators

## Technology Stack

- **Framework**: ASP.NET Core 9.0 MVC
- **Database**: PostgreSQL with Entity Framework Core 9.0
- **Caching**: Redis with StackExchange.Redis
- **Authentication**: ASP.NET Core Identity
- **Validation**: FluentValidation
- **Token Management**: JWT Bearer Authentication
- **Frontend**: Razor Views, Bootstrap 5

## Prerequisites

- .NET 9.0 SDK
- PostgreSQL 13+
- Redis 6.0+
- Visual Studio 2022 or VS Code with C# extension
- Git

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/IdentityProvider.git
cd IdentityProvider
```

### 2. Database Setup

#### PostgreSQL Installation
Ensure PostgreSQL is installed and running on your system:

```bash
# macOS
brew install postgresql
brew services start postgresql

# Ubuntu/Debian
sudo apt-get install postgresql postgresql-contrib
sudo systemctl start postgresql

# Windows - Download installer from https://www.postgresql.org/download/windows/
```

Create the database:

```bash
psql -U postgres
CREATE DATABASE IdentityProviderDb;
CREATE USER admin WITH PASSWORD '12345';
GRANT ALL PRIVILEGES ON DATABASE IdentityProviderDb TO admin;
\q
```

### 3. Redis Setup

```bash
# macOS
brew install redis
brew services start redis

# Ubuntu/Debian
sudo apt-get install redis-server
sudo systemctl start redis-server

# Windows - Download from https://github.com/microsoftarchive/redis/releases
```

### 4. Configure Application

Update the connection strings in `src/IdentityProvider/appsettings.json`:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Port=5432;Database=IdentityProviderDb;User Id=admin;Password=YourSecurePassword;",
    "Redis": "localhost:6379"
  },
  "Jwt": {
    "Issuer": "https://localhost:5001",
    "Audience": "https://localhost:5001",
    "Key": "your-256-bit-secret-key-for-jwt-token-generation-keep-this-secure"
  },
  "DefaultAdmin": {
    "Email": "admin@yourdomain.com",
    "Password": "YourSecureAdminPassword123!",
    "UserName": "admin"
  }
}
```

### 5. Apply Database Migrations

```bash
cd src/IdentityProvider
dotnet ef database update
```

### 6. Build and Run

```bash
# Development mode
dotnet run

# Or with watch mode for auto-reload
dotnet watch run
```

The application will be available at:
- HTTPS: `https://localhost:5001`
- HTTP: `http://localhost:5000`

## Project Structure

```
IdentityProvider/
├── src/
│   ├── IdentityProvider/           # Main Identity Provider application
│   │   ├── Areas/
│   │   │   └── Admin/             # Admin panel (users, roles, clients)
│   │   │       ├── Controllers/   # Admin controllers
│   │   │       ├── Models/        # Admin view models
│   │   │       └── Views/         # Admin UI views
│   │   ├── Authorization/         # Custom authorization handlers
│   │   ├── Controllers/           # Main application controllers
│   │   │   ├── AuthenticationController.cs  # Login/logout/register
│   │   │   ├── HomeController.cs           # Landing pages
│   │   │   └── PermissionsController.cs    # Permission management
│   │   ├── Database/              # Database context and configurations
│   │   │   └── ApplicationDbContext.cs
│   │   ├── Migrations/            # EF Core database migrations
│   │   ├── Models/                # Domain models and DTOs
│   │   │   ├── AuthorizationModels.cs  # OAuth/OIDC models
│   │   │   ├── OAuthClient.cs          # OAuth client entity
│   │   │   ├── Permissions.cs          # Permission definitions
│   │   │   └── RolePermission.cs       # Role-permission mapping
│   │   ├── Options/               # Configuration option classes
│   │   ├── Services/              # Business logic services
│   │   │   ├── AuthorizationService.cs     # OAuth authorization
│   │   │   ├── TokenService.cs             # JWT token generation
│   │   │   ├── RolePermissionService.cs    # Permission management
│   │   │   ├── IPermissionCacheService.cs  # Redis caching interface
│   │   │   └── JwksService.cs              # JWKS endpoint service
│   │   ├── Validation/            # FluentValidation validators
│   │   ├── Views/                 # Razor views
│   │   ├── wwwroot/               # Static files (CSS, JS, images)
│   │   ├── Program.cs             # Application entry point
│   │   ├── appsettings.json      # Configuration
│   │   └── IdentityProvider.csproj
│   │
│   └── IdentityWebClient/         # Sample client application
│       ├── Controllers/
│       ├── Models/
│       ├── Views/
│       └── Program.cs
│
└── IdentityProvider.sln           # Solution file
```

## API Endpoints

### Authentication Endpoints
- `GET /Authentication/Login` - Login page
- `POST /Authentication/Login` - Process login
- `GET /Authentication/Register` - Registration page
- `POST /Authentication/Register` - Process registration
- `POST /Authentication/Logout` - Logout user

### OAuth 2.0 / OpenID Connect Endpoints
- `GET /connect/authorize` - Authorization endpoint
- `POST /connect/token` - Token endpoint
- `GET /connect/userinfo` - UserInfo endpoint
- `GET /.well-known/openid-configuration` - Discovery endpoint
- `GET /.well-known/jwks.json` - JWKS endpoint

### Admin Endpoints (Requires Admin Role)
- `/Admin/Dashboard` - Admin dashboard
- `/Admin/Users` - User management
- `/Admin/Roles` - Role management
- `/Admin/Clients` - OAuth client management

## Configuration

### OAuth Client Configuration

Clients can be configured in `appsettings.json`:

```json
{
  "OpenIdConnect": {
    "Clients": [
      {
        "ClientId": "web-client",
        "ClientName": "Web Application",
        "ClientSecret": "your-client-secret",
        "RedirectUris": ["https://yourapp.com/signin-oidc"],
        "PostLogoutRedirectUris": ["https://yourapp.com/signout-callback-oidc"],
        "AllowedScopes": ["openid", "profile", "email", "api"],
        "RequirePkce": true,
        "AllowOfflineAccess": true,
        "AccessTokenLifetimeMinutes": 60,
        "RefreshTokenLifetimeDays": 30
      }
    ]
  }
}
```

### Redis Caching Configuration

The application uses Redis for caching user permissions and session data:

- **Cache Expiration**: 30 minutes (configurable)
- **Cache Keys Format**: `IdentityProvider:UserPermissions:{userId}`
- **Automatic Invalidation**: On role/permission changes

## Security Features

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

### Account Lockout
- 5 failed login attempts trigger lockout
- 15-minute lockout duration
- Configurable in `Program.cs`

### Token Security
- JWT tokens with RS256 signing
- Short-lived access tokens (60 minutes)
- Refresh token rotation
- PKCE for public clients

## Development

### Running Tests

```bash
# Run all tests
dotnet test

# Run with coverage
dotnet test /p:CollectCoverage=true /p:CoverletOutputFormat=opencover
```

### Database Migrations

```bash
# Add a new migration
dotnet ef migrations add MigrationName

# Update database
dotnet ef database update

# Remove last migration
dotnet ef migrations remove
```

### Code Style

The project follows standard C# coding conventions:
- Use PascalCase for public members
- Use camelCase for private fields
- Use async/await for asynchronous operations
- Follow SOLID principles

## Deployment

### Docker Deployment

```dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY ["src/IdentityProvider/IdentityProvider.csproj", "IdentityProvider/"]
RUN dotnet restore "IdentityProvider/IdentityProvider.csproj"
COPY . .
WORKDIR "/src/IdentityProvider"
RUN dotnet build "IdentityProvider.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "IdentityProvider.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "IdentityProvider.dll"]
```

### Environment Variables

For production deployment, use environment variables:

```bash
export ConnectionStrings__DefaultConnection="Server=prod-server;..."
export ConnectionStrings__Redis="redis-server:6379"
export Jwt__Key="your-production-secret-key"
export ASPNETCORE_ENVIRONMENT=Production
```

## Monitoring & Logging

The application uses ASP.NET Core's built-in logging framework:

- **Information**: General application flow
- **Warning**: Abnormal or unexpected events
- **Error**: Error conditions that don't halt the application
- **Critical**: Failures that require immediate attention

Configure logging levels in `appsettings.json`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "Microsoft.EntityFrameworkCore": "Information"
    }
  }
}
```

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Verify PostgreSQL is running: `pg_isready`
   - Check connection string in appsettings.json
   - Ensure database exists and user has permissions

2. **Redis Connection Failed**
   - Verify Redis is running: `redis-cli ping`
   - Check Redis connection string
   - Ensure Redis server allows connections

3. **Migration Errors**
   - Delete Migrations folder and recreate: `dotnet ef migrations add Initial`
   - Ensure database is accessible before running migrations

4. **SSL/HTTPS Issues**
   - Trust the development certificate: `dotnet dev-certs https --trust`
   - For production, use proper SSL certificates

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -am 'Add new feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues, questions, or suggestions, please:
1. Check the [Issues](https://github.com/yourusername/IdentityProvider/issues) page
2. Create a new issue if your problem isn't already listed
3. Provide detailed information about your environment and the issue

## Acknowledgments

- ASP.NET Core team for the excellent framework
- OpenID Foundation for OAuth 2.0 and OpenID Connect specifications
- Community contributors and maintainers