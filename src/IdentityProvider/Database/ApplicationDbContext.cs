using IdentityProvider.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityProvider.Database;

public class ApplicationDbContext : IdentityDbContext<IdentityUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<RefreshToken> RefreshTokens { get; set; } = null!;
    public DbSet<AuthorizationCode> AuthorizationCodes { get; set; } = null!;
    public DbSet<OAuthClient> OAuthClients { get; set; } = null!;
    public DbSet<RolePermission> RolePermissions { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<RefreshToken>()
            .HasKey(r => r.Id);

        builder.Entity<RefreshToken>()
            .HasIndex(r => r.Token)
            .IsUnique();

        builder.Entity<AuthorizationCode>()
            .HasKey(a => a.Id);

        builder.Entity<AuthorizationCode>()
            .HasIndex(a => a.Code)
            .IsUnique();

        builder.Entity<OAuthClient>()
            .HasKey(c => c.Id);

        builder.Entity<OAuthClient>()
            .HasIndex(c => c.ClientId)
            .IsUnique();

        builder.Entity<RolePermission>()
            .HasKey(rp => rp.Id);

        builder.Entity<RolePermission>()
            .HasIndex(rp => new { rp.RoleId, rp.Permission })
            .IsUnique();
    }
}