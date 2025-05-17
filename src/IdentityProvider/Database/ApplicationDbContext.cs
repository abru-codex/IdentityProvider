using IdentityProvider.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityProvider.DbContext;

public class ApplicationDbContext : IdentityDbContext<IdentityUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<RefreshToken> RefreshTokens { get; set; } = null!;
    public DbSet<AuthorizationCode> AuthorizationCodes { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Configure RefreshToken
        builder.Entity<RefreshToken>()
            .HasKey(r => r.Id);

        builder.Entity<RefreshToken>()
            .HasIndex(r => r.Token)
            .IsUnique();

        // Configure AuthorizationCode
        builder.Entity<AuthorizationCode>()
            .HasKey(a => a.Id);

        builder.Entity<AuthorizationCode>()
            .HasIndex(a => a.Code)
            .IsUnique();
    }
}