using System.ComponentModel.DataAnnotations;

namespace IdentityProvider.Models
{
    public class RolePermission
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string RoleId { get; set; } = default!;

        [Required]
        [StringLength(100)]
        public string Permission { get; set; } = default!;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        
        // Navigation property (optional, but useful for querying)
        public string? RoleName { get; set; }
    }
}
