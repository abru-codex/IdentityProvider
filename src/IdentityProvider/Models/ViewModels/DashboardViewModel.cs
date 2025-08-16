namespace IdentityProvider.Models.ViewModels
{
    public class DashboardViewModel
    {
        public int TotalUsers { get; set; }
        public int TotalRoles { get; set; }
        public int ActiveSessions { get; set; }
        public int TotalClients { get; set; }
        public int TokensIssued { get; set; }
        public List<RecentUserViewModel> RecentUsers { get; set; } = new();
        public List<UserGrowthData> UserGrowth { get; set; } = new();
    }

    public class RecentUserViewModel
    {
        public string Id { get; set; } = default!;
        public string? Email { get; set; }
        public string? UserName { get; set; }
        public bool EmailConfirmed { get; set; }
    }

    public class UserGrowthData
    {
        public string Date { get; set; } = default!;
        public int Count { get; set; }
    }
}