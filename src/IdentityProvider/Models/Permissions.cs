namespace IdentityProvider.Models
{
    public static class Permissions
    {
        // User Management Permissions
        public const string UserRead = "user.read";
        public const string UserCreate = "user.create";
        public const string UserUpdate = "user.update";
        public const string UserDelete = "user.delete";
        public const string UserManageRoles = "user.manage_roles";

        // Role Management Permissions
        public const string RoleRead = "role.read";
        public const string RoleCreate = "role.create";
        public const string RoleUpdate = "role.update";
        public const string RoleDelete = "role.delete";
        public const string RoleManagePermissions = "role.manage_permissions";

        // Client Management Permissions
        public const string ClientRead = "client.read";
        public const string ClientCreate = "client.create";
        public const string ClientUpdate = "client.update";
        public const string ClientDelete = "client.delete";

        // Dashboard Permissions
        public const string DashboardView = "dashboard.view";
        public const string DashboardManage = "dashboard.manage";

        // System Permissions
        public const string SystemSettings = "system.settings";
        public const string SystemLogs = "system.logs";

        // Authentication Permissions
        public const string AuthorizeClients = "auth.authorize_clients";
        public const string IssueTokens = "auth.issue_tokens";

        public static readonly Dictionary<string, string> PermissionDescriptions = new()
        {
            { UserRead, "View user information" },
            { UserCreate, "Create new users" },
            { UserUpdate, "Update user information" },
            { UserDelete, "Delete users" },
            { UserManageRoles, "Assign and remove user roles" },

            { RoleRead, "View role information" },
            { RoleCreate, "Create new roles" },
            { RoleUpdate, "Update role information" },
            { RoleDelete, "Delete roles" },
            { RoleManagePermissions, "Assign and remove role permissions" },

            { ClientRead, "View OAuth client information" },
            { ClientCreate, "Create new OAuth clients" },
            { ClientUpdate, "Update OAuth client information" },
            { ClientDelete, "Delete OAuth clients" },

            { DashboardView, "Access admin dashboard" },
            { DashboardManage, "Manage dashboard settings" },

            { SystemSettings, "Manage system settings" },
            { SystemLogs, "View system logs" },

            { AuthorizeClients, "Authorize OAuth clients" },
            { IssueTokens, "Issue authentication tokens" }
        };

        public static readonly Dictionary<string, List<string>> PermissionCategories = new()
        {
            {
                "User Management", new List<string>
                {
                    UserRead, UserCreate, UserUpdate, UserDelete, UserManageRoles
                }
            },
            {
                "Role Management", new List<string>
                {
                    RoleRead, RoleCreate, RoleUpdate, RoleDelete, RoleManagePermissions
                }
            },
            {
                "Client Management", new List<string>
                {
                    ClientRead, ClientCreate, ClientUpdate, ClientDelete
                }
            },
            {
                "Dashboard", new List<string>
                {
                    DashboardView, DashboardManage
                }
            },
            {
                "System", new List<string>
                {
                    SystemSettings, SystemLogs
                }
            },
            {
                "Authentication", new List<string>
                {
                    AuthorizeClients, IssueTokens
                }
            }
        };

        public static List<string> GetAllPermissions()
        {
            return PermissionDescriptions.Keys.ToList();
        }

        public static List<string> GetPermissionsByCategory(string category)
        {
            return PermissionCategories.TryGetValue(category, out var permissions) ? permissions : new List<string>();
        }

        public static string GetPermissionDescription(string permission)
        {
            return PermissionDescriptions.TryGetValue(permission, out var description) ? description : permission;
        }

        public static List<string> GetCategories()
        {
            return PermissionCategories.Keys.ToList();
        }
    }
}
