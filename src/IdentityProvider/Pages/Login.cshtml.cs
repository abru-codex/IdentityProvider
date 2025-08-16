using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityProvider.Pages
{
    public class LoginModel : PageModel
    {
        [BindProperty(SupportsGet = true)]
        public string? ReturnUrl { get; set; }

        [BindProperty]
        public string? ErrorMessage { get; set; }

        public void OnGet(string? returnUrl = null)
        {
            ReturnUrl = returnUrl ?? "/";
        }

        public IActionResult OnPost(string username, string password, string? returnUrl = null)
        {
            // This method is here for completeness, but the form posts directly to the API endpoint
            // If you want to handle the post here instead, you can implement the logic
            return Page();
        }
    }
}
