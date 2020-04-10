using System.ComponentModel.DataAnnotations;

namespace IS4.IdentityServer.Models
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
