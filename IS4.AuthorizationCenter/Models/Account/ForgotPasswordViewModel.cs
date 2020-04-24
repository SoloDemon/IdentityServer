using System.ComponentModel.DataAnnotations;

namespace IS4.AuthorizationCenter.Models.Account
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
