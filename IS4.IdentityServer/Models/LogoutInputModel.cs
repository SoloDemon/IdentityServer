using System.ComponentModel.DataAnnotations;

namespace IS4.IdentityServer.Models
{
    public class LogoutInputModel
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
        public bool RememberLogin { get; set; }
        public string ReturnUrl { get; set; }
    }
}
