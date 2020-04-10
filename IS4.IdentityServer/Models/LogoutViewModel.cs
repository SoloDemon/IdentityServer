using System;
namespace IS4.IdentityServer.Models
{
    public class LogoutViewModel: LogoutInputModel
    {

        public bool ShowLogoutPrompt { get; set; } = true;
    }
}
