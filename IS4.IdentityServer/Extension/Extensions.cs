using System.Linq;
using IS4.IdentityServer.Models;
using Microsoft.AspNetCore.Identity;

namespace IS4.IdentityServer
{
    public static class Extensions
    {
        public static ApplicationUser FindByExternalProviderAsync(this UserManager<ApplicationUser> userManager, string provider, string userId)
        {
            return userManager.Users.FirstOrDefault(x => x.ProviderName == provider && x.ProviderSubjectId == userId);
        }
    }
}
