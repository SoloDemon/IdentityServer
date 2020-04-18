using Microsoft.AspNetCore.Identity;
using System;

namespace IS4.AuthorizationCenter.Models.Entity
{
    public class ApplicationUserRole : IdentityUserRole<Guid>
    {
        public virtual ApplicationUser User { get; set; }
        public virtual ApplicationRole Role { get; set; }
    }
}