using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IS4.AuthorizationCenter.Models.Entity;
using Microsoft.AspNetCore.Identity;

namespace IS4.AuthorizationCenter.Extension.Identity
{
    /// <summary>
    /// 自定义密码验证器
    /// </summary>
    public class CustomPasswordValidator : PasswordValidator<ApplicationUser>
    {
        public override async Task<IdentityResult> ValidateAsync(UserManager<ApplicationUser> manager, ApplicationUser user, string password)
        {

            IdentityResult result = await base.ValidateAsync(manager, user, password);
            List<IdentityError> errors = result.Succeeded ? new List<IdentityError>() : result.Errors.ToList();
            if (password.Contains("~"))
            {
                errors.Add(new IdentityError
                {
                    Code = "密码验证出现问题",
                    Description = "密码不能包含 ~"
                });
            }

            return errors.Count == 0 ? IdentityResult.Success
                : IdentityResult.Failed(errors.ToArray());
        }
    }
}