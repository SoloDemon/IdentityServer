using IdentityServer4.Models;
using IdentityServer4.Services;
using IS4.AuthorizationCenter.Models.Entity;
using Microsoft.AspNetCore.Identity;
using System.Linq;
using System.Threading.Tasks;

namespace IS4.AuthorizationCenter.Extensions.IdentityServer
{
    public class CustomProfileService : IProfileService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        public CustomProfileService(UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        /// <summary>
        /// 重新组装claims
        /// </summary>
        /// <param name="context">剖面数据请求上下文</param>
        /// <returns></returns>
        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            //判断是否有请求Claim信息
            if (context.RequestedClaimTypes.Any())
            {
                var claims = context.Subject.Claims.ToList();
                context.AddRequestedClaims(claims.ToArray());
                await Task.CompletedTask;
                ////根据用户唯一标识查找用户信息 
                //var user = await _userManager.FindByIdAsync(context.Subject.Claims.First(x => x.Type == JwtClaimTypes.Subject).Value);
                //if (user != null)
                //{
                //    //调用此方法以后内部会进行过滤，只将用户请求的Claim加入到 context.IssuedClaims 集合中 这样我们的请求方便能正常获取到所需Claim
                //    var roles = await _userManager.GetRolesAsync(user);
                //    foreach (var item in roles)
                //    {
                //        var claim = await _roleManager.GetClaimsAsync(await _roleManager.FindByNameAsync(item));
                //        context.AddRequestedClaims(claim);
                //    }
                //}
            }
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            context.IsActive = true;
            return Task.CompletedTask;
        }
    }
}
