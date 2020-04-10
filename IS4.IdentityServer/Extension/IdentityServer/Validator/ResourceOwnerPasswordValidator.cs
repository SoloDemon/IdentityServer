using IdentityServer4.Validation;
using IS4.IdentityServer.Models;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IS4.IdentityServer.Extension.Validator
{
    /// <summary>
    /// 资源所有者密码验证器
    /// </summary>
    public class ResourceOwnerPasswordValidator : IResourceOwnerPasswordValidator
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        public ResourceOwnerPasswordValidator(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }
        public async Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
        {
            try
            {
                var userName = context.UserName;
                var password = context.Password;

                //验证用户,这么可以到数据库里面验证用户名和密码是否正确
                var claimList = await ValidateUserAsync(userName, password);

                // 验证账号
                context.Result = new GrantValidationResult
                (
                    subject: userName,
                    authenticationMethod: "custom",
                    claims: claimList.ToArray()
                 );
            }
            catch (Exception ex)
            {
                //验证异常结果
                context.Result = new GrantValidationResult()
                {
                    IsError = true,
                    Error = ex.Message
                };
            }
        }

        /// <summary>
        /// 验证用户
        /// </summary>
        /// <param name="loginName"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        private async Task<List<Claim>> ValidateUserAsync(string loginName, string password)
        {
            //TODO:不知道对不对
            var user = _signInManager.PasswordSignInAsync(loginName, password, false, true);

            if (user == null)
            {
                await Task.CompletedTask;
                throw new Exception("登录失败，用户名和密码不正确");
            }

            return new List<Claim>()
            {
                new Claim(ClaimTypes.Name, $"{loginName}"),
            };
        }
    }
}
