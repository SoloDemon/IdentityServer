using System;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Validation;
using IS4.AuthorizationCenter.Extensions.Security;
using IS4.AuthorizationCenter.Models.Entity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace IS4.AuthorizationCenter.Extensions.GrantValidator
{
    public class WeChatGrantValidator : IExtensionGrantValidator
    {
        private readonly AesSecurity _aesSecurity;
        private readonly UserManager<ApplicationUser> _userManager;

        public WeChatGrantValidator(AesSecurity aesSecurity, UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
            _aesSecurity = aesSecurity;
        }

        public async Task ValidateAsync(ExtensionGrantValidationContext context)
        {
            try
            {
                var openId = _aesSecurity.AesDecrypt(context.Request.Raw["openid"]);
                var user = await _userManager.Users.Where(x => x.WeChatOpenId == _aesSecurity.AesDecrypt(openId)).FirstOrDefaultAsync();
                if (user != null)
                {
                    //授权通过返回
                    context.Result = new GrantValidationResult
                    (
                        subject: user.Id.ToString(),
                        authenticationMethod: "WeChat"
                    );
                }
                else
                {
                    context.Result = new GrantValidationResult()
                    {
                        IsError = true,
                        Error = "用户不存在"
                    };
                }
            }
            catch (Exception e)
            {
                context.Result = new GrantValidationResult()
                {
                    IsError = true,
                    Error = e.Message
                };
            }
            
        }

        public string GrantType => GrantTypeCustom.ResourceWeChat;
    }
}