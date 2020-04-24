using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IS4.AuthorizationCenter.Models.Entity;
using IS4.AuthorizationCenter.Models.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;

namespace IS4.AuthorizationCenter
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class ExternalController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly ILogger<ExternalController> _logger;
        private readonly IEventService _events;
        private readonly AccountOptions _accountOptions;

        public ExternalController(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IEventService events,
            ILogger<ExternalController> logger,
            IOptions<AccountOptions> accountOptions,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _interaction = interaction;
            _clientStore = clientStore;
            _logger = logger;
            _events = events;
            _accountOptions = accountOptions.Value;
        }

        /// <summary>
        /// 启动到外部身份验证提供者的往返
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Challenge(string provider, string returnUrl)
        {
            if (string.IsNullOrEmpty(returnUrl)) returnUrl = "~/";

            // 验证returnUrl——它是一个有效的OIDC URL，或者返回到一个本地页面
            if (Url.IsLocalUrl(returnUrl) == false && _interaction.IsValidReturnUrl(returnUrl) == false)
            {
                // 用户可能点击了一个恶意链接-应该被记录
                throw new Exception("无效的返回Url");
            }

            if (_accountOptions.WindowsAuthenticationSchemeName == provider)
            {
                //  windows身份验证需要特殊处理
                return await ProcessWindowsLoginAsync(returnUrl);
            }
            else
            {
                // 开始挑战和往返的返回URL和方案
                var props = new AuthenticationProperties
                {
                    RedirectUri = Url.Action(nameof(Callback)),
                    Items =
                    {
                        { "returnUrl", returnUrl },
                        { "scheme", provider },
                    }
                };

                return Challenge(props, provider);
            }
        }

        /// <summary>
        /// 外部认证的后处理
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Callback()
        {
            // 从临时cookie读取外部标识
            var result = await HttpContext.AuthenticateAsync(IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme);
            if (result?.Succeeded != true)
            {
                throw new Exception("外部身份验证错误");
            }
            //手动尝试http获取用户信息
            //var token = result.Properties.Items[".Token.access_token"];
            //var userInfo = await _httpHelper.PostAsync("https://openapi.baidu.com/rest/2.0/passport/users/getInfo", $"access_token={token}");
            // 查找我们的用户和外部提供商信息
            var (user, provider, providerUserId, claims) = await FindUserFromExternalProviderAsync(result);
            //没有在is4找到用户
            if (user == null)
            {
                //如果用户不存在,创建用户
                user = await AutoProvisionUserAsync(provider, providerUserId, claims);
            }

            //这使我们能够收集任何额外的权利要求书或财产
            //用于特定的prtotocols，并将它们存储在本地的auth cookie中。
            //这通常用于存储从这些协议中退出所需要的数据。
            var additionalLocalClaims = new List<Claim>();
            var localSignInProps = new AuthenticationProperties();
            ProcessLoginCallbackForOidc(result, additionalLocalClaims, localSignInProps);
            ProcessLoginCallbackForWsFed(result, additionalLocalClaims, localSignInProps);
            ProcessLoginCallbackForSaml2p(result, additionalLocalClaims, localSignInProps);

            // 为用户发布认证cookie
            await _events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, user.Id.ToString(), user.UserName));
            await HttpContext.SignInAsync(user.Id.ToString(), user.UserName, provider, localSignInProps, additionalLocalClaims.ToArray());

            // 删除外部身份验证期间使用的临时cookie
            await HttpContext.SignOutAsync(IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme);

            // 检索返回的URL
            var returnUrl = result.Properties.Items["returnUrl"] ?? "~/";

            // 检查外部登录是否在OIDC请求的上下文中
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);


            if (context != null)
            {
                if (context.IsNativeClient())
                {
                    // The client is native, so this change in how to
                    // return the response is for better UX for the end user.
                    return this.LoadingPage("Redirect", returnUrl);
                }
            }

            return Redirect(returnUrl);
        }

        /// <summary>
        /// 处理windos登录
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        private async Task<IActionResult> ProcessWindowsLoginAsync(string returnUrl)
        {
            // 查看windows验证是否已经被请求并成功
            var result = await HttpContext.AuthenticateAsync(_accountOptions.WindowsAuthenticationSchemeName);
            if (result?.Principal is WindowsPrincipal wp)
            {
                //我们将发出外部cookie，然后重定向
                //用户返回到外部回调，本质上是处理窗口
                //与其他外部认证机制相同
                var props = new AuthenticationProperties()
                {
                    RedirectUri = Url.Action("Callback"),
                    Items =
                    {
                        { "returnUrl", returnUrl },
                        { "scheme", _accountOptions.WindowsAuthenticationSchemeName },
                    }
                };

                var id = new ClaimsIdentity(_accountOptions.WindowsAuthenticationSchemeName);
                id.AddClaim(new Claim(JwtClaimTypes.Subject, wp.FindFirst(ClaimTypes.PrimarySid).Value));
                id.AddClaim(new Claim(JwtClaimTypes.Name, wp.Identity.Name));

                // 将组作为声明添加——如果组的数量太大，请小心
                if (_accountOptions.IncludeWindowsGroups)
                {
                    var wi = wp.Identity as WindowsIdentity;
                    var groups = wi.Groups.Translate(typeof(NTAccount));
                    var roles = groups.Select(x => new Claim(JwtClaimTypes.Role, x.Value));
                    id.AddClaims(roles);
                }

                await HttpContext.SignInAsync(
                    IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme,
                    new ClaimsPrincipal(id),
                    props);
                return Redirect(props.RedirectUri);
            }
            else
            {
                //触发窗口验证
                //由于windows认证不支持重定向uri，
                //当我们调用challenge时，将重新触发此URL
                return Challenge(_accountOptions.WindowsAuthenticationSchemeName);
            }
        }

        /// <summary>
        /// 从外部提供者信息查找用户
        /// </summary>
        /// <param name="result">返回url</param>
        /// <returns></returns>
        private async Task<(ApplicationUser user, string provider, string providerUserId, IEnumerable<Claim> claims)> FindUserFromExternalProviderAsync(AuthenticateResult result)
        {
            //获取外部用户信息
            var externalUser = result.Principal;

            //尝试查找外部用户唯一身份Id
            //最常见的Claim类型是Subject和NameIdentifier
            //根据外部提供者的不同，可能会使用其他一些Claim类型
            var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                              externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                              throw new Exception("未知的用户标识");

            //删除用户id声明，这样我们在提供用户时就不会将其包含为额外声明
            var claims = externalUser.Claims.ToList();
            claims.Remove(userIdClaim);

            //外部提供者Scheme
            var provider = result.Properties.Items["scheme"];
            //外部用户唯一身份Id
            var providerUserId = userIdClaim.Value;

            //寻找外部用户
            var user = await _userManager.FindByLoginAsync(provider, providerUserId);

            return (user, provider, providerUserId, claims);
        }

        /// <summary>
        /// 自动创建外部登陆用户
        /// </summary>
        /// <param name="provider">外部供应商</param>
        /// <param name="providerUserId">外部用户唯一身份Id</param>
        /// <param name="claims">声明</param>
        /// <returns></returns>
        private async Task<ApplicationUser> AutoProvisionUserAsync(string provider, string providerUserId, IEnumerable<Claim> claims)
        {
            //创建一个需要添加的Claim列表
            var claimList = new List<Claim>();
            //获取用户名
            var userName = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Name)?.Value ??
                claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;
            if (userName != null)
            {
                claimList.Add(new Claim(JwtClaimTypes.Name, userName));
            }
            else
            {
                var first = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName)?.Value ??
                    claims.FirstOrDefault(x => x.Type == ClaimTypes.GivenName)?.Value;
                var last = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName)?.Value ??
                    claims.FirstOrDefault(x => x.Type == ClaimTypes.Surname)?.Value;
                if (first != null && last != null)
                {
                    claimList.Add(new Claim(JwtClaimTypes.Name, first + " " + last));
                }
                else if (first != null)
                {
                    claimList.Add(new Claim(JwtClaimTypes.Name, first));
                }
                else if (last != null)
                {
                    claimList.Add(new Claim(JwtClaimTypes.Name, last));
                }
            }
            //email
            var email = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email)?.Value ??
                claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email)?.Value;
            if (email != null)
            {
                claimList.Add(new Claim(JwtClaimTypes.Email, email));
            }
            //创建用户
            var user = CreateUser(provider, claims);
            var identityResult = await _userManager.CreateAsync(user);
            if (!identityResult.Succeeded)
                throw new Exception(identityResult.Errors.First().Description);
            if (claimList.Any())
            {
                identityResult = await _userManager.AddClaimsAsync(user, claimList);
                if (!identityResult.Succeeded)
                    throw new Exception(identityResult.Errors.First().Description);
            }
            identityResult = await _userManager.AddLoginAsync(user, new UserLoginInfo(provider, providerUserId, provider));
            if (!identityResult.Succeeded)
                throw new Exception(identityResult.Errors.First().Description);
            return user;
        }

        /// <summary>
        /// 创建用户
        /// </summary>
        /// <param name="provider">第三方供应商</param>
        /// <param name="claims">声明列表</param>
        /// <returns></returns>
        private ApplicationUser CreateUser(string provider, IEnumerable<Claim> claims)
        {
            string portrait = "";
            switch (provider)
            {
                case "Baidu":
                    //头像
                    portrait = claims.FirstOrDefault(x => x.Type == "urn:baidu:portrait")?.Value ?? "";
                    break;
                case "QQ":
                    portrait = claims.FirstOrDefault(x => x.Type == "urn:qq:avatar_full")?.Value ?? "";
                    break;
            }
            return new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = Guid.NewGuid().ToString(),
                Portrait = portrait
            };
        }

        /// <summary>
        /// oidc处理登录回调
        /// </summary>
        /// <param name="externalResult"></param>
        /// <param name="localClaims"></param>
        /// <param name="localSignInProps"></param>
        private void ProcessLoginCallbackForOidc(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
            //如果外部系统发送了一个会话id声明，请将其复制过来
            //这样我们就可以用它来单次签收了
            var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
            if (sid != null)
            {
                localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
            }

            // 如果外部提供者发出了id_token，我们将保留它以供注销
            var id_token = externalResult.Properties.GetTokenValue("id_token");
            if (id_token != null)
            {
                localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = id_token } });
            }
        }

        private void ProcessLoginCallbackForWsFed(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
        }

        private void ProcessLoginCallbackForSaml2p(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
        }
    }
}
