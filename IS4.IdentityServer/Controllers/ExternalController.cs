using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IS4.IdentityServer.Extension.Attributes;
using IS4.IdentityServer.Extension.IdentityServer;
using IS4.IdentityServer.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace IS4.IdentityServer.Controllers
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class ExternalController : Controller
    {
        private readonly TestUserStore _users;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IEventService _events;
        private readonly AccountOptions _accountOptions;

        public ExternalController(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IEventService events,
            IOptions<AccountOptions> accountOptions,
            TestUserStore users = null)
        {
            //如果TestUserStore不在DI中，那么我们将只使用全局用户集合
            //在这里你可以插入你自己的自定义身份管理库。净的身份)
            _users = users ?? new TestUserStore(TestUsers.Users);
            _accountOptions = accountOptions.Value;
            _interaction = interaction;
            _clientStore = clientStore;
            _events = events;
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
                throw new Exception("invalid return URL");
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
                throw new Exception("External authentication error");
            }

            // 查找我们的用户和外部提供商信息
            var (user, provider, providerUserId, claims) = FindUserFromExternalProvider(result);
            if (user == null)
            {
                ///这可能是您启动用户注册的自定义工作流的地方
                //在这个示例中，我们没有展示如何实现它，而是作为我们的示例实现
                //简单地自动提供新的外部用户
                user = AutoProvisionUser(provider, providerUserId, claims);
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
            await _events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, user.SubjectId, user.Username));
            await HttpContext.SignInAsync(user.SubjectId, user.Username, provider, localSignInProps, additionalLocalClaims.ToArray());

            // 删除外部身份验证期间使用的临时cookie
            await HttpContext.SignOutAsync(IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme);

            // 检索返回的URL
            var returnUrl = result.Properties.Items["returnUrl"] ?? "~/";

            // 检查外部登录是否在OIDC请求的上下文中
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context != null)
            {
                if (await _clientStore.IsPkceClientAsync(context.ClientId))
                {
                    //如果客户端是PKCE，那么我们就假定它是本地的，所以这是如何改变的
                    //响应是为了最终用户更好的用户体验。
                    return View("Redirect", new RedirectViewModel { RedirectUrl = returnUrl });
                }
            }

            return Redirect(returnUrl);
        }

        private async Task<IActionResult> ProcessWindowsLoginAsync(string returnUrl)
        {
            //查看是否已经请求windows验证并成功
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
                id.AddClaim(new Claim(JwtClaimTypes.Subject, wp.Identity.Name));
                id.AddClaim(new Claim(JwtClaimTypes.Name, wp.Identity.Name));

                //将组作为索赔添加——如果组的数量太大，请小心
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

        private (TestUser user, string provider, string providerUserId, IEnumerable<Claim> claims) FindUserFromExternalProvider(AuthenticateResult result)
        {
            var externalUser = result.Principal;

            //尝试确定外部用户的唯一id(由提供程序发出)
            //最常见的索赔类型是子索赔和NameIdentifier
            //根据外部提供者的不同，可能会使用其他一些索赔类型
            var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                              externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                              throw new Exception("Unknown userid");

            //删除用户id声明，这样我们在提供用户时就不会将其包含为额外声明
            var claims = externalUser.Claims.ToList();
            claims.Remove(userIdClaim);

            var provider = result.Properties.Items["scheme"];
            var providerUserId = userIdClaim.Value;

            //寻找外部用户
            var user = _users.FindByExternalProvider(provider, providerUserId);

            return (user, provider, providerUserId, claims);
        }

        private TestUser AutoProvisionUser(string provider, string providerUserId, IEnumerable<Claim> claims)
        {
            var user = _users.AutoProvisionUser(provider, providerUserId, claims.ToList());
            return user;
        }

        private void ProcessLoginCallbackForOidc(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
            //如果外部系统发送了一个会话id声明，请将其复制过来
            //这样我们就可以用它来单次签收了
            var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
            if (sid != null)
            {
                localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
            }

            //如果外部提供者发出了id_token，我们将保留它以供注销
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