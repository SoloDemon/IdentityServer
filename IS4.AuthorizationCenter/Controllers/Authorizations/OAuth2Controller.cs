using IdentityModel;
using IdentityServer4;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IS4.AuthorizationCenter.Models.Entity;
using IS4.AuthorizationCenter.Models.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IS4.AuthorizationCenter
{
    public class OAuth2Controller : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;
        private readonly AccountOptions _accountOptions;

        public OAuth2Controller(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            IOptions<AccountOptions> accountOptions,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<ApplicationRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
            _accountOptions = accountOptions.Value;
            _roleManager = roleManager;
        }

        #region 登陆

        /// <summary>
        /// 显示登陆页面
        /// </summary>
        /// <param name="returnUrl">返回的url</param>
        /// <returns></returns>
        [HttpGet]
        public async Task<IActionResult> Authorization(string returnUrl)
        {
            // 创建登陆页面使用的数据模型
            LoginViewModel vm = await BuildLoginViewModelAsync(returnUrl);
            var a = new Secret("Secret.js".Sha256());
            var b = new Secret("Secret".Sha256());
            var c = new Secret("Sucm.Api.Secret".Sha256());
            var d = new Secret("Sucm".Sha256());
            //如果是外部登陆
            if (vm.IsExternalLoginOnly)
            {
                // 跳转到外部登陆页面
                return RedirectToAction("Challenge", "External", new { provider = vm.ExternalLoginScheme, returnUrl });
            }
            return View(vm);
        }

        /// <summary>
        /// 处理用户名/密码登录的回发
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Authorization(LoginInputModel model, string button)
        {
            if (button != "login")
            {
                // 用户点击取消按钮
                var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);
                if (context != null)
                {
                    //如果用户取消，将结果发送回IdentityServer
                    //拒绝同意(即使这个客户不需要同意)。
                    //这将向客户端发送一个拒绝访问的OIDC错误响应。
                    //await _interaction.GrantConsentAsync(context, ConsentResponse.Denied);
                    await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                    //我们可以信任模型。ReturnUrl因为GetAuthorizationContextAsync返回非空
                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // 因为我们没有有效的上下文，所以我们只能返回到主页
                    return Redirect("~/");
                }
            }

            if (ModelState.IsValid)
            {
                //通过用户名查找用户
                var user = await _userManager.FindByNameAsync(model.Username);

                if (!user.IsDelete)
                {
                    //通过密码登录
                    var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberLogin, lockoutOnFailure: true);
                    if (result.Succeeded)
                    {
                        //创建登录成功事件
                        await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id.ToString(), user.UserName));

                        //确保returnUrl仍然有效，如果是，则重定向回authorize endpoint或本地页面
                        // IsLocalUrl检查是必要的，如果你想支持额外的本地页面，否则IsValidReturnUrl是更严格的
                        if (_interaction.IsValidReturnUrl(model.ReturnUrl) || Url.IsLocalUrl(model.ReturnUrl))
                        {
                            return Redirect(model.ReturnUrl);
                        }

                        return Redirect("~/");
                    }
                }

                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, _accountOptions.InvalidUserErrorMessage));

                ModelState.AddModelError("", _accountOptions.InvalidCredentialsErrorMessage);
            }

            // 出了差错，用错误来表示
            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }

        /// <summary>
        /// 建立登录展示模型
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServerConstants.LocalIdentityProvider;

                // 这意味着要使UI短路，只触发一个外部IdP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null ||
                            x.Name.Equals(_accountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase)
                )
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName ?? x.Name,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.Client?.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = _accountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && _accountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        /// <summary>
        /// 建立登录展示模型
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        #endregion

        #region 退出登陆

        /// <summary>
        /// 显示注销页
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // 构建一个模型，以便注销页面知道要显示什么
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                //如果从IdentityServer正确地验证了注销请求，则
                //我们不需要显示提示，直接将用户登出即可。
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// 处理注销页面回发
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            //建立一个模型，以便登出页面知道要显示什么
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // 删除本地认证cookie
                await _signInManager.SignOutAsync();

                // 引发注销事件
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // 检查我们是否需要在上游身份提供商处触发退出
            if (vm.TriggerExternalSignout)
            {
                //建立一个返回URL，这样上游提供商将重定向回来
                //在用户登出后发给我们。这让我们可以
                //完成我们的单次签出处理。
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // 这将触发重定向到外部提供程序进行注销
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }

        /// <summary>
        /// 建立登出展示模型
        /// </summary>
        /// <param name="logoutId"></param>
        /// <returns></returns>
        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = _accountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                //如果用户没有通过身份验证，那么只显示登出页面
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                //自动退出是安全的
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            //显示注销提示。这可以防止用户受到攻击
            //被另一个恶意网页自动注销。
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // 获取上下文信息(客户端名称、退出后重定向URI和联邦签名的iframe)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = _accountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            //如果当前没有注销上下文，我们需要创建一个
                            //从当前登录用户获取必要的信息
                            //在我们注销并重定向到外部IdP进行注销之前
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }

        #endregion
    }
}