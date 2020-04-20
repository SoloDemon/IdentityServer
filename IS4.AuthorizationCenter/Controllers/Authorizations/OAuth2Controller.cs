using IdentityServer4;
using IdentityServer4.Events;
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
using System.Threading.Tasks;

namespace IS4.AuthorizationCenter.Controllers.Authorizations
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
        public async Task<IActionResult> Login(LoginInputModel model, string button)
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
                    await _interaction.GrantConsentAsync(context, ConsentResponse.Denied);

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
            if (context?.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.ClientId);
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
    }
}