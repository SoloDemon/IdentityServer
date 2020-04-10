using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IS4.IdentityServer.Extension.Attributes;
using IS4.IdentityServer.Extension.IdentityServer;
using IS4.IdentityServer.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

// 有关为空项目启用MVC的更多信息，请访问 https://go.microsoft.com/fwlink/?LinkID=397860

namespace IS4.IdentityServer.Controllers
{
    [SecurityHeaders]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IClientStore _clientStore;
        private readonly IEventService _events;
        private readonly AccountOptions _accountOptions;
        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IIdentityServerInteractionService interaction,
            IAuthenticationSchemeProvider schemeProvider,
            IClientStore clientStore,
            IEventService events,
            RoleManager<ApplicationRole> roleManager,
            IOptions<AccountOptions> accountOptions)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _interaction = interaction;
            _schemeProvider = schemeProvider;
            _clientStore = clientStore;
            _events = events;
            _roleManager = roleManager;
            _accountOptions = accountOptions.Value;
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        /// <summary>
        /// 显示登陆页面
        /// </summary>
        /// <param name="returnUrl">返回的url</param>
        /// <returns></returns>
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
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
        /// 登录Post请求
        /// </summary>
        /// <param name="model">登录用户数据</param>
        /// <param name="button">按钮</param>
        /// <returns></returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            if (button != "login")
            {
                AuthorizationRequest context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);
                if (context != null)
                {
                    await _interaction.GrantConsentAsync(context, ConsentResponse.Denied);
                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    return Redirect("~/");
                }
            }

            if (ModelState.IsValid)
            {
                ApplicationUser user = await _userManager.FindByNameAsync(model.Username);
                if (user != null)
                {
                    if (user?.IsDelete == false)
                    {
                        var result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberLogin, true);
                        if (result.Succeeded)
                        {
                            await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id.ToString(),
                                user.UserName));
                            if (_interaction.IsValidReturnUrl(model.ReturnUrl) || Url.IsLocalUrl(model.ReturnUrl))
                            {
                                return Redirect(model.ReturnUrl);
                            }

                            return Redirect("~/");
                        }
                    }

                    await _events.RaiseAsync(new UserLoginFailureEvent(user.UserName, _accountOptions.InvalidUserErrorMessage));
                    ModelState.AddModelError("", _accountOptions.InvalidCredentialsErrorMessage);
                }
                else
                {
                    ModelState.AddModelError("", _accountOptions.InvalidUserErrorMessage);
                }
            }
            else
            {
                return Redirect(model.ReturnUrl);
            }
            LoginViewModel vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }

        /// <summary>
        /// 注册页面
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public IActionResult Register(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        /// <summary>
        /// HttpPost注册
        /// </summary>
        /// <param name="model">注册数据模型</param>
        /// <param name="returnUrl">返回url</param>
        /// <param name="roleName">角色名</param>
        /// <returns></returns>
        [HttpPost]
        [Route("account/register")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null, string roleName = "AdminTest")
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {
                ApplicationUser user = await _userManager.FindByNameAsync(model.LoginName);
                IdentityResult result = new IdentityResult();
                if (null == user)
                {
                    ApplicationUser newUser = new ApplicationUser
                    {
                        Email = model.Email,
                        UserName = model.LoginName,
                        NickName = model.RealName,
                        Sex = model.Sex,
                        Age = model.Birth.Year - DateTime.Now.Year,
                        IsDelete = false,
                        City = "南京",
                        Country = "中国",
                        Province = "江苏省"
                    };
                    result = await _userManager.CreateAsync(newUser, model.Password);
                    if (result.Succeeded)
                    {
                        result = await _userManager.AddClaimsAsync(newUser, new List<Claim>
                        {
                            new Claim(JwtClaimTypes.Name, model.RealName),
                            new Claim(JwtClaimTypes.Email, model.Email),
                            new Claim(JwtClaimTypes.EmailVerified, "false", ClaimValueTypes.Boolean),
                            new Claim(JwtClaimTypes.Role, roleName)
                        });
                        if (result.Succeeded)
                        {
                            //登陆
                            //await _signInManager.SignInAsync(user, isPersistent: false);

                            return RedirectToLocal(returnUrl);
                        }
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, $"用户:{user?.UserName}  已存在!");
                }
                AddErrors(result);
            }

            return View(model);
        }

        /// <summary>
        /// 用户信息
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [HttpGet]
        [Route("account/users")]
        [Authorize]
        public IActionResult Users(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            List<ApplicationUser> users = _userManager.Users.Where(d => !d.IsDelete).OrderBy(d => d.UserName).ToList();

            return View(users);
        }

        /// <summary>
        /// 退出登录页面
        /// </summary>
        /// <param name="logoutId"></param>
        /// <returns></returns>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // 构建一个模型，以便注销页面知道要显示什么
            LogoutViewModel vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                //如果从IdentityServer正确地验证了注销请求，则我们不需要显示提示，直接将用户登出即可。
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// HttpPost退出登录
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // 构建一个模型，以便注销页面知道要显示什么
            LoggedOutViewModel vm =
                await BuildLoggedOutViewModelAsync(model.LogoutId);
            Microsoft.AspNetCore.Http.HttpContext aaa = HttpContext;

            if (User?.Identity.IsAuthenticated == true)
            {
                //删除本地授权cookie
                await _signInManager.SignOutAsync();

                //引发注销事件
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // 检查我们是否需要在第三方身份提供商处触发退出
            if (vm.TriggerExternalSignout)
            {
                //建立一个返回URL，这样第三方提供商将重定向回来
                //在用户登出后发给我们。这让我们可以完成我们的单次签出处理。
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // 这将触发重定向到外部提供者以进行注销
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }

        [HttpGet("{id}")]
        [Route("account/edit/{id}")]
        [Authorize(Roles = "SuperAdmin")]
        public async Task<IActionResult> Edit(string id, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (id == null)
            {
                return NotFound();
            }

            var user = await _userManager.FindByIdAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            return View(new EditViewModel(user.Id.ToString(), user.NickName, user.UserName, user.Email));
        }


        [HttpPost]
        [Route("account/edit/{id}")]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "SuperAdmin")]
        public async Task<IActionResult> Edit(EditViewModel model, string id, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            IdentityResult result = new IdentityResult();

            if (ModelState.IsValid)
            {
                var userItem = _userManager.FindByIdAsync(model.Id).Result;

                if (userItem != null)
                {
                    userItem.UserName = model.LoginName;
                    userItem.NickName = model.UserName;
                    userItem.Email = model.Email;
                    userItem.RealName = model.UserName;


                    result = await _userManager.UpdateAsync(userItem);

                    if (result.Succeeded)
                    {
                        return RedirectToLocal(returnUrl);
                    }

                }
                else
                {
                    ModelState.AddModelError(string.Empty, $"{userItem?.UserName} no exist!");
                }

                AddErrors(result);
            }

            // 如果我们走到这一步，有什么失败了，重新显示
            return View(model);
        }



        [HttpPost]
        [Route("account/delete/{id}")]
        [Authorize(Roles = "SuperAdmin")]
        public async Task<JsonResult> Delete(string id)
        {
            IdentityResult result = new IdentityResult();

            if (ModelState.IsValid)
            {
                var userItem = _userManager.FindByIdAsync(id).Result;

                if (userItem != null)
                {
                    userItem.IsDelete = true;


                    result = await _userManager.UpdateAsync(userItem);

                    if (result.Succeeded)
                    {
                        return Json(result);
                    }

                }
                else
                {
                    ModelState.AddModelError(string.Empty, $"{userItem?.UserName} no exist!");
                }

                AddErrors(result);
            }

            return Json(result.Errors);

        }

        [HttpGet]
        [Route("account/confirm-email")]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{userId}'.");
            }
            var result = await _userManager.ConfirmEmailAsync(user, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        [HttpGet]
        [Route("account/forgot-password")]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [Route("account/forgot-password")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                //if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                if (user == null)
                {
                    // 不要透露用户不存在或未被确认
                    return RedirectToAction(nameof(ForgotPasswordConfirmation));
                }

                // 有关如何启用帐户确认和密码重置的详细信息，请参阅
                // visit https://go.microsoft.com/fwlink/?LinkID=532713
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);

                var callbackUrl = Url.ResetPasswordCallbackLink(user.Id.ToString(), code, Request.Scheme);


                var ResetPassword = $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>";

                return RedirectToAction(nameof(ForgotPasswordConfirmation), new { ResetPassword = ResetPassword });
            }

            // 如果我们走到这一步，有什么失败了，重新显示
            return View(model);
        }

        [HttpGet]
        [Route("account/forgot-password-confirmation")]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation(string ResetPassword)
        {
            ViewBag.ResetPassword = ResetPassword;
            return View();
        }

        [HttpGet]
        [Route("account/reset-password")]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
        {
            if (code == null)
            {
                throw new ApplicationException("A code must be supplied for password reset.");
            }
            var model = new ResetPasswordViewModel { Code = code };
            return View(model);
        }

        [HttpPost]
        [Route("account/reset-password")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // 不要透露用户不存在
                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }
            AddErrors(result);
            return View();
        }

        [HttpGet]
        [Route("account/reset-password-confirmation")]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        /// <summary>
        /// 生成登陆展示模型
        /// </summary>
        /// <param name="returnUrl">返回url</param>
        /// <returns></returns>
        public async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

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
                            (x.Name.Equals(_accountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase))
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
        /// 生成登陆展示模型
        /// </summary>
        /// <param name="model">登陆输入模型</param>
        /// <returns></returns>
        public async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        /// <summary>
        /// 生成退出登录展示模型
        /// </summary>
        /// <param name="logoutId">退出的用户id</param>
        /// <returns></returns>
        public async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            //获取上下文信息(客户端名称、退出后重定向URI和联邦签名的iframe)
            LogoutRequest logout = await _interaction.GetLogoutContextAsync(logoutId);

            LoggedOutViewModel vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = _accountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                string idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    if (await HttpContext.GetSchemeSupportsSignOutAsync(idp))
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

        /// <summary>
        /// 生成退出登录展示模型
        /// </summary>
        /// <param name="logoutId">退出的用户id</param>
        /// <param name="user">主要的声明</param>
        /// <returns></returns>
        public async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            LogoutViewModel vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = _accountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                //如果用户没有通过身份验证，那么只显示登出页面
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            LogoutRequest context = await _interaction.GetLogoutContextAsync(logoutId);
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

        /// <summary>
        /// 跳转到
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(AccountController.Login), "Account");
            }
        }

        /// <summary>
        /// 添加错误信息
        /// </summary>
        /// <param name="result"></param>
        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
    }
}
