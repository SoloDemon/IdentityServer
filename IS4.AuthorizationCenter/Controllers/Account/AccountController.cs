// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IS4.AuthorizationCenter.Controllers.Authorizations;
using IS4.AuthorizationCenter.Models.Account;
using IS4.AuthorizationCenter.Models.Entity;
using IS4.AuthorizationCenter.Models.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IS4.AuthorizationCenter.Controllers.Account
{
    /// <summary>
    ///这个控制器为本地和外部帐户实现了一个典型的登录/注销/注册。
    ///登录服务封装了与用户数据存储的交互。
    ///交互服务为UI与identityserver进行验证和上下文检索提供了一种通信方式
    [SecurityHeaders]
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;
        private readonly AccountOptions _accountOptions;

        public AccountController(
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
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null, string roleName = "User")
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
                        Id = Guid.NewGuid(),
                        Email = model.Email,
                        UserName = model.LoginName,
                        NickName = model.NickName,
                        Sex = model.Sex,
                        Age = model.Birth.Year - DateTime.Now.Year,
                        IsDelete = false
                    };
                    result = await _userManager.CreateAsync(newUser, model.Password);
                    if (result.Succeeded)
                    {
                        result = await _userManager.AddClaimsAsync(newUser, new List<Claim>
                        {
                            new Claim(JwtClaimTypes.Name, model.NickName),
                            new Claim(JwtClaimTypes.Email, model.Email),
                            new Claim(JwtClaimTypes.EmailVerified, "false", ClaimValueTypes.Boolean),
                            new Claim(JwtClaimTypes.Role, roleName)
                        });
                        if (result.Succeeded)
                        {
                            ////确保returnUrl仍然有效，如果是，则重定向回authorize endpoint或本地页面
                            //if (_interaction.IsValidReturnUrl(returnUrl) )
                            //{
                            //    //登陆
                            //    await _signInManager.SignInAsync(user, isPersistent: false);
                            //    return Redirect(returnUrl);
                            //}

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
                throw new ApplicationException($"无法用ID加载用户 '{userId}'.");
            }
            var result = await _userManager.ConfirmEmailAsync(user, code);
            return View(result.Succeeded ? "谢谢你确认你的邮件。" : "确认邮件出错");
        }

        /// <summary>
        /// 删除用户
        /// </summary>
        /// <param name="id">用户id</param>
        /// <returns></returns>
        [HttpPost]
        [Route("account/delete/{id}")]
        [Authorize(Roles = "SuperAdmin")]
        public async Task<JsonResult> Delete(string id)
        {
            IdentityResult result = new IdentityResult();

            if (ModelState.IsValid)
            {
                //用过id查找用户
                var userItem = await _userManager.FindByIdAsync(id);

                if (userItem != null)
                {
                    userItem.IsDelete = true;

                    //更新用户
                    result = await _userManager.UpdateAsync(userItem);

                    if (result.Succeeded)
                    {
                        return Json(result);
                    }

                }
                else
                {
                    ModelState.AddModelError(string.Empty, $"{userItem?.UserName} 不存在");
                }

                AddErrors(result);
            }

            return Json(result.Errors);

        }

        /// <summary>
        /// 编辑用户
        /// </summary>
        /// <param name="id"></param>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
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
            //通过id查找用户
            var user = await _userManager.FindByIdAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            return View(new EditViewModel(user.Id.ToString(), user.UserName, user.NickName, user.Email));
        }

        /// <summary>
        /// 编辑用户
        /// </summary>
        /// <param name="model"></param>
        /// <param name="id"></param>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
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
                //通过id查找用户
                var userItem = await _userManager.FindByIdAsync(model.Id);

                if (userItem != null)
                {
                    userItem.NickName = model.NickName;
                    userItem.UserName = model.UserName;
                    userItem.Email = model.Email;
                    userItem.RealName = model.UserName;

                    //更新用户信息
                    result = await _userManager.UpdateAsync(userItem);

                    if (result.Succeeded)
                    {
                        return RedirectToLocal(returnUrl);
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, $"{userItem?.UserName} 不存在!");
                }
                AddErrors(result);
            }

            // 如果我们走到这一步，有什么失败了，重新显示
            return View(model);
        }

        /// <summary>
        /// 忘记密码
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("account/forgot-password")]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        /// <summary>
        /// 忘记密码
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("account/forgot-password")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                //通过email查找用户
                var user = await _userManager.FindByEmailAsync(model.Email);
                //if (user == null || !(await _userManager.IsEmailConfirmedAsync(user))) //如果没有验证email,就不能通过email找回密码
                if (user == null)
                {
                    //不要透露用户不存在或未被确认
                    return RedirectToAction(nameof(ForgotPasswordConfirmation));
                }

                var code = await _userManager.GeneratePasswordResetTokenAsync(user);

                var callbackUrl = Url.Action(action: nameof(AccountController.ConfirmEmail), controller: "Account", values: new { user.Id, code }, protocol: Request.Scheme);

                var ResetPassword = $"请按此重设密码: <a href='{callbackUrl}'>重设密码</a>";

                return RedirectToAction(nameof(ForgotPasswordConfirmation), new { ResetPassword = ResetPassword });
            }

            // 如果我们走到这一步，有什么失败了，重新显示
            return View(model);
        }

        /// <summary>
        /// 确认忘记密码
        /// </summary>
        /// <param name="ResetPassword"></param>
        /// <returns></returns>
        [HttpGet]
        [Route("account/forgot-password-confirmation")]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation(string ResetPassword)
        {
            ViewBag.ResetPassword = ResetPassword;
            return View();
        }

        /// <summary>
        /// 确认忘记密码
        /// </summary>
        /// <param name="code"></param>
        /// <returns></returns>
        [HttpGet]
        [Route("account/reset-password")]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
        {
            if (code == null)
            {
                throw new ApplicationException("必须为密码重置提供一个代码。");
            }
            var model = new ResetPasswordViewModel { Code = code };
            return View(model);
        }

        /// <summary>
        /// 重置密码
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
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
            //重置密码
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }
            AddErrors(result);
            return View();
        }

        /// <summary>
        /// 确认重置密码
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("account/reset-password-confirmation")]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

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
                await HttpContext.SignOutAsync();

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

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }


        /*****************************************/
        /* helper APIs for the AccountController */
        /*****************************************/

        

      

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
                return RedirectToAction(nameof(OAuth2Controller.Authorization), "OAuth2");
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
