// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Test;
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
    ///���������Ϊ���غ��ⲿ�ʻ�ʵ����һ�����͵ĵ�¼/ע��/ע��/��ɫ/�û�����
    ///��¼�����װ�����û����ݴ洢�Ľ�����
    ///��������ΪUI��identityserver������֤�������ļ����ṩ��һ��ͨ�ŷ�ʽ
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
        /// ��ʾ��½ҳ��
        /// </summary>
        /// <param name="returnUrl">���ص�url</param>
        /// <returns></returns>
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            // ������½ҳ��ʹ�õ�����ģ��
            LoginViewModel vm = await BuildLoginViewModelAsync(returnUrl);

            //������ⲿ��½
            if (vm.IsExternalLoginOnly)
            {
                // ��ת���ⲿ��½ҳ��
                return RedirectToAction("Challenge", "External", new { provider = vm.ExternalLoginScheme, returnUrl });
            }

            return View(vm);
        }

        /// <summary>
        /// �����û���/�����¼�Ļط�
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            if (button != "login")
            {
                // �û����ȡ����ť
                var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);
                if (context != null)
                {
                    //����û�ȡ������������ͻ�IdentityServer
                    //�ܾ�ͬ��(��ʹ����ͻ�����Ҫͬ��)��
                    //�⽫��ͻ��˷���һ���ܾ����ʵ�OIDC������Ӧ��
                    await _interaction.GrantConsentAsync(context, ConsentResponse.Denied);

                    //���ǿ�������ģ�͡�ReturnUrl��ΪGetAuthorizationContextAsync���طǿ�
                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // ��Ϊ����û����Ч�������ģ���������ֻ�ܷ��ص���ҳ
                    return Redirect("~/");
                }
            }

            if (ModelState.IsValid)
            {
                //ͨ���û��������û�
                var user = await _userManager.FindByNameAsync(model.Username);


                if (!user.IsDelete)
                {
                    //ͨ�������¼
                    var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberLogin, lockoutOnFailure: true);
                    if (result.Succeeded)
                    {
                        //������¼�ɹ��¼�
                        await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id.ToString(), user.UserName));

                        //ȷ��returnUrl��Ȼ��Ч������ǣ����ض����authorize endpoint�򱾵�ҳ��
                        // IsLocalUrl����Ǳ�Ҫ�ģ��������֧�ֶ���ı���ҳ�棬����IsValidReturnUrl�Ǹ��ϸ��
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

            // ���˲���ô�������ʾ
            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }

        /// <summary>
        /// ע��ҳ��
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public IActionResult Register(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        /// <summary>
        /// HttpPostע��
        /// </summary>
        /// <param name="model">ע������ģ��</param>
        /// <param name="returnUrl">����url</param>
        /// <param name="roleName">��ɫ��</param>
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
                            ////ȷ��returnUrl��Ȼ��Ч������ǣ����ض����authorize endpoint�򱾵�ҳ��
                            //if (_interaction.IsValidReturnUrl(returnUrl) )
                            //{
                            //    //��½
                            //    await _signInManager.SignInAsync(user, isPersistent: false);
                            //    return Redirect(returnUrl);
                            //}

                            return RedirectToLocal(returnUrl);
                        }
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, $"�û�:{user?.UserName}  �Ѵ���!");
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
                throw new ApplicationException($"�޷���ID�����û� '{userId}'.");
            }
            var result = await _userManager.ConfirmEmailAsync(user, code);
            return View(result.Succeeded ? "лл��ȷ������ʼ���" : "ȷ���ʼ�����");
        }

        /// <summary>
        /// ɾ���û�
        /// </summary>
        /// <param name="id">�û�id</param>
        /// <returns></returns>
        [HttpPost]
        [Route("account/delete/{id}")]
        [Authorize(Roles = "SuperAdmin")]
        public async Task<JsonResult> Delete(string id)
        {
            IdentityResult result = new IdentityResult();

            if (ModelState.IsValid)
            {
                //�ù�id�����û�
                var userItem = await _userManager.FindByIdAsync(id);

                if (userItem != null)
                {
                    userItem.IsDelete = true;

                    //�����û�
                    result = await _userManager.UpdateAsync(userItem);

                    if (result.Succeeded)
                    {
                        return Json(result);
                    }

                }
                else
                {
                    ModelState.AddModelError(string.Empty, $"{userItem?.UserName} ������");
                }

                AddErrors(result);
            }

            return Json(result.Errors);

        }

        /// <summary>
        /// �༭�û�
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
            //ͨ��id�����û�
            var user = await _userManager.FindByIdAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            return View(new EditViewModel(user.Id.ToString(), user.UserName, user.NickName, user.Email));
        }

        /// <summary>
        /// �༭�û�
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
                //ͨ��id�����û�
                var userItem = await _userManager.FindByIdAsync(model.Id);

                if (userItem != null)
                {
                    userItem.NickName = model.NickName;
                    userItem.UserName = model.UserName;
                    userItem.Email = model.Email;
                    userItem.RealName = model.UserName;

                    //�����û���Ϣ
                    result = await _userManager.UpdateAsync(userItem);

                    if (result.Succeeded)
                    {
                        return RedirectToLocal(returnUrl);
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, $"{userItem?.UserName} ������!");
                }
                AddErrors(result);
            }

            // ��������ߵ���һ������ʲôʧ���ˣ�������ʾ
            return View(model);
        }

        /// <summary>
        /// ��������
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
        /// ��������
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
                //ͨ��email�����û�
                var user = await _userManager.FindByEmailAsync(model.Email);
                //if (user == null || !(await _userManager.IsEmailConfirmedAsync(user))) //���û����֤email,�Ͳ���ͨ��email�һ�����
                if (user == null)
                {
                    //��Ҫ͸¶�û������ڻ�δ��ȷ��
                    return RedirectToAction(nameof(ForgotPasswordConfirmation));
                }

                var code = await _userManager.GeneratePasswordResetTokenAsync(user);

                var callbackUrl = Url.Action(action: nameof(AccountController.ConfirmEmail), controller: "Account", values: new { user.Id, code }, protocol: Request.Scheme);

                var ResetPassword = $"�밴����������: <a href='{callbackUrl}'>��������</a>";

                return RedirectToAction(nameof(ForgotPasswordConfirmation), new { ResetPassword = ResetPassword });
            }

            // ��������ߵ���һ������ʲôʧ���ˣ�������ʾ
            return View(model);
        }

        /// <summary>
        /// ȷ����������
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
        /// ȷ����������
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
                throw new ApplicationException("����Ϊ���������ṩһ�����롣");
            }
            var model = new ResetPasswordViewModel { Code = code };
            return View(model);
        }

        /// <summary>
        /// ��������
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
                // ��Ҫ͸¶�û�������
                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }
            //��������
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }
            AddErrors(result);
            return View();
        }

        /// <summary>
        /// ȷ����������
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("account/reset-password-confirmation")]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        #region ��ɫ����

        /// <summary>
        /// ��ӽ�ɫ
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [HttpGet]
        [Route("account/Roleregister")]
        public IActionResult RoleRegister(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        /// <summary>
        /// ��ӽ�ɫ
        /// </summary>
        /// <param name="model"></param>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("account/Roleregister")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RoleRegister(RoleRegisterViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            IdentityResult result = new IdentityResult();

            if (ModelState.IsValid)
            {
                //ͨ����ɫ�����ҽ�ɫ
                var roleItem = await _roleManager.FindByNameAsync(model.RoleName);

                if (roleItem == null)
                {

                    var role = new ApplicationRole
                    {
                        Name = model.RoleName
                    };


                    result = await _roleManager.CreateAsync(role);

                    if (result.Succeeded)
                    {

                        if (result.Succeeded)
                        {
                            return RedirectToLocal(returnUrl);
                        }
                    }

                }
                else
                {
                    ModelState.AddModelError(string.Empty, $"{roleItem?.Name} �Ѿ�����");

                }

                AddErrors(result);
            }

            // ��������ߵ���һ������ʲôʧ���ˣ�������ʾ
            return View(model);
        }

        /// <summary>
        /// ��ɫ�б�
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [HttpGet]
        [Route("account/Roles")]
        [Authorize]
        public IActionResult Roles(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            var roles = _roleManager.Roles.Where(d => !d.IsDeleted).ToList();

            return View(roles);
        }

        /// <summary>
        /// �༭��ɫ
        /// </summary>
        /// <param name="id"></param>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [HttpGet("{id}")]
        [Route("account/Roleedit/{id}")]
        [Authorize(Roles = "SuperAdmin")]
        public async Task<IActionResult> RoleEdit(string id, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (id == null)
            {
                return NotFound();
            }

            var user = await _roleManager.FindByIdAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            return View(new RoleEditViewModel(user.Id.ToString(), user.Name));
        }

        /// <summary>
        /// �༭��ɫ
        /// </summary>
        /// <param name="model"></param>
        /// <param name="id"></param>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("account/Roleedit/{id}")]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "SuperAdmin")]
        public async Task<IActionResult> RoleEdit(RoleEditViewModel model, string id, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            IdentityResult result = new IdentityResult();

            if (ModelState.IsValid)
            {
                //ͨ����ɫid��ѯ��ɫ
                var roleItem =await _roleManager.FindByIdAsync(model.Id);

                if (roleItem != null)
                {
                    roleItem.Name = model.RoleName;

                    result = await _roleManager.UpdateAsync(roleItem);

                    if (result.Succeeded)
                    {
                        return RedirectToLocal(returnUrl);
                    }

                }
                else
                {
                    ModelState.AddModelError(string.Empty, $"{roleItem?.Name} no exist!");
                }

                AddErrors(result);
            }

            // ��������ߵ���һ������ʲôʧ���ˣ�������ʾ
            return View(model);
        }


        /// <summary>
        /// ɾ����ɫ
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("account/Roledelete/{id}")]
        [Authorize(Roles = "SuperAdmin")]
        public async Task<JsonResult> RoleDelete(string id)
        {
            IdentityResult result = new IdentityResult();

            if (ModelState.IsValid)
            {
                var roleItem = _roleManager.FindByIdAsync(id).Result;

                if (roleItem != null)
                {
                    roleItem.IsDeleted = true;


                    result = await _roleManager.UpdateAsync(roleItem);

                    if (result.Succeeded)
                    {
                        return Json(result);
                    }

                }
                else
                {
                    ModelState.AddModelError(string.Empty, $"{roleItem?.Name} ������");
                }

                AddErrors(result);
            }

            return Json(result.Errors);

        }

        #endregion


        /// <summary>
        /// ��ʾע��ҳ
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // ����һ��ģ�ͣ��Ա�ע��ҳ��֪��Ҫ��ʾʲô
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                //�����IdentityServer��ȷ����֤��ע��������
                //���ǲ���Ҫ��ʾ��ʾ��ֱ�ӽ��û��ǳ����ɡ�
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// ����ע��ҳ��ط�
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            //����һ��ģ�ͣ��Ա�ǳ�ҳ��֪��Ҫ��ʾʲô
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // ɾ��������֤cookie
                await HttpContext.SignOutAsync();

                // ����ע���¼�
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // ��������Ƿ���Ҫ����������ṩ�̴������˳�
            if (vm.TriggerExternalSignout)
            {
                //����һ������URL�����������ṩ�̽��ض������
                //���û��ǳ��󷢸����ǡ��������ǿ���
                //������ǵĵ���ǩ������
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // �⽫�����ض����ⲿ�ṩ�������ע��
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
        /// ������¼չʾģ��
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServerConstants.LocalIdentityProvider;

                // ����ζ��ҪʹUI��·��ֻ����һ���ⲿIdP
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

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        /// <summary>
        /// �����ǳ�չʾģ��
        /// </summary>
        /// <param name="logoutId"></param>
        /// <returns></returns>
        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = _accountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                //����û�û��ͨ�������֤����ôֻ��ʾ�ǳ�ҳ��
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                //�Զ��˳��ǰ�ȫ��
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            //��ʾע����ʾ������Է�ֹ�û��ܵ�����
            //����һ��������ҳ�Զ�ע����
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // ��ȡ��������Ϣ(�ͻ������ơ��˳����ض���URI������ǩ����iframe)
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
                            //�����ǰû��ע�������ģ�������Ҫ����һ��
                            //�ӵ�ǰ��¼�û���ȡ��Ҫ����Ϣ
                            //������ע�����ض����ⲿIdP����ע��֮ǰ
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }



        /// <summary>
        /// ��ת��
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
        /// ��Ӵ�����Ϣ
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
