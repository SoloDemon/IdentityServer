using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IS4.IdentityServer.Extension.Attributes;
using IS4.IdentityServer.Extension.IdentityServer;
using IS4.IdentityServer.Models;
using IS4.IdentityServer.Models.Options;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace IS4.IdentityServer.Controllers
{
    [SecurityHeaders]
    [Authorize]
    public class ConsentController : Controller
    {
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IResourceStore _resourceStore;
        private readonly IEventService _events;
        private readonly ILogger<ConsentController> _logger;
        private readonly ConsentOptions _consentOptions;

        public ConsentController(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IResourceStore resourceStore,
            IEventService events,
            ILogger<ConsentController> logger,
            IOptions<ConsentOptions> consentOptions
            )
        {
            _interaction = interaction;
            _clientStore = clientStore;
            _resourceStore = resourceStore;
            _events = events;
            _logger = logger;
            _consentOptions = consentOptions.Value;
        }
        /// <summary>
        /// 显示同意屏幕
        /// </summary>
        /// <param name="returnUrl">返回url</param>
        /// <returns></returns>
        [HttpGet]
        public async Task<IActionResult> Index(string returnUrl)
        {
            var vm = await BuildViewModelAsync(returnUrl);
            if (vm != null)
            {
                return View("Index", vm);
            }

            return View("Error");
        }

        /// <summary>
        /// 处理同意屏幕回发
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(ConsentInputModel model)
        {
            var result = await ProcessConsent(model);

            if (result.IsRedirect)
            {
                if (await _clientStore.IsPkceClientAsync(result.ClientId))
                {
                    //如果客户端是PKCE，那么我们就假定它是本地的，所以这是如何改变的
                    //响应是为了最终用户更好的用户体验。
                    return View("Redirect", new RedirectViewModel { RedirectUrl = result.RedirectUri });
                }

                return Redirect(result.RedirectUri);
            }

            if (result.HasValidationError)
            {
                ModelState.AddModelError(string.Empty, result.ValidationError);
            }

            if (result.ShowView)
            {
                return View("Index", result.ViewModel);
            }

            return View("Error");
        }

          /***************************************/
         /*      ConsentController助手Api       */
        /***************************************/
        private async Task<ProcessConsentResult> ProcessConsent(ConsentInputModel model)
        {
            var result = new ProcessConsentResult();

            // 验证返回url仍然有效
            var request = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);
            if (request == null) return result;

            ConsentResponse grantedConsent = null;

            // 用户点击“否”-发送回标准的“access_denied”响应
            if (model?.Button == "no")
            {
                grantedConsent = ConsentResponse.Denied;

                // 释放事件
                await _events.RaiseAsync(new ConsentDeniedEvent(User.GetSubjectId(), request.ClientId, request.ScopesRequested));
            }
            // 用户点击“是”-验证数据
            else if (model?.Button == "yes")
            {
                // 如果用户同意某个范围，则构建响应模型
                if (model.ScopesConsented != null && model.ScopesConsented.Any())
                {
                    var scopes = model.ScopesConsented;
                    if (_consentOptions.EnableOfflineAccess == false)
                    {
                        scopes = scopes.Where(x => x != IdentityServer4.IdentityServerConstants.StandardScopes.OfflineAccess);
                    }

                    grantedConsent = new ConsentResponse
                    {
                        RememberConsent = model.RememberConsent,
                        ScopesConsented = scopes.ToArray()
                    };

                    // 释放事件
                    await _events.RaiseAsync(new ConsentGrantedEvent(User.GetSubjectId(), request.ClientId, request.ScopesRequested, grantedConsent.ScopesConsented, grantedConsent.RememberConsent));
                }
                else
                {
                    result.ValidationError = _consentOptions.MustChooseOneErrorMessage;
                }
            }
            else
            {
                result.ValidationError = _consentOptions.InvalidSelectionErrorMessage;
            }

            if (grantedConsent != null)
            {
                // 将同意的结果反馈给身份服务器
                await _interaction.GrantConsentAsync(request, grantedConsent);

                // 表示可以重定向回授权端点
                result.RedirectUri = model.ReturnUrl;
                result.ClientId = request.ClientId;
            }
            else
            {
                // 我们需要重新显示同意用户界面
                result.ViewModel = await BuildViewModelAsync(model.ReturnUrl, model);
            }

            return result;
        }

        /// <summary>
        /// 建立展示模型
        /// </summary>
        /// <param name="returnUrl">返回url</param>
        /// <param name="model">同意输入模型</param>
        /// <returns></returns>
        private async Task<ConsentViewModel> BuildViewModelAsync(string returnUrl, ConsentInputModel model = null)
        {
            var request = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (request != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(request.ClientId);
                if (client != null)
                {
                    var resources = await _resourceStore.FindEnabledResourcesByScopeAsync(request.ScopesRequested);
                    if (resources != null && (resources.IdentityResources.Any() || resources.ApiResources.Any()))
                    {
                        return CreateConsentViewModel(model, returnUrl, request, client, resources);
                    }
                    else
                    {
                        _logger.LogError("没有范围匹配: {0}", request.ScopesRequested.Aggregate((x, y) => x + ", " + y));
                    }
                }
                else
                {
                    _logger.LogError("无效的客户端ID: {0}", request.ClientId);
                }
            }
            else
            {
                _logger.LogError("没有同意请求匹配请求: {0}", returnUrl);
            }

            return null;
        }

        /// <summary>
        /// 创造同意展示模型
        /// </summary>
        /// <param name="model">模型</param>
        /// <param name="returnUrl">返回Url</param>
        /// <param name="request">请求</param>
        /// <param name="client">客户端</param>
        /// <param name="resources">资源</param>
        /// <returns></returns>
        private ConsentViewModel CreateConsentViewModel(
             ConsentInputModel model, string returnUrl,
             AuthorizationRequest request,
             Client client, Resources resources)
        {
            var vm = new ConsentViewModel
            {
                RememberConsent = model?.RememberConsent ?? true,
                ScopesConsented = model?.ScopesConsented ?? Enumerable.Empty<string>(),

                ReturnUrl = returnUrl,

                ClientName = client.ClientName ?? client.ClientId,
                ClientUrl = client.ClientUri,
                ClientLogoUrl = client.LogoUri,
                AllowRememberConsent = client.AllowRememberConsent
            };

            vm.IdentityScopes = resources.IdentityResources.Select(x => CreateScopeViewModel(x, vm.ScopesConsented.Contains(x.Name) || model == null)).ToArray();
            vm.ResourceScopes = resources.ApiResources.SelectMany(x => x.Scopes).Select(x => CreateScopeViewModel(x, vm.ScopesConsented.Contains(x.Name) || model == null)).ToArray();
            if (_consentOptions.EnableOfflineAccess && resources.OfflineAccess)
            {
                vm.ResourceScopes = vm.ResourceScopes.Union(new ScopeViewModel[] {
                    GetOfflineAccessScope(vm.ScopesConsented.Contains(IdentityServer4.IdentityServerConstants.StandardScopes.OfflineAccess) || model == null)
                });
            }

            return vm;
        }

        private ScopeViewModel CreateScopeViewModel(IdentityResource identity, bool check)
        {
            return new ScopeViewModel
            {
                Name = identity.Name,
                DisplayName = identity.DisplayName,
                Description = identity.Description,
                Emphasize = identity.Emphasize,
                Required = identity.Required,
                Checked = check || identity.Required
            };
        }

        /// <summary>
        /// 创建区域展示模型
        /// </summary>
        /// <param name="scope"></param>
        /// <param name="check"></param>
        /// <returns></returns>
        public ScopeViewModel CreateScopeViewModel(Scope scope, bool check)
        {
            return new ScopeViewModel
            {
                Name = scope.Name,
                DisplayName = scope.DisplayName,
                Description = scope.Description,
                Emphasize = scope.Emphasize,
                Required = scope.Required,
                Checked = check || scope.Required
            };
        }

        /// <summary>
        /// 获取离线访问区域
        /// </summary>
        /// <param name="check"></param>
        /// <returns></returns>
        private ScopeViewModel GetOfflineAccessScope(bool check)
        {
            return new ScopeViewModel
            {
                Name = IdentityServer4.IdentityServerConstants.StandardScopes.OfflineAccess,
                DisplayName = _consentOptions.OfflineAccessDisplayName,
                Description = _consentOptions.OfflineAccessDescription,
                Emphasize = true,
                Checked = check
            };
        }
    }
}