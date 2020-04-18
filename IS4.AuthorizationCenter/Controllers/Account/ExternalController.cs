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
        /// �������ⲿ�����֤�ṩ�ߵ�����
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Challenge(string provider, string returnUrl)
        {
            if (string.IsNullOrEmpty(returnUrl)) returnUrl = "~/";

            // ��֤returnUrl��������һ����Ч��OIDC URL�����߷��ص�һ������ҳ��
            if (Url.IsLocalUrl(returnUrl) == false && _interaction.IsValidReturnUrl(returnUrl) == false)
            {
                // �û����ܵ����һ����������-Ӧ�ñ���¼
                throw new Exception("��Ч�ķ���Url");
            }

            if (_accountOptions.WindowsAuthenticationSchemeName == provider)
            {
                //  windows�����֤��Ҫ���⴦��
                return await ProcessWindowsLoginAsync(returnUrl);
            }
            else
            {
                // ��ʼ��ս�������ķ���URL�ͷ���
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
        /// �ⲿ��֤�ĺ���
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Callback()
        {
            // ����ʱcookie��ȡ�ⲿ��ʶ
            var result = await HttpContext.AuthenticateAsync(IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme);
            if (result?.Succeeded != true)
            {
                throw new Exception("�ⲿ�����֤����");
            }
            //�ֶ�����http��ȡ�û���Ϣ
            //var token = result.Properties.Items[".Token.access_token"];
            //var userInfo = await _httpHelper.PostAsync("https://openapi.baidu.com/rest/2.0/passport/users/getInfo", $"access_token={token}");
            // �������ǵ��û����ⲿ�ṩ����Ϣ
            var (user, provider, providerUserId, claims) = await FindUserFromExternalProviderAsync(result);
            //û����is4�ҵ��û�
            if (user == null)
            {
                //����û�������,�����û�
                user = await AutoProvisionUserAsync(provider, providerUserId, claims);
            }

            //��ʹ�����ܹ��ռ��κζ����Ȩ��Ҫ�����Ʋ�
            //�����ض���prtotocols���������Ǵ洢�ڱ��ص�auth cookie�С�
            //��ͨ�����ڴ洢����ЩЭ�����˳�����Ҫ�����ݡ�
            var additionalLocalClaims = new List<Claim>();
            var localSignInProps = new AuthenticationProperties();
            ProcessLoginCallbackForOidc(result, additionalLocalClaims, localSignInProps);
            ProcessLoginCallbackForWsFed(result, additionalLocalClaims, localSignInProps);
            ProcessLoginCallbackForSaml2p(result, additionalLocalClaims, localSignInProps);

            // Ϊ�û�������֤cookie
            await _events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, user.Id.ToString(), user.UserName));
            await HttpContext.SignInAsync(user.Id.ToString(), user.UserName, provider, localSignInProps, additionalLocalClaims.ToArray());

            // ɾ���ⲿ�����֤�ڼ�ʹ�õ���ʱcookie
            await HttpContext.SignOutAsync(IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme);

            // �������ص�URL
            var returnUrl = result.Properties.Items["returnUrl"] ?? "~/";

            // ����ⲿ��¼�Ƿ���OIDC�������������
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
        /// ����windos��¼
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        private async Task<IActionResult> ProcessWindowsLoginAsync(string returnUrl)
        {
            // �鿴windows��֤�Ƿ��Ѿ������󲢳ɹ�
            var result = await HttpContext.AuthenticateAsync(_accountOptions.WindowsAuthenticationSchemeName);
            if (result?.Principal is WindowsPrincipal wp)
            {
                //���ǽ������ⲿcookie��Ȼ���ض���
                //�û����ص��ⲿ�ص����������Ǵ�����
                //�������ⲿ��֤������ͬ
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

                // ������Ϊ������ӡ�������������̫����С��
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
                //����������֤
                //����windows��֤��֧���ض���uri��
                //�����ǵ���challengeʱ�������´�����URL
                return Challenge(_accountOptions.WindowsAuthenticationSchemeName);
            }
        }

        /// <summary>
        /// ���ⲿ�ṩ����Ϣ�����û�
        /// </summary>
        /// <param name="result">����url</param>
        /// <returns></returns>
        private async Task<(ApplicationUser user, string provider, string providerUserId, IEnumerable<Claim> claims)> FindUserFromExternalProviderAsync(AuthenticateResult result)
        {
            //��ȡ�ⲿ�û���Ϣ
            var externalUser = result.Principal;

            //���Բ����ⲿ�û�Ψһ���Id
            //�����Claim������Subject��NameIdentifier
            //�����ⲿ�ṩ�ߵĲ�ͬ�����ܻ�ʹ������һЩClaim����
            var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                              externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                              throw new Exception("δ֪���û���ʶ");

            //ɾ���û�id�����������������ṩ�û�ʱ�Ͳ��Ὣ�����Ϊ��������
            var claims = externalUser.Claims.ToList();
            claims.Remove(userIdClaim);

            //�ⲿ�ṩ��Scheme
            var provider = result.Properties.Items["scheme"];
            //�ⲿ�û�Ψһ���Id
            var providerUserId = userIdClaim.Value;

            //Ѱ���ⲿ�û�
            var user = await _userManager.FindByLoginAsync(provider, providerUserId);

            return (user, provider, providerUserId, claims);
        }

        /// <summary>
        /// �Զ������ⲿ��½�û�
        /// </summary>
        /// <param name="provider">�ⲿ��Ӧ��</param>
        /// <param name="providerUserId">�ⲿ�û�Ψһ���Id</param>
        /// <param name="claims">����</param>
        /// <returns></returns>
        private async Task<ApplicationUser> AutoProvisionUserAsync(string provider, string providerUserId, IEnumerable<Claim> claims)
        {
            //����һ����Ҫ��ӵ�Claim�б�
            var claimList = new List<Claim>();
            //��ȡ�û���
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
            //�����û�
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
        /// �����û�
        /// </summary>
        /// <param name="provider">��������Ӧ��</param>
        /// <param name="claims">�����б�</param>
        /// <returns></returns>
        private ApplicationUser CreateUser(string provider, IEnumerable<Claim> claims)
        {
            string portrait = "";
            switch (provider)
            {
                case "Baidu":
                    //ͷ��
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
        /// oidc�����¼�ص�
        /// </summary>
        /// <param name="externalResult"></param>
        /// <param name="localClaims"></param>
        /// <param name="localSignInProps"></param>
        private void ProcessLoginCallbackForOidc(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
            //����ⲿϵͳ������һ���Ựid�������뽫�临�ƹ���
            //�������ǾͿ�������������ǩ����
            var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
            if (sid != null)
            {
                localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
            }

            // ����ⲿ�ṩ�߷�����id_token�����ǽ��������Թ�ע��
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
