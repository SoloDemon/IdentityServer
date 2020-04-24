using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IS4.AuthorizationCenter.Models.Options
{
    public class AccountOptions
    {
        /// <summary>
        /// 允许本地登录
        /// </summary>
        public bool AllowLocalLogin { get; set; }
        /// <summary>
        /// 允许记住登陆状态
        /// </summary>
        public bool AllowRememberLogin { get; set; }
        /// <summary>
        /// 记住登陆有效时间
        /// </summary>
        public TimeSpan RememberMeLoginDuration { get; } = TimeSpan.FromDays(30);
        /// <summary>
        /// 显示登出提示
        /// </summary>
        public bool ShowLogoutPrompt { get; set; }
        /// <summary>
        /// 自动跳回原项目并登出
        /// </summary>
        public bool AutomaticRedirectAfterSignOut { get; set; }
        /// <summary>
        /// windows身份验证方案
        /// </summary>
        public string WindowsAuthenticationSchemeName { get; } = Microsoft.AspNetCore.Server.IISIntegration.IISDefaults.AuthenticationScheme;
        /// <summary>
        /// 如果用户使用windows验证，我们是否应该从windows加载组
        /// </summary>
        public bool IncludeWindowsGroups { get; set; }
        /// <summary>
        /// 无效的证书错误信息
        /// </summary>
        public string InvalidCredentialsErrorMessage { get; set; }
        /// <summary>
        /// 无效用户错误信息
        /// </summary>
        public string InvalidUserErrorMessage { get; set; }
    }
}
