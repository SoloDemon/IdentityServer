using System;
namespace IS4.IdentityServer.Models
{
    public class AccountOptions
    {
        public static bool AllowLocalLogin = true;
        public static bool AllowRememberLogin = true;
        //记住登陆有效时间
        public static TimeSpan RememberMeLoginDuration = TimeSpan.FromDays(30);

        public static bool ShowLogoutPrompt = true;
        public static bool AutomaticRedirectAfterSignOut = true;//自动跳回原项目

        // windows身份验证方案
        public static readonly string WindowsAuthenticationSchemeName = Microsoft.AspNetCore.Server.IISIntegration.IISDefaults.AuthenticationScheme;
        // 如果用户使用windows验证，我们是否应该从windows加载组
        public static bool IncludeWindowsGroups = false;

        public static string InvalidCredentialsErrorMessage = "无效的用户名或密码";
    }
}
