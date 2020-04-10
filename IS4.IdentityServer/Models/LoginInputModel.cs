using System.ComponentModel.DataAnnotations;

namespace IS4.IdentityServer.Models
{
    /// <summary>
    /// 登陆输入模型
    /// </summary>
    public class LoginInputModel
    {
        /// <summary>
        /// 用户名
        /// </summary>
        [Required]
        public string Username { get; set; }
        /// <summary>
        /// 密码
        /// </summary>
        [Required]
        public string Password { get; set; }
        /// <summary>
        /// 记住登陆状态
        /// </summary>
        public bool RememberLogin { get; set; }
        /// <summary>
        /// 返回Url
        /// </summary>
        public string ReturnUrl { get; set; }
    }
}