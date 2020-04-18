using System;
using System.ComponentModel.DataAnnotations;

namespace IS4.AuthorizationCenter.Models.Account
{
    public class RegisterViewModel
    {
        [Required]
        [Display(Name = "昵称")]
        public string NickName { get; set; }

        [Required]
        [Display(Name = "登录名")]
        public string LoginName { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "邮箱")]
        public string Email { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "{0}必须和{2}一致,并且不能大于{1}个字符.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "密码")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "确认密码")]
        [Compare("Password", ErrorMessage = "密码和确认密码不一致")]
        public string ConfirmPassword { get; set; }


        [Display(Name = "性别")]
        public byte Sex { get; set; } = 0;

        [Display(Name = "生日")]
        public DateTime Birth { get; set; } = DateTime.Now;
    }
}
