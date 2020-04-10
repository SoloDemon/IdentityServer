using System;
using System.ComponentModel.DataAnnotations;

namespace IS4.IdentityServer.Models
{
    public class EditViewModel
    {
        public EditViewModel()
        {

        }
        /// <summary>
        /// 编辑展示模型
        /// </summary>
        /// <param name="Id">用户id</param>
        /// <param name="Name">昵称</param>
        /// <param name="LoginName">登录名</param>
        /// <param name="Email">email</param>
        public EditViewModel(string Id, string Name, string LoginName, string Email)
        {
            this.Id = Id;
            this.LoginName = LoginName;
            this.Email = Email;
            this.UserName = Name;
        }

        public string Id { get; set; }

        [Required]
        [Display(Name = "昵称")]
        public string UserName { get; set; }

        [Required]
        [Display(Name = "登录名")]
        public string LoginName { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "邮箱")]
        public string Email { get; set; }




        [Display(Name = "性别")]
        public int Sex { get; set; } = 0;

        [Display(Name = "生日")]
        public DateTime Birth { get; set; } = DateTime.Now;
    }
}
