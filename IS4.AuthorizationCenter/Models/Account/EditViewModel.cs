using System;
using System.ComponentModel.DataAnnotations;

namespace IS4.AuthorizationCenter.Models.Account
{
    public class EditViewModel
    {
        public EditViewModel()
        {

        }
        public EditViewModel(string Id, string NickName, string UserName, string Email)
        {
            this.Id = Id;
            this.UserName = UserName;
            this.Email = Email;
            this.NickName = NickName;
        }

        public string Id { get; set; }

        [Required]
        [Display(Name = "昵称")]
        public string NickName { get; set; }

        [Required]
        [Display(Name = "登录名")]
        public string UserName { get; set; }

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
