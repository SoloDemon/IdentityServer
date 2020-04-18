namespace IS4.AuthorizationCenter.Models.Account
{
    public class RoleRegisterViewModel
    {
        [Required]
        [Display(Name = "角色名")]
        public string RoleName { get; set; }
    }
}
