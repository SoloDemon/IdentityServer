namespace IS4.AuthorizationCenter.Models.Account
{
    public class RoleEditViewModel
    {
        public RoleEditViewModel()
        {

        }
        public RoleEditViewModel(string Id, string Name)
        {
            this.Id = Id;
            this.RoleName = Name;
        }

        public string Id { get; set; }

        [Required]
        [Display(Name = "角色名")]
        public string RoleName { get; set; }
    }
}
