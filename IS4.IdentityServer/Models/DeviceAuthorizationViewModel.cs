namespace IS4.IdentityServer.Models
{
    public class DeviceAuthorizationViewModel: ConsentViewModel
    {
        public string UserCode { get; set; }
        public bool ConfirmUserCode { get; set; }
    }
}