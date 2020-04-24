namespace IS4.AuthorizationCenter.Models.Options
{
    public class ConsentOptions
    {
        public bool EnableOfflineAccess { get; set; }
        public string OfflineAccessDisplayName { get; set; }
        public string OfflineAccessDescription { get; set; }

        public string MustChooseOneErrorMessage { get; set; }
        public string InvalidSelectionErrorMessage { get; set; }
    }
}
