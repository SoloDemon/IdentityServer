using System.Threading.Tasks;

namespace IS4.IdentityServer.Extension.Commands
{
    public interface IHttpHelper
    {
        Task<string> PostAsync(string url, string datajson);
    }
}
