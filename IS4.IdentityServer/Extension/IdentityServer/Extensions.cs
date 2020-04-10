using System.Threading.Tasks;
using IdentityServer4.Stores;

namespace IS4.IdentityServer.Extension.IdentityServer
{
    public static class Extensions
    {
        /// <summary>
        /// 确定客户端是否配置为使用PKCE。
        /// </summary>
        /// <param name="store">The store.</param>
        /// <param name="clientId">客户端标识符。</param>
        /// <returns></returns>
        public static async Task<bool> IsPkceClientAsync(this IClientStore store, string clientId)
        {
            if (!string.IsNullOrWhiteSpace(clientId))
            {
                var client = await store.FindEnabledClientByIdAsync(clientId);
                return client?.RequirePkce == true;
            }

            return false;
        }
    }
}