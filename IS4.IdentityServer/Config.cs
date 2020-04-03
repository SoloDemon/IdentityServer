using System.Collections.Generic;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Test;

namespace IS4.IdentityServer
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> GetIdentityResources => new List<IdentityResource>
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResource("roles","角色",new List<string>{JwtClaimTypes.Role})
        };

        public static IEnumerable<ApiResource> GetApiResources =>
            new List<ApiResource>
            {
                new ApiResource("Client.Api", "客户端api")
                {
                    UserClaims = {JwtClaimTypes.Name,JwtClaimTypes.Role}
                }
            };

        public static IEnumerable<Client> GetClients =>
            new List<Client>
            {
                new Client
                {
                    ClientId = "Client", //客户端名称
                    ClientSecrets = new List<Secret> //客户端用来获取token
                    {
                        new Secret("Secret".Sha256())
                    },
                    AllowedGrantTypes = GrantTypes.ResourceOwnerPasswordAndClientCredentials, //使用资源所有者密码和客户端证书模式获取token
                    AllowedCorsOrigins = {"http://localhost:5001"},
                    AllowedScopes = new List<string> //允许的访问范围
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "Client.Api",
                        "roles"
                    },
                    AllowOfflineAccess = true //允许刷新token

                }
            };
    }

}