using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;
using IS4.AuthorizationCenter.Extensions.GrantValidator;

namespace IS4.AuthorizationCenter
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> GetIdentityResources => new List<IdentityResource>
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResource("roles","用户角色",new List<string>{JwtClaimTypes.Role})
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
                    ClientId = "Client.ROP", //客户端ID
                    ClientName="资源所有者密码模式",
                    ClientSecrets = new List<Secret> //客户端用来获取token
                    {
                        new Secret("Secret".Sha256())
                    },
                    AllowedGrantTypes = GrantTypes.ResourceOwnerPassword, //使用资源所有者密码和客户端证书模式获取token
                    AllowedCorsOrigins = {"http://localhost:5001"},
                    AllowedScopes = new List<string> //允许的访问范围
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "Client.Api",
                        "roles"
                    },
                    AllowOfflineAccess = true //允许刷新token

                },
                new Client
                {
                    ClientId="Client.Implicit",
                    ClientName="隐式许可模式",
                    ClientSecrets=new List<Secret>
                    {
                        new Secret("Secret.js".Sha256())
                    },
                    AllowedGrantTypes=GrantTypes.Implicit,
                    //Cors设置
                    AllowedCorsOrigins = {"http://client.hwyuan.com"},
                    // 登录成功回调处理地址，处理回调返回的数据
                    RedirectUris = { "http://client.hwyuan.com/signin-oidc" },

                    // 登出地址
                    PostLogoutRedirectUris = { "http://client.hwyuan.com/signout-callback-oidc" },
                    //展示同意授权页面
                    RequireConsent=true,
                    AllowedScopes = new List<string> //允许的访问范围
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "Client.Api",
                        "roles"
                    }

                },
                new Client
                {
                    ClientId = "Client.Credentials",
                    ClientName = "客户端证书模式",
                    ClientSecrets = {new Secret("secret".Sha256())},
                    AllowedGrantTypes=GrantTypes.ClientCredentials,
                    AllowedCorsOrigins = {"http://localhost:5001"},
                    AllowedScopes = new List<string> //允许的访问范围
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "Client.Api",
                        "roles"
                    }
                },
                new Client
                {
                    ClientId = "Client.AuthorizationCode",
                    ClientName = "授权码模式",
                    ClientSecrets = {new Secret("secret".Sha256())},
                    AllowedGrantTypes = GrantTypes.Code,   //授权码模式
                    RequireConsent = false,//隐藏同意授权页面
                    RequirePkce = true,
                    
                    // 登陆后跳转地址
                    RedirectUris = { "http://localhost:5001/signin-oidc" },

                    // 登出后跳转地址
                    PostLogoutRedirectUris = { "http://localhost:5001/signout-callback-oidc" },

                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "Client.Api",
                        "roles"
                    },
                    AllowOfflineAccess = true
                },
                new Client
                {
                    ClientId = "SUCM",
                    ClientName = "校服收费管理系统",
                    ClientSecrets = {new Secret("Sucm".Sha256())},
                    //授权模式
                    AllowedGrantTypes = new List<string>
                    {
                        GrantTypeCustom.ResourceWeChat,
                        GrantType.Implicit
                    }, 
                    RequireConsent = false,//隐藏同意授权页面
                    RequirePkce = true,
                    
                    // 登陆后跳转地址
                    RedirectUris = { "http://localhost:5001/signin-oidc" },

                    // 登出后跳转地址
                    PostLogoutRedirectUris = { "http://localhost:5001/signout-callback-oidc" },

                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "Client.Api",
                        "roles"
                    },
                    AllowOfflineAccess = true
                }
            };
    }
}
