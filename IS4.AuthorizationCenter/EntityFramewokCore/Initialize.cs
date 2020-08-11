using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;

namespace IS4.AuthorizationCenter.EntityFramewokCore
{
    public static class Initialize
    {
        /// <summary>
        /// 初始化IdentityServer4数据库
        /// </summary>
        /// <param name="app"></param>
        public static void InitializeIdentityServerDatabase(this IApplicationBuilder app)
        {
            //获取服务
            using var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope();
            //配置Identity数据库ApplicationDbContext迁移,如果不存在就迁移数据库,这样就不用手动执行数据库迁移命令
            //serviceScope.ServiceProvider.GetRequiredService<ApplicationDbContext>().Database.Migrate();
            //配置PersistedGrantDbContext迁移,如果不存在就迁移数据库,这样就不用手动执行数据库迁移命令
            serviceScope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();
            //配置ConfigurationDbContext迁移,如果不存在就迁移数据库,这样就不用手动执行数据库迁移命令
            var context = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
            context.Database.Migrate();
            //写入种子数据
            EnsureSeedData(context);

        }

        /// <summary>
        /// 迁移数据
        /// </summary>
        /// <param name="context"></param>
        private static void EnsureSeedData(ConfigurationDbContext context)
        {
            if (!context.Clients.Any())
            {
                Console.WriteLine("客户端初始化数据");
                foreach (var client in Config.GetClients.ToList())
                {
                    context.Clients.Add(client.ToEntity());
                }
                context.SaveChanges();
            }
            else
            {
                Console.WriteLine("客户端数据已存在");
            }

            if (!context.IdentityResources.Any())
            {
                Console.WriteLine("开始初始化身份资源数据");
                foreach (var resource in Config.GetIdentityResources.ToList())
                {
                    context.IdentityResources.Add(resource.ToEntity());
                }
                context.SaveChanges();
            }
            else
            {
                Console.WriteLine("身份资源数据已存在");
            }

            if (!context.ApiResources.Any())
            {
                Console.WriteLine("开始初始化Api资源数据");
                foreach (var resource in Config.GetApiResources.ToList())
                {
                    context.ApiResources.Add(resource.ToEntity());
                }
                context.SaveChanges();
            }
            else
            {
                Console.WriteLine("Api资源数据已存在");
            }
        }
    }
}
