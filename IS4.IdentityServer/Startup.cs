using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using IS4.IdentityServer.EntityFramework;
using IS4.IdentityServer.Extension.Identity;
using IS4.IdentityServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace IS4.IdentityServer
{
    public class Startup
    {
        private IConfiguration Configuration { get; }
        private IWebHostEnvironment env { get; }

        public Startup(IConfiguration configuration, IWebHostEnvironment env)
        {
            Configuration = configuration;
            this.env = env;
        }
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews(); //启用mvc
            services.AddRazorPages();

            /*
             * 1、add-migration InitialPersistedGrantDb -c PersistedGrantDbContext -OutputDir EntityFramework/Migrations/PersistedGrantDb 
               2、add-migration InitialConfigurationDb -c ConfigurationDbContext -OutputDir EntityFramework/Migrations/ConfigurationDb
               3、add-migration InitialApplicationDb -c ApplicationDbContext -OutputDir EntityFramework/Migrations/ApplicationDb
               4、update-database -c PersistedGrantDbContext
               5、update-database -c ConfigurationDbContext
               6、update-database -c ApplicationDbContext
             */
            var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            //注册Identity数据库Context
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("IdentityServer")));

            //启用 Identity 服务 添加指定的用户和角色类型的默认标识系统配置
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
                {
                    //密码设置
                    options.Password = new PasswordOptions
                    {
                        RequireDigit = true,//要求密码中的数字介于0-9 之间。
                        RequiredLength = 8,//密码的最小长度。
                        RequireNonAlphanumeric = false,//密码中需要一个非字母数字字符。
                        RequireLowercase = true,//密码中需要小写字符。
                        RequireUppercase = true,//密码中需要大写字符。
                        RequiredUniqueChars = 1//需要密码中的非重复字符数。
                    };
                    //锁定设置
                    options.Lockout = new LockoutOptions
                    {
                        AllowedForNewUsers = true,//确定新用户是否可以锁定。
                        DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5),//	锁定发生时用户被锁定的时间长度。
                        MaxFailedAccessAttempts = 3 //如果启用了锁定，则在用户被锁定之前失败的访问尝试次数。
                    };
                    //登陆设置
                    options.SignIn = new SignInOptions
                    {
                        RequireConfirmedEmail = false, //需要确认电子邮件登录。
                        RequireConfirmedPhoneNumber = false//需要确认电话号码才能登录。
                    };
                    //用户设置
                    options.User = new UserOptions
                    {
                        AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.",//用户名中允许使用的字符。
                        RequireUniqueEmail = true //要求每个用户都有唯一的电子邮件。
                    };
                    
                })
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            //注册自定义密码验证器
            services.AddTransient<IPasswordValidator<ApplicationUser>, CustomPasswordValidator>();
            services.AddTransient<IEmailSender, EmailSender>();

            var builder = services.AddIdentityServer()

                //注册配置数据<客户端和资源>
                .AddConfigurationStore(options =>
                    options.ConfigureDbContext = cfg =>
                        cfg.UseSqlServer(Configuration.GetConnectionString("NetCoreIdentity"),
                            sql => sql.MigrationsAssembly(migrationsAssembly)))

                //注册操作数据 (codes, tokens, consents)
                .AddOperationalStore(options =>
                {
                    options.ConfigureDbContext = cfg =>
                        cfg.UseSqlServer(Configuration.GetConnectionString("NetCoreIdentity"),
                            sql => sql.MigrationsAssembly(migrationsAssembly));

                    //启动自动清理token
                    options.EnableTokenCleanup = true;
                    //清理token间隔时间
                    options.TokenCleanupInterval = 3600;
                })

                .AddAspNetIdentity<ApplicationUser>();

            //开发环境使用开发证书,正式环境使用正式证书
            if (env.IsDevelopment())
            {
                builder.AddDeveloperSigningCredential();
            }
            else
            {
                builder.AddSigningCredential(new X509Certificate2(
                    Path.Combine(Directory.GetCurrentDirectory(), Configuration["Certificates:Path"]),
                    Configuration["Certificates:Password"]));
            }

            services.AddAuthentication(); //注入认证


        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseStaticFiles();

            app.UseRouting();

            app.UseIdentityServer();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });
        }
    }
}
