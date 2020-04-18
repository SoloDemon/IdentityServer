using IdentityServer4;
using IS4.AuthorizationCenter.EntityFramewokCore;
using IS4.AuthorizationCenter.Extension.Identity;
using IS4.AuthorizationCenter.Models.Entity;
using IS4.AuthorizationCenter.Models.Options;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace IS4.AuthorizationCenter
{
    public class Startup
    {
        private IConfiguration Configuration { get; }
        private IWebHostEnvironment env { get; }

        public Startup(IConfiguration configuration, IWebHostEnvironment Env)
        {
            Configuration = configuration;
            env = Env;
        }
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
            /*
             * 手动创建数据库迁移命令
             * 1、add-migration InitialPersistedGrantDb -c PersistedGrantDbContext -OutputDir EntityFramework/Migrations/PersistedGrantDb 
               2、add-migration InitialConfigurationDb -c ConfigurationDbContext -OutputDir EntityFramework/Migrations/ConfigurationDb
               3、add-migration InitialApplicationDb -c ApplicationDbContext -OutputDir EntityFramework/Migrations/ApplicationDb
               4、update-database -c PersistedGrantDbContext
               5、update-database -c ConfigurationDbContext
               6、update-database -c ApplicationDbContext
             */
            var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            #region Identity配置

            //注册Identity数据库Context
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("IdentityServer")));

            //启用 Identity 服务 添加指定的用户和角色类型的默认标识系统配置
            services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
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
                    AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.-",//用户名中允许使用的字符。
                    RequireUniqueEmail = false //要求每个用户都有唯一的电子邮件。
                };

            })
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            #endregion

            //注入容器
            services.AddTransient<IEmailSender, EmailSender>();

            services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = new PathString("/account/login");
                options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
            });

            var builder = services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;
                options.IssuerUri = "https://authorize.hwyuan.com";
                options.PublicOrigin = "https://authorize.hwyuan.com";
                options.UserInteraction = new IdentityServer4.Configuration.UserInteractionOptions
                {
                    LoginUrl = "/account/login",//登录地址  
                };
            })
                //扩展授权验证器
                //.AddExtensionGrantValidator<WeiXinOpenGrantValidator>()

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

            services.AddAuthentication()
            //TODO:这里可以扩展更多第三方外部登陆
                .AddQQ(options =>
                {
                    options.ClientId = Configuration["OpenPlatform:QQ:AppId"];
                    options.ClientSecret = Configuration["OpenPlatform:QQ:AppKey"];
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.SaveTokens = true;
                })
                .AddWeixin(options => {
                    options.ClientId = Configuration["OpenPlatform:WeiXin:AppId"];
                    options.ClientSecret = Configuration["OpenPlatform:WeiXin:AppKey"];
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.SaveTokens = true;
                });


            //注册全局配置信息
            services.Configure<AccountOptions>(Configuration.GetSection("AccountOptions"));
            services.Configure<ConsentOptions>(Configuration.GetSection("ConsentOptions"));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app)
        {

            //初始化数据库,如果需要初始化数据库,请在启动的时候加入参数 --InitDB=true.
            if (Configuration["InitDB"] == "true")
            {
                app.InitializeIdentityServerDatabase();
            }
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
                    pattern: "{controller=Account}/{action=Login}/{id?}");
            });
        }
    }
}
