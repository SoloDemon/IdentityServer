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
             * �ֶ��������ݿ�Ǩ������
             * 1��add-migration InitialPersistedGrantDb -c PersistedGrantDbContext -OutputDir EntityFramework/Migrations/PersistedGrantDb 
               2��add-migration InitialConfigurationDb -c ConfigurationDbContext -OutputDir EntityFramework/Migrations/ConfigurationDb
               3��add-migration InitialApplicationDb -c ApplicationDbContext -OutputDir EntityFramework/Migrations/ApplicationDb
               4��update-database -c PersistedGrantDbContext
               5��update-database -c ConfigurationDbContext
               6��update-database -c ApplicationDbContext
             */
            var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            #region Identity����

            //ע��Identity���ݿ�Context
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("IdentityServer")));

            //���� Identity ���� ���ָ�����û��ͽ�ɫ���͵�Ĭ�ϱ�ʶϵͳ����
            services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
            {
                //��������
                options.Password = new PasswordOptions
                {
                    RequireDigit = true,//Ҫ�������е����ֽ���0-9 ֮�䡣
                    RequiredLength = 8,//�������С���ȡ�
                    RequireNonAlphanumeric = false,//��������Ҫһ������ĸ�����ַ���
                    RequireLowercase = true,//��������ҪСд�ַ���
                    RequireUppercase = true,//��������Ҫ��д�ַ���
                    RequiredUniqueChars = 1//��Ҫ�����еķ��ظ��ַ�����
                };
                //��������
                options.Lockout = new LockoutOptions
                {
                    AllowedForNewUsers = true,//ȷ�����û��Ƿ����������
                    DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5),//	��������ʱ�û���������ʱ�䳤�ȡ�
                    MaxFailedAccessAttempts = 3 //��������������������û�������֮ǰʧ�ܵķ��ʳ��Դ�����
                };
                //��½����
                options.SignIn = new SignInOptions
                {
                    RequireConfirmedEmail = false, //��Ҫȷ�ϵ����ʼ���¼��
                    RequireConfirmedPhoneNumber = false//��Ҫȷ�ϵ绰������ܵ�¼��
                };
                //�û�����
                options.User = new UserOptions
                {
                    AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.-",//�û���������ʹ�õ��ַ���
                    RequireUniqueEmail = false //Ҫ��ÿ���û�����Ψһ�ĵ����ʼ���
                };

            })
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            #endregion

            //ע������
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
                    LoginUrl = "/account/login",//��¼��ַ  
                };
            })
                //��չ��Ȩ��֤��
                //.AddExtensionGrantValidator<WeiXinOpenGrantValidator>()

                //ע����������<�ͻ��˺���Դ>
                .AddConfigurationStore(options =>
                    options.ConfigureDbContext = cfg =>
                        cfg.UseSqlServer(Configuration.GetConnectionString("NetCoreIdentity"),
                            sql => sql.MigrationsAssembly(migrationsAssembly)))

                //ע��������� (codes, tokens, consents)
                .AddOperationalStore(options =>
                {
                    options.ConfigureDbContext = cfg =>
                        cfg.UseSqlServer(Configuration.GetConnectionString("NetCoreIdentity"),
                            sql => sql.MigrationsAssembly(migrationsAssembly));

                    //�����Զ�����token
                    options.EnableTokenCleanup = true;
                    //����token���ʱ��
                    options.TokenCleanupInterval = 3600;
                })


                .AddAspNetIdentity<ApplicationUser>();

            //��������ʹ�ÿ���֤��,��ʽ����ʹ����ʽ֤��
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
            //TODO:���������չ����������ⲿ��½
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


            //ע��ȫ��������Ϣ
            services.Configure<AccountOptions>(Configuration.GetSection("AccountOptions"));
            services.Configure<ConsentOptions>(Configuration.GetSection("ConsentOptions"));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app)
        {

            //��ʼ�����ݿ�,�����Ҫ��ʼ�����ݿ�,����������ʱ�������� --InitDB=true.
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
