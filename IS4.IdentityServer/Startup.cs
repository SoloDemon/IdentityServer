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
            services.AddControllersWithViews(); //����mvc
            services.AddRazorPages();

            /*
             * 1��add-migration InitialPersistedGrantDb -c PersistedGrantDbContext -OutputDir EntityFramework/Migrations/PersistedGrantDb 
               2��add-migration InitialConfigurationDb -c ConfigurationDbContext -OutputDir EntityFramework/Migrations/ConfigurationDb
               3��add-migration InitialApplicationDb -c ApplicationDbContext -OutputDir EntityFramework/Migrations/ApplicationDb
               4��update-database -c PersistedGrantDbContext
               5��update-database -c ConfigurationDbContext
               6��update-database -c ApplicationDbContext
             */
            var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            //ע��Identity���ݿ�Context
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("IdentityServer")));

            //���� Identity ���� ���ָ�����û��ͽ�ɫ���͵�Ĭ�ϱ�ʶϵͳ����
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
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
                        AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.",//�û���������ʹ�õ��ַ���
                        RequireUniqueEmail = true //Ҫ��ÿ���û�����Ψһ�ĵ����ʼ���
                    };
                    
                })
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            //ע���Զ���������֤��
            services.AddTransient<IPasswordValidator<ApplicationUser>, CustomPasswordValidator>();
            services.AddTransient<IEmailSender, EmailSender>();

            var builder = services.AddIdentityServer()

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

            services.AddAuthentication(); //ע����֤


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
