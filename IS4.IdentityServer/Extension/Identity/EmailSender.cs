using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;

namespace IS4.IdentityServer.Extension.Identity
{
    public class EmailSender : IEmailSender
    {
        private IConfiguration Configuration { get; }
        public EmailSender(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        /// <summary>
        /// 发送Email
        /// </summary>
        /// <param name="email">email地址</param>
        /// <param name="subject">主题</param>
        /// <param name="htmlMessage">内容</param>
        /// <returns></returns>
        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            // 设置邮件内容
            var mail = new MailMessage
            {
                Subject = subject,
                Body = htmlMessage,
                IsBodyHtml = true,
                BodyEncoding = Encoding.UTF8,
                Priority = MailPriority.High,
                SubjectEncoding = Encoding.UTF8,
                HeadersEncoding = Encoding.UTF8,
                From = new MailAddress(Configuration["EmailConfig:From"], 
                    Configuration["EmailConfig:DisplayName"], Encoding.UTF8),
                To = { new MailAddress(email) }
            };
            //邮件优先级
            // 设置SMTP服务器
            var smtp = new SmtpClient(Configuration["EmailConfig:Smtp"], int.Parse(Configuration["EmailConfig:Port"]));
            smtp.UseDefaultCredentials = false;
            smtp.Credentials = new System.Net.NetworkCredential(Configuration["EmailConfig:From"], 
                Configuration["EmailConfig:Password"]);
            smtp.DeliveryMethod = SmtpDeliveryMethod.Network;
            await smtp.SendMailAsync(mail);
        }
    }
}