using Newtonsoft.Json;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace IS4.IdentityServer.Extension.Commands
{
    public class HttpHelper : IHttpHelper
    {
        private readonly IHttpClientFactory _httpClientFactory;
        public HttpHelper(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        public async Task<string> PostAsync(string url, string datajson)
        {
            HttpClient httpClient = _httpClientFactory.CreateClient();
            //表头参数
            httpClient.DefaultRequestHeaders.Accept.Clear();
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            //转为链接需要的格式
            HttpContent httpContent = new JsonContent(datajson);
            //请求
            HttpResponseMessage response = await httpClient.PostAsync(url, httpContent);
            if (response.IsSuccessStatusCode)
            {
                Task<string> t = response.Content.ReadAsStringAsync();
                if (t != null)
                {
                    return t.Result;
                }
            }
            return "";
        }
    }



    public class JsonContent : StringContent
    {
        public JsonContent(string obj) :
           base(obj, Encoding.UTF8, "application/json")
        { }
    }
}
