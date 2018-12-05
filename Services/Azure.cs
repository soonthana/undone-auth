using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Undone.Auth.Models;

namespace Undone.Auth.Services
{
  public class Azure
  {
    private IConfiguration _config;
    private string accessToken = string.Empty;
    private string azAuthUrl = string.Empty;
    private string azTenantId = string.Empty;
    private string azAppClientId = string.Empty;
    private string azAppSecretKey = string.Empty;
    private string azAppUrl = string.Empty;
    private string azProjectUrl = string.Empty;
    private string azKVResource = string.Empty;

    public Azure(IConfiguration config)
    {
      _config = config;
      azTenantId = _config["Azure:ActiveDirectory:TenantId"];
      azAuthUrl = string.Format(_config["Azure:ActiveDirectory:AuthUrl"], azTenantId);
      azAppClientId = _config["Azure:ActiveDirectory:Application:ClientAppId"];
      azAppSecretKey = _config["Azure:ActiveDirectory:Application:ClientAppSecretKey"];
      azProjectUrl = _config["Azure:KeyVault:Url"];
      azKVResource = _config["Azure:KeyVault:Resource"];
      accessToken = GetAccessToken().Result;
    }

    #region PUBLIC METHODS
    public string TestGetAccessToken()
    {
      return GetAccessToken().Result;
    }

    #region Azure Undone KeyVault
    // GET https://undone.vault.azure.net/secrets/<SECRET_NAME>?api-version=7.0
    public async Task<HttpResponseMessage> GetValueBySecretName(string secret)
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(azProjectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
      client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

      var response = await client.GetAsync("secrets/" + secret + "?api-version=7.0");

      HttpResponseMessage resp = new HttpResponseMessage();

      var content = response.Content.ReadAsStringAsync().Result;

      if (response.StatusCode == HttpStatusCode.OK)
      {
        var secretObj = JsonConvert.DeserializeObject<KeyVaultSecretPayload>(content);

        if (secretObj.contentType == "" || secretObj.contentType == null || secretObj.contentType == "null")
        {
          resp.StatusCode = HttpStatusCode.NotFound;
        }
        else
        {
          resp.StatusCode = HttpStatusCode.OK;
          var resultObj = new SecretPayload();
          resultObj.contentType = secretObj.contentType;
          resultObj.value = secretObj.value;

          resp.Content = new StringContent(JsonConvert.SerializeObject(resultObj));
        }
      }
      else
      {
        resp.StatusCode = response.StatusCode;
      }

      return resp;
    }
    #endregion
    #endregion

    #region PRIVATE METHODS
    private async Task<string> GetAccessToken()
    {
      var body = "grant_type=client_credentials&client_id=" + azAppClientId + "&client_secret=" + System.Net.WebUtility.UrlEncode(azAppSecretKey) + "&resource=" + System.Net.WebUtility.UrlEncode(azKVResource);

      var client = new HttpClient();
      client.BaseAddress = new Uri(azAuthUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var response = await client.PostAsync("token", new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded"));

      if (response.StatusCode == HttpStatusCode.OK)
      {
        var jsonContent = response.Content.ReadAsStringAsync().Result;
        var obj = JsonConvert.DeserializeObject<AzureAccessToken>(jsonContent);

        return obj.access_token;
      }
      else
      {
        return "";
      }
    }

    private class AzureAccessToken
    {
      public string token_type { get; set; }
      public string expires_in { get; set; }
      public string ext_expires_in { get; set; }
      public string expires_on { get; set; }
      public string not_before { get; set; }
      public string resource { get; set; }
      public string access_token { get; set; }
    }

    private class KeyVaultSecretPayload
    {
      public string value { get; set; }
      public string contentType { get; set; }
      public string id { get; set; }
    }

    private class KeyValutSecretAttributes
    {
      public bool enabled { get; set; }
      public int created { get; set; }
      public int updated { get; set; }
      public string recoveryLevel { get; set; }
    }

    private class KeyValutSecretTags
    {
    }
    #endregion
  }
}