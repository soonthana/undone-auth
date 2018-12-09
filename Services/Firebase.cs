using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Undone.Auth.Framework;
using Undone.Auth.Models;
using Undone.Auth.Utils;

namespace Undone.Auth.Services
{
  public class Firebase
  {
    private IConfiguration _config;
    private string accessToken = string.Empty;
    private string projectUrl = string.Empty;
    private Azure _azObj;

    public Firebase(IConfiguration config)
    {
      _config = config;
      _azObj = new Azure(_config);
      projectUrl = _config["GoogleApi:Firebase:UndoneAuth:ProjectUrl"];
      accessToken = GetAccessToken().Result;
    }

    #region PUBLIC METHODS
    public string TestGetAccessToken()
    {
      return GetAccessToken().Result;
    }

    #region Firebase UndoneAuth.AppAudiences
    // GET https://undone-auth.firebaseio.com/AppAudiences/<SPECIFIC_NODE>.json?access_token=<ACCESS_TOKEN>
    public async Task<HttpResponseMessage> GetAppAudiencesById(string node)
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(projectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var response = await client.GetAsync("AppAudiences/" + node + ".json?access_token=" + accessToken);

      return response;
    }

    // PUT https://undone-auth.firebaseio.com/AppAudiences.json?access_token=<ACCESS_TOKEN>
    public async Task<HttpResponseMessage> PutAppAudiences(AppAudiences app)
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(projectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var jsonString = JsonConvert.SerializeObject(app);
      var uniqueId = app.Id.ToString();
      var response = await client.PutAsync("AppAudiences/" + uniqueId + ".json?access_token=" + accessToken, new StringContent(jsonString, Encoding.UTF8, "application/json"));

      return response;
    }

    // PATCH https://undone-auth.firebaseio.com/AppAudiences/<SPECIFIC_NODE>.json?access_token=<ACCESS_TOKEN>
    public async Task<HttpResponseMessage> PatchAppAudiences(string node, string jsonString)
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(projectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var reqMsg = new HttpRequestMessage();
      reqMsg.Method = new HttpMethod("PATCH");
      reqMsg.RequestUri = new Uri(projectUrl + "AppAudiences/" + node + ".json?access_token=" + accessToken);
      reqMsg.Content = new StringContent(jsonString, Encoding.UTF8, "application/json");

      var response = await client.SendAsync(reqMsg);

      return response;
    }

    // DELETE https://undone-auth.firebaseio.com/AppAudiences/<SPECIFIC_NODE>.json?access_token=<ACCESS_TOKEN>
    public async Task<HttpResponseMessage> DeleteAppAudiences(string node)
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(projectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var response = await client.DeleteAsync("AppAudiences/" + node + ".json?access_token=" + accessToken);

      return response;
    }
    #endregion

    #region Firebase UndoneAuth.AccessTokens
    // GET https://undone-auth.firebaseio.com/AccessTokens/<SPECIFIC_NODE>.json?access_token=<ACCESS_TOKEN>
    public async Task<HttpResponseMessage> GetAccessTokenByToken(string node)
    {
      node = node.Replace(".", "---");

      var client = new HttpClient();
      client.BaseAddress = new Uri(projectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var response = await client.GetAsync("AccessTokens/" + node + ".json?access_token=" + accessToken);

      return response;
    }

    // PUT https://undone-auth.firebaseio.com/AccessTokens.json?access_token=<ACCESS_TOKEN>
    public async Task<HttpResponseMessage> PutAccessTokens(AccessTokens token)
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(projectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var jsonString = JsonConvert.SerializeObject(token);
      var uniqueId = token.AccessToken.Replace(".", "---");
      var response = await client.PutAsync("AccessTokens/" + uniqueId + ".json?access_token=" + accessToken, new StringContent(jsonString, Encoding.UTF8, "application/json"));

      return response;
    }

    // PATCH https://undone-auth.firebaseio.com/AccessTokens/<SPECIFIC_NODE>.json?access_token=<ACCESS_TOKEN>
    public async Task<HttpResponseMessage> PatchAccessTokens(string node, string jsonString)
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(projectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var reqMsg = new HttpRequestMessage();
      reqMsg.Method = new HttpMethod("PATCH");
      reqMsg.RequestUri = new Uri(projectUrl + "AccessTokens/" + node + ".json?access_token=" + accessToken);
      reqMsg.Content = new StringContent(jsonString, Encoding.UTF8, "application/json");

      var response = await client.SendAsync(reqMsg);

      return response;
    }

    // DELETE https://undone-auth.firebaseio.com/AccessTokens/<SPECIFIC_NODE>.json?access_token=<ACCESS_TOKEN>
    public async Task<HttpResponseMessage> DeleteAccessTokens(string node)
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(projectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var response = await client.DeleteAsync("AccessTokens/" + node + ".json?access_token=" + accessToken);

      return response;
    }
    #endregion

    #region Firebase UndoneAuth.RefreshTokens
    // GET https://undone-auth.firebaseio.com/RefreshTokens/<SPECIFIC_NODE>.json?access_token=<ACCESS_TOKEN>
    public async Task<HttpResponseMessage> GetRefreshTokenByToken(string node)
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(projectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var response = await client.GetAsync("RefreshTokens/" + node + ".json?access_token=" + accessToken);

      return response;
    }

    // GET https://undone-auth.firebaseio.com/RefreshTokens/<SPECIFIC_NODE>/AccessTokens.json?access_token=<ACCESS_TOKEN>
    public async Task<HttpResponseMessage> GetRefreshTokenAccessTokensByToken(string node)
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(projectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var response = await client.GetAsync("RefreshTokens/" + node + "/AccessTokens.json?access_token=" + accessToken);

      return response;
    }

    // PUT https://undone-auth.firebaseio.com/RefreshTokens/<UNIQUE_ID>.json?access_token=<ACCESS_TOKEN>
    public async Task<HttpResponseMessage> PutRefreshTokens(RefreshTokens token)
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(projectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var jsonString = JsonConvert.SerializeObject(token);
      var uniqueId = token.RefreshToken;
      var response = await client.PutAsync("RefreshTokens/" + uniqueId + ".json?access_token=" + accessToken, new StringContent(jsonString, Encoding.UTF8, "application/json"));

      return response;
    }

    // PUT https://undone-auth.firebaseio.com/RefreshTokens/<SPECIFIC_NODE>/AccessTokens/<UNIQUE_ID>.json?access_token=<ACCESS_TOKEN>
    public async Task<HttpResponseMessage> PutRefreshTokensAccessToken(string node, string token, string stampDateTime)
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(projectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      token = token.Replace(".", "---");
      stampDateTime = "\"" + stampDateTime + "\"";
      var response = await client.PutAsync("RefreshTokens/" + node + "/AccessTokens/" + token + ".json?access_token=" + accessToken, new StringContent(stampDateTime, Encoding.UTF8, "application/json"));

      return response;
    }

    // PATCH https://undone-auth.firebaseio.com/RefreshTokens/<SPECIFIC_NODE>.json?access_token=<ACCESS_TOKEN>
    public async Task<HttpResponseMessage> PatchRefreshTokens(string node, string jsonString)
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(projectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var reqMsg = new HttpRequestMessage();
      reqMsg.Method = new HttpMethod("PATCH");
      reqMsg.RequestUri = new Uri(projectUrl + "RefreshTokens/" + node + ".json?access_token=" + accessToken);
      reqMsg.Content = new StringContent(jsonString, Encoding.UTF8, "application/json");

      var response = await client.SendAsync(reqMsg);

      return response;
    }

    // DELETE https://undone-auth.firebaseio.com/RefreshTokens/<SPECIFIC_NODE>.json?access_token=<ACCESS_TOKEN>
    public async Task<HttpResponseMessage> DeleteRefreshTokens(string node)
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(projectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var response = await client.DeleteAsync("RefreshTokens/" + node + ".json?access_token=" + accessToken);

      return response;
    }
    #endregion

    #region Firebase UndoneAuth.AuthorizationCodes
    // GET https://undone-auth.firebaseio.com/AuthorizationCodes/<SPECIFIC_NODE>.json?access_token=<ACCESS_TOKEN>
    public async Task<HttpResponseMessage> GetAuthorizationCodesById(string node)
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(projectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var response = await client.GetAsync("AuthorizationCodes/" + node + ".json?access_token=" + accessToken);

      return response;
    }

    // PUT https://undone-auth.firebaseio.com/AuthorizationCodes.json?access_token=<ACCESS_TOKEN>
    public async Task<HttpResponseMessage> PutAuthorizationCodes(AuthorizationCodes code)
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(projectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var jsonString = JsonConvert.SerializeObject(code);
      var uniqueId = code.Id.ToString();
      var response = await client.PutAsync("AuthorizationCodes/" + uniqueId + ".json?access_token=" + accessToken, new StringContent(jsonString, Encoding.UTF8, "application/json"));

      return response;
    }

    // DELETE https://undone-auth.firebaseio.com/AuthorizationCodes/<SPECIFIC_NODE>.json?access_token=<ACCESS_TOKEN>
    public async Task<HttpResponseMessage> DeleteAuthorizationCodes(string node)
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(projectUrl);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var response = await client.DeleteAsync("AuthorizationCodes/" + node + ".json?access_token=" + accessToken);

      return response;
    }
    #endregion

    #endregion

    #region PRIVATE METHODS
    // POST https://www.googleapis.com/oauth2/v4/token
    private async Task<string> GetAccessToken()
    {
      var jwtRequest = GenerateJwtRequestByRSAKey();

      var body = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + jwtRequest;

      var client = new HttpClient();
      client.BaseAddress = new Uri(_config["GoogleApi:Firebase:UndoneAuth:RequestTokenUrl"]);
      client.DefaultRequestHeaders.Accept.Clear();
      client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

      var response = await client.PostAsync("oauth2/v4/token", new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded"));

      if (response.StatusCode == HttpStatusCode.OK)
      {
        var jsonContent = response.Content.ReadAsStringAsync().Result;
        var obj = JsonConvert.DeserializeObject<GoogleAccessToken>(jsonContent);

        return obj.access_token;
      }
      else
      {
        return "";
      }
    }

    private string GenerateJwtRequestByRSAKey()
    {
      var payloadObj = new Payload();
      payloadObj.iss = _config["GoogleApi:Firebase:UndoneAuth:ServiceAccount"];
      payloadObj.scope = _config["GoogleApi:Firebase:UndoneAuth:Scope"];
      payloadObj.aud = _config["GoogleApi:Firebase:UndoneAuth:RequestTokenUrl"] + "oauth2/v4/token";
      payloadObj.exp = Convert.ToInt32(DateTimes.ConvertToUnixTimeByDateTime(DateTime.UtcNow.AddMinutes(60)));
      payloadObj.iat = Convert.ToInt32(DateTimes.ConvertToUnixTimeByDateTime(DateTime.UtcNow));

      SigningCredentials creds;
      var result = string.Empty;

      using (RSA privateRsa = RSA.Create())
      {
        var privateKeyXml = string.Empty;
        var resp = _azObj.GetValueBySecretName(_config["GoogleApi:Firebase:UndoneAuth:Key:RS256:PrivateKeyXml"]).Result;
        if (resp.StatusCode == HttpStatusCode.OK)
        {
          var content = resp.Content.ReadAsStringAsync().Result;
          var obj = JsonConvert.DeserializeObject<SecretPayload>(content);
          privateKeyXml = obj.value;
        }
        privateRsa.fromXmlString(privateKeyXml);
        var privateKey = new RsaSecurityKey(privateRsa);
        creds = new SigningCredentials(privateKey, SecurityAlgorithms.RsaSha256);

        var claims = new[] {
          new Claim("scope", payloadObj.scope),
          new Claim(JwtRegisteredClaimNames.Iat, payloadObj.iat.ToString()),
          new Claim(JwtRegisteredClaimNames.Exp, payloadObj.exp.ToString())
        };
        var token = new JwtSecurityToken(
          payloadObj.iss,
          payloadObj.aud,
          claims,
          signingCredentials: creds
        );

        result = new JwtSecurityTokenHandler().WriteToken(token);
      }

      return result;
    }

    private class Payload
    {
      public string iss { get; set; }
      public string scope { get; set; }
      public string aud { get; set; }
      public int exp { get; set; }
      public int iat { get; set; }
    }

    private class GoogleAccessToken
    {
      public string access_token { get; set; }
      public string token_type { get; set; }
      public int expires_in { get; set; }
    }
    #endregion
  }
}