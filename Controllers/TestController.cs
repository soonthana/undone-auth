using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Undone.Auth.Framework;
using Undone.Auth.Models;
using Undone.Auth.Services;
using Undone.Auth.Utils;

namespace Undone.Auth.Controllers
{
  [Route("api/[controller]")]
  [ApiController]
  public class TestController : ControllerBase
  {
    private IConfiguration _config;
    private Azure _azObj;
    private Firebase _fbObj;

    public TestController(IConfiguration config)
    {
      _config = config;
      _azObj = new Azure(_config);
      _fbObj = new Firebase(_config);
    }

    // GET api/test/5
    [HttpGet("{id}")]
    public string Get(int id)
    {
      if (id == 1)
      {
        return _azObj.TestGetAccessToken();
      }
      else if (id == 2)
      {
        return _fbObj.TestGetAccessToken();
      }
      else
      {
        return "8100,8105 ALL ES256";
      }
    }


    // GET api/test
    [HttpGet]
    public async Task<ActionResult> Get()
    {
      // var resp = await _azObj.GetValueBySecretName("test-TXT");
      // var resp = await _azObj.GetValueBySecretName(_config["Jwt:Key:HS256:SymmetricKeyJson"]);
      // var resp = await _azObj.GetValueBySecretName(_config["Jwt:Key:ES256:PrivateKeyJson"]);
      // var resp = await _azObj.GetValueBySecretName(_config["Jwt:Key:RS256:PublicKeyXml"]);
      var resp = await _azObj.GetValueBySecretName(_config["GoogleApi:Firebase:UndoneAuth:Key:RS256:PrivateKeyXml"]);

      if (resp.StatusCode == HttpStatusCode.OK)
      {
        var content = resp.Content.ReadAsStringAsync().Result;
        var obj = JsonConvert.DeserializeObject<SecretPayload>(content);

        if (obj.contentType.ToLower() == "json")
        {
          var jObj = JObject.Parse(obj.value);
          var result = (string)jObj["Key"];

          return Ok(result);
        }
        else
        {
          return Ok(obj.value);
        }
      }
      else
      {
        return NotFound("No");
      }
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

  }
}