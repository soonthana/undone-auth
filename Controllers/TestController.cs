using System;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
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

    public TestController(IConfiguration config)
    {
      _config = config;
      _azObj = new Azure(_config);
    }

    // GET api/test
    [HttpGet]
    public async Task<ActionResult> Get()
    {
      
      // return _azObj.TestGetAccessToken();

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
  }
}