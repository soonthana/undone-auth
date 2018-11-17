using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Undone.Auth.Models;
using Undone.Auth.Services;

namespace Undone.Auth.Controllers
{
  [Authorize]
  [ApiVersion("1.0")]
  [Route("api/[controller]/v{ver:ApiVersion}")]
  public class ClientAppController : Controller
  {
    private IConfiguration _config;

    public ClientAppController(IConfiguration config)
    {
      _config = config;
    }

    // GET api/ClientApp
    [HttpGet]
    public string Get()
    {
      return null;
    }

    // GET api/ClientApp/5
    [HttpGet]
    public string Get(int id)
    {
      return null;
    }

    // POST api/ClientApp
    [HttpPost]
    public async Task<IActionResult> Post([FromBody]ClientAppModel client)
    {
      IActionResult response = Unauthorized();

      try
      {
        if (ModelState.IsValid)
        {
          var app = new AppAudiences();
          app.Id = Guid.NewGuid();
          
          //app.AppSecretKey = GetRandomCharacter(16, RemoveCharacter(app.Id.ToString("N")));
          var key = Encoding.UTF8.GetBytes(client.Password);
          var message = Encoding.UTF8.GetBytes(app.Id.ToString("N"));
          app.AppSecretKey = ReplaceInvalidCharacterForJwt(Convert.ToBase64String(HashingByHMACSHA256(message, key)));
          
          app.CreatedDateTime = DateTime.UtcNow;
          app.ExpiryDate = DateTime.UtcNow.AddMonths(3);
          app.CreatedBy = client.CreatedBy;
          app.Name = client.Name;
          app.ContactEmail = client.ContactEmail;

          var fb = new Firebase(_config);
          var resp = await fb.PutAppAudiences(app);
          var jsonString = resp.Content.ReadAsStringAsync().Result.ToString();

          if (resp.StatusCode == HttpStatusCode.OK)
          {
            response = Ok(app);
            return response;
          }
          else
          {
            return response;
          }
        }
        else
        {
          response = BadRequest();
          return response;
        }
      }
      catch (Exception ex)
      {
        response = BadRequest(ex.Message);
        return response;
      }
    }

    // PUT api/ClientApp/5
    [HttpPut("{id}")]
    public void Put(int id, [FromBody]string value)
    {
    }

    // DELETE api/ClientApp/5
    [HttpDelete("{id}")]
    public void Delete(int id)
    {
    }



    /// <summary>
    /// ใช้สำหรับ Random ตัวอักษรเท่านั้น
    /// </summary>
    /// <param name="numChars">จำนวนตัวอักษรที่ต้องการให้ Random ออกมา</param>
    /// <param name="seed">จำนวน seed ที่จะใช้</param>
    /// <returns></returns>
    public string GetRandomCharacter(int numChars, int seed)
    {
      string[] chars = { "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "P", "Q", "R", "S",
                        "T", "U", "V", "W", "X", "Y", "Z", "2", "3", "4", "5", "6", "7", "8", "9" };

      Random rnd = new Random(seed);
      string random = string.Empty;
      for (int i = 0; i < numChars; i++)
      {
        random = random + chars[rnd.Next(0, chars.Length)];
      }

      return random;
    }

    /// <summary>
    /// ใช้สำหรับ remove เอาตัวอักษรออกไป ให้เหลือเฉพาะตัวเลขจำนวนเต็มบวก
    /// </summary>
    /// <param name="TextToRemove"></param>
    /// <returns></returns>
    public int RemoveCharacter(string TextToRemove)
    {
      string result = "";
      Regex regex = new Regex(@"^\d+$");

      for (int i = 0; i < TextToRemove.Length; i++)
      {
        if (regex.IsMatch(TextToRemove.Substring(i, 1)))
        {
          result += TextToRemove.Substring(i, 1);
        }
      }

      if (result.Length > 10)
      {
        result = result.Substring(0, 9);
      }

      return Convert.ToInt32(result);
    }

    private byte[] HashingByHMACSHA256(byte[] message, byte[] key)
    {
      var hash = new HMACSHA256(key);

      return hash.ComputeHash(message);
    }

    private string ReplaceInvalidCharacterForJwt(string textToReplace)
    {
      return textToReplace.Replace("+", "-").Replace("/", "_").Replace("-", "");
    }

  }
}