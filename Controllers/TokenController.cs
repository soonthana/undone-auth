using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Undone.Auth.Models;
using Undone.Auth.Services;
using Undone.Auth.Utils;

namespace Undone.Auth.Controllers
{
  [Authorize]
  [ApiVersion("1.0")]
  [Route("api/[controller]")]
  public class TokenController : Controller
  {
    private IConfiguration _config;
    private Firebase _authObj;

    public TokenController(IConfiguration config)
    {
      _config = config;
      _authObj = new Firebase(_config);
    }

    // POST api/token
    [AllowAnonymous]
    [HttpPost]
    public IActionResult CreateToken([FromBody] AuthenticationModel authen)
    {
      IActionResult response = Unauthorized();
      var objResult = new ObjectResult(String.Empty);

      try
      {
        if (ModelState.IsValid) // ModelState อาจจะไม่จำเป็นต้องใช้ หรือใช้ไม่ได้กับ API
        {
          if (authen.Grant_Type.ToLower() == "password")
          {
            if (authen.Client_Id != string.Empty)
            {
              if (authen.Client_Secret_Key != string.Empty)
              {
                if (authen.User_Id != string.Empty)
                {
                  var appAudObj = GetAppAudiencesById(authen.Client_Id).Result;

                  if (appAudObj != null)
                  {
                    if (appAudObj.ExpiryDate > DateTime.UtcNow)
                    {
                      if (appAudObj.AppSecretKey == authen.Client_Secret_Key)
                      {
                        var refreshTokenObj = BuildRefreshToken(authen.User_Id, authen.Client_Id);
                        var accessTokenObj = BuildAccessToken(authen.User_Id, authen.Client_Id, refreshTokenObj.RefreshToken, Jwt.Algorithm.ES256);

                        response = Ok(new { access_token = accessTokenObj.AccessToken, token_type = "Bearer", expires_in = _config["Jwt:Expires"], refresh_token = refreshTokenObj.RefreshToken, refresh_token_expires_in = _config["Jwt:RefreshTokenExpires"] });
                      }
                      else
                      {
                        response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND992", "Unauthorized, Invalid Client App Secret Key (" + authen.Client_Secret_Key + ").", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจาก App Secret Key ไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The App Secret Key is invalid, please contact your Application Administrator.");
                      }
                    }
                    else
                    {
                      response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND991", "Unauthorized, Invalid Client App Id (" + authen.Client_Id + ") , Expired (" + appAudObj.ExpiryDate + ").", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจาก App Id หมดอายุแล้ว, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The App Id is expired, please contact your Application Administrator.");
                    }
                  }
                  else
                  {
                    response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND991", "Unauthorized, Invalid Client App Id (" + authen.Client_Id + ").", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจาก App Id ไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The App Id is invalid, please contact your Application Administrator.");
                  }
                }
                else
                {
                  response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND995", "Unauthorized, Empty User Id.", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจาก User Id ไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The User Id is incorrect, please contact your Application Administrator.");
                }
              }
              else
              {
                response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND994", "Unauthorized, Empty Client App Secret Key.", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจาก App Secret ไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The App Secret is incorrect, please contact your Application Administrator.");
              }
            }
            else
            {
              response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND993", "Unauthorized, Empty Client App Id.", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจาก App Id ไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The App Id is incorrect, please contact your Application Administrator.");
            }
          }
          else if (authen.Grant_Type.ToLower() == "refresh_token")
          {
            if (authen.Client_Id != string.Empty)
            {
              if (authen.Refresh_Token != string.Empty)
              {
                var appAudObj = GetAppAudiencesById(authen.Client_Id).Result;

                if (appAudObj != null)
                {
                  var userId = GetUserIdByRefreshToken(authen.Refresh_Token, authen.Client_Id).Result;

                  if (userId != null)
                  {
                    var accessTokenObj = BuildAccessToken(userId, authen.Client_Id, authen.Refresh_Token, Jwt.Algorithm.ES256);

                    response = Ok(new { access_token = accessTokenObj.AccessToken, token_type = "Bearer", expires_in = _config["Jwt:Expires"], refresh_token = authen.Refresh_Token, refresh_token_expires_in = _config["Jwt:RefreshTokenExpires"] });
                  }
                  else
                  {
                    response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND998", "Unauthorized, Invalid RefreshToken (" + authen.Refresh_Token + ").", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจาก RefreshToken ไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The RefreshToken is invalid, please contact your Application Administrator.");
                  }
                }
                else
                {
                  response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND991", "Unauthorized, Invalid Client App Id (" + authen.Client_Id + ").", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจาก App Id ไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The App Id is invalid, please contact your Application Administrator.");
                }
              }
              else
              {
                response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND998", "Unauthorized, Invalid RefreshToken (" + authen.Refresh_Token + ").", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจาก RefreshToken ไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The RefreshToken is invalid, please contact your Application Administrator.");
              }
            }
            else
            {
              response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND993", "Unauthorized, Empty Client App Id.", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจาก App Id ไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The App Id is incorrect, please contact your Application Administrator.");
            }
          }
          else
          {
            response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND996", "Unauthorized, Invalid Model (grant_type: '" + authen.Grant_Type.ToLower() + "', client_id: '" + authen.Client_Id + "', user_id: '" + authen.User_Id + "', refresh_token: '" + authen.Refresh_Token + "').", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจากส่งคำร้องขอมาไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The request is invalid, please contact your Application Administrator.");
          }
        }
        else // ModelState อาจจะไม่จำเป็นต้องใช้ หรือใช้ไม่ได้กับ API
        {
          response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND996", "Unauthorized, Invalid Model (grant_type: '" + authen.Grant_Type.ToLower() + "', client_id: '" + authen.Client_Id + "', user_id: '" + authen.User_Id + "', refresh_token: '" + authen.Refresh_Token + "').", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจากส่งคำร้องขอมาไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The request is invalid, please contact your Application Administrator.");
        }
      }
      catch (Exception ex)
      {
        response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND997", "Unauthorized, Exception occurred (" + ex.Message + " - " + ex.Source + " - " + ex.StackTrace + " - " + ex.InnerException + " - " + ex.HelpLink + ").", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจากส่งคำร้องขอมาไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The request is invalid, please contact your Application Administrator.");
      }

      return response;
    }

    private AccessTokens BuildAccessToken(string userId, string clientAppId, string refreshToken, Jwt.Algorithm alg)
    {
      var obj = new AccessTokens();
      obj.Id = Guid.NewGuid();
      obj.RefreshToken = refreshToken;
      obj.IssuedDateTime = DateTime.UtcNow;
      obj.ExpiryDateTime = DateTime.UtcNow.AddSeconds(Convert.ToDouble(_config["Jwt:Expires"]));

      var claims = new[] {
        new Claim(JwtRegisteredClaimNames.UniqueName, userId),
        new Claim(JwtRegisteredClaimNames.Sub, userId),
        new Claim(JwtRegisteredClaimNames.Jti, obj.Id.ToString("N"))
      };

      var token = new JwtSecurityToken(
        _config["Jwt:Issuer"],
        _config["Jwt:Audience"],
        claims,
        expires: obj.ExpiryDateTime,
        signingCredentials: Jwt.CreateSigningCredentials(alg, _config)
      );

      obj.AccessToken = new JwtSecurityTokenHandler().WriteToken(token);
      obj.Status = true;

      // Write Generated AccessToken to AuthDB (For future checking)
      var authAccessToken = _authObj.PutAccessTokens(obj);

      // Update RefreshToken to AuthDB (For future checking)
      var authRefreshToken = _authObj.PutRefreshTokensAccessToken(refreshToken, obj.AccessToken, DateTimes.ConvertToUtcDateTimeInThaiTimeZone(obj.IssuedDateTime, DateTimes.DateTimeFormat.YearMonthDayHourMinuteSecond, DateTimes.LanguageCultureName.ENGLISH_UNITED_STATES, DateTimes.DateTimeUtcOffset.HHMM));

      return obj;
    }

    private RefreshTokens BuildRefreshToken(string userId, string clientAppId)
    {
      var obj = new RefreshTokens();
      obj.Id = Guid.NewGuid();
      obj.AppAudienceId = clientAppId;
      obj.ResourceOwnerId = userId;
      obj.IssuedDateTime = DateTime.UtcNow;
      obj.ExpiryDateTime = DateTime.UtcNow.AddSeconds(Convert.ToDouble(_config["Jwt:RefreshTokenExpires"]));

      var key = Encoding.UTF8.GetBytes(obj.AppAudienceId);
      var message = Encoding.UTF8.GetBytes(obj.Id.ToString("N"));

      obj.RefreshToken = ReplaceInvalidCharacterForJwt(Convert.ToBase64String(HashingByHMACSHA256(message, key)));
      obj.Status = true;

      // Write Generated RefreshToken to AuthDB (For future checking)
      var authRefreshToken = _authObj.PutRefreshTokens(obj);

      return obj;
    }

    private async Task<AppAudiences> GetAppAudiencesById(string clientAppId)
    {
      // Get an client application from AuthDB
      var authAppAudience = await _authObj.GetAppAudiencesById(clientAppId);
      var authAppAudienceJsonString = authAppAudience.Content.ReadAsStringAsync().Result.ToString();

      if (authAppAudience.StatusCode == HttpStatusCode.OK && (authAppAudienceJsonString != "null" && authAppAudienceJsonString != null))
      {
        return JsonConvert.DeserializeObject<AppAudiences>(authAppAudienceJsonString);
      }
      else
      {
        return null;
      }
    }

    private async Task<string> GetUserIdByRefreshToken(string refreshToken, string clientAppId)
    {
      if (refreshToken != "")
      {
        // Get a RefreshToken from AuthDB
        var authRefreshToken = await _authObj.GetRefreshTokenByToken(refreshToken);
        var authRefreshTokenJsonString = authRefreshToken.Content.ReadAsStringAsync().Result.ToString();

        if (authRefreshToken.StatusCode == HttpStatusCode.OK && (authRefreshTokenJsonString != "null" && authRefreshTokenJsonString != null))
        {
          var rftkObj = JsonConvert.DeserializeObject<RefreshTokens>(authRefreshTokenJsonString);

          // Check ClientAppId is valid for RefreshToken
          if (rftkObj.AppAudienceId == clientAppId)
          {
            // Check is valid RefreshToken
            if (rftkObj.ExpiryDateTime > DateTime.UtcNow && rftkObj.Status == true)
            {
              // Get latest AccessToken
              var authRefreshTokenAccessToken = await _authObj.GetRefreshTokenAccessTokensByToken(refreshToken);
              var authRefreshTokenAccessTokenJsonString = authRefreshTokenAccessToken.Content.ReadAsStringAsync().Result.ToString();

              if (authRefreshTokenAccessToken.StatusCode == HttpStatusCode.OK && (authRefreshTokenAccessTokenJsonString != "null" && authRefreshTokenAccessTokenJsonString != null))
              {
                var accessTokenList = JObject.Parse(authRefreshTokenAccessTokenJsonString);
                var jkvList = new List<JsonKeyValue>();

                foreach (var item in accessTokenList)
                {
                  var jkv = new JsonKeyValue();
                  jkv.Key = item.Key.Replace("---", ".");
                  jkv.Value = item.Value.ToString();

                  jkvList.Add(jkv);
                }

                var latestAccessToken = jkvList.OrderByDescending(o => o.Value).FirstOrDefault();
                var accessToken = latestAccessToken.Key;

                // Decoding latest Access Token from DB (not use key)
                var handler = new JwtSecurityTokenHandler();
                var token = handler.ReadToken(accessToken) as JwtSecurityToken;
                var jwtUniqueName = string.Empty;

                foreach (Claim c in token.Claims)
                {
                  if (c.Type == "unique_name")
                  {
                    jwtUniqueName = c.Value;
                  }
                }

                return jwtUniqueName;
              }
              else
              {
                return null;
              }
            }
            else
            {
              return null;
            }
          }
          else
          {
            return null;
          }
        }
        else
        {
          return null;
        }
      }
      else
      {
        return null;
      }
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

    private class JsonKeyValue
    {
      public string Key { get; set; }
      public string Value { get; set; }
    }
  }
}