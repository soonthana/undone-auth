using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Undone.Auth.Models;
using Undone.Auth.Utils;

namespace Undone.Auth.Controllers
{
  [Authorize]
  [ApiVersion("1.0")]
  [Route("api/[controller]")]
  public class AuthController : Controller
  {
    private IConfiguration _config;

    public AuthController(IConfiguration config)
    {
      _config = config;
    }

    // POST api/auth
    [AllowAnonymous]
    [HttpPost]
    public IActionResult ValidateToken([FromHeader(Name = "Auth-Jwt")] string token)
    {
      IActionResult response = Unauthorized();

      var headerKeys = string.Empty;
      foreach (var key in Request.Headers.Keys)
      {
        headerKeys += key.ToString() + ", ";
      }
      headerKeys = headerKeys.Substring(0, headerKeys.Length - 2);

      if (Request.Headers.Keys.Contains("Auth-Jwt"))
      {
        try
        {
          if (ModelState.IsValid) // ModelState อาจจะไม่จำเป็นต้องใช้ หรือใช้ไม่ได้กับ API
          {
            string[] jwtArray = token.Split('.');
            var jwtHeader = JwtHeader.Base64UrlDeserialize(jwtArray[0]);
            var jwtPayload = JwtPayload.Base64UrlDeserialize(jwtArray[1]);

            Jwt.Algorithm jwtAlg;

            if (jwtHeader.Alg == "HS256")
            {
              jwtAlg = Jwt.Algorithm.HS256;
            }
            else if (jwtHeader.Alg == "RS256")
            {
              jwtAlg = Jwt.Algorithm.RS256;
            }
            else if (jwtHeader.Alg == "ES256")
            {
              jwtAlg = Jwt.Algorithm.ES256;
            }
            else
            {
              jwtAlg = Jwt.Algorithm.HS256;
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
              var claimPrincipal = tokenHandler.ValidateToken(token, new TokenValidationParameters
              {
                ValidIssuer = _config["Jwt:Issuer"],
                ValidAudience = _config["Jwt:Audience"],
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.Zero,
                IssuerSigningKey = Jwt.GetSecurityKey(jwtAlg, _config)
              }, out var parsedToken);

              var result = claimPrincipal.Identity.IsAuthenticated;

              if (result)
              {
                return Ok(token);
              }
              else
              {
                response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND999", "Unauthorized, Invalid AccessToken (" + token + ").", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจาก AccessToken ไม่ถูกต้อง หรือหมดอายุแล้ว, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The AccessToken is invalid or expired, please contact your Application Administrator.");
              }
            }
            catch
            {
              response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND999", "Unauthorized, Invalid AccessToken (" + token + ").", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจาก AccessToken ไม่ถูกต้อง หรือหมดอายุแล้ว, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The AccessToken is invalid or expired, please contact your Application Administrator.");
            }
          }
          else // ModelState อาจจะไม่จำเป็นต้องใช้ หรือใช้ไม่ได้กับ API
          {
            response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND996", "Unauthorized, Invalid Model (There is invalid header key '" + headerKeys + "').", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจากส่งคำร้องขอมาไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The request is invalid, please contact your Application Administrator.");
          }
        }
        catch (Exception ex)
        {
          response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND997", "Unauthorized, Exception occurred (" + ex.Message + " - " + ex.Source + " - " + ex.StackTrace + " - " + ex.InnerException + " - " + ex.HelpLink + ").", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจากส่งคำร้องขอมาไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The request is invalid, please contact your Application Administrator.");
        }
      }
      else
      {
        response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, "UND996", "Unauthorized, Invalid Model (There is invalid header key '" + headerKeys + "').", "แอพฯ ของคุณไม่มีสิทธิ์ใช้งาน เนื่องจากส่งคำร้องขอมาไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ", "The request is invalid, please contact your Application Administrator.");
      }

      return response;
    }
  }
}