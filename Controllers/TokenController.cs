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
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Undone.Auth.Models;
using Undone.Auth.Services;
using Undone.Auth.Utils;

namespace Undone.Auth.Controllers
{
  [Authorize]
  [ApiVersion("1.0")]
  // [Route("api/[controller]")]
  public class TokenController : Controller
  {
    private IConfiguration _config;
    private Firebase _authObj;
    private Azure _azObj;
    private const string HEADER_AUTH = "Auth-Jwt";
    private const string GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    private const string GRANT_TYPE_PASSWORD = "password";
    private const string GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
    private const string GRANT_TYPE_REFRESH_TOKEN = "refresh_token";

    public TokenController(IConfiguration config)
    {
      _config = config;
      _authObj = new Firebase(_config);
      _azObj = new Azure(_config);
    }

    #region PUBLIC METHODS
    // POST api/token
    [AllowAnonymous]
    [HttpPost]
    [Route("api/token")]
    public IActionResult CreateToken([FromBody] AuthenticationModel authen)
    {
      IActionResult response = Unauthorized();
      var objResult = new ObjectResult(String.Empty);

      try
      {
        if (ModelState.IsValid) // ModelState อาจจะไม่จำเป็นต้องใช้ หรือใช้ไม่ได้กับ API
        {
          if (authen.grant_type.ToLower() == GRANT_TYPE_CLIENT_CREDENTIALS)
          {
            if (authen.client_id != string.Empty && authen.client_id != "null" && authen.client_id != null)
            {
              if (authen.client_secret != string.Empty && authen.client_secret != "null" && authen.client_secret != null)
              {
                var appAudObj = GetAppAudiencesById(authen.client_id).Result;

                if (appAudObj != null)
                {
                  if (appAudObj.ExpiryDate > DateTime.UtcNow)
                  {
                    if (appAudObj.AppSecretKey == authen.client_secret)
                    {
                      var refreshTokenObj = BuildRefreshToken(authen.username, authen.client_id, GRANT_TYPE_CLIENT_CREDENTIALS, authen.authen_to_system, authen.code);
                      var accessTokenObj = BuildAccessToken(authen.username, authen.client_id, refreshTokenObj.RefreshToken, Jwt.Algorithm.ES256, GRANT_TYPE_CLIENT_CREDENTIALS);

                      var tokenResp = new TokenResponse();
                      tokenResp.token_type = "Bearer";
                      tokenResp.access_token = accessTokenObj.AccessToken;
                      tokenResp.expires_in = _config["Jwt:Expires"];
                      tokenResp.refresh_token = refreshTokenObj.RefreshToken;
                      tokenResp.refresh_token_expires_in = _config["Jwt:RefreshTokenExpires"];

                      response = Ok(tokenResp);
                    }
                    else
                    {
                      response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientSecretKey, "Unauthorized, Client App Secret Key (" + authen.client_secret + ") is invalid.");
                    }
                  }
                  else
                  {
                    response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientAppId, "Unauthorized, Client App Id (" + authen.client_id + ") is expired (" + appAudObj.ExpiryDate + ").");
                  }
                }
                else
                {
                  response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientAppId, "Unauthorized, Client App Id (" + authen.client_id + ") is invalid.");
                }
              }
              else
              {
                response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientSecretKey, "Unauthorized, Client App Secret Key is empty.");
              }
            }
            else
            {
              response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientAppId, "Unauthorized, Client App Id is empty.");
            }
          }
          else if (authen.grant_type.ToLower() == GRANT_TYPE_PASSWORD)
          {
            if (authen.client_id != string.Empty && authen.client_id != "null" && authen.client_id != null)
            {
              if (authen.client_secret != string.Empty && authen.client_secret != "null" && authen.client_secret != null)
              {
                if (authen.username != string.Empty && authen.username != "null" && authen.username != null)
                {
                  if (authen.password != string.Empty && authen.password != "null" && authen.password != null)
                  {
                    if (authen.authen_to_system != string.Empty && authen.authen_to_system != "null" && authen.authen_to_system != null)
                    {
                      var appAudObj = GetAppAudiencesById(authen.client_id).Result;

                      if (appAudObj != null)
                      {
                        if (appAudObj.ExpiryDate > DateTime.UtcNow)
                        {
                          if (appAudObj.AppSecretKey == authen.client_secret)
                          {
                            var IsValidated = false;

                            switch (authen.authen_to_system.ToLower())
                            {
                              case "mtl-agent":
                                // TODO: TO VALIDATE USERNAME AND PASSWORD AGAINST MTL AGENT SYSTEM
                                break;
                              case "mtl-smileclub":
                                // TODO: TO VALIDATE USERNAME AND PASSWORD AGAINST MTL SMILE CLUB SYSTEM
                                break;
                              case "mtl-employee":
                                // TODO: TO VALIDATE USERNAME AND PASSWORD AGAINST MTL EMPLOYEE SYSTEM
                                IsValidated = true;
                                break;
                            }

                            if (IsValidated)
                            {
                              var refreshTokenObj = BuildRefreshToken(authen.username, authen.client_id, GRANT_TYPE_PASSWORD, authen.authen_to_system, authen.code);
                              var accessTokenObj = BuildAccessToken(authen.username, authen.client_id, refreshTokenObj.RefreshToken, Jwt.Algorithm.ES256, GRANT_TYPE_PASSWORD);

                              var tokenResp = new TokenResponse();
                              tokenResp.token_type = "Bearer";
                              tokenResp.access_token = accessTokenObj.AccessToken;
                              tokenResp.expires_in = _config["Jwt:Expires"];
                              tokenResp.refresh_token = refreshTokenObj.RefreshToken;
                              tokenResp.refresh_token_expires_in = _config["Jwt:RefreshTokenExpires"];

                              response = Ok(tokenResp);
                            }
                            else
                            {
                              response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.ExceptionalOccured, "Unauthorized, Username and Password is not valid for the system (" + authen.authen_to_system + ").");
                            }
                          }
                          else
                          {
                            response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientSecretKey, "Unauthorized, Client App Secret Key (" + authen.client_secret + ") is invalid.");
                          }
                        }
                        else
                        {
                          response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientAppId, "Unauthorized, Client App Id (" + authen.client_id + ") is expired (" + appAudObj.ExpiryDate + ").");
                        }
                      }
                      else
                      {
                        response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientAppId, "Unauthorized, Client App Id (" + authen.client_id + ") is invalid.");
                      }
                    }
                    else
                    {
                      response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.ExceptionalOccured, "Unauthorized, Authentication System is empty.");
                    }
                  }
                  else
                  {
                    response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_Password, "Unauthorized, Password is empty.");
                  }
                }
                else
                {
                  response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_Username, "Unauthorized, Username is empty.");
                }
              }
              else
              {
                response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientSecretKey, "Unauthorized, Client App Secret Key is empty.");
              }
            }
            else
            {
              response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientAppId, "Unauthorized, Client App Id is empty.");
            }
          }
          else if (authen.grant_type.ToLower() == GRANT_TYPE_AUTHORIZATION_CODE)
          {
            if (authen.client_id != string.Empty && authen.client_id != "null" && authen.client_id != null)
            {
              if (authen.client_secret != string.Empty && authen.client_secret != "null" && authen.client_secret != null)
              {
                if (authen.code != string.Empty && authen.code != "null" && authen.code != null)
                {
                  if (authen.redirect_uri != string.Empty && authen.redirect_uri != "null" && authen.redirect_uri != null)
                  {
                    var appAudObj = GetAppAudiencesById(authen.client_id).Result;

                    if (appAudObj != null)
                    {
                      if (appAudObj.ExpiryDate > DateTime.UtcNow)
                      {
                        if (appAudObj.AppSecretKey == authen.client_secret)
                        {
                          var authCode = GetAuthorizationCodesById(authen.code).Result;

                          if (authCode != null)
                          {
                            if (authCode.ClientAppId == authen.client_id)
                            {
                              if (DateTime.Parse(authCode.ExpiryDateTime.Replace("Z", ".0000000")) > DateTime.Parse(DateTimes.ConvertToUtcDateTimeInThaiTimeZone(DateTime.UtcNow, DateTimes.DateTimeFormat.YearMonthDayByDashTHourMinuteSecondByColonZ, DateTimes.LanguageCultureName.ENGLISH_UNITED_STATES, DateTimes.DateTimeUtcOffset.HHMMByColon).Replace("Z", ".0000000")))
                              {
                                var refreshTokenObj = BuildRefreshToken(authen.username, authen.client_id, GRANT_TYPE_AUTHORIZATION_CODE, authen.authen_to_system, authen.code);
                                var accessTokenObj = BuildAccessToken(authen.username, authen.client_id, refreshTokenObj.RefreshToken, Jwt.Algorithm.ES256, GRANT_TYPE_AUTHORIZATION_CODE);

                                var tokenResp = new TokenResponse();
                                tokenResp.token_type = "Bearer";
                                tokenResp.access_token = accessTokenObj.AccessToken;
                                tokenResp.expires_in = _config["Jwt:Expires"];
                                tokenResp.refresh_token = refreshTokenObj.RefreshToken;
                                tokenResp.refresh_token_expires_in = _config["Jwt:RefreshTokenExpires"];

                                response = Ok(tokenResp);
                              }
                              else
                              {
                                response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_AuthorizationCode, "Unauthorized, Authorization Code (" + authen.code + ") is expired (" + authCode.ExpiryDateTime + ").");
                              }
                            }
                            else
                            {
                              response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_AuthorizationCode, "Unauthorized, Authorization Code (" + authen.code + ") is invalid (AuthorizationCode is not belong to Client App Id).");
                            }
                          }
                          else
                          {
                            response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_AuthorizationCode, "Unauthorized, Authorization Code (" + authen.code + ") is invalid.");
                          }
                        }
                        else
                        {
                          response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientSecretKey, "Unauthorized, Client App Secret Key (" + authen.client_secret + ") is invalid.");
                        }
                      }
                      else
                      {
                        response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientAppId, "Unauthorized, Client App Id (" + authen.client_id + ") is expired (" + appAudObj.ExpiryDate + ").");
                      }
                    }
                    else
                    {
                      response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientAppId, "Unauthorized, Client App Id (" + authen.client_id + ") is invalid.");
                    }
                  }
                  else
                  {
                    response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_RedirectUri, "Unauthorized, Client App Redirect Uri is empty.");
                  }
                }
                else
                {
                  response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_AuthorizationCode, "Unauthorized, Authorization Code is empty.");
                }
              }
              else
              {
                response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientSecretKey, "Unauthorized, Client App Secret Key is empty.");
              }
            }
            else
            {
              response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientAppId, "Unauthorized, Client App Id is empty.");
            }
          }
          else if (authen.grant_type.ToLower() == GRANT_TYPE_REFRESH_TOKEN)
          {
            if (authen.client_id != string.Empty && authen.client_id != "null" && authen.client_id != null)
            {
              if (authen.client_secret != string.Empty && authen.client_secret != "null" && authen.client_secret != null)
              {
                if (authen.refresh_token != string.Empty && authen.refresh_token != "null" && authen.refresh_token != null)
                {
                  var appAudObj = GetAppAudiencesById(authen.client_id).Result;

                  if (appAudObj != null)
                  {
                    if (appAudObj.ExpiryDate > DateTime.UtcNow)
                    {
                      if (appAudObj.AppSecretKey == authen.client_secret)
                      {
                        var rftkObj = GetRefreshTokenByToken(authen.refresh_token).Result;

                        if (rftkObj != null)
                        {
                          if (rftkObj.AppAudienceId == authen.client_id)
                          {
                            if (DateTime.Parse(rftkObj.ExpiryDateTime.Replace("Z", ".0000000")) > DateTime.Parse(DateTimes.ConvertToUtcDateTimeInThaiTimeZone(DateTime.UtcNow, DateTimes.DateTimeFormat.YearMonthDayByDashTHourMinuteSecondByColonZ, DateTimes.LanguageCultureName.ENGLISH_UNITED_STATES, DateTimes.DateTimeUtcOffset.HHMMByColon).Replace("Z", ".0000000")) && rftkObj.Status == true)
                            {
                              var alg = GetLastestAccessTokenAlgorithmByRefreshToken(authen.refresh_token).Result;

                              if (rftkObj.GrantType == GRANT_TYPE_PASSWORD)
                              {
                                var userId = GetUserIdByRefreshToken(authen.refresh_token).Result;

                                if (userId != null)
                                {
                                  var accessTokenObj = BuildAccessToken(userId, authen.client_id, authen.refresh_token, alg, GRANT_TYPE_REFRESH_TOKEN);

                                  var tokenResp = new TokenResponse();
                                  tokenResp.token_type = "Bearer";
                                  tokenResp.access_token = accessTokenObj.AccessToken;
                                  tokenResp.expires_in = _config["Jwt:Expires"];
                                  tokenResp.refresh_token = authen.refresh_token;
                                  tokenResp.refresh_token_expires_in = _config["Jwt:RefreshTokenExpires"];

                                  response = Ok(tokenResp);
                                }
                                else
                                {
                                  response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.Invalid_RefreshToken, "Unauthorized, RefreshToken (" + authen.refresh_token + ") is invalid (UserId is not found).");
                                }
                              }
                              else
                              {
                                var accessTokenObj = BuildAccessToken(authen.username, authen.client_id, authen.refresh_token, alg, GRANT_TYPE_REFRESH_TOKEN);

                                var tokenResp = new TokenResponse();
                                tokenResp.token_type = "Bearer";
                                tokenResp.access_token = accessTokenObj.AccessToken;
                                tokenResp.expires_in = _config["Jwt:Expires"];
                                tokenResp.refresh_token = authen.refresh_token;
                                tokenResp.refresh_token_expires_in = _config["Jwt:RefreshTokenExpires"];

                                response = Ok(tokenResp);
                              }
                            }
                            else
                            {
                              response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.Invalid_RefreshToken, "Unauthorized, RefreshToken (" + authen.refresh_token + ") is expired (" + rftkObj.ExpiryDateTime + ").");
                            }
                          }
                          else
                          {
                            response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.Invalid_RefreshToken, "Unauthorized, RefreshToken (" + authen.refresh_token + ") is invalid (RefreshToken is not belong to Client App Id).");
                          }
                        }
                        else
                        {
                          response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.Invalid_RefreshToken, "Unauthorized, RefreshToken (" + authen.refresh_token + ") is not found.");
                        }
                      }
                      else
                      {
                        response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientSecretKey, "Unauthorized, Client App Secret Key (" + authen.client_secret + ") is invalid.");
                      }
                    }
                    else
                    {
                      response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientAppId, "Unauthorized, Client App Id (" + authen.client_id + ") is expired (" + appAudObj.ExpiryDate + ").");
                    }
                  }
                  else
                  {
                    response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientAppId, "Unauthorized, Client App Id (" + authen.client_id + ") is invalid.");
                  }
                }
                else
                {
                  response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.Invalid_RefreshToken, "Unauthorized, RefreshToken is empty.");
                }
              }
              else
              {
                response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientSecretKey, "Unauthorized, Client App Secret Key is empty.");
              }
            }
            else
            {
              response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.InvalidOrEmpty_ClientAppId, "Unauthorized, Client App Id is empty.");
            }
          }
          else
          {
            response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.ExceptionalOccured, "Unauthorized, Grant Type (" + authen.grant_type.ToLower() + ") is invalid.");
          }
        }
        else // ModelState อาจจะไม่จำเป็นต้องใช้ หรือใช้ไม่ได้กับ API
        {
          response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.ExceptionalOccured, "Unauthorized, Input Model (grant_type: '" + authen.grant_type.ToLower() + "', client_id: '" + authen.client_id + "', user_id: '" + authen.username + "', refresh_token: '" + authen.refresh_token + "') is invalid.");
        }
      }
      catch (Exception ex)
      {
        response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.ExceptionalOccured, "Unauthorized, Exception occurred (" + ex.Message + " - " + ex.Source + " - " + ex.StackTrace + " - " + ex.InnerException + " - " + ex.HelpLink + ").");
      }

      return response;
    }

    // POST api/token/verify
    [AllowAnonymous]
    [HttpPost]
    [Route("api/token/verify")]
    public IActionResult VerifyToken([FromHeader(Name = HEADER_AUTH)] string token)
    {
      IActionResult response = Unauthorized();

      var headerKeys = string.Empty;
      foreach (var key in Request.Headers.Keys)
      {
        headerKeys += key.ToString() + ", ";
      }
      headerKeys = headerKeys.Substring(0, headerKeys.Length - 2);

      if (Request.Headers.Keys.Contains(HEADER_AUTH))
      {
        var reqHeader = Request.Headers.FirstOrDefault(h => h.Key == HEADER_AUTH);
        if (reqHeader.Value != string.Empty && reqHeader.Value != "null")
        {
          try
          {
            if (ModelState.IsValid) // ModelState อาจจะไม่จำเป็นต้องใช้ หรือใช้ไม่ได้กับ API
            {
              try
              {
                var handler = new JwtSecurityTokenHandler();
                var jwtSecToken = handler.ReadToken(token) as JwtSecurityToken;

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
                    IssuerSigningKey = Jwt.GetSecurityKey(jwtAlg, _config, _azObj)
                  }, out var parsedToken);

                  var isAuthen = claimPrincipal.Identity.IsAuthenticated;

                  if (isAuthen)
                  {
                    var result = "valid";
                    return Ok(new { result, token });
                  }
                  else
                  {
                    response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.Invalid_AccessToken, "Unauthorized, AccessToken (" + token + ") is invalid (Can Not Authenticated).");
                  }
                }
                catch (Exception ex)
                {
                  response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.Invalid_AccessToken, "Unauthorized, AccessToken (" + token + ") is invalid (>> " + ex.Message + ").");
                }
              }
              catch (Exception ex)
              {
                response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.Invalid_AccessToken, "Unauthorized, AccessToken (" + token + ") is invalid (> " + ex.Message + ").");
              }
            }
            else // ModelState อาจจะไม่จำเป็นต้องใช้ หรือใช้ไม่ได้กับ API
            {
              response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.ExceptionalOccured, "Unauthorized, Input Model ('" + headerKeys + "') is invalid.");
            }
          }
          catch (Exception ex)
          {
            response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.ExceptionalOccured, "Unauthorized, Exception occurred (" + ex.Message + " - " + ex.Source + " - " + ex.StackTrace + " - " + ex.InnerException + " - " + ex.HelpLink + ").");
          }
        }
        else
        {
          response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.Invalid_AccessToken, "Unauthorized, AccessToken is empty");
        }
      }
      else
      {
        response = CustomHttpResponse.Error(HttpStatusCode.Unauthorized, Errors.ExceptionalOccured, "Unauthorized, Input Model is invalid (There is no Auth-Jwt).");
      }

      return response;
    }
    #endregion

    #region PRIVATE METHODS
    private AccessTokens BuildAccessToken(string userId, string clientAppId, string refreshToken, Jwt.Algorithm alg, string grantType)
    {
      var obj = new AccessTokens();
      obj.Id = Guid.NewGuid();
      obj.RefreshToken = refreshToken;
      obj.IssuedDateTime = DateTimes.GetCurrentUtcDateTimeInThaiTimeZone(DateTimes.DateTimeFormat.YearMonthDayByDashTHourMinuteSecondByColonZ, DateTimes.LanguageCultureName.ENGLISH_UNITED_STATES, DateTimes.DateTimeUtcOffset.HHMMByColon);
      var AccessTokenExpiryDateTime = DateTime.UtcNow.AddSeconds(Convert.ToDouble(_config["Jwt:Expires"]));
      obj.ExpiryDateTime = DateTimes.ConvertToUtcDateTimeInThaiTimeZone(AccessTokenExpiryDateTime, DateTimes.DateTimeFormat.YearMonthDayByDashTHourMinuteSecondByColonZ, DateTimes.LanguageCultureName.ENGLISH_UNITED_STATES, DateTimes.DateTimeUtcOffset.HHMMByColon);

      Claim[] claims;

      if (grantType == GRANT_TYPE_PASSWORD)
      {
        claims = new[] {
          new Claim(JwtRegisteredClaimNames.Sub, userId),
          new Claim(JwtRegisteredClaimNames.Jti, obj.Id.ToString("N")),
          new Claim(JwtRegisteredClaimNames.Iat, DateTimes.ConvertToUnixTimeByDateTime(DateTime.UtcNow).ToString(), System.Security.Claims.ClaimValueTypes.Integer32),
          new Claim(JwtRegisteredClaimNames.Nbf, DateTimes.ConvertToUnixTimeByDateTime(DateTime.UtcNow).ToString(), System.Security.Claims.ClaimValueTypes.Integer32),
          new Claim("appid", clientAppId)
        };
      }
      else
      {
        claims = new[] {
          new Claim(JwtRegisteredClaimNames.Jti, obj.Id.ToString("N")),
          new Claim(JwtRegisteredClaimNames.Iat, DateTimes.ConvertToUnixTimeByDateTime(DateTime.UtcNow).ToString(), System.Security.Claims.ClaimValueTypes.Integer32),
          new Claim(JwtRegisteredClaimNames.Nbf, DateTimes.ConvertToUnixTimeByDateTime(DateTime.UtcNow).ToString(), System.Security.Claims.ClaimValueTypes.Integer32),
          new Claim("appid", clientAppId)
        };
      }

      var token = new JwtSecurityToken(
        issuer: _config["Jwt:Issuer"],
        audience: _config["Jwt:Audience"],
        claims: claims,
        expires: AccessTokenExpiryDateTime,
        notBefore: DateTime.UtcNow,
        signingCredentials: Jwt.CreateSigningCredentials(alg, _config, _azObj)
      );

      obj.AccessToken = new JwtSecurityTokenHandler().WriteToken(token);
      obj.Status = true;

      // Write Generated AccessToken to AuthDB (For future checking)
      var authAccessToken = _authObj.PutAccessTokens(obj);

      // Update RefreshToken to AuthDB (For future checking)
      var authRefreshToken = _authObj.PutRefreshTokensAccessToken(refreshToken, obj.AccessToken, obj.IssuedDateTime);

      return obj;
    }

    private RefreshTokens BuildRefreshToken(string userId, string clientAppId, string grantType, string authenToSystem, string authorizationCode)
    {
      var obj = new RefreshTokens();
      obj.Id = Guid.NewGuid();
      obj.AppAudienceId = clientAppId;
      obj.IssuedDateTime = DateTimes.GetCurrentUtcDateTimeInThaiTimeZone(DateTimes.DateTimeFormat.YearMonthDayByDashTHourMinuteSecondByColonZ, DateTimes.LanguageCultureName.ENGLISH_UNITED_STATES, DateTimes.DateTimeUtcOffset.HHMMByColon);
      var RefreshTokenExpiryDateTime = DateTime.UtcNow.AddSeconds(Convert.ToDouble(_config["Jwt:RefreshTokenExpires"]));
      obj.ExpiryDateTime = DateTimes.ConvertToUtcDateTimeInThaiTimeZone(RefreshTokenExpiryDateTime, DateTimes.DateTimeFormat.YearMonthDayByDashTHourMinuteSecondByColonZ, DateTimes.LanguageCultureName.ENGLISH_UNITED_STATES, DateTimes.DateTimeUtcOffset.HHMMByColon);
      obj.GrantType = grantType;
      if (grantType == GRANT_TYPE_PASSWORD)
      {
        obj.ResourceOwnerId = userId;
        obj.AuthenToSystem = authenToSystem;
      }
      if (grantType == GRANT_TYPE_AUTHORIZATION_CODE)
      {
        obj.AuthorizationCode = authorizationCode;
      }

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

    private async Task<RefreshTokens> GetRefreshTokenByToken(string refreshToken)
    {
      var authRefreshToken = await _authObj.GetRefreshTokenByToken(refreshToken);
      var authRefreshTokenJsonString = authRefreshToken.Content.ReadAsStringAsync().Result.ToString();

      if (authRefreshToken.StatusCode == HttpStatusCode.OK && (authRefreshTokenJsonString != "null" && authRefreshTokenJsonString != null))
      {
        return JsonConvert.DeserializeObject<RefreshTokens>(authRefreshTokenJsonString);
      }
      else
      {
        return null;
      }
    }

    private async Task<string> GetUserIdByRefreshToken(string refreshToken)
    {
      var accessToken = await GetLastestAccessTokenByRefreshToken(refreshToken);

      if (accessToken != null)
      {
        var jwtUniqueName = string.Empty;

        foreach (Claim c in accessToken.Claims)
        {
          if (c.Type == "sub")
          {
            jwtUniqueName = c.Value;
          }
        }

        return jwtUniqueName == string.Empty ? null : jwtUniqueName;
      }
      else
      {
        return null;
      }
    }

    private async Task<Jwt.Algorithm> GetLastestAccessTokenAlgorithmByRefreshToken(string refreshToken)
    {
      var accessToken = await GetLastestAccessTokenByRefreshToken(refreshToken);

      if (accessToken != null)
      {
        var jwtHeaderAlg = accessToken.Header.Alg;

        Jwt.Algorithm jwtAlg;

        if (jwtHeaderAlg == "HS256")
        {
          jwtAlg = Jwt.Algorithm.HS256;
        }
        else if (jwtHeaderAlg == "RS256")
        {
          jwtAlg = Jwt.Algorithm.RS256;
        }
        else if (jwtHeaderAlg == "ES256")
        {
          jwtAlg = Jwt.Algorithm.ES256;
        }
        else
        {
          jwtAlg = Jwt.Algorithm.HS256;
        }

        return jwtAlg;
      }
      else
      {
        return Jwt.Algorithm.HS256;
      }
    }

    private async Task<JwtSecurityToken> GetLastestAccessTokenByRefreshToken(string refreshToken)
    {
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

        var latestAccessToken = jkvList.OrderByDescending(o => DateTime.Parse(o.Value.Replace("Z", ".0000000"))).FirstOrDefault();

        var handler = new JwtSecurityTokenHandler();
        var jwtSecToken = handler.ReadToken(latestAccessToken.Key) as JwtSecurityToken;

        return jwtSecToken;
      }
      else
      {
        return null;
      }
    }

    private async Task<AuthorizationCodes> GetAuthorizationCodesById(string code)
    {
      var authCode = await _authObj.GetAuthorizationCodesById(code);
      var authCodeJsonString = authCode.Content.ReadAsStringAsync().Result.ToString();

      if (authCode.StatusCode == HttpStatusCode.OK && (authCodeJsonString != "null" && authCodeJsonString != null))
      {
        return JsonConvert.DeserializeObject<AuthorizationCodes>(authCodeJsonString);
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
    #endregion
  }
}