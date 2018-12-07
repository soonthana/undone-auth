using System;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Undone.Auth.Models;
using Undone.Auth.Services;
using Undone.Auth.Utils;

namespace Undone.Auth.Controllers
{
  public class AuthController : Controller
  {
    private IConfiguration _config;
    private Firebase _authObj;

    public AuthController(IConfiguration config)
    {
      _config = config;
      _authObj = new Firebase(_config);
    }

    // GET /Auth/
    public IActionResult Index([FromQuery] string response_type, string client_id, string redirect_uri, string state, string authen_to_system)
    {
      if (response_type != string.Empty && response_type != "null" && response_type != null && response_type.ToLower() == "code")
      {
        if (client_id != string.Empty && client_id != "null" & client_id != null)
        {
          if (redirect_uri != string.Empty && redirect_uri != "null" && redirect_uri != null)
          {
            if (authen_to_system != string.Empty && authen_to_system != "null" && authen_to_system != null)
            {
              var authAppAudience = _authObj.GetAppAudiencesById(client_id).Result;
              var authAppAudienceJsonString = authAppAudience.Content.ReadAsStringAsync().Result.ToString();

              if (authAppAudience.StatusCode == HttpStatusCode.OK && (authAppAudienceJsonString != "null" && authAppAudienceJsonString != null))
              {
                var authCodeObj = new AuthorizationCodeModel();

                return View();
              }
              else
              {
                return CustomHttpResponse.Error(HttpStatusCode.BadRequest, Errors.InvalidOrEmpty_ClientAppId, "Client_Id is invalid");
              }
            }
            else
            {
              return CustomHttpResponse.Error(HttpStatusCode.BadRequest, Errors.ExceptionalOccured, "Authen_To_System is empty");
            }
          }
          else
          {
            return CustomHttpResponse.Error(HttpStatusCode.BadRequest, Errors.ExceptionalOccured, "Redirect_Uri is empty");
          }
        }
        else
        {
          return CustomHttpResponse.Error(HttpStatusCode.BadRequest, Errors.ExceptionalOccured, "Client_Id is empty");
        }
      }
      else
      {
        return CustomHttpResponse.Error(HttpStatusCode.BadRequest, Errors.ExceptionalOccured, "Response_Type is invalid");
      }
    }

    // POST /Auth/
    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Index([Bind("Response_Type,Client_Id,Redirect_Uri,State,Authen_To_System,username,password")] string username, string password, AuthorizationCodeModel authCodeObj)
    {
      try
      {
        IActionResult response = Unauthorized();

        if (ModelState.IsValid)
        {
          if (username != string.Empty && username != "null" && username != null)
          {
            if (password != string.Empty && password != "null" && password != null)
            {
              var IsValidated = false;

              switch (authCodeObj.Authen_To_System.ToLower())
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
                var code = Guid.NewGuid();

                if (authCodeObj.State != string.Empty && authCodeObj.State != "null" && authCodeObj.State != null)
                {
                  response = Redirect(authCodeObj.Redirect_Uri + "?code=" + code + "&state=" + authCodeObj.State);
                }
                else
                {
                  response = Redirect(authCodeObj.Redirect_Uri + "?code=" + code);
                }

                return response;
              }
              else
              {
                return View();
              }
            }
            else
            {
              return View();
            }
          }
          else
          {
            return View();
          }
        }
        else
        {
          return View();
        }
      }
      catch
      {
        return View();
      }
    }
  }
}