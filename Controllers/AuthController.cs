using System;
using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Undone.Auth.Models;
using Undone.Auth.Services;
using Undone.Auth.Utils;

namespace Undone.Auth.Controllers
{
  [Authorize]
  [ApiVersion("1.0")]
  public class AuthController : Controller
  {
    private IConfiguration _config;
    private Azure _azObj;

    public AuthController(IConfiguration config)
    {
      _config = config;
      // _azObj = new Azure(_config);
    }

    // GET /api/auth?response_type=code&client_id=<CLIENT_APP_ID>&redirect_uri=<CLIENT_APP_REDIRECT_URI>&state=<CLIENT_APP_STATE>
    [AllowAnonymous]
    [HttpGet]
    [Route("api/auth")]
    public IActionResult CreateAuthorizationCode([FromQuery] string response_type, string client_id, string redirect_uri, string state, string authen_to_system)
    {
      IActionResult response = Unauthorized();

      if (response_type != string.Empty && response_type != "null" && response_type != null && response_type.ToLower() == "code")
      {
        if (client_id != string.Empty && client_id != "null" & client_id != null)
        {
          if (redirect_uri != string.Empty && redirect_uri != "null" && redirect_uri != null)
          {
            if (authen_to_system != string.Empty && authen_to_system != "null" && authen_to_system != null)
            {
              // TODO: REDIRECT TO USER VALIDATION FORM AND VALIDATE IT

              var code = Guid.NewGuid();

              if (state != string.Empty && state != "null" && state != null)
              {
                response = Redirect(redirect_uri + "?code=" + code + "&state=" + state);
              }
              else
              {
                response = Redirect(redirect_uri + "?code=" + code);
              }

              return response;
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
  }
}