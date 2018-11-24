using System;
using Microsoft.AspNetCore.Mvc;

namespace Undone.Auth.Controllers
{
  [Route("api/[controller]")]
  [ApiController]
  public class TestController : ControllerBase
  {
    private string azAuthUrl = "https://login.microsoftonline.com/#[AZTENANTID]#/oauth2/";
    private string azTenantId = "36727d4d-abcb-4dc8-abd3-03c84096b2d1";
    private string azAppClientId = "54277f90-56ba-4f9c-aa0d-2377d1d5e601";
    private string azAppSecretKey = "RzS7i+vc8AUxq6Q2yFYtTozEKRF/BrPlvsX/96cbFas=";
    private string azAppUrl = "https://soonthanagmail.onmicrosoft.com/4ad4212e-a16f-4f09-a3aa-e1323308a64d";
    private string azProjKVUrl = "https://stntestkv.vault.azure.net/";

    // GET api/test
    [HttpGet]
    public ActionResult<string> Get()
    {
      return "test test";
    }

    private string GetAccessToken()
    {
      var authUrl = azAuthUrl.Replace("#[AZTENANTID]#", azTenantId) + "token";

      /* FOR AZURE OAUTH2 v2.0 */
      // var authUrl = azAuthUrl.Replace("#[AZTENANTID]#", azTenantId) + "v2.0/token";
      // var appUrl = azAppUrl + "/.default";

      return "";
    }
  }
}