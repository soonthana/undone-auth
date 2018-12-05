using System;
using Microsoft.AspNetCore.Mvc;

namespace Undone.Auth.Controllers
{
  [Route("[controller]/[action]/{id?}")]
  public class WebController : Controller
  {
    public IActionResult Index()
    {
      return View();
    }
  }
}