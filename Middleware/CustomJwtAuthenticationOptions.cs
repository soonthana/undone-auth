using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Primitives;

namespace Undone.Auth.Middleware
{
  public class CustomJwtAuthenticationOptions : AuthenticationSchemeOptions
  {
    public const string DefaultScheme = "Undone-CustomJwtAuth";
    public string Scheme => DefaultScheme;
  }
}