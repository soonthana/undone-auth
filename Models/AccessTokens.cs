using System;

namespace Undone.Auth.Models
{
  public class AccessTokens
  {
    public Guid Id { get; set; }
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
    public string IssuedDateTime { get; set; }
    public string ExpiryDateTime { get; set; }
    public bool Status { get; set; }
  }
}