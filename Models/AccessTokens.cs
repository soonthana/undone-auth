using System;

namespace Undone.Auth.Models
{
  public class AccessTokens
  {
    public Guid Id { get; set; }
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
    public DateTime IssuedDateTime { get; set; }
    public DateTime ExpiryDateTime { get; set; }
    public bool Status { get; set; }
  }
}