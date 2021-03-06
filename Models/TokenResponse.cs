using System;

namespace Undone.Auth.Models
{
  public class TokenResponse
  {
    public string token_type { get; set; }
    public string access_token { get; set; }
    public string expires_in { get; set; }
    public string refresh_token { get; set; }
    public string refresh_token_expires_in { get; set; }
  }
}