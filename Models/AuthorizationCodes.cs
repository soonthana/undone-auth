using System;

namespace Undone.Auth.Models
{
  public class AuthorizationCodes
  {
    public Guid Id { get; set; }
    public string ClientAppId { get; set; }
    public string RedirectUri { get; set; }
    public string State { get; set; }
    public string CreatedDateTime { get; set; }
    public string ExpiryDateTime { get; set; }
    public string AuthenToSystem { get; set; }
  }
}