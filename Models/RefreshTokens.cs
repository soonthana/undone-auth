using System;

namespace Undone.Auth.Models
{
  public class RefreshTokens
  {
    public Guid Id { get; set; }
    public string RefreshToken { get; set; }
    public string AppAudienceId { get; set; }
    public string ResourceOwnerId { get; set; }
    public string IssuedDateTime { get; set; }
    public string ExpiryDateTime { get; set; }
    public bool Status { get; set; }
    public string GrantType { get; set; }
    public string AuthenToSystem { get; set; }
    public string AuthorizationCode { get; set; }
  }
}