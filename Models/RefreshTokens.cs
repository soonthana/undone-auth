using System;

namespace Undone.Auth.Models
{
  public class RefreshTokens
  {
    public Guid Id { get; set; }
    public string RefreshToken { get; set; }
    public string AppAudienceId { get; set; }
    public string ResourceOwnerId { get; set; }
    public DateTime IssuedDateTime { get; set; }
    public DateTime ExpiryDateTime { get; set; }
    public bool Status { get; set; }
  }
}