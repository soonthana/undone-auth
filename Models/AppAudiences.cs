using System;

namespace Undone.Auth.Models
{
  public class AppAudiences
  {
    public Guid Id { get; set; }
    public string AppSecretKey { get; set; }
    public string Name { get; set; }
    public string ContactEmail { get; set; }
    public DateTime CreatedDateTime { get; set; }
    public string CreatedBy { get; set; }
    public DateTime ExpiryDate { get; set; }

  }
}