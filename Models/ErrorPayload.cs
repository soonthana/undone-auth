using System;

namespace Undone.Auth.Models
{
  public class ErrorPayload
  {
    public string errorId { get; set; }
    public string code { get; set; }
    public string messageToDeveloper { get; set; }
    public MessageToUserDetail messageToUser { get; set; }
    public string created { get; set; }
  }

  public class MessageToUserDetail
  {
    public string langTh { get; set; }
    public string langEn { get; set; }
  }
}