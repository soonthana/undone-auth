using System;

namespace Undone.Auth.Models
{
  public class AuthorizationCodeModel
  {
    public string Response_Type { get; set; }
    public string Client_Id { get; set; }
    public string Redirect_Uri { get; set; }
    public string State { get; set; }
    public string Authen_To_System { get; set; }
  }
}