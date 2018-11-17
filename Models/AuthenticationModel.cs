using System;

namespace Undone.Auth.Models
{
  public class AuthenticationModel
  {
    public string Grant_Type { get; set; }
    public string Client_Id { get; set; }
    public string Client_Secret_Key { get; set; }
    public string User_Id { get; set; }
    public string Refresh_Token { get; set; }
  }
}