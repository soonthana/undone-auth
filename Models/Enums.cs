using System;

namespace Undone.Auth.Models
{
  public enum Errors
  {
    ExceptionalOccured = 990,
    InvalidOrEmpty_ClientAppId = 991,
    InvalidOrEmpty_ClientSecretKey = 992,
    InvalidOrEmpty_Username = 993,
    InvalidOrEmpty_Password = 994,
    InvalidOrEmpty_AuthorizationCode = 995,
    InvalidOrEmpty_RedirectUri = 996,
    Invalid_Scope = 997,
    Invalid_RefreshToken = 998,
    Invalid_AccessToken = 999
  }

  public enum Languages
  {
    Thai = 1,
    English = 2
  }
}