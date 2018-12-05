using System;

namespace Undone.Auth.Services
{
  public interface IMtlAuthentication
  {
      bool Check(string username, string password);
  }
}