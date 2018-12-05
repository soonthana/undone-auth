using System;
using System.Collections.Generic;
using Undone.Auth.Models;

namespace Undone.Auth.Utils
{
  public static class AuthErrors
  {
    private static Dictionary<int, string> ErrorCode = new Dictionary<int, string>
    {
      {990, "UND990"},
      {991, "UND991"},
      {992, "UND992"},
      {993, "UND993"},
      {994, "UND994"},
      {995, "UND995"},
      {996, "UND996"},
      {997, "UND997"},
      {998, "UND998"},
      {999, "UND999"}
    };

    private static Dictionary<int, string> MessageToUserTh = new Dictionary<int, string>
    {
      {990, "ไม่มีสิทธิ์ใช้งาน เนื่องจากส่งคำร้องขอมาไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ"},
      {991, "ไม่มีสิทธิ์ใช้งาน เนื่องจาก App Id ไม่ถูกต้องหรือหมดอายุแล้ว, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ"},
      {992, "ไม่มีสิทธิ์ใช้งาน เนื่องจาก App Secret Key ไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ"},
      {993, "ไม่มีสิทธิ์ใช้งาน เนื่องจาก Username ของคุณไม่ถูกต้อง"},
      {994, "ไม่มีสิทธิ์ใช้งาน เนื่องจาก Password ของคุณไม่ถูกต้อง"},
      {995, "ไม่มีสิทธิ์ใช้งาน เนื่องจาก Authorization Code ไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ"},
      {996, "ไม่มีสิทธิ์ใช้งาน เนื่องจากส่งคำร้องขอมาไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ"},
      {997, "ไม่มีสิทธิ์ใช้งาน เนื่องจากส่งคำร้องขอมาไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ"},
      {998, "ไม่มีสิทธิ์ใช้งาน เนื่องจาก RefreshToken ไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ"},
      {999, "ไม่มีสิทธิ์ใช้งาน เนื่องจาก AccessToken ไม่ถูกต้อง, กรุณาติดต่อผู้ดูแลแอพฯ ของคุณ"}
    };

    private static Dictionary<int, string> MessageToUserEn = new Dictionary<int, string>
    {
      {990, "The request is invalid, please contact your Application Administrator."},
      {991, "The App Id is not correct or expired, please contact your Application Administrator."},
      {992, "The App Secret Key is not correct, please contact your Application Administrator."},
      {993, "Your Username is not correct."},
      {994, "Your Password is not correct."},
      {995, "The Authorization Code is invalid, please contact your Application Administrator."},
      {996, "The request is invalid, please contact your Application Administrator."},
      {997, "The request is invalid, please contact your Application Administrator."},
      {998, "The RefreshToken is invalid, please contact your Application Administrator."},
      {999, "The AccessToken is invalid, please contact your Application Administrator."}
    };

    public static string GetErrorCode(Errors error)
    {
      return ErrorCode[Convert.ToInt32(error.ToString("D"))];
    }

    public static string GetMessageToUser(Errors error, Languages lang)
    {
      if (lang.Equals(Languages.Thai))
      {
        return MessageToUserTh[Convert.ToInt32(error.ToString("D"))];
      }
      else
      {
        return MessageToUserEn[Convert.ToInt32(error.ToString("D"))];
      }
    }
  }
}