using System;
using System.Text.RegularExpressions;

namespace Undone.Auth.Utils
{
  public static class Validations
  {
    #region Public Static Methods
    /// <summary>
    /// ใช้สำหรับตรวจสอบว่าเป็น URL ที่ถูกต้องหรือไม่
    /// </summary>
    /// <param name="value"></param>
    /// <returns></returns>
    public static bool IsURL(string value)
    {
      return Regex.IsMatch(value, @"(https?|ftp)://(-\.)?([^\s/?\.#-]+\.?)+(/[^\s]*)?$", RegexOptions.IgnoreCase); //@imme_emosol https://mathiasbynens.be/demo/url-regex
    }

    /// <summary>
    /// ใช้สำหรับตรวจสอบว่าเป็นหมายเลขโทรศัพท์พื้นฐานของไทยที่ถูกต้องหรือไม่
    /// </summary>
    /// <param name="value"></param>
    /// <returns></returns>
    public static bool IsThaiPhoneNumber(string value)
    {
      return Regex.IsMatch(value, @"^02\d{7}$|032\d{6}$|033\d{6}$|034\d{6}$|035\d{6}$|036\d{6}$|037\d{6}$|038\d{6}$|039\d{6}$|042\d{6}$|043\d{6}$|044\d{6}$|045\d{6}$|053\d{6}$|054\d{6}$|055\d{6}$|056\d{6}$|073\d{6}$|074\d{6}$|075\d{6}$|076\d{6}$|077\d{6}$", RegexOptions.IgnoreCase); //https://th.wikipedia.org/wiki/%E0%B8%AB%E0%B8%A1%E0%B8%B2%E0%B8%A2%E0%B9%80%E0%B8%A5%E0%B8%82%E0%B9%82%E0%B8%97%E0%B8%A3%E0%B8%A8%E0%B8%B1%E0%B8%9E%E0%B8%97%E0%B9%8C%E0%B9%83%E0%B8%99%E0%B8%9B%E0%B8%A3%E0%B8%B0%E0%B9%80%E0%B8%97%E0%B8%A8%E0%B9%84%E0%B8%97%E0%B8%A2
    }

    /// <summary>
    /// ใช้สำหรับตรวจสอบว่าเป็นหมายเลขโทรศัพท์เคลื่อนที่ของไทยที่ถูกต้องหรือไม่
    /// </summary>
    /// <param name="value"></param>
    /// <returns></returns>
    public static bool IsThaiMobileNumber(string value)
    {
      return Regex.IsMatch(value, @"^08\d{8}$|^09\d{8}$|^06\d{8}$", RegexOptions.IgnoreCase); //https://th.wikipedia.org/wiki/%E0%B8%AB%E0%B8%A1%E0%B8%B2%E0%B8%A2%E0%B9%80%E0%B8%A5%E0%B8%82%E0%B9%82%E0%B8%97%E0%B8%A3%E0%B8%A8%E0%B8%B1%E0%B8%9E%E0%B8%97%E0%B9%8C%E0%B9%83%E0%B8%99%E0%B8%9B%E0%B8%A3%E0%B8%B0%E0%B9%80%E0%B8%97%E0%B8%A8%E0%B9%84%E0%B8%97%E0%B8%A2
    }

    /// <summary>
    /// ใช้สำหรับตรวจสอบว่าเป็น E-mail Address ที่ถูกต้องหรือไม่
    /// </summary>
    /// <param name="value"></param>
    /// <returns></returns>
    public static bool IsEmailAddress(string value)
    {
      return Regex.IsMatch(value, @"^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$", RegexOptions.IgnoreCase); //http://emailregex.com/
    }

    /// <summary>
    /// ใช้สำหรับตรวจสอบว่าเป็นพิกัดละติจูดที่ถูกต้องหรือไม่
    /// </summary>
    /// <param name="value"></param>
    /// <returns></returns>
    public static bool IsGeolocationLatitude(string value)
    {
      return Regex.IsMatch(value, @"^(\+|-)?(?:90(?:(?:\.0{1,6})?)|(?:[0-9]|[1-8][0-9])(?:(?:\.[0-9]{1,6})?))$", RegexOptions.IgnoreCase); //https://stackoverflow.com/questions/3518504/regular-expression-for-matching-latitude-longitude-coordinates
    }

    /// <summary>
    /// ใช้ตรวจสอบว่าเป็นพิกัดลองจิจูดที่ถูกต้องหรือไม่
    /// </summary>
    /// <param name="value"></param>
    /// <returns></returns>
    public static bool IsGeolocationLongitude(string value)
    {
      return Regex.IsMatch(value, @"^(\+|-)?(?:180(?:(?:\.0{1,6})?)|(?:[0-9]|[1-9][0-9]|1[0-7][0-9])(?:(?:\.[0-9]{1,6})?))$", RegexOptions.IgnoreCase); //https://stackoverflow.com/questions/3518504/regular-expression-for-matching-latitude-longitude-coordinates
    }

    /// <summary>
    /// ใช้สำหรับตรวจสอบว่าเป็นเลขประจำตัวประชาชนที่ถูกต้องหรือไม่
    /// </summary>
    /// <param name="IDNumber">เลขประจำตัวประชาชน</param>
    /// <returns>ผลลัพธ์ True / False</returns>
    public static bool IsThaiNationalId(string value)
    {
      if (IsNumericValue(value) != true || value.Length != 13)
      {
        return false;
      }
      else
      {
        int pos13 = Convert.ToInt32(value.Substring(12, 1));

        int mod11Value, checkDigit;
        int sum12Position = 0;
        int j = 13;
        for (int i = 0; i <= 11; i++)
        {
          sum12Position = sum12Position + (Convert.ToInt32(value.Substring(i, 1)) * j);
          j = j - 1;
        }

        mod11Value = sum12Position % 11;
        checkDigit = 11 - mod11Value;

        if (checkDigit.ToString().Length > 1)
        {
          checkDigit = Convert.ToInt32(checkDigit.ToString().Substring(1, 1));
        }

        if (pos13 == checkDigit)
        {
          return true;
        }
        else
        {
          return false;
        }
      }
    }

    /// <summary>
    /// ใช้สำหรับตรวจสอบว่าเป็นเลขบัตรเครดิตที่ถูกต้องหรือไม่
    /// </summary>
    /// <param name="CreditCardNumber">เลขบัตรเครดิต</param>
    /// <returns>ผลลัพธ์ True / False</returns>
    public static bool IsCreditCardNumber(string value)
    {
      if (IsNumericValue(value) != true || value.Length != 16)
      {
        return false;
      }
      else
      {
        int sumValue = 0;
        for (int i = 0; i < 15; i++)
        {
          int posValue = Convert.ToInt32(value.Substring(i, 1));
          if (((i + 1) % 2) == 0)
          {
            sumValue += posValue;
          }
          else
          {
            int sum = posValue * 2;
            if (sum.ToString().Length > 1)
            {
              sumValue += Convert.ToInt32(sum.ToString().Substring(0, 1)) + Convert.ToInt32(sum.ToString().Substring(1, 1));
            }
            else
            {
              sumValue += sum;
            }
          }
        }

        int checkDigit = 0;
        if ((sumValue % 10) == 0)
        {
          checkDigit = 0;
        }
        else
        {
          checkDigit = (((sumValue / 10) + 1) * 10) - sumValue;
        }

        if (checkDigit == Convert.ToInt32(value.Substring(15, 1)))
        {
          return true;
        }
        else
        {
          return false;
        }
      }
    }

    /// <summary>
    /// ใช้ตรวจสอบว่าเป็น Numeric หรือไม่
    /// </summary>
    /// <param name="value"></param>
    /// <returns></returns>
    public static bool IsNumericValue(string value)
    {
      return Regex.IsMatch(value, @"^\d+$", RegexOptions.IgnoreCase);
    }

    /// <summary>
    /// ใช้ตรวจสอบว่าเป็น Alphanumeric หรือไม่ (96 characters)
    /// </summary>
    /// <param name="value"></param>
    /// <returns></returns>
    public static bool IsAlphanumericSpecialValue(string value)
    {
      return Regex.IsMatch(value, @"^\w+|\W+|\d+|\D+$", RegexOptions.IgnoreCase);
    }

    /// <summary>
    /// ใช้ตรวจสอบว่าเป็น String หรือไม่
    /// </summary>
    /// <param name="value"></param>
    /// <returns></returns>
    public static bool IsStringValue(string value)
    {
      return Regex.IsMatch(value, @"^\w+$", RegexOptions.IgnoreCase);
    }
    #endregion
  }
}