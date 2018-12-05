using System;
using System.Net;
using Microsoft.AspNetCore.Mvc;
using Undone.Auth.Models;
using Undone.Auth.Utils;

namespace Undone.Auth.Utils
{
  public static class CustomHttpResponse
  {
    #region Public Static Methods
    public static ObjectResult Error(HttpStatusCode httpStatusCode, Errors err, string messageToDeveloper)
    {
      var error = new ErrorPayload
      {
        errorId = Guid.NewGuid().ToString(),
        code = AuthErrors.GetErrorCode(err),
        messageToDeveloper = messageToDeveloper,
        messageToUser = new MessageToUserDetail
        {
          langTh = AuthErrors.GetMessageToUser(err, Languages.Thai),
          langEn = AuthErrors.GetMessageToUser(err, Languages.English)
        },
        created = DateTimes.GetCurrentUtcDateTimeInThaiTimeZone(DateTimes.DateTimeFormat.YearMonthDayByDashTHourMinuteSecondByColonZ, DateTimes.LanguageCultureName.ENGLISH_UNITED_STATES, DateTimes.DateTimeUtcOffset.HHMM)
      };

      var objResult = new ObjectResult(new { error });
      objResult.StatusCode = (int)httpStatusCode;

      return objResult;
    }
    #endregion
  }
}