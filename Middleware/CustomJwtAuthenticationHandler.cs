using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using System.IdentityModel.Tokens.Jwt;
using Undone.Auth.Utils;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Undone.Auth.Middleware
{
  public class CustomJwtAuthenticationHandler : AuthenticationHandler<CustomJwtAuthenticationOptions>
  {
    private IConfiguration _config;

    public CustomJwtAuthenticationHandler(IOptionsMonitor<CustomJwtAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, IConfiguration config)
            : base(options, logger, encoder, clock)
    {
      _config = config;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
      // Get Authorization header value
      if (!Request.Headers.TryGetValue(HeaderNames.Authorization, out var authorization))
      {
        return Task.FromResult(AuthenticateResult.Fail("Cannot read authorization header."));
      }

      var jwtString = authorization.First();
      jwtString = jwtString.Replace("Bearer ", "");
      string[] jwtArray = jwtString.Split('.');
      var jwtHeader = JwtHeader.Base64UrlDeserialize(jwtArray[0]);

      Jwt.Algorithm jwtAlg;

      if (jwtHeader.Alg == "HS256")
      {
        jwtAlg = Jwt.Algorithm.HS256;
      }
      else if (jwtHeader.Alg == "RS256")
      {
        jwtAlg = Jwt.Algorithm.RS256;
      }
      else if (jwtHeader.Alg == "ES256")
      {
        jwtAlg = Jwt.Algorithm.ES256;
      }
      else
      {
        jwtAlg = Jwt.Algorithm.HS256;
      }

      var tokenHandler = new JwtSecurityTokenHandler();

      try
      {
        var claimPrincipal = tokenHandler.ValidateToken(jwtString, new TokenValidationParameters
        {
          ValidIssuer = _config["Jwt:Issuer"],
          ValidAudience = _config["Jwt:Audience"],
          ValidateIssuer = true,
          ValidateAudience = true,
          ValidateLifetime = true,
          ValidateIssuerSigningKey = true,
          ClockSkew = TimeSpan.Zero,
          IssuerSigningKey = Jwt.GetSecurityKey(jwtAlg, _config)
        }, out var parsedToken);

        var result = claimPrincipal.Identity.IsAuthenticated;

        if (result)
        {
          var identities = new List<ClaimsIdentity> { new ClaimsIdentity("Undone-CustomJwtAuthType") };
          var ticket = new AuthenticationTicket(new ClaimsPrincipal(identities), Options.Scheme);
          return Task.FromResult(AuthenticateResult.Success(ticket));
        }
        else
        {
          return Task.FromResult(AuthenticateResult.Fail("Cannot read authorization header."));
        }
      }
      catch (Exception ex)
      {
        return Task.FromResult(AuthenticateResult.Fail(ex.Message));
      }
    }
  }
}