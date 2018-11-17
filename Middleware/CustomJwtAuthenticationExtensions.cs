using System;
using Microsoft.AspNetCore.Authentication;

namespace Undone.Auth.Middleware
{
  public static class CustomJwtAuthenticationExtensions
  {
    // Custom authentication extension method
    public static AuthenticationBuilder AddCustomJwtAuthentition(this AuthenticationBuilder builder, Action<CustomJwtAuthenticationOptions> configureOptions)
    {
      // Add custom authentication scheme with custom options and custom handler
      return builder.AddScheme<CustomJwtAuthenticationOptions, CustomJwtAuthenticationHandler>(CustomJwtAuthenticationOptions.DefaultScheme, configureOptions);
    }
  }
}