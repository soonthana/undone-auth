using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Undone.Auth.Framework;

namespace Undone.Auth.Utils
{
  public static class Jwt
  {
    public static SigningCredentials CreateSigningCredentials(Algorithm alg, IConfiguration config)
    {
      SigningCredentials creds;
      string readKeyIntoString = string.Empty;
      var keyModel = new KeyModel();

      switch (alg)
      {
        case Algorithm.HS256:
          readKeyIntoString = File.ReadAllText(config["Jwt:Key:HS256:SymmetricKeyJson"]);
          keyModel = JsonConvert.DeserializeObject<KeyModel>(readKeyIntoString);
          var hs256SymmetricKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyModel.Key));
          creds = new SigningCredentials(hs256SymmetricKey, SecurityAlgorithms.HmacSha256);
          break;
        case Algorithm.RS256:
          using (RSA privateRsa = RSA.Create())
          {
            readKeyIntoString = File.ReadAllText(config["Jwt:Key:RS256:PrivateKeyXml"]);
            privateRsa.fromXmlString(readKeyIntoString);
            var privateKeyRsa = new RsaSecurityKey(privateRsa);
            creds = new SigningCredentials(privateKeyRsa, SecurityAlgorithms.RsaSha256);
          }
          break;
        case Algorithm.ES256:
          readKeyIntoString = File.ReadAllText(config["Jwt:Key:ES256:PrivateKeyJson"]);
          keyModel = JsonConvert.DeserializeObject<KeyModel>(readKeyIntoString);
          var privateKeyECDsa = CryptoECDsa.ConvertToECDsaByBase58CngPrivateKey(keyModel.Key, CngAlgorithm.ECDsaP256);
          creds = new SigningCredentials(new ECDsaSecurityKey(privateKeyECDsa), SecurityAlgorithms.EcdsaSha256);
          break;
        default:
          readKeyIntoString = File.ReadAllText(config["Jwt:Key:HS256:SymmetricKeyJson"]);
          keyModel = JsonConvert.DeserializeObject<KeyModel>(readKeyIntoString);
          var hs256Key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyModel.Key));
          creds = new SigningCredentials(hs256Key, SecurityAlgorithms.HmacSha256);
          break;
      }

      return creds;
    }

    public static SecurityKey GetSecurityKey(Algorithm alg, IConfiguration config)
    {
      SecurityKey securityKey;
      string readKeyIntoString = string.Empty;
      var keyModel = new KeyModel();

      switch (alg)
      {
        case Algorithm.HS256:
          readKeyIntoString = File.ReadAllText(config["Jwt:Key:HS256:SymmetricKeyJson"]);
          keyModel = JsonConvert.DeserializeObject<KeyModel>(readKeyIntoString);
          securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyModel.Key));
          break;
        case Algorithm.RS256:
          using (RSA publicRsa = RSA.Create())
          {
            readKeyIntoString = File.ReadAllText(config["Jwt:Key:RS256:PublicKeyXml"]);
            publicRsa.fromXmlString(readKeyIntoString);
            securityKey = new RsaSecurityKey(publicRsa);
          }
          break;
        case Algorithm.ES256:
          readKeyIntoString = File.ReadAllText(config["Jwt:Key:ES256:PublicKeyJson"]);
          keyModel = JsonConvert.DeserializeObject<KeyModel>(readKeyIntoString);
          securityKey = new ECDsaSecurityKey(CryptoECDsa.ConvertToECDsaByBase58CngPublicKey(keyModel.Key, CngAlgorithm.ECDsaP256));
          break;
        default:
          readKeyIntoString = File.ReadAllText(config["Jwt:Key:HS256:SymmetricKeyJson"]);
          keyModel = JsonConvert.DeserializeObject<KeyModel>(readKeyIntoString);
          securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyModel.Key));
          break;
      }

      return securityKey;
    }

    public enum Algorithm
    {
      HS256,
      RS256,
      ES256
    }

    private class KeyModel
    {
      public string Key { get; set; }
    }
  }
}