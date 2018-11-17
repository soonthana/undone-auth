using System;
using System.Security.Cryptography;

namespace Undone.Auth.Utils
{
  public static class CryptoECDsa
  {
    #region Public Static Methods
    /// <summary>
    /// ใช้สร้าง Base64 Private Key และ Public Key รูปแบบ ECDsa Cng ตาม Algorithm ที่กำหนด https://www.nuget.org/packages/System.Security.Cryptography.Cng/
    /// </summary>
    /// <param name="alg"></param>
    /// <returns></returns>
    public static KeyPairs GenerateBase64CngKeyPairs(CngAlgorithm alg)
    {
      var keyPairs = new KeyPairs();
      var key = CngKey.Create(alg, "stn.auth.api",
      new CngKeyCreationParameters
      {
        KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
        KeyUsage = CngKeyUsages.AllUsages,
        ExportPolicy = CngExportPolicies.AllowPlaintextExport
      });

      keyPairs.PrivateKey = Convert.ToBase64String(key.Export(CngKeyBlobFormat.EccPrivateBlob));
      keyPairs.PublicKey = Convert.ToBase64String(key.Export(CngKeyBlobFormat.EccPublicBlob));
      key.Dispose();

      return keyPairs;
    }

    /// <summary>
    /// ใช้สร้าง Base58 Private Key และ Public Key รูปแบบ ECDsa Cng ตาม Algorithm ที่กำหนด https://www.nuget.org/packages/System.Security.Cryptography.Cng/
    /// </summary>
    /// <param name="alg"></param>
    /// <returns></returns>
    public static KeyPairs GenerateBase58CngKeyPairs(CngAlgorithm alg)
    {
      var keyPairs = new KeyPairs();
      var key = CngKey.Create(alg, "stn.auth.api",
      new CngKeyCreationParameters
      {
        KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
        KeyUsage = CngKeyUsages.AllUsages,
        ExportPolicy = CngExportPolicies.AllowPlaintextExport
      });

      keyPairs.PrivateKey = Base58Encoding.Encode(key.Export(CngKeyBlobFormat.EccPrivateBlob));
      keyPairs.PublicKey = Base58Encoding.Encode(key.Export(CngKeyBlobFormat.EccPublicBlob));
      key.Dispose();

      return keyPairs;
    }

    /// <summary>
    /// ใช้แปลง Base64 Private Key เป้นรูปแบบ ECDsa Cng ตาม Algorithm ที่กำหนด https://www.nuget.org/packages/System.Security.Cryptography.Cng/
    /// </summary>
    /// <param name="privateKey"></param>
    /// <param name="alg"></param>
    /// <returns></returns>
    public static ECDsa ConvertToECDsaByBase64CngPrivateKey(string privateKey, CngAlgorithm alg)
    {
      return LoadBase64CngPrivateKey(privateKey, alg);
    }

    /// <summary>
    /// ใช้แปลง Base64 Public Key เป้นรูปแบบ ECDsa Cng ตาม Algorithm ที่กำหนด https://www.nuget.org/packages/System.Security.Cryptography.Cng/
    /// </summary>
    /// <param name="publicKey"></param>
    /// <param name="alg"></param>
    /// <returns></returns>
    public static ECDsa ConvertToECDsaByBase64CngPublicKey(string publicKey, CngAlgorithm alg)
    {
      return LoadBase64CngPublicKey(publicKey, alg);
    }

    /// <summary>
    /// ใช้แปลง Base58 Private Key เป้นรูปแบบ ECDsa Cng ตาม Algorithm ที่กำหนด https://www.nuget.org/packages/System.Security.Cryptography.Cng/
    /// </summary>
    /// <param name="privateKey"></param>
    /// <param name="alg"></param>
    /// <returns></returns>
    public static ECDsa ConvertToECDsaByBase58CngPrivateKey(string privateKey, CngAlgorithm alg)
    {
      return LoadBase58CngPrivateKey(privateKey, alg);
    }

    /// <summary>
    /// ใช้แปลง Base58 Public Key เป้นรูปแบบ ECDsa Cng ตาม Algorithm ที่กำหนด https://www.nuget.org/packages/System.Security.Cryptography.Cng/
    /// </summary>
    /// <param name="publicKey"></param>
    /// <param name="alg"></param>
    /// <returns></returns>
    public static ECDsa ConvertToECDsaByBase58CngPublicKey(string publicKey, CngAlgorithm alg)
    {
      return LoadBase58CngPublicKey(publicKey, alg);
    }
    #endregion

    #region Public Classes Models
    public class KeyPairs
    {
      public string PrivateKey { get; set; }
      public string PublicKey { get; set; }
    }
    #endregion

    #region Private Static Methods
    private static ECDsa LoadBase64CngPrivateKey(string privateKey, CngAlgorithm alg)
    {
      var ecDsaCng = new ECDsaCng(CngKey.Import(Convert.FromBase64String(privateKey), CngKeyBlobFormat.EccPrivateBlob));
      ecDsaCng.HashAlgorithm = alg;
      return ecDsaCng;
    }

    private static ECDsa LoadBase64CngPublicKey(string publicKey, CngAlgorithm alg)
    {
      var ecDsaCng = new ECDsaCng(CngKey.Import(Convert.FromBase64String(publicKey), CngKeyBlobFormat.EccPublicBlob));
      ecDsaCng.HashAlgorithm = alg;
      return ecDsaCng;
    }

    private static ECDsa LoadBase58CngPrivateKey(string privateKey, CngAlgorithm alg)
    {
      var ecDsaCng = new ECDsaCng(CngKey.Import(Base58Encoding.Decode(privateKey), CngKeyBlobFormat.EccPrivateBlob));
      ecDsaCng.HashAlgorithm = alg;
      return ecDsaCng;
    }

    private static ECDsa LoadBase58CngPublicKey(string publicKey, CngAlgorithm alg)
    {
      var ecDsaCng = new ECDsaCng(CngKey.Import(Base58Encoding.Decode(publicKey), CngKeyBlobFormat.EccPublicBlob));
      ecDsaCng.HashAlgorithm = alg;
      return ecDsaCng;
    }
    #endregion
  }
}