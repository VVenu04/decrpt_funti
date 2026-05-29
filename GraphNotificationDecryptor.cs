using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace GraphWebhookDecrypt;

/// <summary>
/// Decrypts Microsoft Graph change notification encryptedContent per
/// https://learn.microsoft.com/en-us/graph/change-notifications-with-resource-data
/// (matches Microsoft.Graph IDecryptableContentExtensions).
/// </summary>
public sealed class GraphNotificationDecryptor
{
    private readonly FileLogWriter _fileLog;

    public GraphNotificationDecryptor(FileLogWriter fileLog)
    {
        _fileLog = fileLog;
    }

    public JsonDocument Decrypt(EncryptedContentDto encryptedContent, X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(encryptedContent);
        ArgumentNullException.ThrowIfNull(certificate);

        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException(
                "Certificate must include a private key. Export the PFX used when creating the Graph subscription.");
        }

        using var rsaPrivateKey = certificate.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("Certificate does not contain an RSA private key.");

        var decryptedSymmetricKey = rsaPrivateKey.Decrypt(
            Convert.FromBase64String(encryptedContent.DataKey),
            RSAEncryptionPadding.OaepSHA1);

        using var hashAlg = new HMACSHA256(decryptedSymmetricKey);
        var expectedSignature = Convert.ToBase64String(
            hashAlg.ComputeHash(Convert.FromBase64String(encryptedContent.Data)));

        if (!string.Equals(encryptedContent.DataSignature, expectedSignature, StringComparison.Ordinal))
        {
            _fileLog.LogError("dataSignature validation failed.");
            throw new InvalidDataException("dataSignature does not match decrypted payload.");
        }

        var decryptedBytes = AesDecrypt(Convert.FromBase64String(encryptedContent.Data), decryptedSymmetricKey);
        var json = Encoding.UTF8.GetString(decryptedBytes);
        return JsonDocument.Parse(json);
    }

    public X509Certificate2 LoadCertificateFromEnvironment()
    {
        var base64Pfx = Environment.GetEnvironmentVariable("GRAPH_WEBHOOK_CERTIFICATE_BASE64");
        var pfxPath = Environment.GetEnvironmentVariable("GRAPH_WEBHOOK_CERTIFICATE_PATH");
        var password = Environment.GetEnvironmentVariable("GRAPH_WEBHOOK_CERTIFICATE_PASSWORD") ?? string.Empty;

        if (!string.IsNullOrWhiteSpace(base64Pfx))
        {
            var pfxBytes = Convert.FromBase64String(base64Pfx.Trim());
            var cert = new X509Certificate2(pfxBytes, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
            _fileLog.LogInfo($"Certificate loaded from GRAPH_WEBHOOK_CERTIFICATE_BASE64. thumbprint={cert.Thumbprint}");
            return cert;
        }

        if (!string.IsNullOrWhiteSpace(pfxPath))
        {
            var cert = new X509Certificate2(pfxPath, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
            _fileLog.LogInfo($"Certificate loaded from GRAPH_WEBHOOK_CERTIFICATE_PATH. thumbprint={cert.Thumbprint}");
            return cert;
        }

        _fileLog.LogError("Certificate settings missing (GRAPH_WEBHOOK_CERTIFICATE_BASE64 or GRAPH_WEBHOOK_CERTIFICATE_PATH).");
        throw new InvalidOperationException(
            "Set GRAPH_WEBHOOK_CERTIFICATE_BASE64 (PFX bytes, base64) or GRAPH_WEBHOOK_CERTIFICATE_PATH.");
    }

    private static byte[] AesDecrypt(byte[] dataToDecrypt, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;

        var iv = new byte[16];
        Array.Copy(key, iv, 16);
        aes.IV = iv;

        using var memoryStream = new MemoryStream();
        using var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write);
        cryptoStream.Write(dataToDecrypt, 0, dataToDecrypt.Length);
        cryptoStream.FlushFinalBlock();
        return memoryStream.ToArray();
    }
}

public sealed class EncryptedContentDto
{
    public string Data { get; set; } = string.Empty;
    public string DataKey { get; set; } = string.Empty;
    public string DataSignature { get; set; } = string.Empty;
    public string? EncryptionCertificateId { get; set; }
    public string? EncryptionCertificateThumbprint { get; set; }
}

public sealed class DecryptRequestDto
{
    public EncryptedContentDto? EncryptedContent { get; set; }
}
