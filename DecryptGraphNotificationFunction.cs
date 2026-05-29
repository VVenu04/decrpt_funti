using System.Net;
using System.Text.Json;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;

namespace GraphWebhookDecrypt;

public sealed class DecryptGraphNotificationFunction
{
    private readonly GraphNotificationDecryptor _decryptor;
    private readonly FileLogWriter _fileLog;
    private readonly ILogger _logger;

    public DecryptGraphNotificationFunction(
        GraphNotificationDecryptor decryptor,
        FileLogWriter fileLog,
        ILoggerFactory loggerFactory)
    {
        _decryptor = decryptor;
        _fileLog = fileLog;
        _logger = loggerFactory.CreateLogger<DecryptGraphNotificationFunction>();
    }

    [Function("DecryptGraphNotification")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req)
    {
        _fileLog.LogInfo($"Decrypt request received. Log folder: {_fileLog.LogDirectory}");

        DecryptRequestDto? request;
        try
        {
            request = await JsonSerializer.DeserializeAsync<DecryptRequestDto>(
                req.Body,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (Exception ex)
        {
            _fileLog.LogError("Invalid JSON body.", ex);
            _logger.LogError(ex, "Invalid JSON body.");
            return await WriteJsonAsync(req, HttpStatusCode.BadRequest, new { error = "Invalid JSON body.", detail = ex.Message });
        }

        if (request?.EncryptedContent == null
            || string.IsNullOrWhiteSpace(request.EncryptedContent.Data)
            || string.IsNullOrWhiteSpace(request.EncryptedContent.DataKey)
            || string.IsNullOrWhiteSpace(request.EncryptedContent.DataSignature))
        {
            _fileLog.LogWarning("Missing encryptedContent fields (data, dataKey, or dataSignature).");
            return await WriteJsonAsync(req, HttpStatusCode.BadRequest, new { error = "encryptedContent with data, dataKey, and dataSignature is required." });
        }

        _fileLog.LogInfo(
            $"encryptedContent received. certId={request.EncryptedContent.EncryptionCertificateId}, thumbprint={request.EncryptedContent.EncryptionCertificateThumbprint}");

        try
        {
            using var certificate = _decryptor.LoadCertificateFromEnvironment();
            using var eventDoc = _decryptor.Decrypt(request.EncryptedContent, certificate);

            var eventId = eventDoc.RootElement.TryGetProperty("id", out var idProp)
                ? idProp.GetString()
                : null;
            var seriesMasterId = eventDoc.RootElement.TryGetProperty("seriesMasterId", out var seriesProp)
                ? seriesProp.GetString()
                : null;

            _fileLog.LogInfo($"Decrypt success. eventId={eventId}, seriesMasterId={seriesMasterId}");

            var response = req.CreateResponse(HttpStatusCode.OK);
            response.Headers.Add("Content-Type", "application/json; charset=utf-8");
            await response.WriteStringAsync(eventDoc.RootElement.GetRawText());
            return response;
        }
        catch (Exception ex)
        {
            _fileLog.LogError("Decryption failed.", ex);
            _logger.LogError(ex, "Failed to decrypt Graph notification.");
            return await WriteJsonAsync(req, HttpStatusCode.BadRequest, new { error = "Decryption failed.", detail = ex.Message });
        }
    }

    private static async Task<HttpResponseData> WriteJsonAsync(HttpRequestData req, HttpStatusCode status, object body)
    {
        var response = req.CreateResponse(status);
        response.Headers.Add("Content-Type", "application/json; charset=utf-8");
        await response.WriteStringAsync(JsonSerializer.Serialize(body));
        return response;
    }
}
