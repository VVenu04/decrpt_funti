using System.Net;
using System.Text.Json;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;

namespace GraphWebhookDecrypt;

public sealed class DecryptGraphNotificationFunction
{
    private readonly GraphNotificationDecryptor _decryptor;
    private readonly ILogger _logger;

    public DecryptGraphNotificationFunction(
        GraphNotificationDecryptor decryptor,
        ILoggerFactory loggerFactory)
    {
        _decryptor = decryptor;
        _logger = loggerFactory.CreateLogger<DecryptGraphNotificationFunction>();
    }

    [Function("DecryptGraphNotification")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req)
    {
        DecryptRequestDto? request;
        try
        {
            request = await JsonSerializer.DeserializeAsync<DecryptRequestDto>(
                req.Body,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (Exception ex)
        {
            return await WriteJsonAsync(req, HttpStatusCode.BadRequest, new { error = "Invalid JSON body.", detail = ex.Message });
        }

        if (request?.EncryptedContent == null
            || string.IsNullOrWhiteSpace(request.EncryptedContent.Data)
            || string.IsNullOrWhiteSpace(request.EncryptedContent.DataKey)
            || string.IsNullOrWhiteSpace(request.EncryptedContent.DataSignature))
        {
            return await WriteJsonAsync(req, HttpStatusCode.BadRequest, new { error = "encryptedContent with data, dataKey, and dataSignature is required." });
        }

        try
        {
            using var certificate = _decryptor.LoadCertificateFromEnvironment();
            using var eventDoc = _decryptor.Decrypt(request.EncryptedContent, certificate);

            var response = req.CreateResponse(HttpStatusCode.OK);
            response.Headers.Add("Content-Type", "application/json; charset=utf-8");
            await response.WriteStringAsync(eventDoc.RootElement.GetRawText());
            return response;
        }
        catch (Exception ex)
        {
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
