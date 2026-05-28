# Graph Webhook Decrypt (Azure Function)

Decrypts Microsoft Graph `encryptedContent` from rich change notifications (same algorithm as Microsoft Graph SDK).

## Prerequisites

1. **PFX with private key** matching the public certificate used in `outlookWebhookSubscription.txt` (`encryptionCertificate`).
2. Azure Function App (or run locally for testing).

## Configuration

Set one of these in Function App **Application settings** (or `local.settings.json` for local run):

| Setting | Description |
|--------|-------------|
| `GRAPH_WEBHOOK_CERTIFICATE_BASE64` | Base64-encoded `.pfx` file bytes |
| `GRAPH_WEBHOOK_CERTIFICATE_PATH` | Full path to `.pfx` on disk (local dev) |
| `GRAPH_WEBHOOK_CERTIFICATE_PASSWORD` | PFX password |

## Deploy

```powershell
cd GraphWebhookDecrypt
dotnet publish -c Release -o ./publish
# Deploy ./publish to Azure Function App (func azure functionapp publish <app-name>)
```

Function endpoint: `POST /api/DecryptGraphNotification`  
Auth: Function key (`x-functions-key` header).

## Request / response

**Request:**
```json
{
  "encryptedContent": {
    "data": "...",
    "dataKey": "...",
    "dataSignature": "...",
    "encryptionCertificateId": "optimo-cert-2026-01",
    "encryptionCertificateThumbprint": "502DCCB9A1232FB78C0E48C49108C81B26EC2BFE"
  }
}
```

**Response (200):** decrypted event JSON (`id`, `changeKey`, `seriesMasterId`, `type`, `isCancelled`, `start`, `end`, …).

## Wire Logic App receiver

In `outlookWebhookReceiver.txt` parameters:

- `decrypt_function_url` → `https://<your-app>.azurewebsites.net/api/DecryptGraphNotification`
- `decrypt_function_key` → Function default key (or host key)

Receiver flow: decrypt → use fields for SP + recurring create/update/delete routing.

## Create PFX from subscription cert (if you only have public .cer)

You must have generated a key pair when creating the subscription. If you only uploaded the public cert to Graph, locate the original `.pfx` used to export the public certificate. Graph cannot decrypt without your private key.
