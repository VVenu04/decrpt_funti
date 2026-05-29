namespace GraphWebhookDecrypt;

/// <summary>
/// Writes one log file per UTC date under the configured logs folder.
/// Set GRAPH_WEBHOOK_LOG_DIRECTORY to override (e.g. D:\home\LogFiles\DecryptLogs on Azure).
/// </summary>
public sealed class FileLogWriter
{
    private readonly string _logDirectory;
    private readonly object _writeLock = new();

    public FileLogWriter()
    {
        _logDirectory = Environment.GetEnvironmentVariable("GRAPH_WEBHOOK_LOG_DIRECTORY")
            ?? GetDefaultLogDirectory();
    }

    public string LogDirectory => _logDirectory;

    public void LogInfo(string message) => Write("INFO", message);

    public void LogWarning(string message) => Write("WARN", message);

    public void LogError(string message, Exception? exception = null)
    {
        var text = exception is null ? message : $"{message} | {exception}";
        Write("ERROR", text);
    }

    private static string GetDefaultLogDirectory()
    {
        var home = Environment.GetEnvironmentVariable("HOME");
        if (!string.IsNullOrWhiteSpace(home))
        {
            return Path.Combine(home, "data", "logs");
        }

        return Path.Combine(AppContext.BaseDirectory, "logs");
    }

    private void Write(string level, string message)
    {
        try
        {
            Directory.CreateDirectory(_logDirectory);

            var fileName = $"decrypt-{DateTime.UtcNow:yyyy-MM-dd}.log";
            var filePath = Path.Combine(_logDirectory, fileName);
            var line = $"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff} UTC [{level}] {message}{Environment.NewLine}";

            lock (_writeLock)
            {
                File.AppendAllText(filePath, line);
            }
        }
        catch
        {
            // Never break decrypt flow because logging failed.
        }
    }
}
