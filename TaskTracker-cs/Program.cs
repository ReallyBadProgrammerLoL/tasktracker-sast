// TaskTracker — учебный веб-API (ASP.NET Core minimal API + SQLite): учёт задач пользователей.
// ВНИМАНИЕ: код содержит НАМЕРЕННЫЕ уязвимости для лабораторной работы по SAST.
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

const string ConnStr = "Data Source=tasks.db";
const string AdminPassword = "Admin123!";        // CWE-798: захардкоженные учётные данные
const string ApiKey = "sk_live_51H8xExampleKey"; // CWE-798: захардкоженный секрет

InitDb();

// CWE-89: SQL-инъекция — параметр owner подставляется в запрос строкой
app.MapGet("/tasks", (string owner) =>
{
    using var conn = new SqliteConnection(ConnStr);
    conn.Open();
    var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT id, title FROM tasks WHERE owner = '" + owner + "'";
    var result = new List<object>();
    using var r = cmd.ExecuteReader();
    while (r.Read())
        result.Add(new { id = r.GetInt32(0), title = r.GetString(1) });
    return Results.Json(result);
});

// CWE-89 + CWE-327: инъекция в логине и слабый хеш пароля (MD5)
app.MapPost("/login", (string username, string password) =>
{
    using var conn = new SqliteConnection(ConnStr);
    conn.Open();
    var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT COUNT(*) FROM users WHERE name = '" + username +
                      "' AND pass_hash = '" + Md5(password) + "'";
    var ok = Convert.ToInt32(cmd.ExecuteScalar()) > 0;
    return ok ? Results.Ok(new { token = ApiKey }) : Results.Unauthorized();
});

// CWE-79: отражённый XSS — ввод пользователя попадает в HTML без экранирования
app.MapGet("/search", (string q) =>
    Results.Content("<html><body><h1>Results for: " + q + "</h1></body></html>", "text/html"));

// CWE-22: обход каталога — имя файла не проверяется
app.MapGet("/files", (string name) =>
{
    var path = Path.Combine("uploads", name);
    return File.Exists(path) ? Results.Text(File.ReadAllText(path)) : Results.NotFound();
});

// CWE-78: внедрение команды ОС
app.MapGet("/ping", (string host) =>
{
    var psi = new ProcessStartInfo("cmd.exe", "/c ping -n 1 " + host)
    {
        RedirectStandardOutput = true,
        UseShellExecute = false
    };
    using var p = Process.Start(psi)!;
    return Results.Text(p.StandardOutput.ReadToEnd());
});

// CWE-918 (SSRF) + CWE-295: произвольный URL и отключённая проверка сертификата
app.MapGet("/fetch", async (string url) =>
{
    var handler = new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true
    };
    using var client = new HttpClient(handler);
    return Results.Text(await client.GetStringAsync(url));
});

app.Run();

static string Md5(string s) =>
    Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

static void InitDb()
{
    Directory.CreateDirectory("uploads");
    using var conn = new SqliteConnection(ConnStr);
    conn.Open();
    var cmd = conn.CreateCommand();
    cmd.CommandText = @"
        CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY, owner TEXT, title TEXT);
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, pass_hash TEXT);
        INSERT OR IGNORE INTO tasks (id, owner, title) VALUES (1, 'alice', 'Prepare report'), (2, 'bob', 'Fix bug #42');
        INSERT OR IGNORE INTO users (id, name, pass_hash) VALUES (1, 'admin', '" + Md5(AdminPassword) + "');";
    cmd.ExecuteNonQuery();
}
