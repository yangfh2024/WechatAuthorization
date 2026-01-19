using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddHttpClient("n8n", client =>
{
    client.Timeout = TimeSpan.FromSeconds(2); // 一定要小于企业微信 3 秒  
});
var app = builder.Build();

//// 从配置读取 WeChat 配置（支持 appsettings.json、环境变量和用户机密）
//var wechatToken = app.Configuration["WeChat:Token"] ?? string.Empty;
//var wechatCorpId = app.Configuration["WeChat:CorpId"] ?? string.Empty;
//var wechatEncodingAESKey = app.Configuration["WeChat:EncodingAESKey"] ?? string.Empty;
//var PassText = app.Configuration["WeChat:PassText"] ?? string.Empty;
//var UnpassText = app.Configuration["WeChat:UnpassText"] ?? string.Empty;
//var n8nURL = app.Configuration["WeChat:n8nURL"] ?? string.Empty;

var wechatToken = Environment.GetEnvironmentVariable("WECHAT_TOKEN");
var wechatCorpId = Environment.GetEnvironmentVariable("WECHAT_CORP_ID");
var wechatEncodingAESKey = Environment.GetEnvironmentVariable("WECHAT_AES_KEY");
var PassText = Environment.GetEnvironmentVariable("WECHAT_PASS_TEXT");
var UnpassText = Environment.GetEnvironmentVariable("WECHAT_UNPASS_TEXT");
var n8nURL = Environment.GetEnvironmentVariable("WECHAT_N8N_URL");

// Configure the HTTP request pipeline.
//if ((app.Environment.IsDevelopment() || app.Environment.IsEnvironment("Docker")))
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/wechatauthorization", (HttpRequest request) =>
{
    // GET 校验  
    // ===== 配置来自 app.Configuration（已在外部读取） =====  
    string token = wechatToken;
    string corpId = wechatCorpId;
    string encodingAESKey = wechatEncodingAESKey;


    // ===== ✅ 获取 query 参数 =====  
    string msgSignature = request.Query["msg_signature"];
    string timestamp = request.Query["timestamp"];
    string nonce = request.Query["nonce"];
    string echostr = request.Query["echostr"];

    // ===== 1️⃣ 校验签名 =====  
    string raw = string.Concat(
        new[] { token, timestamp, nonce, echostr }.OrderBy(x => x)
    );

    string sha1;
    using (var sha = SHA1.Create())
    {
        sha1 = BitConverter
            .ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(raw)))
            .Replace("-", "")
            .ToLower();
    }

    if (sha1 != msgSignature)
        throw new CryptographicException("Signature verification failed");

    // ===== 2️⃣ AES 解密 =====  
    byte[] aesKey = Convert.FromBase64String(encodingAESKey + "=");
    byte[] iv = aesKey[..16];
    byte[] encrypted = Convert.FromBase64String(echostr);

    byte[] decrypted;
    using (var aes = Aes.Create())
    {
        aes.KeySize = 256;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;
        aes.Key = aesKey;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();
        decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
    }

    // ===== 3️⃣ 去 PKCS7 padding =====  
    int pad = decrypted[^1];
    decrypted = decrypted[..^pad];

    // ===== 4️⃣ 去 16 位随机数 =====  
    var content = decrypted[16..];

    // ===== 5️⃣ 读取内容长度（网络字节序）=====  
    int msgLen = BitConverter.ToInt32(
        content[..4].Reverse().ToArray(), 0
    );

    // ===== 6️⃣ 明文 =====  
    string msg = Encoding.UTF8.GetString(content, 4, msgLen);

    // ===== 7️⃣ 校验 CorpId =====  
    string receiveCorpId = Encoding.UTF8.GetString(
        content, 4 + msgLen, content.Length - 4 - msgLen
    );

    if (receiveCorpId != corpId)
        throw new CryptographicException("CorpId mismatch");

    return msg;
})
    .WithName("Getwechatauthorization")
    .WithOpenApi();

app.MapPost("/wechatauthorization", async (HttpRequest request, IHttpClientFactory clientFactory) =>
{
    // ===== 0️⃣ 固定配置 =====   
    // ===== 配置来自 app.Configuration（已在外部读取） =====  
    string token = wechatToken;
    string corpId = wechatCorpId;
    string encodingAESKey = wechatEncodingAESKey;

    // ===== 1️⃣ Query 参数 =====  
    string msgSignature = request.Query["msg_signature"];
    string timestamp = request.Query["timestamp"];
    string nonce = request.Query["nonce"];

    if (string.IsNullOrEmpty(msgSignature) ||
        string.IsNullOrEmpty(timestamp) ||
        string.IsNullOrEmpty(nonce))
    {
        return Results.BadRequest("Missing query parameters");
    }

    // ===== 2️⃣ 读取 Body（XML）=====  
    string body;
    using (var reader = new StreamReader(request.Body, Encoding.UTF8))
    {
        body = await reader.ReadToEndAsync();
    }

    if (string.IsNullOrWhiteSpace(body))
        return Results.BadRequest("Empty body");

    // ===== 3️⃣ 解析 Encrypt =====  
    var xml = XDocument.Parse(body);
    string encrypt = xml.Root?.Element("Encrypt")?.Value;

    if (string.IsNullOrEmpty(encrypt))
        return Results.BadRequest("Missing Encrypt node");

    // ===== 4️⃣ 校验签名 =====  
    string raw = string.Concat(
        new[] { token, timestamp, nonce, encrypt }.OrderBy(x => x)
    );

    string sha1;
    using (var sha = SHA1.Create())
    {
        sha1 = BitConverter
            .ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(raw)))
            .Replace("-", "")
            .ToLower();
    }

    if (sha1 != msgSignature)
        throw new CryptographicException("Signature verification failed");

    // ===== 5️⃣ AES 解密 =====  
    byte[] aesKey = Convert.FromBase64String(encodingAESKey + "=");
    byte[] iv = aesKey[..16];
    byte[] encrypted = Convert.FromBase64String(encrypt);

    byte[] decrypted;
    using (var aes = Aes.Create())
    {
        aes.KeySize = 256;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;
        aes.Key = aesKey;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();
        decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
    }

    // ===== 6️⃣ 去 PKCS7 padding =====  
    int pad = decrypted[^1];
    decrypted = decrypted[..^pad];

    // ===== 7️⃣ 去 16 位随机数 =====  
    var content = decrypted[16..];

    // ===== 8️⃣ 消息长度 =====  
    int msgLen = BitConverter.ToInt32(
        content[..4].Reverse().ToArray(), 0
    );

    // ===== 9️⃣ 明文 XML =====  
    string msgXml = Encoding.UTF8.GetString(content, 4, msgLen);

    // ===== 🔟 CorpId 校验 =====  
    string receiveCorpId = Encoding.UTF8.GetString(
        content, 4 + msgLen, content.Length - 4 - msgLen
    );

    if (receiveCorpId != corpId)
        throw new CryptographicException("CorpId mismatch");

    var msgDoc = XDocument.Parse(msgXml);
    string msgType = msgDoc.Root?.Element("MsgType")?.Value;
    if (msgType == "text")
    {
        string contentText = msgDoc.Root?.Element("Content")?.Value ?? string.Empty;

        // 从配置读取触发短语（支持数组配置：WeChat:TriggerPhrases:0, WeChat:TriggerPhrases:1 ...）
        var triggers = new[] { PassText,UnpassText};

        // 如果配置为空，仍然回退到原来的两个短语（向后兼容）
        if (triggers.Length == 0)
        {
            triggers = new[] { "审核通过", "审核退回" };
        }

        // 匹配任意触发短语（忽略大小写）
        bool matched = triggers.Any(t => !string.IsNullOrWhiteSpace(t) &&
                                         contentText.Contains(t, StringComparison.OrdinalIgnoreCase));

        if (matched)
        {
            //向https:webn8n.666103.xyz/webhook/wechat_post发送POST请求
            try
            {
               // var client = httpFactory.CreateClient();
                var webhookUrl = n8nURL;
                var event1= "wechat_message";
                var payload = new
                {
                    event1,
                    msgType,
                    content = contentText,
                    originalXml = msgXml
                }; 
                string json = JsonSerializer.Serialize(payload);
                using var httpContent = new StringContent(json, Encoding.UTF8, "application/json");
                var client = clientFactory.CreateClient();
                // 发送请求但不阻塞最终对企业微信的返回（捕获异常，不抛出）
                var resp = await client.PostAsync(webhookUrl, httpContent);
                // 可选：在此处记录非成功状态码
            }
            catch
            {
                // 忽略 webhook 发送失败，保证返回 "success" 给企业微信
            }
        }
    }

    // ===== 11️⃣ 返回 success（企业微信要求）=====  
    // POST 消息  
    return Results.Text("success");
})
 .WithName("Postwechatauthorization")
 .WithOpenApi();

app.Run();

internal record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
