using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading.RateLimiting;
using LoginApp.Data;
using LoginApp.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var jwtSecret = builder.Configuration["Jwt:Secret"]
    ?? throw new InvalidOperationException("Jwt:Secret is not configured.");
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "LoginApp";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "LoginApp";

JwtSecretValidator.Validate(jwtSecret, builder.Environment);

builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("auth", httpContext =>
        RateLimitPartition.GetSlidingWindowLimiter(
            httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                SegmentsPerWindow = 2,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            }));

    options.OnRejected = (context, cancellationToken) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.HttpContext.Response.ContentType = "application/json";
        return new ValueTask(context.HttpContext.Response.WriteAsync(
            """{"error":"Too many requests. Please try again later."}""",
            cancellationToken));
    };
});

builder.Services.AddSingleton<Database>(sp =>
{
    var connString = sp.GetRequiredService<IConfiguration>().GetConnectionString("Default")
        ?? "Data Source=loginapp.db";
    return new Database(connString);
});

builder.Services.AddSingleton<TokenBlocklist>();

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret)),
            ClockSkew = TimeSpan.Zero
        };

        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = context =>
            {
                var blocklist = context.HttpContext.RequestServices
                    .GetRequiredService<TokenBlocklist>();
                var jti = context.Principal?.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;

                if (jti is not null && blocklist.IsBlocked(jti))
                    context.Fail("Token has been revoked.");

                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddSingleton<AuthService>();

var app = builder.Build();

await app.Services.GetRequiredService<Database>().InitializeAsync();

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/register", async (RegisterRequest req, AuthService auth) =>
{
    if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
        return Results.BadRequest(new { error = "Email and password are required." });

    if (!Validators.IsValidEmail(req.Email.Trim()))
        return Results.BadRequest(new { error = "Invalid email format." });

    if (req.Password.Length < 8)
        return Results.BadRequest(new { error = "Password must be at least 8 characters." });

    var (success, error) = await auth.RegisterAsync(req.Email.Trim(), req.Password);

    return success
        ? Results.Created("/me", new { message = "Account created." })
        : Results.Conflict(new { error });
})
.RequireRateLimiting("auth");

app.MapPost("/login", async (LoginRequest req, AuthService auth) =>
{
    if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
        return Results.BadRequest(new { error = "Email and password are required." });

    var result = await auth.LoginAsync(req.Email.Trim(), req.Password);

    return result.success
        ? Results.Ok(new { accessToken = result.accessToken, refreshToken = result.refreshToken })
        : Results.Unauthorized();
})
.RequireRateLimiting("auth");

app.MapPost("/refresh", async (RefreshRequest req, AuthService auth) =>
{
    if (string.IsNullOrWhiteSpace(req.RefreshToken))
        return Results.BadRequest(new { error = "Refresh token is required." });

    var result = await auth.RefreshAsync(req.RefreshToken);

    return result.success
        ? Results.Ok(new { accessToken = result.accessToken, refreshToken = result.refreshToken })
        : Results.Unauthorized();
})
.RequireRateLimiting("auth");

app.MapPost("/logout", async (LogoutRequest req, HttpContext ctx, AuthService auth, TokenBlocklist blocklist) =>
{
    var sub = ctx.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)
           ?? ctx.User.FindFirst("sub");

    if (sub is null || !int.TryParse(sub.Value, out var userId))
        return Results.Unauthorized();

    var jti = ctx.User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
    var expClaim = ctx.User.FindFirst(JwtRegisteredClaimNames.Exp)?.Value;

    if (jti is not null && long.TryParse(expClaim, out var expUnix))
    {
        var expiry = DateTimeOffset.FromUnixTimeSeconds(expUnix).UtcDateTime;
        blocklist.Block(jti, expiry);
    }

    if (!string.IsNullOrWhiteSpace(req.RefreshToken))
        await auth.RevokeRefreshTokenAsync(req.RefreshToken, userId);

    return Results.NoContent();
})
.RequireAuthorization();

app.MapGet("/me", async (HttpContext ctx, AuthService auth) =>
{
    var sub = ctx.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)
           ?? ctx.User.FindFirst("sub");

    if (sub is null || !int.TryParse(sub.Value, out var userId))
        return Results.Unauthorized();

    var user = await auth.FindUserByIdAsync(userId);
    return user is null
        ? Results.Unauthorized()
        : Results.Ok(new { id = user.Id, email = user.Email, createdAt = user.CreatedAt });
})
.RequireAuthorization();

app.Run();

record RegisterRequest(string Email, string Password);
record LoginRequest(string Email, string Password);
record RefreshRequest(string RefreshToken);
record LogoutRequest(string? RefreshToken);

internal static class Validators
{
    // Uses MailAddress for RFC-compliant validation without regex.
    // The addr.Address == email guard rejects display-name format: "Alice" <alice@example.com>
    internal static bool IsValidEmail(string email)
    {
        try
        {
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch { return false; }
    }
}

// Required for WebApplicationFactory<Program> in the test project.
public partial class Program { }
