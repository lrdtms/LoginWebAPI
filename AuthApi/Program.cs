using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using AuthApi.Data;

var builder = WebApplication.CreateBuilder(args);

// === JWT Configuration ===
var jwtKey = "YourSuperSecretKey123!"; // Use a secure secret in production
var jwtIssuer = "UniversalLoginPortal";
var jwtAudience = "UniversalLoginPortal";

// === Add Services ===
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// === Configure EF Core with MySQL ===
// ✅ FIX: Remove duplicate DbContext registration
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseMySql(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        new MySqlServerVersion(new Version(8, 0, 36)),
        mysqlOptions => mysqlOptions.EnableRetryOnFailure()
    ));

// === Configure JWT Bearer Authentication ===
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
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
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// === Middleware Pipeline ===
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

// === Public Login Endpoint ===
app.MapPost("/login", (LoginRequest request) =>
{
    // Dummy user auth logic
    if (request.Username == "admin" && request.Password == "password")
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, request.Username),
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: jwtIssuer,
            audience: jwtAudience,
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds
        );

        var jwt = new JwtSecurityTokenHandler().WriteToken(token);
        return Results.Ok(new { token = jwt });
    }

    return Results.Unauthorized();
})
.WithName("Login");

// === Secure Endpoint Example ===
app.MapGet("/secure", (ClaimsPrincipal user) =>
{
    var username = user.Identity?.Name;
    return Results.Ok($"Welcome, {username}. This is a secure endpoint.");
})
.RequireAuthorization()
.WithName("SecureEndpoint");

app.Run();

// === Request Models ===
record LoginRequest(string Username, string Password);
record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary);
