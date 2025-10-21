using Microsoft.AspNetCore.Authentication;
using Microsoft.OpenApi.Models;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// configuraciones: ruta al serviceAccount (ajusta a tu ruta local)
var firebaseServiceAccountPath = Path.Combine(builder.Environment.ContentRootPath, "secrets", "serviceAccountKey.json");
FirebaseService.Initialize(firebaseServiceAccountPath);

// Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = FirebaseAuthHandler.SchemeName;
    options.DefaultChallengeScheme = FirebaseAuthHandler.SchemeName;
})
.AddScheme<FirebaseAuthenticationOptions, FirebaseAuthHandler>(FirebaseAuthHandler.SchemeName, options => { });

builder.Services.AddAuthorization();

// Controllers (si usas controllers) o minimal endpoints
builder.Services.AddControllers();

// Swagger con soporte Bearer (para probar con Firebase ID token)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Auth API (Firebase)", Version = "v1" });

    var bearerScheme = new OpenApiSecurityScheme
    {
        Description = "Ingrese 'Bearer {token}' (ID token de Firebase)",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    };
    c.AddSecurityDefinition("Bearer", bearerScheme);

    var requirement = new OpenApiSecurityRequirement {
        { bearerScheme, new string[] { } }
    };
    c.AddSecurityRequirement(requirement);
});

var app = builder.Build();

// Middleware
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Auth API (Firebase) v1");
});

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers(); // si usas controllers

// Minimal endpoints de ejemplo
app.MapGet("/", () => Results.Ok(new { message = "API de autenticación con Firebase" }));

app.MapGet("/secure/profile", (ClaimsPrincipal user) =>
{
    if (!user.Identity?.IsAuthenticated ?? false)
        return Results.Unauthorized();

    var uid = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var email = user.FindFirst(ClaimTypes.Email)?.Value;
    var name = user.FindFirst(ClaimTypes.Name)?.Value;

    return Results.Ok(new { uid, email, name });
}).RequireAuthorization();
app.MapGet("/debug/env", () =>
{
    var content = builder.Environment.ContentRootPath;
    var path = Path.Combine(content, "secrets", "serviceAccountKey.json");
    var exists = System.IO.File.Exists(path);
    return Results.Ok(new { contentRootPath = content, jsonPath = path, fileExists = exists });
});


app.Run();
