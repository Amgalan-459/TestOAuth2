using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using TestOAuth2.Services;

var builder = WebApplication.CreateBuilder(args);

//var key = new byte[32]
//{ 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
//  17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 };

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opts => {
        opts.RequireHttpsMetadata = false;
        opts.TokenValidationParameters = new TokenValidationParameters {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(new byte[32]
{ 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
  17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 }),
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization();

builder.Services.AddSingleton<JwtService>();
builder.Services.AddSingleton<GoogleTokenValidator>();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddControllers();

builder.Services.AddCors(options =>
{
    options.AddPolicy("DevCors", builder =>
    {
        builder
            .WithOrigins("http://localhost:4200")
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });

    options.AddPolicy("ProdCors", builder => {
        builder
            .WithOrigins("https://test-o-auth.vercel.app", "http://localhost:4200")
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

builder.Services.Configure<GoogleOptions>(
    builder.Configuration.GetSection("Google"));

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.UseSwagger();
app.UseSwaggerUI();

if (app.Environment.IsDevelopment()) {
    app.UseCors("DevCors");
    app.UseSwagger();
    app.UseSwaggerUI();
}
else {
    app.UseCors("ProdCors");
}

app.Run();
