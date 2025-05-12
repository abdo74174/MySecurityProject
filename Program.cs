
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SecureAuth.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<UserService>();
builder.Services.AddSingleton<EncryptionService>();
builder.Services.AddControllers();
var app = builder.Build();

app.MapControllers();
app.Run();










