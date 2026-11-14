using Shop.Models;
using Shop.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorComponents();
builder.Services.AddScoped<BasketState>();
var app = builder.Build();
app.MapGet("/receipt", () => ReceiptFactory.Create());
app.Run();
