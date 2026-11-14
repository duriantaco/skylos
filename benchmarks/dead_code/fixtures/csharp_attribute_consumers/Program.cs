using Probe.Views;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddScoped<CatalogServices>();
var app = builder.Build();
System.Console.WriteLine(new BadgeViewModel().ToString() + new InlineSlots().AsSpan().Length + new PlainSlots().Read());
app.Run();
