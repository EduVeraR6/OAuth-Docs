var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();


// Configurar la autenticación basada en cookies
builder.Services.AddAuthentication("CookieAutenticacion")
    .AddCookie("CookieAutenticacion", options =>
    {
        options.Cookie.Name = "Cookie";
        options.LoginPath = "/api/account/login"; //a ruta de inicio de sesión
        options.AccessDeniedPath = "/api/account/accessdenied";//ruta de acceso denegado al recurso
    });



var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();



