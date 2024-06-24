using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddMvc();

//Autenticacion
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/iniciarSesion";
        options.LogoutPath = "/cerrarSesion";
        options.Cookie.Name = "ASGcookie";
        options.ExpireTimeSpan = TimeSpan.FromDays(5);
    });
builder.Services.AddAuthorization();
builder.Services.AddHttpClient();

var app = builder.Build();

app.UseDeveloperExceptionPage();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllerRoute(name: "default", pattern: "{area:exists}/{controller=Home}/{action=Index}/{id?}");
app.MapDefaultControllerRoute();
app.Run();