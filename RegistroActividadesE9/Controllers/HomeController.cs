using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;
using System.Net;
using System.Security.Claims;
using System.Text;
using RegistroActividadesE9.Models.ViewModels;
using System.Text.Json;
using System.IdentityModel.Tokens.Jwt;

namespace RegistroActividadesE9.Controllers
{
    public class HomeController(HttpClient httpClient) : Controller
    {
        private readonly HttpClient client = httpClient;

        [HttpGet]
        public IActionResult Index()
        {
            if (User.Identity is null || User.Identity.IsAuthenticated is false)
                return RedirectToAction(nameof(Login));

            if (User.IsInRole("Admin"))
                return RedirectToAction("Index", "Home", new { area = "Admin" });

            return RedirectToAction("Index", "Home", new { area = "Usuario" });
        }

        [HttpGet("/iniciarSesion")]
        [HttpGet("/home/iniciarSesion")]
        public IActionResult Login() => View();


        [HttpPost("/iniciarSesion")]
        [HttpPost("/home/iniciarSesion")]
        public async Task<IActionResult> Login(LoginViewModel viewModel)
        {
            client.BaseAddress = new Uri("https://actividadese9.websitos256.com/");


            var json = JsonSerializer.Serialize(viewModel);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await client.PostAsync("/api/Login", content);
            var usu = viewModel.nombre;
            var contraseña = viewModel.contrasena;
            if (!response.IsSuccessStatusCode)
            {
                if (response.StatusCode == HttpStatusCode.BadRequest)
                    ModelState.AddModelError(string.Empty, "Nombre de usuario y/o contraseña incorrectos");
                else
                    ModelState.AddModelError(string.Empty, "Error en la autenticación");

                return View(viewModel);
            }

            var token = await response.Content.ReadAsStringAsync();

            // Agregar el token a las cabeceras de la petición
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            // Decodificar el token para obtener las reclamaciones
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);


            var nameClaim = jwtToken.Claims.FirstOrDefault(claim => claim.Type == ClaimTypes.Name);
            var roleClaim = jwtToken.Claims.FirstOrDefault(claim => claim.Type == ClaimTypes.Role);
            var idDepartamentoClaim = jwtToken.Claims.FirstOrDefault(claim => claim.Type == "IdDepartamento");




            if (roleClaim is null || nameClaim is null || idDepartamentoClaim is null)
            {
                ModelState.AddModelError(string.Empty, "Error en la autenticación");
                return View(viewModel);
            }

           
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, nameClaim.Value),
                new Claim(ClaimTypes.Role, roleClaim.Value),
                new Claim("idDepartamento", idDepartamentoClaim.ToString()),
              
            

            };
          

            var identity = new ClaimsIdentity(claims, "login");

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

            if (roleClaim.Value == "Admin")
            {
                return RedirectToAction("Index", "Home", new { area = "Admin" });
            }

            return RedirectToAction("Index", "Home", new { area = "Usuario" });
        }

        [HttpGet("/cerrarSesion")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction(nameof(Login));
        }
    }
}