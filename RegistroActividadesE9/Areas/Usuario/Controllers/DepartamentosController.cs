using Microsoft.AspNetCore.Mvc;
using RegistroActividadesE9.Areas.Admin.Models;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using System.Text;

namespace RegistroActividadesE9.Areas.Usuario.Controllers
{
    public class DepartamentosController : Controller
    {
        readonly HttpClient httpClient = new();

        public async Task<IActionResult> IndexAsync()
        {
            DepartamentosViewModel vm = new DepartamentosViewModel();
            httpClient.BaseAddress = new Uri("https://actividadese9.websitos256.com/");

            var token = User.Claims.First(x => x.Type == ClaimTypes.UserData).Value;
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var idusuario = User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;
            var response = await httpClient.GetAsync($"/api/departamento/{idusuario}");
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();

              
                var depas = JsonSerializer.Deserialize<IEnumerable<Departamentos>>(content, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (depas != null)
                {

                    vm.Departamentos = depas;
                    return View(vm);
                }
            }
            return View();
        }

       
    }
}
