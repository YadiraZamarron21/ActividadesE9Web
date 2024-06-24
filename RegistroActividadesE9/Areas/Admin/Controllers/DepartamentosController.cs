using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RegistroActividadesE9.Areas.Admin.Models;
using System.Net.Http;
using System.Text;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;

namespace RegistroActividadesE9.Areas.Admin.Controllers
{
    [Authorize(Roles = "Admin")]
    [Area("Admin")]
    public class DepartamentosController : Controller
    {
        readonly HttpClient httpClient = new();

        public async Task<IActionResult> Index()
        {
            var vm = new DepartamentosViewModel();
            httpClient.BaseAddress = new Uri("https://actividadese9.websitos256.com/");

            var token = User.Claims.First(x => x.Type == ClaimTypes.UserData).Value;
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var idusuario = User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;
            var response = await httpClient.GetAsync($"/api/departamento/{idusuario}");
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();

                var dep = JsonSerializer.Deserialize<IEnumerable<Departamentos>>(content, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (dep != null)
                {
                    vm.Departamentos = dep;
                    return View(vm);
                }
            }
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Agregar()
        {
            var vm = new AgregarDepartamentosViewModel();

            httpClient.BaseAddress = new Uri("https://actividadese9.websitos256.com/");

            var token = User.Claims.First(x => x.Type == ClaimTypes.UserData).Value;
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var idusuario = User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;
            var response = await httpClient.GetAsync($"/api/departamento/{idusuario}");

            if (!response.IsSuccessStatusCode) return View();

            var content = await response.Content.ReadAsStringAsync();

            var resp = await httpClient.GetAsync($"/api/departamento/{idusuario}");
            if (resp.IsSuccessStatusCode)
            {
                var content2 = await resp.Content.ReadAsStringAsync();

                // Deserializar la cadena JSON en una lista de ActividadesViewModel
                var depa = JsonSerializer.Deserialize<IEnumerable<Departamentos>>(content2, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (depa != null)
                {

                    vm.Departamentos = depa;
                    return View(vm);
                }
            }

            return View(vm);
        }


        [HttpPost]
        public async Task<IActionResult> Agregar(AgregarDepartamentosViewModel vm)
        {
            var idusuario = User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;
            httpClient.BaseAddress = new Uri("https://actividadese9.websitos256.com/");

            var token = User.Claims.First(x => x.Type == ClaimTypes.UserData).Value;
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            if (vm != null)
            {

                if (vm.idSuperior == 0)
                {

                    vm.idSuperior = int.Parse(idusuario);
                }
                var dep = new Departamentos()
                {
                    id = 0,
                    nombre = vm.nombre,
                    usuario = vm.usuario,
                    contraseña = vm.contraseña,
                    idSuperior = vm.idSuperior,

                };
                var jsonl = System.Text.Json.JsonSerializer.Serialize(dep);
                var content = new StringContent(jsonl, Encoding.UTF8, "application/json");
                var response = await httpClient.PostAsync("/api/departamento", content);
                if (response.IsSuccessStatusCode)
                {
                    return RedirectToAction("Index");

                }
                else
                {
                    var error = await response.Content.ReadAsStringAsync();
                    ModelState.AddModelError("", error);
                    var res = await httpClient.GetAsync($"/api/departamento/{idusuario}");
                    if (res.IsSuccessStatusCode)
                    {
                        var cont = await res.Content.ReadAsStringAsync();

                        // Deserializar la cadena JSON en una lista de ActividadesViewModel
                        var depa = JsonSerializer.Deserialize<IEnumerable<Departamentos>>(cont, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                        if (depa != null)
                        {

                            vm.Departamentos = depa;
                            return View(vm);
                        }
                    }
                    return View(vm);
                }
            }
            return View(vm);
        }


        [HttpGet("/Admin/Departamentos/Editar/{id}")]
        public async Task<IActionResult> Editar(int id)
        {
            var vm = new EDepartamentoViewModel();

            httpClient.BaseAddress = new Uri("https://actividadese9.websitos256.com/");

            var token = User.Claims.First(x => x.Type == ClaimTypes.UserData).Value;
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await httpClient.GetAsync($"/api/departamento/{id}");

            if (!response.IsSuccessStatusCode) return View();

            var content = await response.Content.ReadAsStringAsync();

            var depar = JsonSerializer.Deserialize<Departamentos>(content, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (depar == null) return View();

            vm.id = depar.id;
            vm.nombre = depar.nombre;
            vm.idSuperior = (int)depar.idSuperior;
            vm.usuario = depar.usuario;


            var idusuario = User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;
            var respon = await httpClient.GetAsync($"/api/departamento/{idusuario}");
            if (respon.IsSuccessStatusCode)
            {
                var cont = await respon.Content.ReadAsStringAsync();

                // Deserializar la cadena JSON en una lista de ActividadesViewModel
                var depas = JsonSerializer.Deserialize<IEnumerable<Departamentos>>(cont, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (depas != null)
                {
                    vm.Departamentos = depas;
                    return View(vm);
                }
            }
            return View(vm);
        }

        [HttpPost]
        public async Task<IActionResult> Editar(EDepartamentoViewModel vm)
        {
            var idusuario = int.Parse(User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value);

            httpClient.BaseAddress = new Uri("https://actividadese9.websitos256.com/");

            var token = User.Claims.First(x => x.Type == ClaimTypes.UserData).Value;
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var respo = await httpClient.GetAsync($"/api/departamento/{vm.id}");

            if (!respo.IsSuccessStatusCode) return View();

            var cont = await respo.Content.ReadAsStringAsync();

            var departamento = JsonSerializer.Deserialize<Departamentos>(cont, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (vm.idSuperior == 0)
            {
                vm.idSuperior = (int)departamento.idSuperior;
            }
            var dto = new EditarDepaViewModel()
            {
                id = vm.id,
                nombre = vm.nombre,
                usuario = vm.usuario,
                contraseña = vm.contraseña,
                idSuperior = vm.idSuperior,
            };
            var jsonContent = System.Text.Json.JsonSerializer.Serialize(dto);
            var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

            var response = await httpClient.PutAsync("/api/departamento", content);


            if (response.IsSuccessStatusCode)
            {
                return RedirectToAction("Index");

            }
            else
            {
                var error = await response.Content.ReadAsStringAsync();
                ModelState.AddModelError("", error);
                var res = await httpClient.GetAsync($"/api/departamento/{idusuario}");
                if (res.IsSuccessStatusCode)
                {
                    var con = await res.Content.ReadAsStringAsync();

                    // Deserializar la cadena JSON en una lista de ActividadesViewModel
                    var dep = JsonSerializer.Deserialize<IEnumerable<Departamentos>>(con, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    if (dep != null)
                    {

                        vm.Departamentos = dep;
                        return View(vm);
                    }
                }
                return View(vm);
            }
        }


        [HttpGet("/Admin/Departamentos/Eliminar/{id}")]
        public async Task<IActionResult> Eliminar(int id)
        {
            httpClient.BaseAddress = new Uri("https://actividadese9.websitos256.com/");

            var token = User.Claims.First(x => x.Type == ClaimTypes.UserData).Value;
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await httpClient.DeleteAsync($"/api/departamento/{id}");

            if (response.IsSuccessStatusCode)
            {
                return RedirectToAction("Index");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Error al eliminar la actividad");
                return View(); 
            }
        }

    }


}
