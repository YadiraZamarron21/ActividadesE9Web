using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using RegistroActividadesE9.Models.ViewModels;
using System.Net.Http.Headers;
using System.Net;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Text;
using RegistroActividadesE9.Areas.Usuario.Models;
using RegistroActividadesE9.Helpers;

namespace RegistroActividadesE9.Areas.Usuario.Controllers
{
  // [Authorize(Roles = "Usuario")]
    [Area("Usuario")]
    
    public class HomeController(HttpClient httpClient, IWebHostEnvironment webHostEnvironment) : Controller
    {
        private readonly HttpClient httpClient = httpClient;
        private readonly IWebHostEnvironment webHostEnvironment = webHostEnvironment;

        public async Task<IActionResult> Index([FromQuery] string? departamento, [FromQuery] DateTime? fechaInicio, [FromQuery] DateTime? fechaFin)
        {
            httpClient.BaseAddress = new Uri("https://actividadese9.websitos256.com/");

            var token = User.Claims.First(x => x.Type == ClaimTypes.UserData).Value;

            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            //var idusuario = User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;

            var reponseActividades = httpClient.GetAsync($"/api/actividad");
            var responseDepartamentos = httpClient.GetAsync($"/api/departamento");

            Task.WaitAll(reponseActividades, responseDepartamentos);

            if (reponseActividades.Result.StatusCode == HttpStatusCode.Unauthorized ||
                responseDepartamentos.Result.StatusCode == HttpStatusCode.Unauthorized)
            {
                return RedirectToAction("iniciarSesion", "home", new { area = "" });
            }

            var contentActividades = await reponseActividades.Result.Content.ReadAsStringAsync();
            var contentDepartamentos = await responseDepartamentos.Result.Content.ReadAsStringAsync();

            var actividades = JsonConvert.DeserializeObject<IEnumerable<Models.ActividadesViewModel.ActividadModel>>(contentActividades) ?? [];
            var departamentos = JsonConvert.DeserializeObject<IEnumerable<Models.ActividadesViewModel.DepartamentoModel>>(contentDepartamentos) ?? [];

            // Filtrar actividades
            if (departamento != null) actividades = actividades.Where(act => act.departamento == departamento);
            if (fechaInicio != null) actividades = actividades.Where(act => act.fechaRealizacion != null && act.fechaRealizacion.Value.ToDateTime(TimeOnly.MinValue) >= fechaInicio);
            if (fechaFin != null) actividades = actividades.Where(act => act.fechaRealizacion != null && act.fechaRealizacion.Value.ToDateTime(TimeOnly.MinValue) <= fechaFin);

            var viewModel = new Models.ActividadesViewModel
            {
                Actividades = actividades.Where(act => act.estado != 0),
                Departamentos = departamentos,
                token = token
            };

            return View(viewModel);
        }

        [HttpGet]
        public async Task<IActionResult> Agregar()
        {
            AgregarActivViewModel vm = new AgregarActivViewModel();
            httpClient.BaseAddress = new Uri("https://actividadese9.websitos256.com/");

            var token = User.Claims.First(x => x.Type == ClaimTypes.UserData).Value;
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            //var idusuario = User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;
            var response = await httpClient.GetAsync($"/api/departamento/Agregar");
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();

                var dep = Newtonsoft.Json.JsonConvert.DeserializeObject<List<Departamentos>>(content);
                if (dep != null)
                {
                    vm.Departamentos = dep;
                    return View(vm);
                }

            }
            return View(null);
        }

        [HttpPost]
        public async Task<IActionResult> AgregarAsync(AgregarActivViewModel vm)
        {
            httpClient.BaseAddress = new Uri("https://actividadese9.websitos256.com/");

            var token = User.Claims.First(x => x.Type == ClaimTypes.UserData).Value;
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            if (vm != null)
            {

                if (vm.idDepartamento == 0 || vm.idDepartamento == null)
                {
                    var userid = User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;

                    vm.idDepartamento = int.Parse(userid);
                }


                var converter = new ConverterToBase64(webHostEnvironment);
                var imagenBase64 = "";
                if (vm.archivo != null)
                {
                    var ruta = converter.SaveFile(vm.archivo);
                    imagenBase64 = converter.ImageToBase64(ruta);
                }
                if (vm.fechaCreacion == DateTime.MinValue)
                {
                    vm.fechaCreacion = DateTime.UtcNow;
                }

                var actdto = new ActividadDto()
                {
                    titulo = vm.titulo,
                    fechaActualizacion = vm.fechaActualizacion,
                    descripcion = vm.descripcion,
                    fechaCreacion = vm.fechaCreacion,
                    fechaRealizacion = vm.fechaRealizacion,
                    idDepartamento = vm.idDepartamento ?? 0,
                    estado = 0,
                    imagen = imagenBase64,
                    id = 0
                };
                var loginjson = System.Text.Json.JsonSerializer.Serialize(actdto);
                var content = new StringContent(loginjson, Encoding.UTF8, "application/json");
                var response = await httpClient.PostAsync("/api/actividad", content);
                if (response.IsSuccessStatusCode)
                {

                    return RedirectToAction("Index");
                }
                else
                {
                    var userid = User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;
                    var rresponse = await httpClient.GetAsync($"/api/departamento/{userid}");
                    if (rresponse.IsSuccessStatusCode)
                    {
                        var content2 = await rresponse.Content.ReadAsStringAsync();

                        var depas = Newtonsoft.Json.JsonConvert.DeserializeObject<List<Departamentos>>(content2);
                        if (depas != null)
                        {
                            vm.Departamentos = depas;
                        }

                    }
                    var error = await response.Content.ReadAsStringAsync();
                    ModelState.AddModelError("", error);
                    return View(vm);
                }
            }
            return View(vm);
        }


        [HttpGet("Usuario/Home/Editar/{id}")]
        public async Task<IActionResult> Editar(int id)
        {
            VerActividadViewModel act = new();
            httpClient.BaseAddress = new Uri("https://actividadese9.websitos256.com/");

            var token = User.Claims.First(x => x.Type == ClaimTypes.UserData).Value;
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var r = await httpClient.GetAsync($"/api/actividad/{id}");
            if (r.IsSuccessStatusCode)
            {
                var con = await r.Content.ReadAsStringAsync();
                act.activ = JsonConvert.DeserializeObject<Actividad>(con); ;

                return View(act);
            }
            return View(null);
        }

        [HttpPost]
        public async Task<IActionResult> Editar(VerActividadViewModel actividad)
        {
            httpClient.BaseAddress = new Uri("https://actividadese9.websitos256.com/");

            var token = User.Claims.First(x => x.Type == ClaimTypes.UserData).Value;
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

      
            var converter = new ConverterToBase64(webHostEnvironment);

            var imagenBase64 = "";
            if (actividad.activ.archivo != null)
            {

                var ruta = converter.SaveFile(actividad.activ.archivo);
                imagenBase64 = converter.ImageToBase64(ruta);
            }
            if (actividad.activ.idDepartamento == 0 || actividad.activ.idDepartamento == null)
            {
                var idusuario = User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;

                actividad.activ.idDepartamento = int.Parse(idusuario);
            }
            var acti = new ActividadDto()
            {
                id = actividad.activ.id,
                descripcion = actividad.activ.descripcion,
                titulo = actividad.activ.titulo,
                idDepartamento = actividad.activ.idDepartamento ?? 0,
                fechaCreacion = actividad.activ.fechaCreacion,
                fechaRealizacion = actividad.activ.fechaRealizacion,
                imagen = imagenBase64

            };

            var jsonContent = new StringContent(JsonConvert.SerializeObject(acti), Encoding.UTF8, "application/json");

            var response = await httpClient.PutAsync("/api/actividad", jsonContent);

            if (response.IsSuccessStatusCode)
            {
                return RedirectToAction("Index");
            }
            else
            {

                var r = await httpClient.GetAsync($"/api/actividad/{actividad.activ.id}");
                if (r.IsSuccessStatusCode)
                {
                    var con = await r.Content.ReadAsStringAsync();
                    actividad.activ = JsonConvert.DeserializeObject<Actividad>(con); ;

                    return View(actividad);
                }
            }
            return View(actividad);
        }

        [HttpGet("Usuario/Home/Eliminar/{id}")]
        public async Task<IActionResult> Eliminar(int id)
        {
            httpClient.BaseAddress = new Uri("https://actividadese9.websitos256.com/");

            var token = User.Claims.First(x => x.Type == ClaimTypes.UserData).Value;
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await httpClient.DeleteAsync($"/api/actividad/{id}");

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


        public IActionResult VerMisPublicaciones()
        {
            return View();
        }

        //borradores:
        public IActionResult VerHistorialPubli()
        {
            return View();
        }
    }
}
