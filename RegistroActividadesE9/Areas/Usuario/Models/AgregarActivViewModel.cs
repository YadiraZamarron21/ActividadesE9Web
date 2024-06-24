namespace RegistroActividadesE9.Areas.Usuario.Models
{
    public class AgregarActivViewModel
    {
        public string titulo { get; set; } = null!;

        public string? descripcion { get; set; }

        public int? idDepartamento { get; set; }
        public DateTime? fechaRealizacion { get; set; }
        public DateTime fechaCreacion { get; set; }

        public DateTime fechaActualizacion { get; set; }
        public List<Departamentos> Departamentos { get; set; } = null!;
        public IFormFile? archivo { get; set; }
    }
    public class Departamentos
    {
        public int id { get; set; }

        public string nombre { get; set; } = null!;

        public string usuario { get; set; } = null!;

        public string contraseña { get; set; } = null!;
        public string? departamentoSup { get; set; }

        public int? idSuperior { get; set; }
      
    }
}
