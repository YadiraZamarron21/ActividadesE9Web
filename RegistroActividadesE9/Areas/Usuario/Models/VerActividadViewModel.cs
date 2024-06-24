namespace RegistroActividadesE9.Areas.Usuario.Models
{
    public class VerActividadViewModel
    {
        public Actividad? activ { get; set; }

    }
    public class Actividad
    {
        public int id { get; set; }
        public string titulo { get; set; } = null!;
        public string estado { get; set; } = null!;
        public DateTime fechaCreacion { get; set; }
        public DateTime fechaActualizacion { get; set; }
        public DateTime? fechaRealizacion { get; set; }
        public int? idDepartamento { get; set; }
        public string? descripcion { get; set; }
        public IFormFile? archivo { get; set; }
    }
}
