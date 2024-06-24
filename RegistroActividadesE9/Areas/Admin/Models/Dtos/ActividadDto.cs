namespace RegistroActividadesE9.Areas.Admin.Models.Dtos
{
    public class ActividadDto
    {
        public int id { get; set; }
        public string titulo { get; set; } = null!;
        public string? descripcion { get; set; }
        public int idDepartamento { get; set; }
        public DateTime? fechaRealizacion { get; set; }
        public DateTime? fechaCreacion { get; set; }
        public DateTime? fechaActualizacion { get; set; }
        public int estado { get; set; }
        public string imagen { get; set; }
    }
}
