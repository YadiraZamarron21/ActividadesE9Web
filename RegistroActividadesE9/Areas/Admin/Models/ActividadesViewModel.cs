namespace RegistroActividadesE9.Areas.Admin.Models
{
    public class ActividadesViewModel
    {
        public IEnumerable<ActividadModel> Actividades { get; set; } = [];
        public IEnumerable<DepartamentoModel> Departamentos { get; set; } = [];
        public string token { get; set; } = null!;

        public class DepartamentoModel
        {
            public int id { get; set; }
            public string nombre { get; set; } = null!;
            public IEnumerable<ActividadModel> Actividades { get; set; } = [];
        }

        public class ActividadModel
        {
            public int id { get; set; }
            public string titulo { get; set; } = null!;
            public string descripcion { get; set; } = null!;
            public int? idDepartamento { get; set; }
            public DateOnly? fechaRealizacion { get; set; }
            public DateTime fechaCreacion { get; set; }
            public DateTime fechaActualizacion { get; set; }
            public int estado { get; set; }
            public string departamento { get; set; } = null!;
        }
    }
}