namespace RegistroActividadesE9.Areas.Admin.Models
{
    public class AgregarDepartamentosViewModel
    {
        public string nombre { get; set; } = null!;
        public string usuario { get; set; } = null!;
        public string contraseña { get; set; } = null!;
        public int idSuperior { get; set; }
        public IEnumerable<Departamentos> Departamentos { get; set; }
    }
}
