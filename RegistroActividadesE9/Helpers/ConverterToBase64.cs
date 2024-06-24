using System.IO.Compression;

namespace RegistroActividadesE9.Helpers
{
    public class ConverterToBase64
    {
        private readonly IWebHostEnvironment _hostingEnvironment;


        public ConverterToBase64(IWebHostEnvironment hostingEnvironment)
        {
            _hostingEnvironment = hostingEnvironment;
        }
        public string ImageToBase64(string filePath)
        {
            try
            {
                string wwwRootPath = _hostingEnvironment.WebRootPath;
                string fullFilePath = Path.Combine(wwwRootPath, filePath);

                // Lee el contenido del archivo en un arreglo de bytes
                byte[] fileBytes = File.ReadAllBytes(fullFilePath);

                // Convierte el arreglo de bytes en una cadena Base64
                string base64String = Convert.ToBase64String(fileBytes);

                return base64String;
            }
            catch (Exception ex)
            {
                // Maneja cualquier error que pueda ocurrir al leer el archivo
                Console.WriteLine($"Error al convertir el archivo a Base64: {ex.Message}");
                return null;
            }
        }
        public string SaveFile(IFormFile? file)
        {
          
            var fileName = Guid.NewGuid().ToString() + Path.GetExtension(file.FileName);

            // Ruta donde se guardará el archivo en la carpeta wwwroot
            var filePath = Path.Combine(_hostingEnvironment.WebRootPath, "uploads", fileName);

            var directoryPath = Path.GetDirectoryName(filePath);
            if (!Directory.Exists(directoryPath))
            {
                Directory.CreateDirectory(directoryPath);
            }

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                file.CopyTo(stream);
            }

            // archivo guardado
            return Path.Combine("uploads", fileName);
        }

        public string CompressBase64(string base64String)
        {
            byte[] data = Convert.FromBase64String(base64String);
            using (var output = new MemoryStream())
            {
                using (var gzip = new GZipStream(output, CompressionMode.Compress))
                {
                    gzip.Write(data, 0, data.Length);
                }
                return Convert.ToBase64String(output.ToArray());
            }
        }
    }
}

