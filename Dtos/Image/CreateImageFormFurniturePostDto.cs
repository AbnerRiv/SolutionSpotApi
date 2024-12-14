using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace api.Dtos.Image
{
    public class CreateImageFormFurniturePostDto
    {
        public List<IFormFile> Images {get; set;} = new List<IFormFile>();
        public string? ImageUrls {get; set;}
    }
}