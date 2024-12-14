using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace api.Dtos.Image
{
    public class CreateImageRequestDto
    {
        public int FurnitureId { get; set; }
        public string Url { get; set; } = string.Empty;
    }
}