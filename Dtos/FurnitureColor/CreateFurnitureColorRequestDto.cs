using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace api.Dtos.FurnitureColor
{
    public class CreateFurnitureColorRequestDto
    {
        public int FurnitureId { get; set; }
        public int ColorId { get; set; }
    }
}