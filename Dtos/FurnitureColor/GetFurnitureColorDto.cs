using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace api.Dtos.FurnitureColor
{
    public class GetFurnitureColorDto
    {
        public string ColorName { get; set; } = string.Empty;
        public string ColorCode { get; set; } = string.Empty;
    }
}