using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace api.Dtos.Color
{
    public class CreateColorRequestDto
    {
        public required string Name { get; set; }
        public required string Code { get; set; }
    }
}