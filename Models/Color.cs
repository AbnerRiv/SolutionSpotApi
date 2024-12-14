using System;
using System.Collections.Generic;
using System.Linq;
using System.ComponentModel.DataAnnotations.Schema;
using System.Threading.Tasks;

namespace api.Models
{
    [Table("Colors")]
    public class Color
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
        public ICollection<FurnitureColor> FurnitureColors { get; set; } = new List<FurnitureColor>();
    }
}