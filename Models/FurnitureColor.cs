using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations.Schema;

namespace api.Models
{
    [Table("FurnitureColors")]
    public class FurnitureColor
    {
        public int ColorId {get; set;}
        public int FurnitureId {get; set;}
        // nav properties below
        public Color? Color {get; set;}
        public Furniture? Furniture {get; set;}
    }
}