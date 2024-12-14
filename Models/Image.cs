using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations.Schema;

namespace api.Models
{
    [Table("Images")]
    public class Image
    {
        public int Id { get; set; }
        public int FurnitureId { get; set; }
        public Furniture? Furniture { get; set; }
        public string Url { get; set; } = string.Empty;
    }
}