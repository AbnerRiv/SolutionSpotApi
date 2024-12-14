using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace api.Models
{
    [Table("Furnitures")]
    public class Furniture
    {
        public int Id { get; set; }
        public string ProductId { get; set; } = string.Empty;
        public string Name {get; set;} = string.Empty;
        public string Description {get; set;} = string.Empty;
        public string? TechSpec {get; set;} = string.Empty;
        public int Quantity {get; set;} = 0;
        public ICollection<Image> Images {get; set;} = new List<Image>();
        public ICollection<FurnitureColor> FurnitureColors {get; set;} = new List<FurnitureColor>();
        public int CategoryId {get; set;}
        // Navigation Property
        public Category? Category {get; set;}
        [Column(TypeName = "decimal(18,2)")]
        public decimal Price{get; set;}
        
    }
}