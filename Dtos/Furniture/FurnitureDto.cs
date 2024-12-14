using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using api.Models;

namespace api.Dtos.Furniture
{
    public class FurnitureDto
    {
        public int Id { get; set; }
        public string ProductId { get; set; } = string.Empty;
        public string Name {get; set;} = string.Empty;
        public string Description {get; set;} = string.Empty;
        public string? TechSpec {get; set;} = string.Empty;
        public string? Images {get; set;}
        //public int? CategoryId {get; set;}
        public string? CategoryName {get; set;}
        public decimal Price{get; set;}
        public decimal Quantity{get; set;}
    }
}