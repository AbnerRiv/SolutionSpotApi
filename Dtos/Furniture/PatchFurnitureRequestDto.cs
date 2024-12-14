using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using api.Helpers;

namespace api.Dtos.Furniture
{
    public class PatchFurnitureRequestDto
    {
        [OptionalMinLength(5, ErrorMessage = "ProductId must be at least 5 characters long")]
        public string? ProductId {get; set;}
        [OptionalMinLength(5, ErrorMessage = "Name must be at least 5 characters long")]
        public string? Name {get; set;}
        [OptionalMinLength(10, ErrorMessage = "Description must be at least 10 characters long")]
        public string? Description {get; set;}
        [OptionalMinLength(10, ErrorMessage = "Technical Specification must be at least 10 characters long")]
        public string? TechSpec {get; set;}
        [Range(0, int.MaxValue, ErrorMessage = "Quantity cannot be a negative number")]
        public int? Quantity {get; set;}
        public List<IFormFile>? Images {get; set;} = new List<IFormFile>();
        [Range(1, double.MaxValue, ErrorMessage = "Category Id should be at least 1")]
        public int? CategoryId {get; set;}
        [Range(1, double.MaxValue, ErrorMessage = "Price should be at least 1")]
        public decimal? Price{get; set;}
        public string? ImageUrls {get; set;}
    }
}