using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace api.Dtos.Furniture
{
    public class CreateFurnitureRequestDto
    {
        [Required(ErrorMessage = "ProductId is required")]
        [MinLength(5, ErrorMessage = "ProductId must be at least 5 characters long")]
        public required string ProductId {get; set;}
        [Required(ErrorMessage = "Name is required")]
        [MinLength(5, ErrorMessage = "Name must be at least 5 characters long")]
        public required string Name {get; set;}
        [Required(ErrorMessage = "Description is required")]
        [MinLength(10, ErrorMessage = "Description must be at least 10 characters long")]
        public string Description {get; set;} = string.Empty;
        // [Required(ErrorMessage = "Technical Specification is required")]
        // [MinLength(10, ErrorMessage = "Technical Specification must be at least 10 characters long")]
        public string? TechSpec {get; set;} = string.Empty;
        [Required(ErrorMessage = "Quantity is required")]
        [Range(0, int.MaxValue, ErrorMessage = "Quantity cannot be a negative number")]
        public required int Quantity {get; set;}
        [Required(ErrorMessage = "CategoryId is required")]
        [Range(1, double.MaxValue, ErrorMessage = "Category Id should be at least 1")]
        public required int CategoryId {get; set;}
        [Required(ErrorMessage = "Price is required")]
        [Range(1, double.MaxValue, ErrorMessage = "Price should be at least 1")]
        public required decimal Price{get; set;}
        public List<IFormFile> Images {get; set;} = new List<IFormFile>();
        //image link array parsed
        public string? ImageUrls {get; set;}
    }
}