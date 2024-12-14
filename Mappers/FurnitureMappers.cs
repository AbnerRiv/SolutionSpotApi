using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using api.Dtos.Furniture;
using api.Models;
using System.Text.Json;

namespace api.Mappers
{
    public static class FurnitureMappers
    {
        public static FurnitureDto ToFurnitureDto(this Furniture furnitureModel)
        {
            // Log or debug the image URLs
            return new FurnitureDto
            {
                Id = furnitureModel.Id,
                ProductId = furnitureModel.ProductId,
                Name = furnitureModel.Name,
                Description = furnitureModel.Description,
                TechSpec = furnitureModel.TechSpec,
                //CategoryId = furnitureModel.CategoryId,
                CategoryName = furnitureModel.Category?.Name,
                //Price = furnitureModel.Price,
                Quantity = furnitureModel.Quantity,
                Images = JsonSerializer.Serialize(furnitureModel.Images?.Select(image => image.Url).ToList() ?? new List<string>())
            };
        }

        public static Furniture ToFurnitureFromCreateDto(this CreateFurnitureRequestDto furnitureDto){
            return new Furniture{
                ProductId = furnitureDto.ProductId,
                Name = furnitureDto.Name,
                Description = furnitureDto.Description,
                TechSpec = furnitureDto.TechSpec,
                CategoryId = furnitureDto.CategoryId,
                Price = furnitureDto.Price,
                Quantity = furnitureDto.Quantity,
                //Images = (ICollection<Image>)furnitureDto.Images
            };
        }
    }
}