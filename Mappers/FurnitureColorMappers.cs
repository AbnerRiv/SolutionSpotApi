using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using api.Dtos.FurnitureColor;
using api.Models;

namespace api.Mappers
{
    public static class FurnitureColorMappers
    {
        public static FurnitureColorDto ToFurnitureColorDto(this FurnitureColor colorFurnitureDto)
        {
            return new FurnitureColorDto
            {
                FurnitureId = colorFurnitureDto.FurnitureId,
                ColorId = colorFurnitureDto.ColorId
            };
        }

        public static FurnitureColor ToFurnitureColorFromCreateDto(this CreateFurnitureColorRequestDto colorFurnitureDto)
        {
            return new FurnitureColor
            {
                FurnitureId = colorFurnitureDto.FurnitureId,
                ColorId = colorFurnitureDto.ColorId
            };
        }
    }
}