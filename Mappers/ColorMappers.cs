using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using api.Dtos.Color;
using api.Models;

namespace api.Mappers
{
    public static class ColorMappers
    {
        public static ColorDto ToColorDto(this Color colorModel)
        {
            return new ColorDto
            {
                Id = colorModel.Id,
                Name = colorModel.Name,
                Code = colorModel.Code
            };
        }

        public static Color ToColorFromCreateDto(this CreateColorRequestDto colorDto)
        {
            return new Color
            {
                Name = colorDto.Name,
                Code = colorDto.Code
            };
        }
    }
}