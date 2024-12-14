using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using api.Dtos.Furniture;
using api.Dtos.Image;
using api.Models;

namespace api.Mappers
{
    public static class ImageMappers
    {
        public static ImageDto ToImageDto(this Image imageModel)
        {
            return new ImageDto
            {
                Id = imageModel.Id,
                FurnitureId = imageModel.FurnitureId,
                Url = imageModel.Url
            };
        }

        public static Image ToImageFromCreateDto(this CreateImageRequestDto imageModel)
        {
            return new Image
            {
                FurnitureId = imageModel.FurnitureId,
                Url = imageModel.Url
            };
        }
    }
}