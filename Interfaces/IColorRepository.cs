using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using api.Dtos.Color;
using api.Dtos.FurnitureColor;
using api.Models;

namespace api.Interfaces
{
    public interface IColorRepository
    {
        Task<Color?> UpdateAsync(int id, CreateColorRequestDto colorDto);
        Task<Color> CreateAsync(Color Color);
        Task<List<Color>> GetAllAsync();
        Task<Color?> GetByIdAsync(int id);
        Task<Color?> DeleteAsync(int id);
        Task<FurnitureColor?> CreateAssignedAsync(FurnitureColor furnitureColor);
        Task<List<GetFurnitureColorDto>?> GetAllAssignedAsync(int id);
    }
}