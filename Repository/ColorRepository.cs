using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using api.Data;
using api.Dtos.Color;
using api.Dtos.FurnitureColor;
using api.Interfaces;
using api.Models;
using Microsoft.EntityFrameworkCore;

namespace api.Repository
{
    public class ColorRepository : IColorRepository
    {
        private readonly ApplicationDBContext _context;
        public ColorRepository(ApplicationDBContext context)
        {
            _context = context;
        }
        public async Task<Color> CreateAsync(Color color)
        {
            await _context.Color.AddAsync(color);
            await _context.SaveChangesAsync();
            return color;
        }

        public async Task<Color?> DeleteAsync(int id)
        {
            var color = await _context.Color.FirstOrDefaultAsync(c => c.Id == id);
            if (color == null)
            {
                return null;
            }
            _context.Color.Remove(color);
            await _context.SaveChangesAsync();
            return color;
        }

        public Task<List<Color>> GetAllAsync()
        {
            return _context.Color.ToListAsync();
        }

        public async Task<Color?> GetByIdAsync(int id)
        {
            return await _context.Color.FirstOrDefaultAsync(color => color.Id == id);
        }

        public async Task<Color?> UpdateAsync(int id, CreateColorRequestDto colorDto)
        {
            var colorModel = await _context.Color.FirstOrDefaultAsync(color => color.Id == id);

            if (colorModel == null)
            {
                return null;
            }

            colorModel.Name = colorDto.Name;
            colorModel.Code = colorDto.Code;

            await _context.SaveChangesAsync();

            return colorModel;
        }

        public async Task<FurnitureColor?> CreateAssignedAsync(FurnitureColor furnitureColor)
        {
            var furniture = await _context.Furniture.FirstOrDefaultAsync(f => f.Id == furnitureColor.FurnitureId);
            var color = await _context.Color.FirstOrDefaultAsync(c => c.Id == furnitureColor.ColorId);
            // check if furniture id exist with given Id
            if (furniture == null || color == null)
            {
                return null;
            };

            var furnitureColorModel = new FurnitureColor
            {
                ColorId = color.Id,
                FurnitureId = furniture.Id
            };

            await _context.FurnitureColor.AddAsync(furnitureColorModel);
            await _context.SaveChangesAsync();
            return furnitureColor;
        }

        public async Task<List<GetFurnitureColorDto>?> GetAllAssignedAsync(int id)
        {
            var existingFurniture = await _context.Furniture.FirstOrDefaultAsync(furniture => furniture.Id == id);

            if (existingFurniture == null)
            {
                return null;
            }

            return await _context.FurnitureColor
            .Where(fc => fc.FurnitureId == id)
            .Select(fc => new GetFurnitureColorDto
            {
                ColorName = fc.Color!.Name,
                ColorCode = fc.Color.Code
            })
            .ToListAsync();
        }
    }
}