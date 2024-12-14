using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using api.Data;
using api.Interfaces;
using api.Models;
using Microsoft.EntityFrameworkCore;

namespace api.Repository
{
    public class CategoryRepository : ICategoryRepository
    {
        private readonly ApplicationDBContext _context;
        public CategoryRepository(ApplicationDBContext context)
        {
            _context = context;
        }

        public Task<List<Category>> GetAllAsync()
        {
            return _context.Category.ToListAsync();
        }
        
        public async Task<Category?> GetByIdAsync(int id)
        {
            return await _context.Category.FirstOrDefaultAsync(category => category.Id == id);
        }

        public async Task<Category> CreateAsync(Category category)
        {
            await _context.Category.AddAsync(category);
            await _context.SaveChangesAsync();
            return category;
        }

        public async Task<Category?> DeleteAsync(int id)
        {
            var category = await _context.Category.FirstOrDefaultAsync(category => category.Id == id);
            if (category == null){
                return null;
            }

            _context.Category.Remove(category);
            await _context.SaveChangesAsync();
            return category;
        }

        public Task<Category?> UpdateAsync(int id, Category categoryDto)
        {
            throw new NotImplementedException();
        }
    }
}