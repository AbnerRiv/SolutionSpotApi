using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using api.Dtos.Category;
using api.Models;

namespace api.Interfaces
{
    public interface ICategoryRepository
    {
        Task<Category?> UpdateAsync(int id, Category categoryDto);
        Task<Category> CreateAsync(Category category);
        Task<List<Category>> GetAllAsync();
        Task<Category?> GetByIdAsync(int id);
        Task<Category?> DeleteAsync(int id);
    }
}