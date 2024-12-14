using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using api.Dtos.Image;
using api.Models;

namespace api.Interfaces
{
    public interface IImageRepository
    {
        Task<Image?> GetByIdAsync(int id);
        Task<Image> CreateAsync(Image image);
        Task<Image?> DeleteAsync(int id);
        Task<string> UploadImage(IFormFile file);
    }
}