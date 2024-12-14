using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using api.Dtos.Furniture;
using api.Helpers;
using api.Models;

namespace api.Interfaces
{
    public interface IFurnitureRepository
    {
        Task<PagedResult<FurnitureDto>> GetAllAsync(QueryObjectFurniture query);
        Task<Furniture?> GetByIdAsync(int id);
        Task<Furniture> CreateAsync(Furniture furniture);
        Task<Furniture?> PatchAsync(int id, PatchFurnitureRequestDto furniture);
        Task<Furniture?> DeleteAsync(int id);
        Task<HttpResponseMessage> CreateImagesFormFurnitureCreate(int id, List<IFormFile> images, IHttpContextAccessor httpContextAncestor);
        Task<HttpResponseMessage> CreateImagesBodyFurnitureCreate(int id, string imageUrls, IHttpContextAccessor httpContextAncestor);
    }
}