using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using api.Data;
using api.Dtos.Furniture;
using api.Dtos.Image;
using System.Net.Http.Headers;
using api.Interfaces;
using api.Models;
using Microsoft.EntityFrameworkCore;
using api.Helpers;
using api.Mappers;
using System.Text;

namespace api.Repository
{
    public class FurnitureRepository : IFurnitureRepository
    {
        private readonly ApplicationDBContext _context;
        public FurnitureRepository(ApplicationDBContext context)
        {
            _context = context;
        }

        public async Task<PagedResult<FurnitureDto>> GetAllAsync(QueryObjectFurniture query)
        {
            var furnitures = _context.Furniture
            .Include(f => f.Images)
            .Include(f => f.Category)
            .AsQueryable();

            // Apply filters based on query parameters
            if (!string.IsNullOrWhiteSpace(query.search))
            {
                furnitures = furnitures.Where(f => 
                    f.ProductId.Contains(query.search) ||
                    f.Name.Contains(query.search)||
                    f.Description.Contains(query.search));
            }

            if (query.CategoryIds != null && query.CategoryIds.Any())
            {
                furnitures = furnitures.Where(f => query.CategoryIds.Contains(f.CategoryId));
            }

            if (query.InStock.HasValue)
            {
                // If InStock is true, filter for items with quantity greater than 0
                if (query.InStock.Value)
                {
                    furnitures = furnitures.Where(f => f.Quantity > 0);
                }
            }

            if (query.MinPrice.HasValue && query.MaxPrice.HasValue)
            {
                // Ensure that MaxPrice is greater than or equal to MinPrice
                if (query.MaxPrice.Value >= query.MinPrice.Value)
                {
                    furnitures = furnitures.Where(f => f.Price >= query.MinPrice.Value && f.Price <= query.MaxPrice.Value);
                }
            }

            // Get total count before pagination
            var totalCount = await furnitures.CountAsync();

            // Apply pagination
            var skipNumber = (query.PageNumber - 1) * query.PageSize;
            var paginatedItems = await furnitures.Skip(skipNumber).Take(query.PageSize).ToListAsync();

            // Calculate total pages
            var totalPages = (int)Math.Ceiling((double)totalCount / query.PageSize);

            return new PagedResult<FurnitureDto>
            {
                Items = paginatedItems.Select(furniture => furniture.ToFurnitureDto()).ToList(),
                TotalCount = totalCount,
                TotalPages = totalPages,
                CurrentPage = query.PageNumber
            };
        }

        public async Task<Furniture?> GetByIdAsync(int id)
        {
            return await _context.Furniture.Include(f => f.Images).Include(f => f.Category).FirstOrDefaultAsync(furniture => furniture.Id == id);
        }

        public async Task<Furniture> CreateAsync(Furniture furniture)
        {
            await _context.Furniture.AddAsync(furniture);
            await _context.SaveChangesAsync();
            return furniture;
        }
        public async Task<Furniture?> PatchAsync(int id, PatchFurnitureRequestDto furnitureDto){
            var furnitureModel = await _context.Furniture.Include(f => f.Images).FirstOrDefaultAsync(furniture => furniture.Id == id);

            if(furnitureModel == null)
            {
                return null;
            }

            if (!string.IsNullOrWhiteSpace(furnitureDto.ProductId))
            {
                furnitureModel.ProductId = furnitureDto.ProductId;
            }

            if (!string.IsNullOrWhiteSpace(furnitureDto.Name))
            {
                furnitureModel.Name = furnitureDto.Name;
            }

            if (!string.IsNullOrWhiteSpace(furnitureDto.Description))
            {
                furnitureModel.Description = furnitureDto.Description;
            }

            if (!string.IsNullOrWhiteSpace(furnitureDto.TechSpec))
            {
                furnitureModel.TechSpec = furnitureDto.TechSpec;
            }

            if (furnitureDto.Quantity.HasValue)
            {
                furnitureModel.Quantity = furnitureDto.Quantity.Value;
            }

            // Remove all images linked to the Furniture Id
            if(furnitureDto.Images != null && furnitureDto.Images.Count != 0){
                _context.Image.RemoveRange(furnitureModel.Images);
            }
            else if(furnitureDto.ImageUrls != null && !string.IsNullOrWhiteSpace(furnitureDto.ImageUrls) ){
                _context.Image.RemoveRange(furnitureModel.Images);
            }

            if (furnitureDto.CategoryId.HasValue)
            {
                furnitureModel.CategoryId = furnitureDto.CategoryId.Value;
            }

            if (furnitureDto.Price.HasValue)
            {
                furnitureModel.Price = furnitureDto.Price.Value;
            }

            await _context.SaveChangesAsync();

            return furnitureModel;
        }

        public async Task<Furniture?> DeleteAsync(int id)
        {
            var furniture = await _context.Furniture.FirstOrDefaultAsync(furniture => furniture.Id == id);
            if (furniture == null)
            {
                return null;
            }
            _context.Furniture.Remove(furniture);
            await _context.SaveChangesAsync();
            return furniture;
        }

        public async Task<HttpResponseMessage> CreateImagesBodyFurnitureCreate(int id, string imageUrls, IHttpContextAccessor httpContextAncestor){
            //prepare base url ready to upload images
            var httpClient = new HttpClient();
            var request = httpContextAncestor.HttpContext!.Request;
            var baseUrl = $"{request.Scheme}://{request.Host}";
            httpClient.BaseAddress = new Uri(baseUrl);

            using var content = new MultipartFormDataContent
            {
                //load the string in 'imageUrls' form property
                { new StringContent(imageUrls, Encoding.UTF8), "imageUrls" }
            };

            return await httpClient.PostAsync($"api/image/{id}", content);
        }

        public async Task<HttpResponseMessage> CreateImagesFormFurnitureCreate(int id, List<IFormFile> images, IHttpContextAccessor httpContextAncestor){
            //prepare base url ready to upload images
            var httpClient = new HttpClient();
            var request = httpContextAncestor.HttpContext!.Request;
            var baseUrl = $"{request.Scheme}://{request.Host}";
            httpClient.BaseAddress = new Uri(baseUrl);
            //prepare content for request
            using var content = new MultipartFormDataContent();
            var imageDto = new CreateImageFormFurniturePostDto
            {
                Images = images
            };
            //load all images file in 'Images' from property
            foreach (var file in imageDto.Images)
            {
                var fileContent = new StreamContent(file.OpenReadStream());
                fileContent.Headers.ContentType = MediaTypeHeaderValue.Parse("multipart/form-data");
                content.Add(fileContent, "Images", file.FileName);
            }
            //trigger and wait Image Post request
            return await httpClient.PostAsync($"api/image/{id}", content);
        }
    }
}