using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using api.Data;
using api.Interfaces;
using api.Models;
using Microsoft.EntityFrameworkCore;

namespace api.Repository
{
    public class ImageRepository : IImageRepository
    {
        private readonly ApplicationDBContext _context;
        public ImageRepository(ApplicationDBContext context)
        {
            _context = context;
        }
        public async Task<Image?> GetByIdAsync(int id)
        {
            return await _context.Image.FirstOrDefaultAsync(image => image.Id == id);
        }

        public async Task<Image?> DeleteAsync(int id)
        {
            var image = await _context.Image.FirstOrDefaultAsync(image => image.Id == id);
            if (image == null){
                return null;
            }

            _context.Image.Remove(image);
            await _context.SaveChangesAsync();
            return image;
        }

        public async Task<string> UploadImage(IFormFile file){
            using var content = new MultipartFormDataContent();

            var fileContent = new StreamContent(file.OpenReadStream());
            fileContent.Headers.ContentType = new MediaTypeHeaderValue(file.ContentType); 
            content.Add(fileContent, "image", file.FileName);

            var httpClient = new HttpClient
            {
                BaseAddress = new Uri("https://api.imgbb.com/1/")
            };
            string apiKey = Environment.GetEnvironmentVariable("IMGBB_KEY")!;
            var endpointWithParams = $"upload?key={apiKey}";

            var response = await httpClient.PostAsync(endpointWithParams, content);


            if (response.IsSuccessStatusCode)
            {
                var responseObject =  response.Content.ReadFromJsonAsync<ResponseUploadImage>().Result;
                return responseObject!.Data.Url;
            }
            else
            {
                return "error"; // or handle error as needed
            }
        }

        public class ResponseUploadImage
        {
            public DataObject Data { get; set; } = new DataObject();
        }

        public class DataObject
        {
            public string Name { get; set; } = string.Empty;
            public string Url { get; set; } = string.Empty;
        }

        public async Task<Image> CreateAsync(Image image)
        {
            await _context.Image.AddAsync(image);
            await _context.SaveChangesAsync();
            return image;
        }
    }
}