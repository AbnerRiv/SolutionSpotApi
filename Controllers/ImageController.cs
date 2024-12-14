using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using api.Dtos.Image;
using api.Interfaces;
using api.Mappers;
using api.responses;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;
using Newtonsoft.Json;

namespace api.Controllers
{
    [Route("api/image")]
    [ApiController]
    public class ImageController : ControllerBase
    {
        private readonly IImageRepository _imageRepo;
        private readonly IFurnitureRepository _furnitureRepo;
        public ImageController(IImageRepository imageRepo, IFurnitureRepository furnitureRepo)
        {
            _imageRepo = imageRepo;
            _furnitureRepo = furnitureRepo;
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetById([FromRoute] int id)
        {

            var image = await _imageRepo.GetByIdAsync(id);

            if (image == null)
            {
                return NotFound();
            }

            return Ok(image.ToImageDto());
        }

        [HttpPost]
        [Route("{productId}")]
        [SwaggerOperation(Summary = "Upload an image for product", Description = "Uploads a new image to a product whose id is productId")]
        public async Task<IActionResult> Create([FromRoute] int productId, [FromForm] CreateImageFormFurniturePostDto ImageDto)
        {
            var furniture = await _furnitureRepo.GetByIdAsync(productId);

            if (furniture == null)
            {
                return NotFound();
            }

            var apiResponse = new ApiResponse
            {
                Message = "IMAGES CREATED",
            };

            if((ImageDto.Images == null || ImageDto.Images.Count == 0) && string.IsNullOrWhiteSpace(ImageDto.ImageUrls)){
                //bad request
                apiResponse.Message = "IMAGE OR URLS NOT SENT";
                return StatusCode(400, apiResponse);
            }
            
            //Image Url's sent
            if( ImageDto.ImageUrls != null && !string.IsNullOrWhiteSpace(ImageDto.ImageUrls))
            {
               var decodedImageUrls = JsonConvert.DeserializeObject<string[]>(ImageDto.ImageUrls);
      
               foreach( var url in decodedImageUrls!){
                var imageModel = new CreateImageRequestDto
                {
                    FurnitureId = productId,
                    Url = url
                };

                await _imageRepo.CreateAsync(imageModel.ToImageFromCreateDto());
               }

                apiResponse.Message = "IMAGES CREATED";
                return StatusCode(201, apiResponse);
            }
            // image files sent
            else if( ImageDto.Images != null || ImageDto.Images?.Count > 0 )
            {
                foreach (var imageFile in ImageDto.Images!)
                {
                    if (imageFile.Length > 32 * 1024 * 1024)
                    {
                        return StatusCode(400, new { message = $@"File size should not exceed 32MB. FAILED TO UPLOAD IMAGE {imageFile.FileName}" });
                    }

                    var fileExtension = Path.GetExtension(imageFile.FileName).ToLowerInvariant();
                    if (fileExtension != ".jpg" && fileExtension != ".jpeg" && fileExtension != ".png")
                    {
                        return StatusCode(400, new { message = $@"ONLY JPEG, PNG, AND JPG ARE SUPPORTED. FAILED TO UPLOAD IMAGE {imageFile.FileName}" });
                    }

                    var imageUrl = await _imageRepo.UploadImage(imageFile);

                    if (imageUrl == "error")
                    {
                        return StatusCode(500, new { message = $@"FAILED TO UPLOAD IMAGE {imageFile.FileName}" });
                    }

                    var imageModel = new CreateImageRequestDto
                    {
                        FurnitureId = productId,
                        Url = imageUrl
                    };

                    await _imageRepo.CreateAsync(imageModel.ToImageFromCreateDto());
                }
                apiResponse.Message = "IMAGES CREATED";
                return StatusCode(201, apiResponse);
            }
            
            return StatusCode(500, apiResponse);
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete([FromRoute] int id)
        {
            var image = await _imageRepo.DeleteAsync(id);

            if (image == null)
            {
                var apiResponse = new ApiResponse
                {
                    Message = "IMAGE NOT FOUND",
                };
                return StatusCode(404, apiResponse);
            }

            return NoContent();
        }
    }
}