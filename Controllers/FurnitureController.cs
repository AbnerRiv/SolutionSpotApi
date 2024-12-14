using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using api.Data;
using api.Dtos.Furniture;
using api.Interfaces;
using api.Mappers;
using api.responses;
using Microsoft.AspNetCore.Mvc;
using api.Helpers;

namespace api.Controllers
{
    [Route("api/furniture")]
    [ApiController]
    public class FurnitureController : ControllerBase
    {
        private readonly IFurnitureRepository _furnitureRepo;
        private readonly IHttpContextAccessor _httpContextAncestor;
        public FurnitureController(IFurnitureRepository furnitureRepo, IHttpContextAccessor httpContextAccessor)
        {
            _furnitureRepo = furnitureRepo;
            _httpContextAncestor = httpContextAccessor;
        }

        [HttpGet]
        public async Task<IActionResult> GetAll([FromQuery] QueryObjectFurniture query)
        {
            if (!ModelState.IsValid)
            {
                // Return validation errors if the model is invalid
                return BadRequest(ModelState);
            }

            var furnituresPagedResult = await _furnitureRepo.GetAllAsync(query);

            return Ok(furnituresPagedResult);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetById([FromRoute] int id)
        {
            var furniture = await _furnitureRepo.GetByIdAsync(id);

            if (furniture == null)
            {
                var apiResponse = new ApiResponse
                {
                    Message = "FURNITURE NOT FOUND",
                };
                return StatusCode(404, apiResponse);
            }

            return Ok(furniture.ToFurnitureDto());
        }

        [HttpPost]
        public async Task<IActionResult> Create([FromForm] CreateFurnitureRequestDto furnitureDto)
        {
            if (!ModelState.IsValid)
            {
                // Return validation errors if the model is invalid
                return BadRequest(ModelState);
            }

            var furnitureModel = furnitureDto.ToFurnitureFromCreateDto();
            var furniture = await _furnitureRepo.CreateAsync(furnitureModel);

            var apiResponse = new ApiResponse
            {
                Message = "FURNITURE NOT CREATED",
            };

            if (furniture == null)
            {
                return StatusCode(500, apiResponse);
            }

            HttpResponseMessage? response = null;

            // In case Image files are sent
            if (!(furnitureDto.Images == null || furnitureDto.Images.Count == 0))
            {
                response = await _furnitureRepo.CreateImagesFormFurnitureCreate(furniture.Id, furnitureDto.Images, _httpContextAncestor);
            }
            // In case Image Urls are sent
            else if(!string.IsNullOrWhiteSpace(furnitureDto.ImageUrls))
            {
                response = await _furnitureRepo.CreateImagesBodyFurnitureCreate(furniture.Id, furnitureDto.ImageUrls, _httpContextAncestor);
            }
            
            // In case neither image urls nor files are sent    
            if(response == null)
            {
                apiResponse.Message = "FURNITURE CREATED NO IMAGE SENT";
                apiResponse.Data = furnitureModel.ToFurnitureDto();
                return StatusCode(200, apiResponse);
            }

            // All images created
            if (response.IsSuccessStatusCode)
            {
                apiResponse.Message = "FURNITURE AND IMAGES CREATED";
                apiResponse.Data = await GetById(furniture.Id);
                return StatusCode(201, apiResponse);
            }
            else
            {
                // Some or all images Not successfully created
                apiResponse.Message = "ONLY FURNITURE CREATED";
                apiResponse.Data = furnitureModel.ToFurnitureDto();
                return StatusCode(500, apiResponse);
            }
        }

        [HttpPatch("{id}")]
        public async Task<IActionResult> Patch([FromRoute] int id, [FromForm] PatchFurnitureRequestDto furnitureDto)
        {
            /* 
                The approach to this Patch when sending image files or urls is to replace 
                all images linked to the FurnitureId with the ones coming from the Form
            */
            var furnitureModel = await _furnitureRepo.PatchAsync(id, furnitureDto);

            var apiResponse = new ApiResponse
            {
                Message = "FURNITURE NOT FOUND",
            };

            if (furnitureModel == null)
            {
                return StatusCode(404, apiResponse);
            }

            HttpResponseMessage? response = null;

            // In case Image files are sent
            if (!(furnitureDto.Images == null || furnitureDto.Images.Count == 0))
            {
                response = await _furnitureRepo.CreateImagesFormFurnitureCreate(id, furnitureDto.Images, _httpContextAncestor);
            }
            // In case Image Urls are sent
            else if(!string.IsNullOrWhiteSpace(furnitureDto.ImageUrls))
            {
                response = await _furnitureRepo.CreateImagesBodyFurnitureCreate(id, furnitureDto.ImageUrls, _httpContextAncestor);
            }
            
            // In case neither image urls nor files are sent    
            if(response == null)
            {
                apiResponse.Message = "FURNITURE UPDATED NO IMAGE SENT";
                apiResponse.Data = furnitureModel.ToFurnitureDto();
                return StatusCode(200, apiResponse);
            }

            // All images updated
            if (response.IsSuccessStatusCode)
            {
                apiResponse.Message = "FURNITURE AND IMAGES UPDATED";
                apiResponse.Data = await GetById(id);
                return StatusCode(201, apiResponse);
            }
            else
            {
                // Some or all images Not successfully uploaded
                apiResponse.Message = "ONLY FURNITURE UPDATED";
                apiResponse.Data = furnitureModel.ToFurnitureDto();
                return StatusCode(500, apiResponse);
            }
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete([FromRoute] int id)
        {
            var furniture = await _furnitureRepo.DeleteAsync(id);

            if (furniture == null)
            {
                var apiResponse = new ApiResponse
                {
                    Message = "FURNITURE NOT FOUND",
                };
                return StatusCode(404, apiResponse);
            }

            return NoContent();
        }
    }
}