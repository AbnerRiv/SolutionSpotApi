using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using api.Dtos.Category;
using api.Interfaces;
using api.Mappers;
using api.responses;
using Microsoft.AspNetCore.Mvc;

namespace api.Controllers
{
    [Route("api/category")]
    [ApiController]
    public class CategoryController: ControllerBase
    {
        private readonly ICategoryRepository _categoryRepo;
        public CategoryController(ICategoryRepository categoryRepo)
        {
            _categoryRepo = categoryRepo;
        }

        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            var categories = await _categoryRepo.GetAllAsync();

            var categoriesDto = categories.Select(category => category.ToCategoryDto()).ToList();
            
            return Ok(categoriesDto);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetById([FromRoute] int id){
            var categoryModel = await _categoryRepo.GetByIdAsync(id);
            if (categoryModel == null)
            {
                return NotFound();
            }
            return Ok(categoryModel.ToCategoryDto());
        }


        [HttpPost]
        public async Task<IActionResult> Create([FromBody] CreateCategoryRequestDto categoryDto){
            var categoryModel = categoryDto.ToCategoryFromCreateDto();
            await _categoryRepo.CreateAsync(categoryModel);
            return CreatedAtAction(nameof(GetById), new {id = categoryModel.Id}, categoryModel.ToCategoryDto());
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete([FromRoute] int id)
        {
            var image = await _categoryRepo.DeleteAsync(id);

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