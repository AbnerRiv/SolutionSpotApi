using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using api.Dtos.Color;
using api.Dtos.FurnitureColor;
using api.Interfaces;
using api.Mappers;
using api.responses;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace api.Controllers
{
    [Route("api/color")]
    [ApiController]
    public class ColorController : ControllerBase
    {
        private readonly IColorRepository _colorRepo;
        private readonly IFurnitureRepository _furnitureRepo;
        public ColorController(IColorRepository colorRepo, IFurnitureRepository furnitureRepo)
        {
            _colorRepo = colorRepo;
            _furnitureRepo = furnitureRepo;
        }

        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            var colors = await _colorRepo.GetAllAsync();

            var colorsDto = colors.Select(color => color.ToColorDto()).ToList();

            return Ok(colorsDto);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetById([FromRoute] int id)
        {
            var colorModel = await _colorRepo.GetByIdAsync(id);
            if (colorModel == null)
            {
                return NotFound();
            }
            return Ok(colorModel.ToColorDto());
        }

        [HttpPost]
        public async Task<IActionResult> Create([FromBody] CreateColorRequestDto colorDto)
        {
            var colorModel = colorDto.ToColorFromCreateDto();
            await _colorRepo.CreateAsync(colorModel);
            return CreatedAtAction(nameof(GetById), new { id = colorModel.Id }, colorModel.ToColorDto());
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> Update([FromRoute] int id, [FromBody] CreateColorRequestDto colorDto)
        {
            var colorModel = await _colorRepo.UpdateAsync(id, colorDto);
            if (colorModel == null)
            {
                return NotFound();
            }
            return Ok(colorModel.ToColorDto());
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete([FromRoute] int id)
        {
            var colorModel = await _colorRepo.DeleteAsync(id);

            if (colorModel == null)
            {
                var apiResponse = new ApiResponse
                {
                    Message = "COLOR NOT FOUND",
                };
                return StatusCode(404, apiResponse);
            }

            return NoContent();
        }

        [HttpGet("assign/{furnitureId}")]
        [SwaggerOperation(Summary = "Get colors assigned to a furniture", Description = "Get a list of Color objects associated to a furniture id")]
        public async Task<ActionResult<IEnumerable<FurnitureColorDto>>> GetAssignedById([FromRoute] int furnitureId)
        {
            var furnitureColors = await _colorRepo.GetAllAssignedAsync(furnitureId);
            
            var apiResponse = new ApiResponse
            {
                Message = "FURNITURE NOT FOUND",
            };

            if (furnitureColors == null)
            {
                return StatusCode(404, apiResponse);
            }

            if (furnitureColors.Count == 0)
            {
                apiResponse.Message = $"COLOR NOT FOUND FOR FURNITUREID {furnitureId}";
                return StatusCode(404, apiResponse);
            }

            apiResponse.Message = "LIST OF COLORS ASSIGNED TO FURNITUREID";
            apiResponse.Data = furnitureColors;
            return StatusCode(200, apiResponse);
        }

        [HttpPost("assign")]
        [SwaggerOperation(Summary = "assigns a color to a furniture", Description = "assigns a color to a furniture using colorId and furnitureId")]
        public async Task<IActionResult> AssignColor([FromBody] CreateFurnitureColorRequestDto furnitureColorDto)
        {
            var furnitureColorModel = furnitureColorDto.ToFurnitureColorFromCreateDto();
            furnitureColorModel = await _colorRepo.CreateAssignedAsync(furnitureColorModel);

            var apiResponse = new ApiResponse
            {
                Message = "COLOR OR FURNITURE NOT FOUND",
            };

            if (furnitureColorModel == null)
            {
                return StatusCode(404, apiResponse);
            }

            apiResponse.Message = "COLOR ASSIGNED FOR FURNITURE";
            apiResponse.Data = furnitureColorModel.ToFurnitureColorDto();

            return StatusCode(201, apiResponse);
        }
    }
}