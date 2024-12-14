using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace api.Helpers
{
    public class QueryObjectFurniture
    {
        public string? search {get; set;} = null;
        public List<int>? CategoryIds { get; set; } = null;

        [Range(1, int.MaxValue, ErrorMessage = "Minimum number must be at least 1")]
        public int? MinPrice {get; set;} = null;
        [Range(1, int.MaxValue, ErrorMessage = "Maximum number must be at least 1")]
        public int? MaxPrice {get; set;} = null;
        public bool? InStock {get; set;} = null;
        public int PageNumber {get; set;} = 1;
        public int PageSize {get; set;} = 5;
    }
}