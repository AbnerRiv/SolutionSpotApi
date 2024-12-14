using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace api.responses
{
    public class ApiResponse
    {
        public string? Message { get; set; }
        public object? Data { get; set; } // Use a specific type if needed
    }
}