using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace api.Helpers
{
    public class OptionalMinLengthAttribute: ValidationAttribute
    {
        private readonly int _minLength;

        public OptionalMinLengthAttribute(int minLength)
        {
            _minLength = minLength;
        }

        protected override ValidationResult IsValid(object? value, ValidationContext validationContext)
        {
            if (value is string str && !string.IsNullOrEmpty(str) && str.Length < _minLength)
            {
                return new ValidationResult(ErrorMessage ?? $"The field must be at least {_minLength} characters long.");
            }
            return ValidationResult.Success!;
        }
    }
}