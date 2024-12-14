using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using api.Helpers;

namespace api.Middleware
{
    public class RefererCheckMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly HashSet<string> _allowedReferers;
        private readonly IWebHostEnvironment _env;

        public RefererCheckMiddleware(RequestDelegate next, IConfiguration configuration, IWebHostEnvironment env)
        {
            _next = next;
            _env = env;
            _allowedReferers = configuration.GetSection("AllowedReferers").Get<HashSet<string>>()!;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // logic for Api Key

            if (_env.IsDevelopment())
            {
                // If in development, skip the referer check
                await _next(context);
                return;
            }

            var bearerToken = context.Request.Headers["Authorization"];
            if (!string.IsNullOrEmpty(bearerToken))
            {
                string secretKey = Environment.GetEnvironmentVariable("SECRET_KEY")!;
                string apiKey = Environment.GetEnvironmentVariable("API_KEY")!;

                string decryptedApiKey = ApiDecryptor.DecryptString(bearerToken!, secretKey);

                if (decryptedApiKey != apiKey)
                {
                    // Unauthorized if the keys don't match
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsync("Unauthorized: Invalid Key");
                    return;
                }

            }

            // end api key logic


            var referer = context.Request.Headers["Referer"].ToString();

            if (string.IsNullOrEmpty(referer) || !_allowedReferers.Any(r => referer.StartsWith(r, StringComparison.OrdinalIgnoreCase)))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsync("Forbidden: Invalid Referer");
                return;
            }

            await _next(context);
        }
    }
}
