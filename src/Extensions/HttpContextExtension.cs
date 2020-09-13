using Microsoft.AspNetCore.Http;
using QuickAPI.Exceptions;
using System;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;

namespace QuickAPI.Extensions
{
    public static class HttpContextExtension
    {
        private const string _jsonContentType = "application/json";

        public static Task WriteResponseAsync(this HttpContext httpContext, object data, HttpStatusCode statusCode)
        {
            httpContext.Response.ContentType = _jsonContentType;
            httpContext.Response.StatusCode = (int)statusCode;
            return httpContext.Response.WriteAsync(JsonSerializer.Serialize(data));
        }

        public static Task WriteResponseAsync(this HttpContext httpContext, string json, HttpStatusCode statusCode)
        {
            httpContext.Response.ContentType = _jsonContentType;
            httpContext.Response.StatusCode = (int)statusCode;
            return httpContext.Response.WriteAsync(json);
        }

        public static Task WriteErrorResponseAsync(this HttpContext httpContext, string message)
        {
            httpContext.Response.ContentType = _jsonContentType;
            httpContext.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
            return httpContext.Response.WriteAsync(JsonSerializer.Serialize(new { Error = message }));
        }

        public static Task WriteErrorResponseAsync(this HttpContext httpContext, Exception exception)
        {
            exception = exception.GetBaseException();

            httpContext.Response.ContentType = _jsonContentType;
            httpContext.Response.StatusCode = (int)HttpStatusCode.InternalServerError;

            if (exception is CredentialsException)
            {
                httpContext.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            }

            return httpContext.Response.WriteAsync(JsonSerializer.Serialize(new { Error = exception.Message }));
        }
    }
}
