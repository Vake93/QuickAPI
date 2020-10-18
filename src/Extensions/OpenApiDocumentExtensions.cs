using Microsoft.OpenApi.Any;
using Microsoft.OpenApi.Models;
using QuickAPI.Configurations;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;

namespace QuickAPI.Extensions
{
    public static class OpenApiDocumentExtensions
    {
        private const string _openApiSecuritySchemeReferenceId = "Basic Authorization";
        private const string _defaultGrouping = "QuickAPI";
        private const string _defaultTitle = "QuickAPI";
        private const string _defaultVersion = "1.0.0";

        public static OpenApiSecurityScheme BuildOpenApiSecurityScheme(
            this AuthenticationConfiguration AuthConfig)
        {
            return AuthConfig.AuthType switch
            {
                AuthType.Basic => new OpenApiSecurityScheme
                {
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    Scheme = "basic",
                    In = ParameterLocation.Header,
                    Reference = new OpenApiReference
                    {
                        Id = _openApiSecuritySchemeReferenceId,
                        Type = ReferenceType.SecurityScheme
                    }
                },

                AuthType.Jwt => new OpenApiSecurityScheme
                {
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer",
                    In = ParameterLocation.Header,
                    BearerFormat = "JWT",
                    Reference = new OpenApiReference
                    {
                        Id = _openApiSecuritySchemeReferenceId,
                        Type = ReferenceType.SecurityScheme
                    }
                },

                _ => throw new NotImplementedException()
            };
        }

        public static OpenApiDocument BuildOpenApiDocument(
            this SwaggerConfiguration swaggerConfig,
            OpenApiSecurityScheme? openApiSecurityScheme)
        {
            return new OpenApiDocument
            {
                Info = new OpenApiInfo
                {
                    Version = string.IsNullOrEmpty(swaggerConfig.Version) ? _defaultVersion : swaggerConfig.Version,
                    Title = string.IsNullOrEmpty(swaggerConfig.Title) ? _defaultTitle : swaggerConfig.Title
                },
                Paths = new OpenApiPaths(),
                Components = openApiSecurityScheme is OpenApiSecurityScheme ?
                new OpenApiComponents
                {
                    SecuritySchemes = new Dictionary<string, OpenApiSecurityScheme>
                    {
                        [openApiSecurityScheme.Reference.Id] = openApiSecurityScheme
                    }
                } : null,
            };
        }

        public static void AddOpenApiPathItem(
            this OpenApiDocument openApiDocument,
            EndpointDefinition endpointDefinition,
            OpenApiSecurityScheme? openApiSecurityScheme)
        {
            var anyGrouping = !string.IsNullOrEmpty(endpointDefinition.Grouping);

            var tags = new OpenApiTag[]
            {
                new OpenApiTag
                {
                    Name = anyGrouping ? endpointDefinition.Grouping : _defaultGrouping
                }
            };

            var anyParameters = endpointDefinition.ParameterBindings?.Any() ?? false;

            var parameters = anyParameters ?
                endpointDefinition.ParameterBindings.Select(
                    pb => new OpenApiParameter
                    {
                        Name = pb.Key,
                        In = endpointDefinition.ResolveParameterLocation(pb.Key),
                        Schema = new OpenApiSchema
                        {
                            Type = Enum.GetName(typeof(DbType), pb.Value.Type),
                            Nullable = pb.Value.HasDefaultValue,
                            Default = pb.Value.HasDefaultValue ? new OpenApiString(pb.Value.DefaultValue) : null
                        }
                    })
                .ToArray() : null;

            var responses = new OpenApiResponses
            {
                ["200"] = new OpenApiResponse
                {
                    Description = "Success Response"
                }
            };

            var security = Array.Empty<OpenApiSecurityRequirement>();

            if (openApiSecurityScheme is OpenApiSecurityScheme)
            {
                responses["401"] = new OpenApiResponse
                {
                    Description = "Unauthorized Response"
                };

                security = new OpenApiSecurityRequirement[]
                {
                    new OpenApiSecurityRequirement
                    {
                        [openApiSecurityScheme] = Array.Empty<string>()
                    }
                };
            }

            var openApiPathItem = new OpenApiPathItem
            {
                Operations = new Dictionary<OperationType, OpenApiOperation>
                {
                    [OperationType.Get] = new OpenApiOperation
                    {
                        Tags = tags,
                        Parameters = parameters,
                        Responses = responses,
                        Security = security
                    }
                }
            };

            openApiDocument.Paths[endpointDefinition.EndpointPath] = openApiPathItem;
        }

        public static void AddLoginApiPathItem(
            this OpenApiDocument openApiDocument,
            string loginEndpoint)
        {
            var tags = new OpenApiTag[]
            {
                new OpenApiTag
                {
                    Name = "Authentication"
                }
            };

            var security = Array.Empty<OpenApiSecurityRequirement>();

            var responses = new OpenApiResponses
            {
                ["200"] = new OpenApiResponse
                {
                    Description = "Success Response"
                },
                ["401"] = new OpenApiResponse
                {
                    Description = "Unauthorized Response"
                }
            };

            var requestBody = new OpenApiRequestBody
            {
                Content = new Dictionary<string, OpenApiMediaType>
                {
                    ["application/json"] = new OpenApiMediaType
                    {
                        Schema = new OpenApiSchema
                        {
                            Required = new HashSet<string>
                            {
                                "username",
                                "password"
                            },
                            Type = "object",
                            Properties = new Dictionary<string, OpenApiSchema>
                            {
                                ["username"] = new OpenApiSchema
                                {
                                    Type = "string"
                                },
                                ["password"] = new OpenApiSchema
                                {
                                    Type = "string"
                                },
                            },
                            AdditionalPropertiesAllowed = false,
                        }
                    }
                }
            };

            var openApiPathItem = new OpenApiPathItem
            {
                Operations = new Dictionary<OperationType, OpenApiOperation>
                {
                    [OperationType.Post] = new OpenApiOperation
                    {
                        Tags = tags,
                        Responses = responses,
                        Security = security,
                        RequestBody = requestBody
                    }
                }
            };

            openApiDocument.Paths[loginEndpoint] = openApiPathItem;
        }
    }
}
