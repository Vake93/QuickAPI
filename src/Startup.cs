using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi;
using Microsoft.OpenApi.Any;
using Microsoft.OpenApi.Extensions;
using Microsoft.OpenApi.Models;
using QuickAPI.Configurations;
using QuickAPI.Extensions;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace QuickAPI
{
    public class Startup
    {
        private const string _defaultVersion = "1.0.0";
        private const string _defaultTitle = "QuickAPI";
        private const string _apiDocumentPath = "/api-document";
        private const string _openApiSecuritySchemeReferenceId = "Basic Authorization";

        private readonly OpenApiDocument? _openApiDocument;
        private readonly OpenApiSecurityScheme? _openApiSecurityScheme;

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;

            EndpointConfiguration  = configuration
                .GetSection("EndpointConfiguration")
                .Get<EndpointConfiguration>();

            _openApiSecurityScheme = SwaggerEnabled ? new OpenApiSecurityScheme
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
            } : null;

            _openApiDocument = SwaggerEnabled ? new OpenApiDocument
            {
                Info = new OpenApiInfo
                {
                    Version = string.IsNullOrEmpty(SwaggerConfig?.Version) ? _defaultVersion : SwaggerConfig.Version,
                    Title = string.IsNullOrEmpty(SwaggerConfig?.Title) ? _defaultTitle : SwaggerConfig.Title
                },
                Paths = new OpenApiPaths(),
                Components = EndpointConfiguration.UseDatabaseAuth && _openApiSecurityScheme is OpenApiSecurityScheme ?
                new OpenApiComponents
                {
                    SecuritySchemes = new Dictionary<string, OpenApiSecurityScheme>
                    {
                        [_openApiSecuritySchemeReferenceId] = _openApiSecurityScheme
                    }
                } : null,
            } : null;
        }

        public IConfiguration Configuration { get; }

        public EndpointConfiguration EndpointConfiguration { get; }

        public Swagger? SwaggerConfig => EndpointConfiguration?.Swagger;

        public bool SwaggerEnabled => SwaggerConfig?.Enabled ?? false;

        public void Configure(IApplicationBuilder app, ILogger<Program> logger)
        {
            app.UseRouting();

            if (SwaggerEnabled)
            {
                app.UseSwaggerUI(setup =>
                {
                    setup.RoutePrefix = string.Empty;

                    setup.SwaggerEndpoint(
                        _apiDocumentPath,
                        string.IsNullOrEmpty(SwaggerConfig?.Title) ? _defaultTitle : SwaggerConfig.Title);
                });
            }

            if (EndpointConfiguration is EndpointConfiguration)
            {
                ConfigureEndpoints(app, logger);
            }
            else
            {
                ConfigureFallbackEndpoint(app, logger);
            }
        }

        private void ConfigureEndpoints(IApplicationBuilder app, ILogger logger)
        {
            app.UseEndpoints(endpoints =>
            {
                if (EndpointConfiguration?.Endpoints?.Any() ?? false)
                {
                    foreach (var endpointDefinition in EndpointConfiguration.Endpoints)
                    {
                        endpoints.MapGet(endpointDefinition.EndpointPath, async context =>
                        {
                            await HandleRequestAsync(context, endpointDefinition, logger);
                        });

                        if (SwaggerEnabled && _openApiDocument is OpenApiDocument)
                        {
                            var openApiPathItem = BuilOpenApiPathItem(endpointDefinition);
                            _openApiDocument.Paths[endpointDefinition.EndpointPath] = openApiPathItem;
                        }
                    }
                }

                if (SwaggerEnabled && _openApiDocument is OpenApiDocument)
                {
                    var openApiDocumentJson = _openApiDocument.SerializeAsJson(OpenApiSpecVersion.OpenApi3_0);

                    endpoints.MapGet(_apiDocumentPath, async context =>
                        await context.WriteResponseAsync(openApiDocumentJson, HttpStatusCode.OK));
                }

                endpoints.MapFallback(async context =>
                    await context.WriteErrorResponseAsync("Invalid Endpoint"));
            });
        }

        private async Task HandleRequestAsync(HttpContext context, EndpointDefinition endpointDefinition, ILogger logger)
        {
            try
            {
                var credentials = EndpointConfiguration.UseDatabaseAuth ? Credentials.Authenticate(context) : null;
                var parameterValues = RequestParameterValues.ResolveParameters(context, endpointDefinition);

                using var requestDbConnection = RequestDbConnection.GetRequestDbConnection(EndpointConfiguration, credentials);
                using var requestHandler = RequestHandler.GetRequestHandler(endpointDefinition, requestDbConnection, parameterValues);

                var items = await requestHandler.HandleRequestAsync();
                await context.WriteResponseAsync(new { Items = items }, HttpStatusCode.OK);
            }
            catch (Exception e)
            {
                logger.LogError(e, e.Message);
                await context.WriteErrorResponseAsync(e);
            }
        }

        private void ConfigureFallbackEndpoint(IApplicationBuilder app, ILogger logger)
        {
            logger.LogError("Incomplete or invalid configuration");

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapFallback(async context =>
                    await context.WriteErrorResponseAsync("Incomplete or invalid configuration"));
            });
        }

        private OpenApiPathItem BuilOpenApiPathItem(EndpointDefinition endpointDefinition)
        {
            var anyGrouping = !string.IsNullOrEmpty(endpointDefinition.Grouping);

            var tags = new OpenApiTag[]
            {
                new OpenApiTag
                {
                    Name = anyGrouping ? endpointDefinition.Grouping : _defaultTitle
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

            if (EndpointConfiguration.UseDatabaseAuth)
            {
                responses["401"] = new OpenApiResponse
                {
                    Description = "Unauthorized Response"
                };

                security = new OpenApiSecurityRequirement[]
                {
                    new OpenApiSecurityRequirement
                    {
                        [_openApiSecurityScheme] = Array.Empty<string>()
                    }
                };
            }

            return new OpenApiPathItem
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
        }
    }
}
