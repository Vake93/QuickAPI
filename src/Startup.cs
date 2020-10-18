using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi;
using Microsoft.OpenApi.Extensions;
using Microsoft.OpenApi.Models;
using QuickAPI.Configurations;
using QuickAPI.Extensions;
using QuickAPI.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace QuickAPI
{
    public class Startup
    {
        private const string _defaultTitle = "QuickAPI";
        private const string _loginEndpoint = "/api/login";
        private const string _apiDocumentPath = "/api-document";

        private readonly OpenApiDocument? _openApiDocument;
        private readonly OpenApiSecurityScheme? _openApiSecurityScheme;

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;

            EndpointConfiguration  = configuration
                .GetSection("EndpointConfiguration")
                .Get<EndpointConfiguration>();

            _openApiSecurityScheme = SwaggerEnabled && AuthEnabled ?
                AuthConfig!.BuildOpenApiSecurityScheme() :
                null;

            _openApiDocument = SwaggerEnabled ?
                SwaggerConfig!.BuildOpenApiDocument(_openApiSecurityScheme) :
                null;
        }

        public IConfiguration Configuration { get; }

        public EndpointConfiguration EndpointConfiguration { get; }

        public AuthenticationConfiguration? AuthConfig => EndpointConfiguration?.Authentication;

        public bool AuthEnabled => AuthConfig is AuthenticationConfiguration;

        public SwaggerConfiguration? SwaggerConfig => EndpointConfiguration?.Swagger;

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
                            _openApiDocument.AddOpenApiPathItem(endpointDefinition, _openApiSecurityScheme);
                        }
                    }

                    if (AuthConfig?.AuthType == AuthType.Jwt)
                    {
                        endpoints.MapPost(_loginEndpoint, async context =>
                        {
                            await HanldeLoginAsync(context, logger);
                        });

                        if (SwaggerEnabled && _openApiDocument is OpenApiDocument)
                        {
                            _openApiDocument.AddLoginApiPathItem(_loginEndpoint);
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
                var credentials = AuthEnabled ? Credentials.Authenticate(context, AuthConfig!) : null;
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

        private async Task HanldeLoginAsync(HttpContext context, ILogger logger)
        {
            try
            {
                var credentialData = await context.ReadModelAsync<Dictionary<string, string>>();
                var credentials = new Credentials(credentialData);

                using var requestDbConnection = RequestDbConnection.GetRequestDbConnection(EndpointConfiguration, credentials);
                var loginOk = await requestDbConnection.TestLoginAsync();

                if (loginOk)
                {
                    var tokens = credentials.Login(AuthConfig!);
                    await context.WriteResponseAsync(tokens, HttpStatusCode.OK);
                }
                else
                {
                    await context.WriteResponseAsync(new { Error = "Invalid Credentials" }, HttpStatusCode.Unauthorized);
                }
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
    }
}
