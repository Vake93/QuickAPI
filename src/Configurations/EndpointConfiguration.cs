using Microsoft.OpenApi.Models;
using QuickAPI.Exceptions;
using System.Collections.Generic;
using System.Data;
using System.Text.Json.Serialization;

namespace QuickAPI.Configurations
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum DatabaseType
    {
        PostgreSQL,
        SqlServer
    }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum AuthType
    {
        Basic,
        Jwt
    }

    public class EndpointConfiguration
    {
        public DatabaseType Database { get; set; }

        public AuthenticationConfiguration? Authentication { get; set; }

        public string DatabaseConnection { get; set; } = string.Empty;

        public SwaggerConfiguration? Swagger { get; set; }

        public EndpointDefinition[]? Endpoints { get; set; }
    }

    public class AuthenticationConfiguration
    {
        public AuthType AuthType { get; set; }

        public string? SecurityKey { get; set; }
    }

    public class SwaggerConfiguration
    {
        public bool Enabled { get; set; }

        public string? Title { get; set; }

        public string? Version { get; set; }
    }

    public class EndpointDefinition
    {
        public string EndpointPath { get; set; } = null!;

        public string Sql { get; set; } = null!;

        public string? Grouping { get; set; }

        public Dictionary<string, Parameter>? ParameterBindings { get; set; }

        public ParameterLocation ResolveParameterLocation(string parameterName)
        {
            if (ParameterBindings is null ||
               !ParameterBindings.ContainsKey(parameterName))
            {
                throw new QuickApiException($"Invalid parameter name {parameterName}");
            }

            return EndpointPath.Contains($"{{{parameterName}}}") ?
                ParameterLocation.Path :
                ParameterLocation.Query;
        }
    }

    public class Parameter
    {
        public string Name { get; set; } = null!;

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public DbType Type { get; set; }

        public string? DefaultValue { get; set; }

        public bool HasDefaultValue => !string.IsNullOrEmpty(DefaultValue);
    }
}
