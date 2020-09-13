using Microsoft.AspNetCore.Http;
using QuickAPI.Configurations;
using QuickAPI.Exceptions;
using System;
using System.Collections.Generic;
using System.Data;

namespace QuickAPI
{
    public class RequestParameterValues : Dictionary<string, (DbType type, object value)>
    {
        private RequestParameterValues()
        {
        }

        public static RequestParameterValues ResolveParameters(HttpContext context, EndpointDefinition endpointDefinition)
        {
            var parameterValues = new RequestParameterValues();

            var anyParameters = (endpointDefinition.ParameterBindings?.Count ?? 0) > 0;

            if (anyParameters)
            {
                foreach (var parameter in endpointDefinition.ParameterBindings!)
                {
                    var value = parameter.Value.DefaultValue;

                    if (context.Request.Query.ContainsKey(parameter.Key))
                    {
                        value = context.Request.Query[parameter.Key].ToString();
                    }

                    if (context.Request.RouteValues.ContainsKey(parameter.Key))
                    {
                        value = context.Request.RouteValues[parameter.Key].ToString();
                    }

                    if (string.IsNullOrEmpty(value))
                    {
                        throw new ParameterException($"Value for parameter {parameter.Key} is required");
                    }

                    parameterValues[parameter.Value.Name] = (
                        parameter.Value.Type,
                        ParseParameterValue(parameter.Value, value));
                }
            }

            return parameterValues;
        }

        private static object ParseParameterValue(Parameter parameter, string value)
        {
            return parameter.Type switch
            {
                DbType.Boolean => bool.Parse(value),
                DbType.Date => DateTime.Parse(value),
                DbType.DateTime => DateTime.Parse(value),
                DbType.Decimal => decimal.Parse(value),
                DbType.Double => double.Parse(value),
                DbType.Guid => Guid.Parse(value),
                DbType.Int16 => short.Parse(value),
                DbType.Int32 => int.Parse(value),
                DbType.Int64 => long.Parse(value),
                DbType.Single => float.Parse(value),
                DbType.String => value,
                DbType.Time => DateTime.Parse(value),
                DbType.DateTimeOffset => DateTimeOffset.Parse(value),
                _ => throw new ParameterException($"Parameter type {parameter.Type} is not supported (yet)"),
            };
        }
    }
}
