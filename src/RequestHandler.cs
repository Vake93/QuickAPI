using Dapper;
using QuickAPI.Configurations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace QuickAPI
{
    public class RequestHandler : IDisposable
    {
        private readonly RequestParameterValues _parameterValues;
        private readonly EndpointDefinition _endpointDefinition;
        private readonly RequestDbConnection _requestDbConnection;

        private RequestHandler(
            EndpointDefinition endpointDefinition,
            RequestDbConnection requestDbConnection,
            RequestParameterValues parameterValues)
        {
            _endpointDefinition = endpointDefinition;
            _requestDbConnection = requestDbConnection;
            _parameterValues = parameterValues;
        }

        public Task<IEnumerable<dynamic>> HandleRequestAsync()
        {
            if (_parameterValues.Any())
            {
                var parameters = new DynamicParameters();
                foreach (var parameter in _parameterValues)
                {
                    var (type, value) = parameter.Value;
                    parameters.Add(parameter.Key, value, type);
                }

                return _requestDbConnection.DbConnection.QueryAsync(_endpointDefinition.Sql, parameters);
            }

            return _requestDbConnection.DbConnection.QueryAsync(_endpointDefinition.Sql);
        }

        public void Dispose() => _requestDbConnection.Dispose();

        public static RequestHandler GetRequestHandler(
            EndpointDefinition endpointDefinition,
            RequestDbConnection requestDbConnection,
            RequestParameterValues parameterValues)
        {
            return new RequestHandler(endpointDefinition, requestDbConnection, parameterValues);
        }
    }
}
