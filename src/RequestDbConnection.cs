using Npgsql;
using QuickAPI.Configurations;
using QuickAPI.Security;
using System;
using System.Data;
using System.Data.SqlClient;

namespace QuickAPI
{
    public class RequestDbConnection : IDisposable
    {
        private RequestDbConnection(IDbConnection dbConnection)
        {
            DbConnection = dbConnection;
        }

        public IDbConnection DbConnection { get; }

        public void Dispose() => DbConnection?.Dispose();

        public static RequestDbConnection GetRequestDbConnection(EndpointConfiguration endpointConfiguration, Credentials? credentials)
        {
            var connectionString = endpointConfiguration.DatabaseConnection;

            if (credentials is Credentials)
            {
                connectionString = BuildConnectionStringWithAuthorization(connectionString, credentials);
            }

            return endpointConfiguration.Database switch
            {
                DatabaseType.PostgreSQL => new RequestDbConnection(new NpgsqlConnection(connectionString)),
                DatabaseType.SqlServer => new RequestDbConnection(new SqlConnection(connectionString)),
                _ => null!
            };
        }

        private static string BuildConnectionStringWithAuthorization(string connectionString, Credentials credentials)
        {
            return connectionString
                .Replace("{username}", credentials.Username)
                .Replace("{password}", credentials.Password);
        }
    }
}
