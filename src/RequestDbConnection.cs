using Dapper;
using Npgsql;
using QuickAPI.Configurations;
using QuickAPI.Security;
using System;
using System.Data;
using System.Data.Common;
using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;

namespace QuickAPI
{
    public class RequestDbConnection : IDisposable
    {
        private RequestDbConnection(DatabaseType databaseType, string connectionString)
        {
            DatabaseType = databaseType;

            DbConnection = DatabaseType switch
            {
                DatabaseType.PostgreSQL => new NpgsqlConnection(connectionString),
                DatabaseType.SqlServer => new SqlConnection(connectionString),
                _ => null!
            };
        }

        public IDbConnection DbConnection { get; }

        public DatabaseType DatabaseType { get; }

        public async Task<bool> TestLoginAsync()
        {
            try
            {
                var testQuery = DatabaseType switch
                {
                    DatabaseType.PostgreSQL => "SELECT 1",
                    DatabaseType.SqlServer => "SELECT 1",
                    _ => string.Empty
                };

                var results = await DbConnection.QueryAsync(testQuery);

                return results.Count() == 1;
            }
            catch (DbException)
            {
                return false;
            }
        }

        public void Dispose() => DbConnection?.Dispose();

        public static RequestDbConnection GetRequestDbConnection(EndpointConfiguration endpointConfiguration, Credentials? credentials)
        {
            var connectionString = endpointConfiguration.DatabaseConnection;

            if (credentials is Credentials)
            {
                connectionString = BuildConnectionStringWithAuthorization(connectionString, credentials);
            }

            return new RequestDbConnection(endpointConfiguration.Database, connectionString);
        }

        private static string BuildConnectionStringWithAuthorization(string connectionString, Credentials credentials)
        {
            return connectionString
                .Replace("{username}", credentials.Username)
                .Replace("{password}", credentials.Password);
        }
    }
}
