namespace Cosmos.Samples.Encryption
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Azure.Core;
    using Azure.Identity;
    using Microsoft.Azure.Cosmos;
    using Microsoft.Azure.Cosmos.Encryption.Custom;
    using Microsoft.Azure.Cosmos.Fluent;
    using Microsoft.Data.Encryption.AzureKeyVaultProvider;
    using Microsoft.Extensions.Configuration;
    using Newtonsoft.Json;
    using EncryptionKeyWrapMetadata = Microsoft.Azure.Cosmos.Encryption.Custom.EncryptionKeyWrapMetadata;

    // ----------------------------------------------------------------------------------------------------------
    // Prerequisites - 
    // 
    // 1. An Azure Cosmos account - 
    //    https://docs.microsoft.com/en-us/azure/cosmos-db/create-cosmosdb-resources-portal
    //
    // 2. Microsoft.Azure.Cosmos NuGet package - 
    //    http://www.nuget.org/packages/Microsoft.Azure.Cosmos/ 
    // ----------------------------------------------------------------------------------------------------------
    // Sample - demonstrates the basic usage of client-side encryption support in the Cosmos DB SDK.
    // ----------------------------------------------------------------------------------------------------------

    public class Program
    {
        private const string databaseId = "samples";
        private const string containerId = "encryptedData";
        private const string keyContainerId = "keyContainer";

        // tenant 1
        private const string dek1_Tenant1 = "theDEK1";
        // tenant 2
        private const string dek2_Tenant2 = "theDEK2";

        private static Container containerWithEncryption = null;
        private const string EncryptionAlgorithm = CosmosEncryptionAlgorithm.MdeAeadAes256CbcHmac256Randomized;

        private static CosmosClient client = null;

        // <Main>
#pragma warning disable IDE0060 // Remove unused parameter
        public static async Task Main(string[] args)
#pragma warning restore IDE0060 // Remove unused parameter
        {

            try
            {
                // Read the Cosmos endpointUrl and authorizationKey from configuration.
                // These values are available from the Azure Management Portal on the Cosmos Account Blade under "Keys".
                // Keep these values in a safe and secure location. Together they provide administrative access to your Cosmos account.
                IConfigurationRoot configuration = new ConfigurationBuilder()
                    .AddJsonFile("appSettings.json")
                    .Build();

                Program.client = Program.CreateClientInstance(configuration);
                await Program.InitializeAsync(client, configuration);
                await Program.RunDemoAsync(client);
            }
            catch (CosmosException cre)
            {
                Console.WriteLine(cre.ToString());
            }
            catch (Exception e)
            {
                Exception baseException = e.GetBaseException();
                Console.WriteLine("Message: {0} Error: {1}", baseException.Message, e);
            }
            finally
            {
                Console.WriteLine("End of demo, press any key to exit.");
                Console.ReadKey();
                await Program.CleanupAsync();
            }
        }

        // </Main>
        private static CosmosClient CreateClientInstance(IConfigurationRoot configuration)
        {
            string endpoint = configuration["EndPointUrl"];
            if (string.IsNullOrEmpty(endpoint))
            {
                throw new ArgumentNullException("Please specify a valid endpoint in the appSettings.json");
            }

            string authKey = configuration["AuthorizationKey"];
            if (string.IsNullOrEmpty(authKey) || string.Equals(authKey, "Super secret key"))
            {
                throw new ArgumentException("Please specify a valid AuthorizationKey in the appSettings.json");
            }

            return new CosmosClientBuilder(endpoint, authKey).Build();
        }

        private static X509Certificate2 GetCertificate(string clientCertThumbprint)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindByThumbprint, clientCertThumbprint, false);
            store.Close();

            if (certs.Count == 0)
            {
                throw new ArgumentException("Certificate with thumbprint not found in CurrentUser certificate store");
            }

            return certs[0];
        }

        private static TokenCredential GetTokenCredential(string tenantId, string clientId, string clientCertThumbprint)
        {
            ClientCertificateCredential clientCertificateCredential;
            clientCertificateCredential = new ClientCertificateCredential(tenantId, clientId, Program.GetCertificate(clientCertThumbprint));
            return clientCertificateCredential;
        }

        /// <summary>
        /// Administrative operations - create the database, container, and generate the necessary data encryption keys.
        /// These are initializations and are expected to be invoked only once - do not invoke these before every item request.
        /// </summary>
        private static async Task InitializeAsync(CosmosClient client, IConfigurationRoot configuration)
        {
            Database database = await client.CreateDatabaseIfNotExistsAsync(Program.databaseId);
            Container container;
            
            // Delete the existing container to prevent create item conflicts.
            using (await database.GetContainer(Program.containerId).DeleteContainerStreamAsync())
            { }

            Console.WriteLine("The demo will create a 1000 RU/s container.");

            // Create a container with the appropriate partition key definition (we choose the "AccountNumber" property here) and throughput (we choose 1000 here).
            container = await database.DefineContainer(Program.containerId, "/AccountNumber").CreateAsync(throughput: 1000);

            // Get the Tenant ID 
            string tenantId1 = configuration["TenantId1"];
            if (string.IsNullOrEmpty(tenantId1))
            {
                throw new ArgumentNullException("Please specify a valid TenantId1 in the appSettings.json");
            }
            
            string clientId1 = configuration["ClientId1"];
            if (string.IsNullOrEmpty(clientId1))
            {
                throw new ArgumentNullException("Please specify a valid ClientId1 in the appSettings.json");
            }

            // Certificate's public key must be at least 2048 bits.
            string clientCertThumbprint1 = configuration["ClientCertThumbprint1"];
            if (string.IsNullOrEmpty(clientCertThumbprint1))
            {
                throw new ArgumentNullException("Please specify a valid ClientCertThumbprint1 in the appSettings.json");
            }

            // Get the Tenant ID 
            string tenantId2 = configuration["TenantId2"];
            if (string.IsNullOrEmpty(tenantId1))
            {
                throw new ArgumentNullException("Please specify a valid TenantId2 in the appSettings.json");
            }

            string clientId2 = configuration["ClientId2"];
            if (string.IsNullOrEmpty(clientId1))
            {
                throw new ArgumentNullException("Please specify a valid ClientId2 in the appSettings.json");
            }

            // Certificate's public key must be at least 2048 bits.
            string clientCertThumbprint2 = configuration["ClientCertThumbprint2"];
            if (string.IsNullOrEmpty(clientCertThumbprint1))
            {
                throw new ArgumentNullException("Please specify a valid ClientCertThumbprint2 in the appSettings.json");
            }

            AzureKeyVaultKeyStoreProvider azureKeyVaultKeyStoreProviderTenant1 = new AzureKeyVaultKeyStoreProvider(GetTokenCredential(tenantId1, clientId1, clientCertThumbprint1));
            AzureKeyVaultKeyStoreProvider azureKeyVaultKeyStoreProviderTenant2 = new AzureKeyVaultKeyStoreProvider(GetTokenCredential(tenantId2, clientId2, clientCertThumbprint2));

            // tenant 1 key vault
            string akvKeyVault1 = configuration["MasterKey1Url"];
            if (string.IsNullOrEmpty(akvKeyVault1))
            {
                throw new ArgumentException("Please specify a valid MasterKeyUrl1 in the appSettings.json");
            }

            // tenant 2 key vault
            string akvKeyVault2 = configuration["MasterKey2Url"];
            if (string.IsNullOrEmpty(akvKeyVault2))
            {
                throw new ArgumentException("Please specify a valid MasterKeyUrl2 in the appSettings.json");
            }

            Dictionary<string, AzureKeyVaultKeyStoreProvider> keyStoreProviderMap = new Dictionary<string, AzureKeyVaultKeyStoreProvider>
            {
                { new Uri(akvKeyVault1).Host, azureKeyVaultKeyStoreProviderTenant1 },
                { new Uri(akvKeyVault2).Host, azureKeyVaultKeyStoreProviderTenant2 }
            };

            MultiTenantAkvKeyStoreProvider multiTenantAkvKeyStoreProvider = new MultiTenantAkvKeyStoreProvider(keyStoreProviderMap);
            multiTenantAkvKeyStoreProvider.DataEncryptionKeyCacheTimeToLive = TimeSpan.FromHours(24);

            CosmosDataEncryptionKeyProvider dekProvider = new CosmosDataEncryptionKeyProvider(
                multiTenantAkvKeyStoreProvider,
                dekPropertiesTimeToLive: TimeSpan.FromHours(24));

            
            CosmosEncryptor encryptor = new CosmosEncryptor(dekProvider);
            await dekProvider.InitializeAsync(database, Program.keyContainerId);

            Program.containerWithEncryption = container.WithEncryptor(encryptor);

            /// Generates an encryption key, wraps it using the key wrap metadata provided
            /// with the key wrapping provider configured on the client
            /// and saves the wrapped encryption key in the key container.

            EncryptionKeyWrapMetadata wrapMetadata1 = new EncryptionKeyWrapMetadata("key1", akvKeyVault1);
            await dekProvider.DataEncryptionKeyContainer.CreateDataEncryptionKeyAsync(
                dek1_Tenant1,
                EncryptionAlgorithm,
                wrapMetadata1);

            EncryptionKeyWrapMetadata wrapMetadata2 = new EncryptionKeyWrapMetadata("key2", akvKeyVault2);
            await dekProvider.DataEncryptionKeyContainer.CreateDataEncryptionKeyAsync(
                dek2_Tenant2,
                EncryptionAlgorithm,
                wrapMetadata2);
        }

        private static async Task RunDemoAsync(CosmosClient client)
        {
            /*create an item for Tenant 1 using dataEncryptionKeyId1*/
            string orderId1 = "1456234";           
            string account1 = "Account1";
           
            SalesOrder order1 = Program.GetSalesOrderSample(account1, orderId1);
            ItemResponse<SalesOrder> orderCreate1 =  await Program.containerWithEncryption.CreateItemAsync(
                     order1,
                     new PartitionKey(account1),
                     new EncryptionItemRequestOptions
                     {
                         EncryptionOptions = new EncryptionOptions
                         {
                             DataEncryptionKeyId = dek1_Tenant1,
                             EncryptionAlgorithm = EncryptionAlgorithm,
                             PathsToEncrypt = new List<string> { "/Freight", "/ponumber", "/ShippedDate", "/TotalDue", "/Items" }
                         }
                     });

            if(orderCreate1.StatusCode != HttpStatusCode.Created)
            {
                throw new ApplicationException("Failed to create document");
            }

            Console.WriteLine("\n Created document, reading it back.\n");

            orderCreate1 = await Program.containerWithEncryption.ReadItemAsync<SalesOrder>(orderId1, new PartitionKey(account1));            
            Console.WriteLine(JsonConvert.SerializeObject(orderCreate1.Resource, Formatting.Indented));

            /*create an item for Tenant 2 using dataEncryptionKeyId2*/
            string orderId2 = "34584359";
            string account2 = "Account2";

            SalesOrder order2 = Program.GetSalesOrderSample(account2, orderId2);
            ItemResponse<SalesOrder> orderCreate2 = await Program.containerWithEncryption.CreateItemAsync(
                     order2,
                     new PartitionKey(account2),
                     new EncryptionItemRequestOptions
                     {
                         EncryptionOptions = new EncryptionOptions
                         {
                             DataEncryptionKeyId = dek2_Tenant2,
                             EncryptionAlgorithm = EncryptionAlgorithm,
                             PathsToEncrypt = new List<string> { "/Freight", "/TotalDue", "/Items" }
                         }
                     });

            if (orderCreate2.StatusCode != HttpStatusCode.Created)
            {
                throw new ApplicationException("Failed to create document");
            }

            Console.WriteLine("\n Created document, reading it back.\n");

            orderCreate2 = await Program.containerWithEncryption.ReadItemAsync<SalesOrder>(orderId2, new PartitionKey(account2));            
            Console.WriteLine(JsonConvert.SerializeObject(orderCreate2.Resource, Formatting.Indented));

            Console.WriteLine("\nRunning Query");
            await Program.RunQueryAndDisplayDocumentsAsync(
                Program.containerWithEncryption,
                string.Format("SELECT * FROM c"));
        }

        private static async Task RunQueryAndDisplayDocumentsAsync(
            Container container,
            string query = null,
            SalesOrder expectedDoc = null,
            QueryDefinition queryDefinition = null)
        {
            QueryRequestOptions requestOptions = expectedDoc != null
                ? new QueryRequestOptions()
                {
                    PartitionKey = new PartitionKey(expectedDoc.AccountNumber),
                    MaxItemCount = -1,
                }
                : null;

            FeedIterator<SalesOrder> queryResponseIterator = query != null
                ? container.GetItemQueryIterator<SalesOrder>(query, requestOptions: requestOptions)
                : container.GetItemQueryIterator<SalesOrder>(queryDefinition, requestOptions: requestOptions);
            FeedResponse<SalesOrder> readDocs = await queryResponseIterator.ReadNextAsync();

            Console.WriteLine("Query results : {0}", readDocs.Count);

            foreach (SalesOrder itr in readDocs.Resource)
                Console.WriteLine(JsonConvert.SerializeObject(itr, Formatting.Indented));

            Console.WriteLine("\n");

        }

        private static SalesOrder GetSalesOrderSample(string account, string orderId)
        {
            SalesOrder salesOrder = new SalesOrder
            {
                Id = orderId,
                AccountNumber = account,
                PurchaseOrderNumber = "PO18009186470",
                OrderDate = new DateTime(1111, 11, 11),
                SubTotal = 419.4589m,
                Freight = 472.3108m,
                TotalDue = 985,
                Items = new SalesOrderDetail[]
                {
                    new SalesOrderDetail
                    {
                        OrderQty = 1,
                        ProductId = 760,
                        UnitPrice = 419.4589m,
                        LineTotal = 419.4589m
                    }
                },
            };

            // Set the "ttl" property to auto-expire sales orders in 30 days 
            salesOrder.TimeToLive = 60 * 60 * 24 * 30;
            return salesOrder;
        }

        private static async Task CleanupAsync()
        {
            if (Program.client != null)
            {
                await Program.client.GetDatabase(databaseId).DeleteStreamAsync();
            }
        }
    }
}
