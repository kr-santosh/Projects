namespace Cosmos.Samples.Encryption
{
    using System;
    using Microsoft.Data.Encryption.AzureKeyVaultProvider;
    using Microsoft.Data.Encryption.Cryptography;
    using System.Collections.Generic;

    public class MultiTenantAkvKeyStoreProvider : EncryptionKeyStoreProvider
    {
        public override string ProviderName => "MULTI_TENANT_AKV_VAULT";
        private readonly Dictionary<string, AzureKeyVaultKeyStoreProvider> keyStoreProviderMap;

        public MultiTenantAkvKeyStoreProvider(Dictionary<string, AzureKeyVaultKeyStoreProvider> multiTenantAkvKeyStoreProviderMap)
        {
            this.keyStoreProviderMap = new Dictionary<string, AzureKeyVaultKeyStoreProvider>(multiTenantAkvKeyStoreProviderMap);

            // disable this cache.
            foreach (AzureKeyVaultKeyStoreProvider azureKeyVaultKeyStoreProvider in this.keyStoreProviderMap.Values)
            {
                azureKeyVaultKeyStoreProvider.DataEncryptionKeyCacheTimeToLive = TimeSpan.Zero;
            }
        }

        public override byte[] UnwrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm encryptionAlgorithm, byte[] encryptedKey)
        {
            string keyVault = new Uri(masterKeyPath).Host;

            if (this.keyStoreProviderMap.TryGetValue(keyVault, out AzureKeyVaultKeyStoreProvider azureKeyVaultKeyStoreProvider))
            {
                return azureKeyVaultKeyStoreProvider.UnwrapKey(masterKeyPath, encryptionAlgorithm, encryptedKey);
            }
            else
            {
                throw new InvalidOperationException($"UnwrapKey:AzureKeyVaultKeyStoreProvider missing for key vault {masterKeyPath}");
            }
        }

        public override byte[] WrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm encryptionAlgorithm, byte[] key)
        {
            string keyVault = new Uri(masterKeyPath).Host;            

            if (this.keyStoreProviderMap.TryGetValue(keyVault, out AzureKeyVaultKeyStoreProvider azureKeyVaultKeyStoreProvider))
            {
                return azureKeyVaultKeyStoreProvider.WrapKey(masterKeyPath, encryptionAlgorithm, key);
            }
            else
            {
                throw new InvalidOperationException($"WrapKey:AzureKeyVaultKeyStoreProvider missing for key vault {masterKeyPath}");
            }
        }

        public override byte[] Sign(string masterKeyPath, bool allowEnclaveComputations)
        {
            string keyVault = new Uri(masterKeyPath).Host;

            if (this.keyStoreProviderMap.TryGetValue(keyVault, out AzureKeyVaultKeyStoreProvider azureKeyVaultKeyStoreProvider))
            {
                return azureKeyVaultKeyStoreProvider.Sign(masterKeyPath, allowEnclaveComputations);
            }
            else
            {
                throw new InvalidOperationException($"Sign:AzureKeyVaultKeyStoreProvider missing for key vault {masterKeyPath}");
            }
        }

        public override bool Verify(string masterKeyPath, bool allowEnclaveComputations, byte[] signature)
        {
            string keyVault = new Uri(masterKeyPath).Host;

            if (this.keyStoreProviderMap.TryGetValue(keyVault, out AzureKeyVaultKeyStoreProvider azureKeyVaultKeyStoreProvider))
            {
                return azureKeyVaultKeyStoreProvider.Verify(masterKeyPath, allowEnclaveComputations, signature);
            }
            else
            {
                throw new InvalidOperationException($"Verify:AzureKeyVaultKeyStoreProvider missing for key vault {masterKeyPath}");
            }
        }
    }

}
