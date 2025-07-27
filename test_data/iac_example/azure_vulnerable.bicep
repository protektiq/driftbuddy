// Purposefully vulnerable Azure Bicep configuration for testing
// This file contains multiple security flaws for demonstration

@description('CRITICAL: Storage account with public access')
param storageAccountName string = 'vulnerablestorage12345'
param location string = resourceGroup().location

// CRITICAL: Storage account with public access
resource storageAccount 'Microsoft.Storage/storageAccounts@2021-09-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: true  // CRITICAL: Allows public blob access
    allowSharedKeyAccess: true   // CRITICAL: Allows shared key access
    minimumTlsVersion: 'TLS1_0'  // CRITICAL: Weak TLS version
    supportsHttpsTrafficOnly: false  // CRITICAL: Allows HTTP traffic
    networkAcls: {
      defaultAction: 'Allow'  // CRITICAL: Allows all network access
      ipRules: []
      virtualNetworkRules: []
    }
  }
}

// HIGH: Virtual Network with open NSG
resource virtualNetwork 'Microsoft.Network/virtualNetworks@2021-05-01' = {
  name: 'vulnerable-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'default'
        properties: {
          addressPrefix: '10.0.1.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

// HIGH: Network Security Group with open rules
resource nsg 'Microsoft.Network/networkSecurityGroups@2021-05-01' = {
  name: 'open-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowAllInbound'
        properties: {
          priority: 100
          protocol: '*'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'  // HIGH: Allows all inbound traffic
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'AllowSSH'
        properties: {
          priority: 200
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'  // HIGH: SSH open to internet
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
      {
        name: 'AllowRDP'
        properties: {
          priority: 300
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'  // HIGH: RDP open to internet
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '3389'
        }
      }
    ]
  }
}

// MEDIUM: Virtual Machine with admin credentials
resource vm 'Microsoft.Compute/virtualMachines@2021-07-01' = {
  name: 'vulnerable-vm'
  location: location
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2s_v3'
    }
    osProfile: {
      computerName: 'vulnerable-vm'
      adminUsername: 'admin'  // MEDIUM: Weak admin username
      adminPassword: 'Password123!'  // MEDIUM: Weak password in plain text
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: 'UbuntuServer'
        sku: '18.04-LTS'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Standard_LRS'
        }
      }
    }
  }
}

// MEDIUM: Network Interface with public IP
resource nic 'Microsoft.Network/networkInterfaces@2021-05-01' = {
  name: 'vulnerable-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          publicIPAddress: {
            id: publicIP.id
          }
          subnet: {
            id: virtualNetwork.properties.subnets[0].id
          }
        }
      }
    ]
  }
}

// MEDIUM: Public IP address
resource publicIP 'Microsoft.Network/publicIPAddresses@2021-05-01' = {
  name: 'vulnerable-publicip'
  location: location
  properties: {
    publicIPAllocationMethod: 'Static'  // MEDIUM: Static IP exposed
    dnsSettings: {
      domainNameLabel: 'vulnerable-vm'
    }
  }
}

// LOW: Key Vault without RBAC
resource keyVault 'Microsoft.KeyVault/vaults@2021-06-01-preview' = {
  name: 'vulnerable-keyvault'
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    accessPolicies: [
      {
        tenantId: subscription().tenantId
        objectId: '00000000-0000-0000-0000-000000000000'  // LOW: Generic object ID
        permissions: {
          keys: [
            'all'
          ]
          secrets: [
            'all'
          ]
          certificates: [
            'all'
          ]
        }
      }
    ]
    enabledForDeployment: true  // LOW: Allows VM deployment access
    enabledForTemplateDeployment: true  // LOW: Allows template deployment access
  }
}

// INFO: App Service without HTTPS
resource appService 'Microsoft.Web/sites@2021-02-01' = {
  name: 'vulnerable-app'
  location: location
  properties: {
    serverFarmId: appServicePlan.id
    siteConfig: {
      // INFO: No HTTPS-only configuration
      // httpsOnly: true
    }
  }
}

resource appServicePlan 'Microsoft.Web/serverfarms@2021-02-01' = {
  name: 'vulnerable-plan'
  location: location
  sku: {
    name: 'B1'
    tier: 'Basic'
  }
}
