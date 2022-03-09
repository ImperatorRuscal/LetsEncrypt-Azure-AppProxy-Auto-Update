# LetsEncrypt-Azure-AppProxy-Auto-Update
Azure Automation Runbook that will go through all your AAD Enterprise App Proxy applications and update the SSL certificate with a new one from Lets Encrypt

## Requirements
- Azure Subscription with Azure Active Directory hosting AAD Application Proxy apps
- A storage account (for holding the configuration files used by the runbook)
- A key vault (for holding the SSL certificates, and sensitive secrets that shouldn't be in Automation Account Variables)
- Azure Automation Service (with a Managed Service Identity)
- An AzureAD account (either cloud-native or hybrid-synced will work) with either an unchanging password, or with a method to update the password in the Key Vault

## Installation Instructions
### Automation Account
You can use an existing automation account if you wish; otherwise, create a new Azure Automation Account.
#### Managed Service Identity
Make sure to enable a System Assigned Managed Identity (under Account Settings > Identity)
#### Powershell Modules
Go to Shared Resources > Modules to modify the Powershell Modules that are available to the Automation Account
- Use the "Update Az Modules" button (at the top) to update the 5.1 runtime modules to the newest version (6.5.0 as I type this)
- Use the "Browse Gallery" button to add **AzureAD** (created by AzureADPowerShell)
- Use the "Browse Gallery" button to add **Posh-ACME** (created by rmbolger)
