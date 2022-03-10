# LetsEncrypt-Azure-AppProxy-SSL-Auto-Update
Azure Automation Runbook that will go through all your AAD Enterprise App Proxy applications and update the SSL certificate with a new one from Lets Encrypt.

***These instructions are incomplete.  The runbook works (I'm using it in my production environment), but I don't have all the setup steps documented.  Feel free to use this runbook anyway -- I like to think that I made the parameters self-explanitory enough that you can run it without needing the full documentation.***

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
- Use the "Browse Gallery" button to add **AzureAD** (created by *AzureADPowerShell*)
- Use the "Browse Gallery" button to add **Posh-ACME** (created by *rmbolger*)
### Key Vault
Again, you can use an existing key vault if you with.  That said, I would recommend using a vault dedicated specifically to handling your SSL certificates.  This vault will hold Secrets that contain sensitive variables used by the runbook (no putting privileged passwords in the runbook or in the automation account variables), and it will hold the certificates created by Let's Encrypt for your AAD App Proxy applications.
#### Security
The Managed Identity for the Automation Account will need permissions to access, read, and update the keyvault.  To do this, you'll need to add it to an access policy.  In your Key Vault, choose "Add access policy" and create a new policy.

At the very least you will need **Get** *Secret permissions*, and **Update**, **Create**, and **Import** *Certificate permissions* for this script to work as designed.  Make sure to assign those to your Automation Account's principal.
### Storage Account
What we really need is a Blob Storage container.  It just so happens that those are only available to us within Storage Accounts.  You can make a new Blob Container within an existing Storage Account, or make a whole new Storaage Account.
#### Blob Container
Make a new Blob Container within the storage account.  Ensure that the container is private. (This is important, you don't want to risk exposure of your Lets Encrypt account keys.)
#### Security


