# salesforce-aes256-encryption-in-flow

The script template offers a Salesforce admin-configurable utility designed for Salesforce Flows. It is an automated, native solution built to protect Personal Information (PI) within Salesforce environments by masking values in the user interface to prevent visual exposure and securely capturing tamper-evident audit logs. 

It bridges the compliance and security gap where standard Salesforce record layouts do not encrypt data at rest on the record UI, which creates severe operational risks for insider threats and data leakage.

## Risks Mitigated

* **Insider Threat & Accidental Exposure (Data Minimization):** Limits viewing of unnecessary PI directly at the record level to protect data privacy and minimize accidental data visibility.
* **Malicious Data Export Prevention:** Mitigates the risk of insider data exfiltration or malicious actors leveraging compromised credentials or connected third-party loaders to bulk export unencrypted production data.
* **Regulatory Non-Compliance:** Directly addresses compliance mandates (e.g., GDPR Article 32 - Security of Processing) by ensuring sensitive field data is cryptographically protected via symmetric encryption.

## Key Security & Architecture
Encryption keys are stored outside Apex code inside Custom Metadata Types (`Symmetric_Key_Config__mdt`), decoupling cryptographic secrets from codebase deployments and repository commits.

Key Access Control: Only system administrators with permissions to manage Custom Metadata can view or edit key records in Setup. End-users, standard profiles, and general Apex queries outside admin context cannot view raw secrets.

Security Consideration: Users with "Customize Application" or full administrative Setup permissions can read Custom Metadata records. Ensure administrative roles and profile permissions are strictly governed in production.

---

## Implementation & Setup

### 1. Preparation & AES-256 Key Generation

Before deploying or running the Apex classes, you must generate a cryptographically secure key meeting exact specifications:

* **Algorithm:** Advanced Encryption Standard (AES) operating with a **256-bit key length** (`AES256`).
* **Byte Length Requirement:** A 256-bit key requires **exactly 32 bytes** of raw binary data.
* **Encoding Format:** Base64-encoded string (resulting in a 44-character string ending in `=` or `==`).

#### Generating a Key via OpenSSL:
Run the following command in your terminal:
   ```bash
   openssl rand -base64 32
   ```
The result should give you a 44-character string, 256-bit key 

### 2. Create Custom Metadata Type for Key Storage

To securely store and supply the AES key dynamically to Apex:

1. In Salesforce Setup, search for **Custom Metadata Types**.
2. Click **New Custom Metadata Type** and configure:
   * **Label:** `Symmetric Key Config`
   * **Plural Label:** `Symmetric Key Configs`
   * **Developer Name:** `Symmetric_Key_Config`
   * **Visibility:** Select **Public** (for unmanaged orgs/sandboxes) or **Protected** (if packaging in a managed namespace)
3. Click **Save**.
4. Under **Custom Fields**, click **New** and create the key field:
   * **Data Type:** Text
   * **Field Label:** AES Key
   * **Length:** 255
   * **Field Name:** AES_Key
5. Click **Save**.
6. Click **Manage Symmetric Key Configs**, then click **New**:
   * **Label:** `Default Key`
   * **Symmetric Key Config Name:** `Default_Key`
   * **AES Key:** Paste your 44-character Base64 key string
7. Click **Save**.

### 3. Create Necessary Salesforce Fields
To store the encrypted values and track status, create the following fields on your target object (e.g., Contact):
* **Encrypted Log Field:** Text Area (Rich) maximised to **131,072 characters** to store the complete audit logs (capable of holding logs for up to 400 fields).
* **Status Checkbox Field:** Checkbox field to track whether the record is currently masked.

### 4. Deploy Apex Classes

Deploy both `FlowAES256DataMaskingAction.cls` and `FlowAES256DataUnmaskingAction.cls` into your Salesforce environment via Developer Console or VS Code.

---

### 5. Configure Salesforce Flow

These Apex classes expose Invocable Actions for use inside Record-Triggered Flows, Screen Flows, or Autolaunched Flows.

#### For masking (`FlowAES256DataMaskingAction.cls`): 
Please create a flow to get all targeted records you would like to encrypt, use an assignment to add all the fields that you want to encrypt, and add an action to include the following values:
  1. **Object** (Collection of SObjects)
  2. **Fields Name** (Collection of Text API names)
  3. **Log Field** (Text Area/Rich Text API name for audit logs)
  4. **Checkbox Field** (Status Checkbox API name, e.g., `Data_Masked__c`)

#### For unmasking (`FlowAES256DataUnmaskingAction.cls`):
Similar to masking, but you do not need to specify individual fields for unmasking, as the masked values are already noted in the target fields; it will automatically restore the data.
  1. **Object** (Collection of SObjects)
  2. **Log Field** (Text Area/Rich Text API name storing audit logs)
  3. **Checkbox Field** (Status Checkbox API name to reset)

_(Note: The unmasking action automatically parses field API names from the encrypted audit log and restores original values without requiring manual field mapping)._
