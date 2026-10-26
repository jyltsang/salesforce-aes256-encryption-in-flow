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
* **Encrypted Log Field:** Text Area (Long) maximised to **131,072 characters** to store the complete audit logs (capable of holding logs for up to 400 fields). A Long Text Area is recommended: a Rich Text Area also works, as the unmasking action strips the HTML it adds, but it offers no benefit for machine-written logs.
* **Status Checkbox Field:** Checkbox field to track whether the record is currently masked.

### 4. Deploy Apex Classes

| Class | Purpose |
|---|---|
| `FlowAES256DataMaskingAction` | Flow action: encrypt fields into the log, then mask them |
| `FlowAES256DataUnmaskingAction` | Flow action: decrypt the log and restore the fields |
| `FlowAES256EncryptValueAction` | Flow action: encrypt any text value(s) |
| `FlowAES256DecryptValueAction` | Flow action: decrypt text value(s) |
| `FlowAES256Service` | Bulk engine shared by the masking actions |
| `FlowAES256Util` | Keys, encryption and field-type conversion |
| `FlowAES256TestData` + 5 `*Test` classes | Unit tests (required for production deployment) |

The repository is a Salesforce DX project and also contains the `Symmetric_Key_Config__mdt` type and its `AES_Key__c` field, so you can skip the manual steps in section 2 (apart from creating the `Default_Key` record) and deploy everything with:

```bash
sf project deploy start --source-dir force-app --test-level RunSpecifiedTests \
  --tests FlowAES256UtilTest --tests FlowAES256DataMaskingActionTest --tests FlowAES256DataUnmaskingActionTest \
  --tests FlowAES256BulkTest --tests FlowAES256ValueActionsTest
```

The tests use only standard Contact and Lead fields (`Description` as the log field and `DoNotCall` as the status checkbox) and supply their own keys, so they need no custom fields or Custom Metadata records. Validation rules, required custom fields or triggers on Contact or Lead in your org may need test adjustments; `FlowAES256BulkTest` also converts a Lead, so it needs a converted Lead Status.

---

### 5. Configure Salesforce Flow

These Apex classes expose Invocable Actions for use inside Record-Triggered Flows, Screen Flows, Scheduled Flows or Autolaunched Flows. Every input marked _optional_ can be left empty, so Flows built for earlier versions keep working unchanged.

#### Masking: **AES256 Encrypt and Mask Record Fields**
Create a flow that gets the records you want to protect, use an assignment to add the fields you want to encrypt to a text collection, and add the action with:

| Input | Description |
|---|---|
| **Object** | Collection of records (all of the same object) |
| **Fields Name** | Collection of field API names; `MailingAddress`, `BillingAddress`, `ShippingAddress` and `OtherAddress` expand to their parts |
| **Log Field** | API name of the text area that stores the encrypted log |
| **Checkbox Field** | API name of the status checkbox, e.g. `Data_Masked__c` |
| **Key Name** _(optional)_ | Symmetric Key Config record to encrypt with, e.g. one key per object or region. Defaults to `Default_Key` |
| **Mask Placeholder** _(optional)_ | Text written into _required_ text fields, which cannot be blanked. Defaults to `*****` |
| **All or None** _(optional)_ | `True` (default): if any record fails, nothing in this request changes. `False`: valid records are saved and failures are reported |

#### Unmasking: **AES256 Decrypt and Unmask Record Fields**
No field list is needed: the field names are read from the log.

| Input | Description |
|---|---|
| **Object** | Collection of records |
| **Log Field** | API name of the text area storing the log |
| **Checkbox Field** | API name of the status checkbox to reset |
| **Key Name** _(optional)_ | Key for logs that do not name one (written before this version). Logs written now record their key, so this is rarely needed |
| **All or None** _(optional)_ | As for masking |

#### Outputs of both actions

| Output | Description |
|---|---|
| **Success Flag** | `True` only if nothing failed |
| **Message** | Summary starting with `SUCCESS:` or `ERROR:`, including the reason for each failed record (first 10) |
| **Processed Count** | Records saved |
| **Skipped Count** | Records left alone because there was nothing to do (already masked / nothing to unmask) |
| **Failed Count** / **Failed Record Ids** | Records that were not changed, e.g. to loop over them or send an alert |

#### Encrypting any value: **AES256 Encrypt Text** / **AES256 Decrypt Text**
For encryption that is not tied to masking a record, e.g. a value captured on a Screen Flow, a field on another object or a value sent to another system. Inputs: **Text to Encrypt** (single value) and/or **Texts to Encrypt** (collection, order kept), plus optional **Key Name**. Outputs: **Encrypted Text(s)** as Base64, **Success Flag** and **Message**. Decrypt mirrors this; a value that cannot be decrypted comes back blank and is named in **Message** without stopping the others. Blank inputs stay blank. Numbers and dates should be converted to text in the Flow first (e.g. with a formula).

---

### 6. Supported Field Types & Behaviour

| Field type | Masked value | Restored as |
|---|---|---|
| Text, Text Area, Phone, URL, Email, Picklist, postcode and other address parts | blank (the placeholder if the field is required text) | original text, including leading zeros and line breaks |
| Number, Currency, Percent | blank | original number |
| Date, Date/Time, Time | blank | original value (Date/Time is logged in GMT, so it is unaffected by the user's time zone) |
| Checkbox | unticked | original true/false |
| Lookup | blank | original record Id |

* **Validation before any change:** if a field does not exist, is not editable by the running user, is an unsupported compound type, or is required and cannot be blanked (e.g. a required number or picklist field), the masking action changes nothing for that request and reports every problem in **Message**.
* **Already-masked records are skipped:** masking a record whose checkbox is already ticked would overwrite its log with the masked placeholders and lose the original data, so such records are left untouched and counted in **Skipped Count**.
* **Unmasking never destroys a log it could not read:** if any line of a record's log cannot be decrypted (e.g. the key is missing or the log was edited) or converted back to the field's type, that record is left masked with its log intact and listed in **Failed Record Ids**.
* **Log length:** if the encrypted log would not fit in the log field, that record fails before anything is saved.
* **Record access:** records the running user cannot see (sharing) or that no longer exist are reported as failed.

### 7. Traffic & Governor Limits

A record-triggered or scheduled Flow passes the action up to 200 interviews at once. All interviews in that batch share the work:

* **One query and one update per object** for the whole batch, however many interviews (previously one query and one update per interview, which hit the 100-query limit at around 100 interviews).
* **Keys are read once per transaction** from Custom Metadata, which uses no SOQL.
* **Requests are isolated:** an invalid configuration or failing record in one interview does not affect the others. If an _All or None_ request has a record the database rejects (e.g. a validation rule), the batch is rolled back and saved again without that request (at most 3 attempts).
* **The same record in two interviews** is changed by the first only; the second reports it as failed.
* Encryption itself costs CPU time. `FlowAES256BulkTest` covers 200 interviews masking 10 fields each; for much larger volumes (many fields on thousands of records in one transaction), split the work across several runs, e.g. a Scheduled Flow with smaller batches, and test in a sandbox with your own data.

### 8. Key Rotation

Every log now starts with a `#key: <Key Name>` line recording the key that encrypted it, so unmasking always uses the right key. To rotate:

1. Create a new Symmetric Key Config record (e.g. `Key_2026`) with a newly generated key.
2. Set **Key Name** to `Key_2026` in the masking action (or change the value of `Default_Key` only after all older logs have been unmasked).
3. **Keep the old record** until every log written with it has been unmasked; existing logs keep decrypting with the key they name.

Logs written before this version have no `#key` line and are decrypted with the unmasking action's **Key Name** (default `Default_Key`).
