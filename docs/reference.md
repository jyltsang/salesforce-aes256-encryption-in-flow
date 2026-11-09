# Reference: Flow inputs, field handling, limits and rotation

Every statement here is taken from the Apex classes in `force-app/main/default/classes`. See [verification.md](verification.md) for the evidence for each claim.

Every input marked _optional_ can be left empty.

## Masking: **AES256 Encrypt and Mask Record Fields** (`FlowAES256DataMaskingAction`)

| Input | Required | Description |
|---|---|---|
| **Object** | Yes | Collection of records, all of the same object |
| **Fields Name** | Yes | Collection of field API names. `MailingAddress`, `BillingAddress`, `ShippingAddress` and `OtherAddress` expand to their five component fields. Names are trimmed, matched case-insensitively and de-duplicated |
| **Log Field** | Yes | API name of a Text or Text Area field that stores the encrypted log |
| **Checkbox Field** | Yes | API name of an editable checkbox that records that the record is masked |
| **Key Name** | No | Name of the `Symmetric_Key_Config__mdt` record to encrypt with. Defaults to `Default_Key` |
| **Mask Placeholder** | No | Text written into required text fields, which cannot be blanked. Defaults to `*****`; cut to the field's length |
| **All or None** | No | `True` (default): if any record of this request fails, no record of the request changes. `False`: valid records are saved and failures are reported |

## Unmasking: **AES256 Decrypt and Unmask Record Fields** (`FlowAES256DataUnmaskingAction`)

No field list is needed: the field names are read from the log.

| Input | Required | Description |
|---|---|---|
| **Object** | Yes | Collection of records |
| **Log Field** | Yes | API name of the log field |
| **Checkbox Field** | Yes | API name of the status checkbox to reset |
| **Key Name** | No | Key to use for logs that do not name one (written before the `#key` header existed). Defaults to `Default_Key` |
| **All or None** | No | As for masking |

## Outputs of both record actions

| Output | Description |
|---|---|
| **Success Flag** | `True` only if nothing failed. (Unmasking also reports `False` with `No valid encrypted logs found to decrypt.` when nothing was restored and nothing failed) |
| **Message** | `SUCCESS:` or `ERROR:` followed by a summary, including the reason for each failed record (first 10) |
| **Processed Count** | Records saved |
| **Skipped Count** | Records left alone because there was nothing to do (already masked, or nothing to unmask) |
| **Failed Count** and **Failed Record Ids** | Records that were not changed |

## Encrypting any value: **AES256 Encrypt Text** and **AES256 Decrypt Text**

`FlowAES256EncryptValueAction` and `FlowAES256DecryptValueAction` work on text values that are not tied to a record.

- Inputs: **Text to Encrypt** (single) and/or **Texts to Encrypt** (collection, order kept), plus optional **Key Name**.
- Outputs: **Encrypted Text(s)** as Base64, **Success Flag** and **Message**.
- Decrypt mirrors this. A value that cannot be decrypted comes back blank and is named in **Message**, without stopping the others.
- Blank inputs stay blank. Convert numbers and dates to text in the Flow first.

## Log format

```
#key: <Key Name>
<FieldApiName>: <Base64( IV || AES-256 ciphertext )>
<FieldApiName>: <Base64 …>
```

Field API names and the key name are in plain text. Only the values are encrypted. Fields whose value was empty are not logged. A Rich Text Area wrapper (HTML) around the lines is tolerated when unmasking.

## Supported field types

| Field type | Masked value | Restored as |
|---|---|---|
| Text, Text Area, Phone, URL, Email, Picklist, address parts | Blank (the placeholder if the field is required text) | Original text, including leading zeros and line breaks |
| Number, Currency, Percent, Integer, Long | Blank | Original number |
| Date, Date/Time, Time | Blank | Original value. Date/Time is logged in GMT |
| Checkbox | Unticked | Original true or false |
| Lookup | Blank | Original record Id |

Rules enforced before any change (the request is rejected and every problem is reported):

- A field that does not exist, is not editable by the running user, is a compound address, geolocation or binary field, or is required and cannot be blanked (for example a required number or picklist), stops the whole request.
- The log and checkbox fields cannot be listed as fields to mask.
- A record whose checkbox is already ticked is skipped, so its original log is never overwritten.
- If the encrypted log would not fit in the log field, that record fails.
- Records the running user cannot see, or that no longer exist, are reported as failed.

Unmasking:

- A record is restored only if **every** log line decrypts and converts back to its field's type. Otherwise it is left masked with its log intact and listed in **Failed Record Ids**.
- Restored values overwrite whatever the target fields currently hold.

## Bulk behaviour

A record-triggered or scheduled Flow can pass the action up to 200 interviews at once. In `FlowAES256Service`:

- One query and one update per object serve all interviews in the transaction.
- Keys are read from Custom Metadata once per transaction and cached.
- Requests are isolated: an invalid request does not affect the others.
- If an All-or-None request has a record the database rejects, the batch is rolled back and saved again without that request (at most 3 attempts).
- If the same record is in two requests, the first changes it and the second reports it as failed.
- Encryption uses CPU time. `FlowAES256BulkTest` covers 200 interviews of 10 fields each. Larger volumes have not been tested.

## Key rotation (manual)

1. Create a new `Symmetric_Key_Config__mdt` record (for example `Key_2026`) with a newly generated key.
2. Set **Key Name** to `Key_2026` in the masking action.
3. Keep the old record until every log written with it has been unmasked. Logs name their key, so they keep decrypting with it.

There is no action that re-encrypts existing logs. Logs written before the `#key` header existed use the unmasking action's **Key Name** (default `Default_Key`).
