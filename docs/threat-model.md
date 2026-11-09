# Threat model: salesforce-aes256-encryption-in-flow

This extends the summary in the [README](../README.md#threat-model). It describes what the code does and does not defend against. It is an analysis produced during a documentation pass, not an independent assessment. No independent cryptographic or security review has been done.

## 1. Scope and assumptions

**In scope:** the four invocable actions, `FlowAES256Service`, `FlowAES256Util`, the `Symmetric_Key_Config__mdt` type and its key records, and the log field and status checkbox.

**Out of scope:** Salesforce platform security, the calling Flow, approval processes, scheduling, backups, integrations, and the legal basis for retention or masking.

**Design premise.** The design protects against people who can see records but cannot read the key. It does not protect against anyone who can read the key, because the key and the data are in the same org.

| # | Assumption | If false |
|---|---|---|
| A1 | The key record is readable only by a small, trusted set of people and code | Anyone with access can decrypt all logs that name the key |
| A2 | Access to the Flow and the Apex classes is restricted to those allowed to unmask | Anyone with access can restore PI |
| A3 | `Crypto.encryptWithManagedIV('AES256', …)` provides standard AES-256 encryption with a random IV | The confidentiality of the logs is weaker than assumed |
| A4 | The Flow selects the intended records and fields | Wrong data is masked, or PI stays visible |
| A5 | Masking occurs before values are copied elsewhere | Unmasked copies remain |
| A6 | Key records are not committed, exported or copied beyond the org | The key leaks with them |

## 2. Data flow and trust boundaries

```
[Flow] --(1)--> [Masking / Unmasking / Value actions] --(2)--> [FlowAES256Service]
                          |                                         |
                          | (3) getKey(name)                        | (4) SOQL + DML
                          v                                         v
              [Symmetric_Key_Config__mdt]                  [Record: fields + log + checkbox]
```

| Boundary | What crosses it | Control in this repository |
|---|---|---|
| B1 Users without Setup access / users with it | Ability to read the key | Custom Metadata access only. The type is `Public`. Nothing else |
| B2 Flow / Apex | Record collection, field names, settings | Validation in each action's `prepare`, and `FlowAES256Util.requireField` |
| B3 Record / log field | Log lines | None beyond field edit permission |
| B4 Source control / org | Key records | `.gitignore` for retrieved key records |

## 3. Scenarios

| ID | Scenario | Actor | Effect | Current defence | Residual |
|---|---|---|---|---|---|
| T1 | Administrator reads the key and decrypts logs | Insider admin, stolen admin session | Full disclosure | None | High (inherent in the design) |
| T2 | Any Apex in the org reads the key | Developer, malicious or compromised code | Full disclosure | None | High |
| T3 | Key record retrieved into a project and committed | Developer | Key published | `.gitignore` entries for `Symmetric_Key_Config.*`, `*.pem`, `*.key`. No secret scanning is configured in the repository | Medium |
| T4 | Key record copied by sandbox refresh or backup | Platform process, operator | Key and logs exist together elsewhere | None (platform behaviour not documented here) | Medium |
| T5 | A user who can run the unmask Flow restores PI | Any user with Flow or Apex class access | PI disclosure | None in code. Relies on access to the Flow and Apex classes | Medium to high |
| T6 | Log lines moved between records or fields | User with edit access to the log field | Wrong data restored into a record or field | None. Lines are not bound to record or field | Medium |
| T7 | Log edited or cleared | As T6 | Data lost or restored incorrectly. A line that does not decrypt or convert leaves the record masked (tested). Lines still valid for the same key are accepted | Partial | High for deletion |
| T8 | Key changed or deleted | Admin, accident | Logs naming that key become unreadable | Unmasking leaves the record masked with its log intact (tested). No recovery | High |
| T9 | Wrong key decrypts to garbage | Misconfiguration | Rare chance (padding validity) of garbage restored for text fields | Type conversion catches non-text garbage; nothing catches text garbage | Low probability, high impact |
| T10 | Key replaced with an attacker's key, then masking run | Admin | New logs are readable by the attacker | None | High |
| T11 | Mass masking exhausts limits | Large scheduled run | Failures or partial work | Bulk sharing of queries and DML (tested up to 200 interviews of 10 fields); All-or-None retry limited to 3 attempts | Medium; CPU unmeasured |
| T12 | Unmask overwrites newer values | Business process | Edits made after masking are lost | None | Medium |
| T13 | Debug logs capture values | Anyone with debug log access | PI disclosure | The code contains no `System.debug` calls | Low from this code |
| T14 | Dynamic SOQL injection via field names | Flow author | Unintended query | Field names are validated against object metadata and only the described API names are used in the query | Low |
| T15 | Metadata inference | Anyone who reads the log | Learns which fields were non-empty and which key was used | None. Field names and the key name are plain text | Medium |

## 4. STRIDE by component

| Component | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| **Masking action** | Runs as the caller | Flow author controls fields; validated | Message only; no audit | Writes ciphertext; field names in plain text | Guarded by bulk design | `with sharing`; field updateability checked; no user-mode query |
| **Unmasking action** | Runs as the caller | Accepts any decryptable log | Message only | Writes restored PI back to fields | Missing key stops restore | No permission gate on who may unmask |
| **Value actions** | Runs as the caller | n/a | n/a | Return ciphertext or plaintext to the Flow | n/a | Anyone who can run them can encrypt or decrypt with any named key |
| **FlowAES256Util** | Key record can be replaced | n/a | n/a | Key read and cached in memory for the transaction | n/a | Reads key in system context via `getInstance` |
| **FlowAES256Service** | n/a | Rolls back and retries; the first request wins for a shared record | n/a | n/a | Retry limit of 3 | n/a |
| **Key records** | Editable by metadata editors | Same | Setup audit trail (platform) | Plain-text key | Missing key stops operations | n/a |

## 5. Mitigations that are not implemented (suggestions)

These are ideas, not features of the repository, and they are listed so the gap is visible.

- Gate unmasking behind a custom permission, checked in the action.
- Query and update in user mode, and add tests for users who lack field access.
- Bind each log line to its record Id and field name (for example by including them in the encrypted plaintext, then verifying on restore), and add an authentication code over the whole log.
- Store the key outside the org, or derive per-record keys from a master key that is not in metadata, if the threat model includes administrators.
- Add an action that re-encrypts logs from an old key to a new one.
- Add secret scanning (for example a pre-commit hook or a CI step) to the repository.
- Add a test for the real Custom Metadata lookup path.

## 6. Residual risk statement

The data is protected from users who can see the record but cannot read the key record or run Apex. It is not protected from administrators, developers, compromised org credentials, or any process that can read Custom Metadata. Logs can be moved or removed without reliable detection. Keys cannot be recovered. The cryptography has not been independently reviewed.
