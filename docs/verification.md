# Verification: README claims against the repository

**Meaning of the status column**

- **Verified**: confirmed by reading the named file, function or test, or by a command run during this documentation pass (stated in the evidence).
- **Unverified**: not provable from the repository or from checks possible during this pass. Listed in [unverified.md](unverified.md) and not presented as fact in the README.

**Limits of this review.** No Salesforce org or Salesforce CLI was available, so no Apex was executed and nothing was deployed. "Verified" for an Apex test means the test source contains the stated assertion. It does not mean the test was run by the reviewer. The author reports that the tests passed in a sandbox; no log or coverage report is in the repository (U1). The `openssl` command was run (OpenSSL 3.0.13).

| # | README claim | Evidence | Status |
|---|---|---|---|
| **Summary** | | | |
| 1 | Invocable actions take a record collection and field names, and encrypt with an AES-256 key from `Symmetric_Key_Config__mdt` | `FlowAES256DataMaskingAction.MaskRequest`, `FlowAES256Util.getKey` (`Symmetric_Key_Config__mdt.getInstance`, `AES_Key__c`) | Verified |
| 2 | The log holds `#key: <name>` then `FieldName: <Base64>` lines | `FlowAES256Util.buildLog`; `FlowAES256DataMaskingActionTest.testMasksTextPostcodeDateAndCheckboxFields`, `FlowAES256UtilTest.testLogHeaderNamesTheKey` | Verified |
| 3 | Original fields are blanked, or given a placeholder if required text; the checkbox is ticked | `FlowAES256Util.maskValueFor`; masking tests | Verified |
| 4 | Unmasking decrypts every line with the key named, restores values and clears the log | `FlowAES256DataUnmaskingAction.restoreRecord`; `FlowAES256DataUnmaskingActionTest.testRoundTripRestoresTextPostcodeDateAndCheckboxFields` | Verified |
| 5 | Two further actions encrypt and decrypt arbitrary text | `FlowAES256EncryptValueAction`, `FlowAES256DecryptValueAction`; `FlowAES256ValueActionsTest` | Verified |
| 6 | All interviews in a transaction share one query and one update per object | `FlowAES256Service.queryRecords`, `save`; `FlowAES256BulkTest.test200InterviewsShareQueriesAndUpdates` (asserts at most 10 queries and 10 DML statements) | Verified |
| **Use cases** | | | |
| 7 | The retention Flow scenario (conditions, roll-up, approval, next-run masking) | The Flow is not in the repository | Unverified (U3) |
| 8 | Anyone able to read the key can decrypt everything | One key decrypts every log naming it (`FlowAES256Util.decrypt`); key is in `Symmetric_Key_Config__mdt` | Verified |
| 9 | Sister repository keeps the decryption key off-platform and cannot restore in-org | Hybrid repository: `RSAMaskBatch`, no Apex decryption | Verified |
| 10 | Tampering with the log cannot be detected | No MAC or authentication code in the code; nothing ties a line to a record or field | Verified (by absence) |
| **Architecture** | | | |
| 11 | Components and their roles in the diagram | Class names and comments in `FlowAES256Service` and `FlowAES256Util` | Verified |
| 12 | Already masked records are skipped | `FlowAES256DataMaskingAction.buildChanges`; `testSkipsAlreadyMaskedRecordsSoNoDataIsLost` | Verified |
| 13 | Nothing is changed if validation fails | `prepare`; `testRejectsUnknownFieldWithoutChangingData`, `testRejectsRequiredNonTextField`, `testRejectsReadOnlyCompoundAndLogFields` | Verified |
| 14 | A record is restored only if every line decrypts and converts | `restoreRecord`; `testTamperedOrUnknownLogLinesLeaveRecordsMasked`, `testWrongValueTypeInLogLeavesRecordMasked` | Verified |
| 15 | Encryption uses `Crypto.encryptWithManagedIV('AES256', …)` | `FlowAES256Util.encrypt` | Verified |
| **Key handling** | | | |
| 16 | Key is in `AES_Key__c` (Text, 255) of `Symmetric_Key_Config__mdt`; type visibility is `Public` | `objects/Symmetric_Key_Config__mdt/…` | Verified |
| 17 | Key is readable by Setup users, any Apex, metadata retrieval, sandboxes and backups | Code reads it with `getInstance`; the other routes depend on platform behaviour | Unverified for the platform routes (U4) |
| 18 | `openssl rand -base64 32` gives a 44-character string decoding to 32 bytes | Run in this pass: 44 characters; `FlowAES256Util.getKey` requires 32 bytes (`KEY_BYTES`) | Verified |
| 19 | The code rejects blank, non-Base64 and wrong-length keys | `getKey`; `FlowAES256UtilTest.testGetKeyValidatesKey`, `FlowAES256DataMaskingActionTest.testMissingOrInvalidKeyFailsEveryRequest` | Verified |
| 20 | Keys are cached for the transaction and cause no SOQL | `keyCache`; `FlowAES256UtilTest.testNamedKeysAreSeparateAndCached` (200 lookups, no queries) | Verified |
| 21 | The log names the key, not the key itself | `buildLog`, `readKeyName` | Verified |
| 22 | The code does not log keys or values | The repository contains no `System.debug` call | Verified (by absence) |
| 23 | `.gitignore` excludes key records, `*.pem`, `*.key` | `.gitignore` (added in this change) | Verified |
| 24 | Tests inject keys and bypass the Custom Metadata lookup | `FlowAES256Util.setTestKey`, `testKeys` | Verified |
| 25 | Rotation is manual; old logs still decrypt after the default key changes | `testLogStillDecryptsAfterDefaultKeyIsRotated`; no re-encryption code | Verified |
| 26 | Legacy logs with no `#key` header use the Key Name input | `testLegacyLogWithoutHeaderUsesKeyNameInput` | Verified |
| **Threat model** | | | |
| 27 | Actions use `with sharing`; field updateability is checked; the query is not run in user mode | Class declarations; `FlowAES256Util.requireField`, `prepare`; `Database.query` in `FlowAES256Service.queryRecords` | Verified |
| 28 | There is no permission check on who may unmask | Search for `FeatureManagement`, `CustomPermission`, `hasPermission`, `USER_MODE`, `stripInaccessible` finds nothing | Verified (by absence) |
| 29 | Lines are not bound to record or field | `FlowAES256Util.encrypt(key, plainText)` encrypts the value only | Verified |
| 30 | Decrypting with a wrong key normally fails but can rarely yield garbage | `testDecryptWithWrongKeyFails` accepts an exception or a different value | Verified (test intent); padding probability is general CBC knowledge (U5) |
| 31 | Field names, key name and which fields were non-empty are plain text in the log | `restoreRecord` reads names from the log; masking tests assert `contains('MailingPostalCode: ')`; empty fields are not logged (`testMasksTextPostcodeDateAndCheckboxFields`) | Verified |
| 32 | Dynamic query uses only names validated against object metadata | `FlowAES256Service.queryRecords` uses `getName()` values from describe | Verified |
| 33 | Failed All-or-None batches are retried without the failing request, at most 3 times | `FlowAES256Service.save` (`MAX_SAVE_ATTEMPTS`); `FlowAES256BulkTest.testDatabaseErrorRollsBackOnlyTheAllOrNoneRequest` | Verified |
| 34 | The same record in two requests is processed by the first only | `claimRecords`; `testSameRecordInTwoRequestsIsMaskedOnce` | Verified |
| **Design decisions** | | | |
| 35 | The first commit is dated one day before the hybrid repository's | `git log`: 2026-09-27 here, 2026-09-28 in the hybrid repository | Verified |
| 36 | `Crypto` supports AES directly; the whole cycle runs inside Salesforce | Code uses only `Crypto` and Apex | Verified |
| 37 | Hybrid comparison table (key location, restore, processing, field names, rotation, primitives) | This repository's code and the hybrid repository's `RSAMaskBatch`, `BigInt`, `decrypt_envelope.py` | Verified |
| **Limitations** | | | |
| 38 | No independent cryptographic or security review has been done | Author's statement | Author-confirmed |
| 39 | Cipher mode and padding are not shown by this repository | Absence; platform behaviour | Unverified (U5) |
| 40 | Compound address, geolocation, binary, read-only and required non-text fields are rejected, stopping the request | `isSupportedType`, `canMask`, `prepare`; tests listed in row 13 | Verified |
| 41 | Unmasking overwrites the current values | `restoreRecord` uses `put` without comparing current values | Verified |
| 42 | A record fails if the log does not fit the log field | `buildChanges`; `testLogTooLongFailsRecord` | Verified |
| 43 | The bulk test covers 200 interviews of 10 fields each | `CONTACT_FIELDS` (`MailingAddress` expands to 5) plus 5 other fields = 10; `test200InterviewsShareQueriesAndUpdates` | Verified |
| 44 | Larger volumes, other objects, and orgs with many triggers or rules are untested; performance unmeasured | Absence | Verified (by absence) |
| 45 | Tests use standard Contact and Lead fields and injected keys; no permission or custom data model tests | `FlowAES256TestData` | Verified |
| 46 | Field history, exports, backups, files, notes and integrations are not handled | Search of the code finds none | Verified (by absence) |
| 47 | The log is a recovery record, not an audit trail | Log content: encrypted values and field names only | Verified |
| 48 | The Flow is not in the repository | File list | Verified |
| **Test steps** | | | |
| 49 | 52 test methods in five test classes (14 + 16 + 12 + 5 + 5) | Count of `static void` test methods | Verified (counted) |
| 50 | All Apex tests pass | Author-reported; no log or coverage report stored | Unverified (U1) |
| 51 | Tests use `Description` and `DoNotCall` and need no custom fields | `FlowAES256TestData` | Verified |
| 52 | `FlowAES256BulkTest` converts a Lead and needs a converted status | `testDatabaseErrorRollsBackOnlyTheAllOrNoneRequest` | Verified |
| 53 | Deploy command works as written | Not run | Unverified (U2) |
| 54 | Messages: `SUCCESS: Processed 1 records.`, `SUCCESS: Processed 0 records. Skipped 1 already masked records.`, `SUCCESS: Unmasked 1 records.` | Masking and unmasking test assertions | Verified |
| 55 | Wrong-key unmask message (`could not decrypt … with key …`) and records left masked | `restoreRecord`; `testWrongKeyLeavesRecordMaskedWithLogIntact` | Verified |
| 56 | Named key `Key_Test` is written to the log and used on unmask | `testCustomPlaceholderAndKeyName`, `testLogStillDecryptsAfterDefaultKeyIsRotated` | Verified |
| 57 | The click path for the Flows and screen results | Not executed in any org during this pass | Unverified (U6) |
| **Other sections** | | | |
| 58 | `LICENSE` exists (MIT) | `LICENSE` in the repository root | Verified |
| 59 | Security reports can be made through the Issues tab | Depends on repository settings not checked | Unverified (U7) |
