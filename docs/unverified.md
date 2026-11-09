# Unverified items

These statements could not be confirmed from the code in this repository. The README either omits them or says clearly that they are unverified.

| ID | Item | Why it is unverified | How to close it |
|---|---|---|---|
| U1 | The Apex tests pass (52 methods) | The author reports they passed in a sandbox. The repository holds no test log or coverage result, and no Salesforce org was available during this documentation pass | Run `sf apex run test --class-names FlowAES256UtilTest --class-names FlowAES256DataMaskingActionTest --class-names FlowAES256DataUnmaskingActionTest --class-names FlowAES256BulkTest --class-names FlowAES256ValueActionsTest --code-coverage --result-format human --wait 10` and keep the output |
| U2 | The deploy command and the metadata (`Symmetric_Key_Config__mdt`) deploy cleanly | No Salesforce CLI or org was available | Run the deploy command in a sandbox |
| U3 | The retention Flow scenario (conditions, roll-up check, approval, scheduled next-run masking) | The Flow is not in the repository | Add a sanitised Flow export, or keep the scenario labelled as illustrative |
| U4 | Key readability routes: Setup users, any Apex, metadata retrieval, sandbox refresh, backups | Depends on Salesforce behaviour for `Public` Custom Metadata; not checked against documentation. The README says to *treat* the key as readable by these routes | Cite the current Salesforce documentation |
| U5 | `Crypto.encryptWithManagedIV('AES256', …)` uses CBC with PKCS7 padding (and so a wrong key rarely produces valid padding) | Platform behaviour, not shown in the code | Cite the Salesforce Apex Reference |
| U6 | The Flow click path and screen results in test steps | Written from the code and tests, not executed in an org | Follow the steps once and correct them |
| U7 | The Issues tab is enabled, and private vulnerability reporting is available | Repository settings are not visible from the code | Check the repository settings |
| U8 | The previous README's claim that the log field "can hold the logs for up to 400 fields" | Capacity depends on field names and value lengths. Not demonstrated by any test. Removed from the README | Add a test with a measured log size, or keep it out |
| U9 | The previous README's statements about "tamper-evident" logs, "severe operational risks", GDPR Article 32 and "cannot view raw secrets" | Not supported by the code (no authentication code; Custom Metadata of `Public` visibility; compliance is a legal assessment). Removed or replaced in the README | Do not reinstate without evidence |
| U10 | Real-world use in other orgs, including a nonprofit data model, or in other Salesforce clouds | Not evidenced by the repository; the tests use only standard Contact and Lead fields. Deliberately not stated in the README | Leave out unless it can be shown without naming any organisation |
