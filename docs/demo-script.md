# Demo script: AES-256 masking and unmasking in Flow (3 to 5 minutes)

**Recording link:** _placeholder, to be added after recording_

**Aim:** show a record being masked by a Flow, what is left in the record and the log, the record being restored, and the safe failure when the key is wrong. Be explicit about the main limitation: the key is in the org.

## Before you record

- Use a **sandbox or scratch org** with made-up data only. The [test steps](../README.md#test-steps) cover setup. Set up and rehearse once first.
- Prepare one Contact: last name `Demo Person`, email `demo.person@example.com`, a made-up mailing street and postcode.
- Have these ready: the masking Flow, the unmasking Flow, the Contact record, and *Setup → Custom Metadata Types → Symmetric Key Config → Manage Records*.
- Use a **disposable key** generated for the demo. **Never show the key value on screen**, even a disposable one: show the record list and the field name only, or cover the value before recording.
- Hide anything that identifies an organisation: org URL, user name and avatar, browser tabs and bookmarks, email addresses other than the dummy one. Do not record your real org.
- Close notifications and enlarge the browser zoom.

## Script

| Time | Say | Show |
|---|---|---|
| 0:00 | "This project masks personal data on Salesforce records from a Flow, using AES-256, and can restore it later. It is a proof of concept and has not been independently reviewed." | README title and status banner |
| 0:20 | "Actions take a collection of records and field names. A shared service does one query and one update per object. The key comes from Custom Metadata." | The Mermaid diagram in the README |
| 0:50 | "The key is stored in a Custom Metadata record. That is the main design limit: it is in the same org as the data." | The `Default_Key` record list (key value hidden), then the Limitations heading |
| 1:10 | "Here is a dummy contact before masking." | Contact with email, address, `Data_Masked__c` unticked |
| 1:25 | "The masking Flow gets the record, builds a list of field names, and calls the action. The log and checkbox names are typed as plain text." | Flow canvas and the action inputs |
| 1:50 | "I run it. The message tells me one record was processed." | Run the Flow. Show `SUCCESS: Processed 1 records.` |
| 2:05 | "The email and address are gone, the required last name shows a placeholder, the box is ticked. The log starts with the key name, then one line per field with Base64 ciphertext. Note the field names are readable." | Refresh the Contact and point at the log field |
| 2:35 | "Running it again does not overwrite the log. The record is skipped." | Run again. Show `Skipped 1 already masked records` |
| 2:55 | "Now the unmasking Flow. It needs no field list; it reads the field names from the log." | Run the unmasking Flow. Show `SUCCESS: Unmasked 1 records.` |
| 3:20 | "The values are back, the log is empty and the checkbox is cleared." | Contact record restored |
| 3:35 | "If the key has changed, the record stays masked and the log is kept." | Mask again; edit the key record to a different valid key (value hidden); run unmasking; show the `ERROR:` message and the unchanged Contact. Restore the key |
| 4:10 | "This is not protection against someone who can read the key, and the log is not authenticated. The hybrid repository addresses the first of these but cannot restore in-org." | The README Limitations headings |
| 4:40 | "Tests, threat model and a claim-by-claim verification table are in the repository." | `docs/verification.md`, then stop |

## After recording

- Delete the dummy Contact and any test key records, or reset them.
- Check the recording frame by frame for any real name, email, org URL, identifier or key value.
- Add the link at the top of this file and in the README's Demo section.
