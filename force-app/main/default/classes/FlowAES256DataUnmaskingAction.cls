public with sharing class FlowAES256DataUnmaskingAction {

    public class UnmaskRequest {
        @InvocableVariable(required=true label='Object' description='Collection of records to unmask')
        public List<SObject> recordsToUnmask;

        @InvocableVariable(required=true label='Log Field' description='API Name of the field storing the audit log')
        public String encryptedLogFieldName;

        @InvocableVariable(required=true label='Checkbox Field' description='API Name of the checkbox status field to reset')
        public String statusCheckboxFieldName;

        @InvocableVariable(label='Key Name' description='Optional. Symmetric Key Config record for logs that do not name their key (written before key names were logged). Defaults to Default_Key.')
        public String keyName;

        @InvocableVariable(label='All or None' description='Optional. True (default): if any record fails, no record in this request is changed. False: valid records are restored and failures are reported.')
        public Boolean allOrNone;
    }

    public class UnmaskResult {
        @InvocableVariable(label='Success Flag')
        public Boolean isSuccess;

        @InvocableVariable(label='Message')
        public String message;

        @InvocableVariable(label='Processed Count' description='Records restored and saved')
        public Integer processedCount;

        @InvocableVariable(label='Skipped Count' description='Records left as they were because they had nothing to unmask')
        public Integer skippedCount;

        @InvocableVariable(label='Failed Count' description='Records left masked with their log intact')
        public Integer failedCount;

        @InvocableVariable(label='Failed Record Ids' description='Ids of the records left masked')
        public List<String> failedRecordIds;
    }

    // Validated settings for one request, kept alongside its outcome
    private class Plan {
        public FlowAES256Service.Outcome outcome;
        public Map<String, Schema.SObjectField> fieldMap;
        public String encField;
        public String statusField;
        public String fallbackKeyName;
    }

    @InvocableMethod(label='AES256 Decrypt and Unmask Record Fields' description='Reads the encrypted audit log, decrypts fields using Custom Metadata AES key, restores original values, and clears the log.')
    public static List<UnmaskResult> processRecords(List<UnmaskRequest> requests) {
        List<Plan> plans = new List<Plan>();
        List<FlowAES256Service.Outcome> outcomes = new List<FlowAES256Service.Outcome>();

        for (UnmaskRequest req : requests) {
            Plan plan = new Plan();
            plan.outcome = new FlowAES256Service.Outcome(req.allOrNone);
            try {
                prepare(plan, req);
            } catch (Exception e) {
                plan.outcome.reject(e.getMessage());
            }
            plans.add(plan);
            outcomes.add(plan.outcome);
        }

        try {
            FlowAES256Service.claimRecords(outcomes);
            Map<Id, SObject> recordsById = FlowAES256Service.queryRecords(outcomes);

            for (Plan plan : plans) {
                if (!plan.outcome.isActive()) continue;
                buildChanges(plan, recordsById);
                plan.outcome.abandonIfAllOrNone();
            }

            FlowAES256Service.save(outcomes);
        } catch (Exception e) {
            // Unexpected failure shared by the whole batch, e.g. a query error
            for (FlowAES256Service.Outcome outcome : outcomes) {
                if (outcome.isActive()) outcome.reject(e.getMessage());
            }
        }

        List<UnmaskResult> results = new List<UnmaskResult>();
        for (Plan plan : plans) {
            results.add(toResult(plan.outcome));
        }
        return results;
    }

    private static void prepare(Plan plan, UnmaskRequest req) {
        FlowAES256Service.Outcome outcome = plan.outcome;
        FlowAES256Service.collectRecords(outcome, req.recordsToUnmask);
        if (!outcome.isActive()) return;
        if (outcome.recordIds.isEmpty()) {
            outcome.reject('No records provided in the collection.');
            return;
        }

        String objectName = outcome.sObjectType.getDescribe().getName();
        plan.fieldMap = outcome.sObjectType.getDescribe().fields.getMap();
        plan.encField = FlowAES256Util.requireField(
            plan.fieldMap, req.encryptedLogFieldName, objectName, 'Log field', FlowAES256Util.LOG_FIELD_TYPES, 'a text area field').getName();
        plan.statusField = FlowAES256Util.requireField(
            plan.fieldMap, req.statusCheckboxFieldName, objectName, 'Checkbox field', FlowAES256Util.STATUS_FIELD_TYPES, 'a checkbox').getName();
        plan.fallbackKeyName = FlowAES256Util.resolveKeyName(req.keyName);

        outcome.queryFields.add(plan.encField);
        outcome.queryFields.add(plan.statusField);
    }

    private static void buildChanges(Plan plan, Map<Id, SObject> recordsById) {
        FlowAES256Service.Outcome outcome = plan.outcome;

        for (Id recordId : outcome.recordIds) {
            SObject record = recordsById.get(recordId);
            if (record == null) continue;

            String logContent = (String) record.get(plan.encField);
            if (String.isBlank(logContent)) {
                if ((Boolean) record.get(plan.statusField) == true) {
                    // Masked while every target field was empty, so only the checkbox needs resetting
                    SObject reset = outcome.sObjectType.newSObject(recordId);
                    reset.put(plan.statusField, false);
                    outcome.changes.add(reset);
                } else {
                    outcome.skippedCount++;
                }
                continue;
            }

            // A record is restored only if every line decrypts; otherwise its log is kept so no data is lost
            try {
                outcome.changes.add(restoreRecord(plan, recordId, logContent));
            } catch (Exception e) {
                outcome.fail(recordId, e.getMessage());
            }
        }
    }

    // Parses the multiline log format 'FieldName: EncryptedBase64String' into a record ready to update
    private static SObject restoreRecord(Plan plan, Id recordId, String logContent) {
        SObject restored = plan.outcome.sObjectType.newSObject(recordId);
        List<String> lines = FlowAES256Util.splitLogLines(logContent);

        // Logs name the key that encrypted them, so they still decrypt after the default key is rotated
        String loggedKeyName = FlowAES256Util.readKeyName(lines);
        if (loggedKeyName != null) lines.remove(0);
        String keyName = loggedKeyName != null ? loggedKeyName : plan.fallbackKeyName;
        Blob keyBlob = FlowAES256Util.getKey(keyName);

        for (String line : lines) {
            Integer separatorIndex = line.indexOf(FlowAES256Util.LOG_SEPARATOR);
            if (separatorIndex < 1) {
                throw new FlowAES256Util.AES256Exception('unreadable log line');
            }

            String fieldName = line.left(separatorIndex).trim();
            Schema.DescribeFieldResult fieldDescribe = FlowAES256Util.describeField(plan.fieldMap, fieldName);
            if (fieldDescribe == null || !fieldDescribe.isUpdateable()) {
                throw new FlowAES256Util.AES256Exception(fieldName + ' does not exist or is not editable');
            }

            String originalVal;
            try {
                originalVal = FlowAES256Util.decrypt(keyBlob, line.substring(separatorIndex + FlowAES256Util.LOG_SEPARATOR.length()).trim());
            } catch (Exception decryptEx) {
                throw new FlowAES256Util.AES256Exception('could not decrypt ' + fieldName
                    + ' with key ' + keyName + '; the log may have been altered or the key changed');
            }

            try {
                restored.put(fieldDescribe.getName(), FlowAES256Util.toFieldValue(originalVal, fieldDescribe.getType()));
            } catch (Exception convertEx) {
                throw new FlowAES256Util.AES256Exception('could not restore ' + fieldName + ': ' + convertEx.getMessage());
            }
        }

        // Clear the log and reset status checkbox
        restored.put(plan.encField, null);
        restored.put(plan.statusField, false);
        return restored;
    }

    private static UnmaskResult toResult(FlowAES256Service.Outcome outcome) {
        UnmaskResult res = new UnmaskResult();
        res.isSuccess = outcome.isSuccess();
        res.message = outcome.message('Unmasked', 'records with nothing to unmask');
        // Nothing restored and nothing failed: report it as before, so Flows can branch on it
        if (res.isSuccess && outcome.processedCount == 0) {
            res.isSuccess = false;
            res.message = 'No valid encrypted logs found to decrypt.';
        }
        res.processedCount = outcome.processedCount;
        res.skippedCount = outcome.skippedCount;
        res.failedCount = outcome.failedCount();
        res.failedRecordIds = outcome.failedRecordIds;
        return res;
    }
}
