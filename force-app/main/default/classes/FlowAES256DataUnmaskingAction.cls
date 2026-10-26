public with sharing class FlowAES256DataUnmaskingAction {

    public class UnmaskRequest {
        @InvocableVariable(required=true label='Object' description='Collection of records to unmask')
        public List<SObject> recordsToUnmask;

        @InvocableVariable(required=true label='Log Field' description='API Name of the field storing the audit log')
        public String encryptedLogFieldName;

        @InvocableVariable(required=true label='Checkbox Field' description='API Name of the checkbox status field to reset')
        public String statusCheckboxFieldName;
    }

    public class UnmaskResult {
        @InvocableVariable(label='Success Flag')
        public Boolean isSuccess;

        @InvocableVariable(label='Message')
        public String message;
    }

    @InvocableMethod(label='AES256 Decrypt and Unmask Record Fields' description='Reads the encrypted audit log, decrypts fields using Custom Metadata AES key, restores original values, and clears the log.')
    public static List<UnmaskResult> processRecords(List<UnmaskRequest> requests) {
        List<UnmaskResult> results = new List<UnmaskResult>();

        // Retrieve AES key dynamically from Custom Metadata Type
        Blob keyBlob;
        try {
            keyBlob = FlowAES256Util.getKey();
        } catch (FlowAES256Util.AES256Exception e) {
            for (UnmaskRequest req : requests) {
                results.add(result(false, 'ERROR: ' + e.getMessage()));
            }
            return results;
        }

        for (UnmaskRequest req : requests) {
            try {
                results.add(unmaskRecords(req, keyBlob));
            } catch (Exception e) {
                results.add(result(false, 'ERROR: ' + e.getMessage()));
            }
        }

        return results;
    }

    private static UnmaskResult unmaskRecords(UnmaskRequest req, Blob keyBlob) {
        if (req.recordsToUnmask == null || req.recordsToUnmask.isEmpty()) {
            return result(false, 'No records provided in the collection.');
        }

        Schema.SObjectType sObjectType = req.recordsToUnmask[0].getSObjectType();
        String objectName = sObjectType.getDescribe().getName();
        Map<String, Schema.SObjectField> fieldMap = sObjectType.getDescribe().fields.getMap();

        String encField = FlowAES256Util.requireField(
            fieldMap, req.encryptedLogFieldName, objectName, 'Log field', FlowAES256Util.LOG_FIELD_TYPES, 'a text area field').getName();
        String statusField = FlowAES256Util.requireField(
            fieldMap, req.statusCheckboxFieldName, objectName, 'Checkbox field', FlowAES256Util.STATUS_FIELD_TYPES, 'a checkbox').getName();

        Set<Id> recordIds = new Set<Id>();
        for (SObject sObj : req.recordsToUnmask) {
            if (sObj != null && sObj.Id != null) recordIds.add(sObj.Id);
        }

        // Query live records including the log field
        String soql = 'SELECT Id, ' + encField + ', ' + statusField + ' FROM ' + objectName + ' WHERE Id IN :recordIds';

        List<SObject> recordsToUpdate = new List<SObject>();
        List<String> failures = new List<String>();

        for (SObject record : Database.query(soql)) {
            String logContent = (String) record.get(encField);
            if (String.isBlank(logContent)) {
                // Masked while every target field was empty, so there is nothing to restore
                if ((Boolean) record.get(statusField) == true) {
                    SObject reset = sObjectType.newSObject(record.Id);
                    reset.put(statusField, false);
                    recordsToUpdate.add(reset);
                }
                continue;
            }

            // A record is restored only if every line decrypts; otherwise its log is kept so no data is lost
            try {
                recordsToUpdate.add(restoreRecord(sObjectType, fieldMap, record.Id, logContent, keyBlob, encField, statusField));
            } catch (Exception e) {
                failures.add(record.Id + ' (' + e.getMessage() + ')');
            }
        }

        if (!recordsToUpdate.isEmpty()) {
            update recordsToUpdate;
        }

        if (!failures.isEmpty()) {
            return result(false, 'ERROR: Unmasked ' + recordsToUpdate.size() + ' records. '
                + failures.size() + ' records were left masked with their log intact: ' + String.join(failures, '; '));
        }
        if (recordsToUpdate.isEmpty()) {
            return result(false, 'No valid encrypted logs found to decrypt.');
        }
        return result(true, 'SUCCESS: Unmasked ' + recordsToUpdate.size() + ' records.');
    }

    // Parses the multiline log format 'FieldName: EncryptedBase64String' into a record ready to update
    private static SObject restoreRecord(
        Schema.SObjectType sObjectType,
        Map<String, Schema.SObjectField> fieldMap,
        Id recordId,
        String logContent,
        Blob keyBlob,
        String encField,
        String statusField
    ) {
        SObject restored = sObjectType.newSObject(recordId);

        for (String line : FlowAES256Util.splitLogLines(logContent)) {
            Integer separatorIndex = line.indexOf(FlowAES256Util.LOG_SEPARATOR);
            if (separatorIndex < 1) {
                throw new FlowAES256Util.AES256Exception('unreadable log line');
            }

            String fieldName = line.left(separatorIndex).trim();
            Schema.DescribeFieldResult fieldDescribe = FlowAES256Util.describeField(fieldMap, fieldName);
            if (fieldDescribe == null || !fieldDescribe.isUpdateable()) {
                throw new FlowAES256Util.AES256Exception(fieldName + ' does not exist or is not editable');
            }

            String originalVal;
            try {
                originalVal = FlowAES256Util.decrypt(keyBlob, line.substring(separatorIndex + FlowAES256Util.LOG_SEPARATOR.length()).trim());
            } catch (Exception decryptEx) {
                throw new FlowAES256Util.AES256Exception('could not decrypt ' + fieldName
                    + '; the log may have been altered or the key changed');
            }

            try {
                restored.put(fieldDescribe.getName(), FlowAES256Util.toFieldValue(originalVal, fieldDescribe.getType()));
            } catch (Exception convertEx) {
                throw new FlowAES256Util.AES256Exception('could not restore ' + fieldName + ': ' + convertEx.getMessage());
            }
        }

        // Clear the log and reset status checkbox
        restored.put(encField, null);
        restored.put(statusField, false);
        return restored;
    }

    private static UnmaskResult result(Boolean isSuccess, String message) {
        UnmaskResult res = new UnmaskResult();
        res.isSuccess = isSuccess;
        res.message = message;
        return res;
    }
}
