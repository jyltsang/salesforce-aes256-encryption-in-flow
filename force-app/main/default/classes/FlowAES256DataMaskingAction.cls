public with sharing class FlowAES256DataMaskingAction {

    public class MaskRequest {
        @InvocableVariable(required=true label='Object' description='Collection of records to mask')
        public List<SObject> recordsToMask;

        @InvocableVariable(required=true label='Fields Name' description='Collection of field API names to encrypt and mask')
        public List<String> fieldNamesCollection;

        @InvocableVariable(required=true label='Log Field' description='API Name of the field to store the audit log')
        public String encryptedLogFieldName;

        @InvocableVariable(required=true label='Checkbox Field' description='API Name of the checkbox status field')
        public String statusCheckboxFieldName;
    }

    public class MaskResult {
        @InvocableVariable(label='Success Flag')
        public Boolean isSuccess;

        @InvocableVariable(label='Message')
        public String message;
    }

    @InvocableMethod(label='AES256 Encrypt and Mask Record Fields' description='Encrypts field values into a log using Custom Metadata AES key, then wipes target fields on a collection of records.')
    public static List<MaskResult> processRecords(List<MaskRequest> requests) {
        List<MaskResult> results = new List<MaskResult>();

        // Retrieve AES key dynamically from Custom Metadata Type
        Blob keyBlob;
        try {
            keyBlob = FlowAES256Util.getKey();
        } catch (FlowAES256Util.AES256Exception e) {
            for (MaskRequest req : requests) {
                results.add(result(false, 'ERROR: ' + e.getMessage()));
            }
            return results;
        }

        for (MaskRequest req : requests) {
            try {
                results.add(maskRecords(req, keyBlob));
            } catch (Exception e) {
                results.add(result(false, 'ERROR: ' + e.getMessage()));
            }
        }

        return results;
    }

    private static MaskResult maskRecords(MaskRequest req, Blob keyBlob) {
        if (req.recordsToMask == null || req.recordsToMask.isEmpty()) {
            return result(false, 'No records provided in the collection.');
        }

        Schema.SObjectType sObjectType = req.recordsToMask[0].getSObjectType();
        String objectName = sObjectType.getDescribe().getName();
        Map<String, Schema.SObjectField> fieldMap = sObjectType.getDescribe().fields.getMap();

        Schema.DescribeFieldResult logField = FlowAES256Util.requireField(
            fieldMap, req.encryptedLogFieldName, objectName, 'Log field', FlowAES256Util.LOG_FIELD_TYPES, 'a text area field');
        Schema.DescribeFieldResult statusField = FlowAES256Util.requireField(
            fieldMap, req.statusCheckboxFieldName, objectName, 'Checkbox field', FlowAES256Util.STATUS_FIELD_TYPES, 'a checkbox');
        String encField = logField.getName();
        String statusFieldName = statusField.getName();

        // Validate every target field before touching data, so a typo never leaves PI unmasked silently
        List<Schema.DescribeFieldResult> targetFields = new List<Schema.DescribeFieldResult>();
        Set<String> seenFields = new Set<String>{ encField.toLowerCase(), statusFieldName.toLowerCase() };
        List<String> problems = new List<String>();

        for (String fieldName : resolveFieldNames(req.fieldNamesCollection)) {
            Schema.DescribeFieldResult fieldDescribe = FlowAES256Util.describeField(fieldMap, fieldName);
            if (fieldDescribe == null) {
                problems.add(fieldName + ' does not exist on ' + objectName);
                continue;
            }
            String apiName = fieldDescribe.getName();
            if (apiName == encField || apiName == statusFieldName) {
                problems.add(apiName + ' is the log or checkbox field and cannot be masked');
                continue;
            }
            // Skip duplicates such as 'Email' and 'email'
            if (!seenFields.add(apiName.toLowerCase())) continue;

            if (!fieldDescribe.isUpdateable()) {
                problems.add(apiName + ' is not editable by the running user');
            } else if (!FlowAES256Util.isSupportedType(fieldDescribe.getType())) {
                problems.add(apiName + ' is a ' + fieldDescribe.getType() + ' field, which is not supported');
            } else if (!FlowAES256Util.canMask(fieldDescribe)) {
                problems.add(apiName + ' is a required ' + fieldDescribe.getType() + ' field and cannot be blanked');
            } else {
                targetFields.add(fieldDescribe);
            }
        }

        if (!problems.isEmpty()) {
            return result(false, 'ERROR: No records changed. ' + String.join(problems, '; ') + '.');
        }
        if (targetFields.isEmpty()) {
            return result(false, 'ERROR: No fields provided to mask.');
        }

        Set<Id> recordIds = new Set<Id>();
        for (SObject sObj : req.recordsToMask) {
            if (sObj != null && sObj.Id != null) recordIds.add(sObj.Id);
        }

        List<String> queryFields = new List<String>{ 'Id', encField, statusFieldName };
        for (Schema.DescribeFieldResult fieldDescribe : targetFields) {
            queryFields.add(fieldDescribe.getName());
        }

        String soql = 'SELECT ' + String.join(queryFields, ', ') +
                      ' FROM ' + objectName + ' WHERE Id IN :recordIds';

        List<SObject> recordsToUpdate = new List<SObject>();
        Integer alreadyMasked = 0;

        for (SObject record : Database.query(soql)) {
            // Re-masking would overwrite the log with encrypted placeholders and lose the original data
            if ((Boolean) record.get(statusFieldName) == true) {
                alreadyMasked++;
                continue;
            }

            List<String> logLines = new List<String>();
            for (Schema.DescribeFieldResult fieldDescribe : targetFields) {
                String apiName = fieldDescribe.getName();
                String plainText = FlowAES256Util.toText(record.get(apiName), fieldDescribe.getType());

                if (plainText != null) {
                    logLines.add(apiName + FlowAES256Util.LOG_SEPARATOR + FlowAES256Util.encrypt(keyBlob, plainText));
                }
                record.put(apiName, FlowAES256Util.maskValueFor(fieldDescribe));
            }

            String log = String.join(logLines, '\n');
            if (log.length() > logField.getLength()) {
                throw new FlowAES256Util.AES256Exception('No records changed. The encrypted log for ' + record.Id + ' needs '
                    + log.length() + ' characters but ' + encField + ' holds ' + logField.getLength() + '.');
            }

            record.put(encField, log);
            record.put(statusFieldName, true);
            recordsToUpdate.add(record);
        }

        if (!recordsToUpdate.isEmpty()) {
            update recordsToUpdate;
        }

        String message = 'SUCCESS: Processed ' + recordsToUpdate.size() + ' records.';
        if (alreadyMasked > 0) {
            message += ' Skipped ' + alreadyMasked + ' already masked records.';
        }
        return result(true, message);
    }

    private static MaskResult result(Boolean isSuccess, String message) {
        MaskResult res = new MaskResult();
        res.isSuccess = isSuccess;
        res.message = message;
        return res;
    }

    private static List<String> resolveFieldNames(List<String> fieldNames) {
        List<String> resolved = new List<String>();
        if (fieldNames == null) return resolved;

        for (String f : fieldNames) {
            if (String.isBlank(f)) continue;
            String lower = f.trim().toLowerCase();

            if (lower == 'mailingaddress') {
                resolved.addAll(new List<String>{'MailingStreet', 'MailingCity', 'MailingState', 'MailingPostalCode', 'MailingCountry'});
            } else if (lower == 'billingaddress') {
                resolved.addAll(new List<String>{'BillingStreet', 'BillingCity', 'BillingState', 'BillingPostalCode', 'BillingCountry'});
            } else if (lower == 'shippingaddress') {
                resolved.addAll(new List<String>{'ShippingStreet', 'ShippingCity', 'ShippingState', 'ShippingPostalCode', 'ShippingCountry'});
            } else if (lower == 'otheraddress') {
                resolved.addAll(new List<String>{'OtherStreet', 'OtherCity', 'OtherState', 'OtherPostalCode', 'OtherCountry'});
            } else {
                resolved.add(f.trim());
            }
        }
        return resolved;
    }
}
