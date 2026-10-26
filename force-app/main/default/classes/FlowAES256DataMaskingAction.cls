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

        @InvocableVariable(label='Key Name' description='Optional. Name of the Symmetric Key Config record to encrypt with. Defaults to Default_Key.')
        public String keyName;

        @InvocableVariable(label='Mask Placeholder' description='Optional. Text written into required text fields, which cannot be blanked. Defaults to *****.')
        public String maskPlaceholder;

        @InvocableVariable(label='All or None' description='Optional. True (default): if any record fails, no record in this request is changed. False: valid records are saved and failures are reported.')
        public Boolean allOrNone;
    }

    public class MaskResult {
        @InvocableVariable(label='Success Flag')
        public Boolean isSuccess;

        @InvocableVariable(label='Message')
        public String message;

        @InvocableVariable(label='Processed Count' description='Records masked and saved')
        public Integer processedCount;

        @InvocableVariable(label='Skipped Count' description='Records left as they were because they were already masked')
        public Integer skippedCount;

        @InvocableVariable(label='Failed Count' description='Records that were not masked')
        public Integer failedCount;

        @InvocableVariable(label='Failed Record Ids' description='Ids of the records that were not masked')
        public List<String> failedRecordIds;
    }

    // Validated settings for one request, kept alongside its outcome
    private class Plan {
        public FlowAES256Service.Outcome outcome;
        public List<Schema.DescribeFieldResult> targetFields = new List<Schema.DescribeFieldResult>();
        public Schema.DescribeFieldResult logField;
        public String statusField;
        public String keyName;
        public Blob key;
        public String placeholder;
    }

    @InvocableMethod(label='AES256 Encrypt and Mask Record Fields' description='Encrypts field values into a log using Custom Metadata AES key, then wipes target fields on a collection of records.')
    public static List<MaskResult> processRecords(List<MaskRequest> requests) {
        List<Plan> plans = new List<Plan>();
        List<FlowAES256Service.Outcome> outcomes = new List<FlowAES256Service.Outcome>();

        for (MaskRequest req : requests) {
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

        List<MaskResult> results = new List<MaskResult>();
        for (Plan plan : plans) {
            results.add(toResult(plan.outcome));
        }
        return results;
    }

    // Validates the request before any data is touched, so a typo never leaves PI unmasked silently
    private static void prepare(Plan plan, MaskRequest req) {
        FlowAES256Service.Outcome outcome = plan.outcome;
        FlowAES256Service.collectRecords(outcome, req.recordsToMask);
        if (!outcome.isActive()) return;
        if (outcome.recordIds.isEmpty()) {
            outcome.reject('No records provided in the collection.');
            return;
        }

        plan.keyName = FlowAES256Util.resolveKeyName(req.keyName);
        plan.key = FlowAES256Util.getKey(plan.keyName);
        plan.placeholder = req.maskPlaceholder;

        String objectName = outcome.sObjectType.getDescribe().getName();
        Map<String, Schema.SObjectField> fieldMap = outcome.sObjectType.getDescribe().fields.getMap();

        plan.logField = FlowAES256Util.requireField(
            fieldMap, req.encryptedLogFieldName, objectName, 'Log field', FlowAES256Util.LOG_FIELD_TYPES, 'a text area field');
        plan.statusField = FlowAES256Util.requireField(
            fieldMap, req.statusCheckboxFieldName, objectName, 'Checkbox field', FlowAES256Util.STATUS_FIELD_TYPES, 'a checkbox').getName();
        String encField = plan.logField.getName();

        Set<String> seenFields = new Set<String>{ encField.toLowerCase(), plan.statusField.toLowerCase() };
        List<String> problems = new List<String>();

        for (String fieldName : resolveFieldNames(req.fieldNamesCollection)) {
            Schema.DescribeFieldResult fieldDescribe = FlowAES256Util.describeField(fieldMap, fieldName);
            if (fieldDescribe == null) {
                problems.add(fieldName + ' does not exist on ' + objectName);
                continue;
            }
            String apiName = fieldDescribe.getName();
            if (apiName == encField || apiName == plan.statusField) {
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
                plan.targetFields.add(fieldDescribe);
            }
        }

        if (!problems.isEmpty()) {
            outcome.reject('No records changed. ' + String.join(problems, '; ') + '.');
            return;
        }
        if (plan.targetFields.isEmpty()) {
            outcome.reject('No fields provided to mask.');
            return;
        }

        outcome.queryFields.add(encField);
        outcome.queryFields.add(plan.statusField);
        for (Schema.DescribeFieldResult fieldDescribe : plan.targetFields) {
            outcome.queryFields.add(fieldDescribe.getName());
        }
    }

    private static void buildChanges(Plan plan, Map<Id, SObject> recordsById) {
        FlowAES256Service.Outcome outcome = plan.outcome;
        String encField = plan.logField.getName();

        for (Id recordId : outcome.recordIds) {
            SObject record = recordsById.get(recordId);
            if (record == null) continue;

            // Re-masking would overwrite the log with encrypted placeholders and lose the original data
            if ((Boolean) record.get(plan.statusField) == true) {
                outcome.skippedCount++;
                continue;
            }

            try {
                SObject change = outcome.sObjectType.newSObject(recordId);
                List<String> logLines = new List<String>();
                for (Schema.DescribeFieldResult fieldDescribe : plan.targetFields) {
                    String apiName = fieldDescribe.getName();
                    String plainText = FlowAES256Util.toText(record.get(apiName), fieldDescribe.getType());

                    if (plainText != null) {
                        logLines.add(apiName + FlowAES256Util.LOG_SEPARATOR + FlowAES256Util.encrypt(plan.key, plainText));
                    }
                    change.put(apiName, FlowAES256Util.maskValueFor(fieldDescribe, plan.placeholder));
                }

                String log = FlowAES256Util.buildLog(plan.keyName, logLines);
                if (log.length() > plan.logField.getLength()) {
                    throw new FlowAES256Util.AES256Exception('the encrypted log needs ' + log.length()
                        + ' characters but ' + encField + ' holds ' + plan.logField.getLength());
                }

                change.put(encField, log);
                change.put(plan.statusField, true);
                outcome.changes.add(change);
            } catch (Exception e) {
                outcome.fail(recordId, e.getMessage());
            }
        }
    }

    private static MaskResult toResult(FlowAES256Service.Outcome outcome) {
        MaskResult res = new MaskResult();
        res.isSuccess = outcome.isSuccess();
        res.message = outcome.message('Processed', 'already masked records');
        res.processedCount = outcome.processedCount;
        res.skippedCount = outcome.skippedCount;
        res.failedCount = outcome.failedCount();
        res.failedRecordIds = outcome.failedRecordIds;
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
