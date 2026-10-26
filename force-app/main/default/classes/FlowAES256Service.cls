/**
 * Bulk engine shared by the masking and unmasking actions. A Flow can hand an invocable action
 * up to 200 interviews at once; rather than querying and updating per interview, every request
 * in the transaction shares one query and one update per object, keeping SOQL and DML usage flat.
 */
public inherited sharing class FlowAES256Service {

    // Bounds the rollback-and-retry loop used to honour All or None when other requests succeed
    private static final Integer MAX_SAVE_ATTEMPTS = 3;
    // Keeps Message readable when many records fail; every Id is still in Failed Record Ids
    private static final Integer MAX_REASONS_IN_MESSAGE = 10;

    // Tracks one Flow interview's request from validation to its final counts
    public class Outcome {
        public Boolean allOrNone = true;
        public String error;
        public Schema.SObjectType sObjectType;
        public Set<Id> recordIds = new Set<Id>();
        public Set<String> queryFields = new Set<String>{ 'Id' };
        public List<SObject> changes = new List<SObject>();
        public Integer processedCount = 0;
        public Integer skippedCount = 0;
        public List<String> failedRecordIds = new List<String>();
        private List<String> failureReasons = new List<String>();

        public Outcome(Boolean allOrNone) {
            this.allOrNone = allOrNone != false;
        }

        public Boolean isActive() {
            return error == null;
        }

        public Integer failedCount() {
            return failedRecordIds.size();
        }

        public void fail(Id recordId, String reason) {
            failedRecordIds.add(recordId);
            failureReasons.add(recordId + ' (' + reason + ')');
        }

        // Fails the whole request before anything is saved, e.g. for a missing key or field
        public void reject(String reason) {
            error = reason;
            changes.clear();
            processedCount = 0;
            failedRecordIds.clear();
            failureReasons.clear();
            for (Id recordId : recordIds) failedRecordIds.add(recordId);
        }

        // Applies All or None once record-level failures are known
        public void abandonIfAllOrNone() {
            if (!allOrNone || failedRecordIds.isEmpty()) return;
            error = 'No records changed because ' + failedRecordIds.size() + ' records failed: ' + reasons();
            changes.clear();
            processedCount = 0;
        }

        public Boolean isSuccess() {
            return error == null && failedRecordIds.isEmpty();
        }

        public String message(String doneLabel, String skippedLabel) {
            if (error != null) return 'ERROR: ' + error;
            String text = doneLabel + ' ' + processedCount + ' records.';
            if (skippedCount > 0) text += ' Skipped ' + skippedCount + ' ' + skippedLabel + '.';
            if (!failedRecordIds.isEmpty()) text += ' Failed ' + failedRecordIds.size() + ' records: ' + reasons();
            return (isSuccess() ? 'SUCCESS: ' : 'ERROR: ') + text;
        }

        private String reasons() {
            List<String> shown = new List<String>();
            for (Integer i = 0; i < failureReasons.size() && i < MAX_REASONS_IN_MESSAGE; i++) {
                shown.add(failureReasons[i]);
            }
            String text = String.join(shown, '; ');
            if (failureReasons.size() > MAX_REASONS_IN_MESSAGE) {
                text += '; and ' + (failureReasons.size() - MAX_REASONS_IN_MESSAGE) + ' more';
            }
            return text;
        }
    }

    // Reads the Ids and object type of the Flow's record collection into the outcome
    public static void collectRecords(Outcome outcome, List<SObject> records) {
        if (records == null) return;
        for (SObject record : records) {
            if (record == null || record.Id == null) continue;
            if (outcome.sObjectType == null) outcome.sObjectType = record.getSObjectType();
            if (record.getSObjectType() != outcome.sObjectType) {
                outcome.reject('All records in the collection must be of the same object.');
                return;
            }
            outcome.recordIds.add(record.Id);
        }
    }

    // A record may be changed by one request only; a later request in the same batch reports it as failed
    public static void claimRecords(List<Outcome> outcomes) {
        Set<Id> claimed = new Set<Id>();
        for (Outcome outcome : outcomes) {
            if (!outcome.isActive()) continue;
            for (Id recordId : new List<Id>(outcome.recordIds)) {
                if (claimed.add(recordId)) continue;
                outcome.recordIds.remove(recordId);
                outcome.fail(recordId, 'included in another request in the same transaction');
            }
        }
    }

    // Runs one query per object for all active requests and reports records the user cannot see
    public static Map<Id, SObject> queryRecords(List<Outcome> outcomes) {
        Map<Schema.SObjectType, Set<String>> fieldsByType = new Map<Schema.SObjectType, Set<String>>();
        Map<Schema.SObjectType, Set<Id>> idsByType = new Map<Schema.SObjectType, Set<Id>>();

        for (Outcome outcome : outcomes) {
            if (!outcome.isActive() || outcome.recordIds.isEmpty()) continue;
            if (!fieldsByType.containsKey(outcome.sObjectType)) {
                fieldsByType.put(outcome.sObjectType, new Set<String>());
                idsByType.put(outcome.sObjectType, new Set<Id>());
            }
            // Lower-case names stop 'Email' and 'email' from both being selected
            for (String fieldName : outcome.queryFields) {
                fieldsByType.get(outcome.sObjectType).add(fieldName.toLowerCase());
            }
            idsByType.get(outcome.sObjectType).addAll(outcome.recordIds);
        }

        Map<Id, SObject> recordsById = new Map<Id, SObject>();
        for (Schema.SObjectType sObjectType : fieldsByType.keySet()) {
            Set<Id> recordIds = idsByType.get(sObjectType);
            String soql = 'SELECT ' + String.join(new List<String>(fieldsByType.get(sObjectType)), ', ')
                + ' FROM ' + sObjectType.getDescribe().getName() + ' WHERE Id IN :recordIds';
            recordsById.putAll(Database.query(soql));
        }

        for (Outcome outcome : outcomes) {
            if (!outcome.isActive()) continue;
            for (Id recordId : outcome.recordIds) {
                if (!recordsById.containsKey(recordId)) {
                    outcome.fail(recordId, 'record not found or not shared with the running user');
                }
            }
        }
        return recordsById;
    }

    /**
     * Saves every active request's changes with one update per object. If an All or None request
     * has a failing record, the batch is rolled back and saved again without that request, so its
     * other records are not left half-changed while the remaining requests still succeed.
     */
    public static void save(List<Outcome> outcomes) {
        List<Outcome> pending = new List<Outcome>();
        for (Outcome outcome : outcomes) {
            if (outcome.isActive() && !outcome.changes.isEmpty()) pending.add(outcome);
        }

        for (Integer attempt = 0; attempt < MAX_SAVE_ATTEMPTS && !pending.isEmpty(); attempt++) {
            Savepoint sp = Database.setSavepoint();
            Map<Integer, List<String>> errorsByOutcome = updateGroupedByObject(pending);

            List<Outcome> stillPending = new List<Outcome>();
            Boolean rollbackNeeded = false;
            for (Integer i = 0; i < pending.size(); i++) {
                Outcome outcome = pending[i];
                if (outcome.allOrNone && errorsByOutcome.containsKey(i)) {
                    rollbackNeeded = true;
                } else {
                    stillPending.add(outcome);
                }
            }

            if (!rollbackNeeded) {
                for (Integer i = 0; i < pending.size(); i++) {
                    recordSaveResults(pending[i], errorsByOutcome.get(i));
                }
                return;
            }

            Database.rollback(sp);
            for (Integer i = 0; i < pending.size(); i++) {
                if (pending[i].allOrNone && errorsByOutcome.containsKey(i)) {
                    recordSaveResults(pending[i], errorsByOutcome.get(i));
                    pending[i].abandonIfAllOrNone();
                }
            }
            pending = stillPending;
        }

        // Retries exhausted (the rolled-back batch kept failing): report the rest without saving
        for (Outcome outcome : pending) {
            outcome.reject('No records changed because the batch could not be saved consistently; please retry.');
        }
    }

    // Returns 'recordId|message' entries per outcome index for records the database rejected
    private static Map<Integer, List<String>> updateGroupedByObject(List<Outcome> pending) {
        Map<Schema.SObjectType, List<SObject>> recordsByType = new Map<Schema.SObjectType, List<SObject>>();
        Map<Schema.SObjectType, List<Integer>> ownersByType = new Map<Schema.SObjectType, List<Integer>>();

        for (Integer i = 0; i < pending.size(); i++) {
            Outcome outcome = pending[i];
            if (!recordsByType.containsKey(outcome.sObjectType)) {
                recordsByType.put(outcome.sObjectType, new List<SObject>());
                ownersByType.put(outcome.sObjectType, new List<Integer>());
            }
            for (SObject change : outcome.changes) {
                recordsByType.get(outcome.sObjectType).add(change);
                ownersByType.get(outcome.sObjectType).add(i);
            }
        }

        Map<Integer, List<String>> errorsByOutcome = new Map<Integer, List<String>>();
        for (Schema.SObjectType sObjectType : recordsByType.keySet()) {
            List<SObject> records = recordsByType.get(sObjectType);
            List<Database.SaveResult> saveResults = Database.update(records, false);
            for (Integer j = 0; j < saveResults.size(); j++) {
                if (saveResults[j].isSuccess()) continue;
                Integer owner = ownersByType.get(sObjectType)[j];
                if (!errorsByOutcome.containsKey(owner)) errorsByOutcome.put(owner, new List<String>());
                errorsByOutcome.get(owner).add(records[j].Id + '|' + saveResults[j].getErrors()[0].getMessage());
            }
        }
        return errorsByOutcome;
    }

    private static void recordSaveResults(Outcome outcome, List<String> errors) {
        Integer failed = 0;
        if (errors != null) {
            for (String entry : errors) {
                outcome.fail(Id.valueOf(entry.substringBefore('|')), entry.substringAfter('|'));
                failed++;
            }
        }
        outcome.processedCount = outcome.changes.size() - failed;
    }
}
