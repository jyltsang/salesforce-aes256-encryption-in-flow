/**
 * Simulates Flow traffic: a record-triggered or scheduled Flow hands the action one request per
 * interview, up to 200 at a time. These tests check that the whole batch shares its queries and
 * updates, and that requests in the same batch do not affect each other.
 */
@IsTest
private class FlowAES256BulkTest {

    // Generous ceilings that still fail if work is done per interview; triggers in the org also count
    private static final Integer MAX_QUERIES = 10;
    private static final Integer MAX_DML = 10;

    @IsTest
    static void test200InterviewsShareQueriesAndUpdates() {
        FlowAES256TestData.useNewKey();
        List<Contact> contacts = FlowAES256TestData.insertContacts(200);

        List<FlowAES256DataMaskingAction.MaskRequest> maskRequests = new List<FlowAES256DataMaskingAction.MaskRequest>();
        List<FlowAES256DataUnmaskingAction.UnmaskRequest> unmaskRequests = new List<FlowAES256DataUnmaskingAction.UnmaskRequest>();
        for (Contact c : contacts) {
            maskRequests.add(FlowAES256TestData.maskRequest(new List<SObject>{ c }, FlowAES256TestData.CONTACT_FIELDS));
            unmaskRequests.add(FlowAES256TestData.unmaskRequest(new List<SObject>{ c }));
        }

        Test.startTest();
        List<FlowAES256DataMaskingAction.MaskResult> maskResults = FlowAES256DataMaskingAction.processRecords(maskRequests);
        Integer maskQueries = Limits.getQueries();
        Integer maskDml = Limits.getDmlStatements();
        Test.stopTest();

        System.assertEquals(200, maskResults.size());
        for (FlowAES256DataMaskingAction.MaskResult res : maskResults) {
            System.assert(res.isSuccess, res.message);
            System.assertEquals(1, res.processedCount);
        }
        System.assert(maskQueries <= MAX_QUERIES, 'Masking used ' + maskQueries + ' queries for 200 interviews');
        System.assert(maskDml <= MAX_DML, 'Masking used ' + maskDml + ' DML statements for 200 interviews');
        System.assertEquals(200, [SELECT COUNT() FROM Contact WHERE DoNotCall = true AND Email = null]);

        Integer queriesBefore = Limits.getQueries();
        Integer dmlBefore = Limits.getDmlStatements();
        List<FlowAES256DataUnmaskingAction.UnmaskResult> unmaskResults = FlowAES256DataUnmaskingAction.processRecords(unmaskRequests);

        System.assert(Limits.getQueries() - queriesBefore <= MAX_QUERIES, 'Unmasking used ' + (Limits.getQueries() - queriesBefore) + ' queries');
        System.assert(Limits.getDmlStatements() - dmlBefore <= MAX_DML, 'Unmasking used ' + (Limits.getDmlStatements() - dmlBefore) + ' DML statements');
        for (FlowAES256DataUnmaskingAction.UnmaskResult res : unmaskResults) {
            System.assert(res.isSuccess, res.message);
        }
        System.assertEquals(200, [SELECT COUNT() FROM Contact WHERE DoNotCall = false AND Email = :FlowAES256TestData.EMAIL]);
    }

    @IsTest
    static void testRequestsForDifferentObjectsAndSettingsInOneBatch() {
        FlowAES256TestData.useNewKey();
        FlowAES256TestData.useNewKey('Sales_Key');
        Contact c = FlowAES256TestData.insertContacts(1)[0];
        Lead l = FlowAES256TestData.insertLead();

        FlowAES256DataMaskingAction.MaskRequest contactReq = FlowAES256TestData.maskRequest(new List<SObject>{ c }, new List<String>{ 'Email', 'LastName' });
        contactReq.maskPlaceholder = 'HIDDEN';
        FlowAES256DataMaskingAction.MaskRequest leadReq = FlowAES256TestData.maskRequest(new List<SObject>{ l }, new List<String>{ 'AnnualRevenue' });
        leadReq.keyName = 'Sales_Key';

        List<FlowAES256DataMaskingAction.MaskResult> results = FlowAES256DataMaskingAction.processRecords(
            new List<FlowAES256DataMaskingAction.MaskRequest>{ contactReq, leadReq });

        System.assert(results[0].isSuccess, results[0].message);
        System.assert(results[1].isSuccess, results[1].message);
        System.assertEquals('HIDDEN', FlowAES256TestData.requeryContact(c.Id).LastName);
        Lead maskedLead = FlowAES256TestData.requeryLead(l.Id);
        System.assertEquals(null, maskedLead.AnnualRevenue);
        System.assert(maskedLead.Description.startsWith('#key: Sales_Key'), maskedLead.Description);
    }

    @IsTest
    static void testFailingRequestDoesNotAffectOthersInBatch() {
        FlowAES256TestData.useNewKey();
        List<Contact> contacts = FlowAES256TestData.insertContacts(2);

        FlowAES256DataMaskingAction.MaskRequest good = FlowAES256TestData.maskRequest(new List<SObject>{ contacts[0] }, new List<String>{ 'Email' });
        FlowAES256DataMaskingAction.MaskRequest bad = FlowAES256TestData.maskRequest(new List<SObject>{ contacts[1] }, new List<String>{ 'Shoe_Size__c' });

        List<FlowAES256DataMaskingAction.MaskResult> results = FlowAES256DataMaskingAction.processRecords(
            new List<FlowAES256DataMaskingAction.MaskRequest>{ good, bad });

        System.assert(results[0].isSuccess, results[0].message);
        System.assert(!results[1].isSuccess);
        System.assertEquals(null, FlowAES256TestData.requeryContact(contacts[0].Id).Email);
        System.assertEquals(FlowAES256TestData.EMAIL, FlowAES256TestData.requeryContact(contacts[1].Id).Email);
    }

    @IsTest
    static void testSameRecordInTwoRequestsIsMaskedOnce() {
        FlowAES256TestData.useNewKey();
        Contact c = FlowAES256TestData.insertContacts(1)[0];

        FlowAES256DataMaskingAction.MaskRequest first = FlowAES256TestData.maskRequest(new List<SObject>{ c }, new List<String>{ 'Email' });
        FlowAES256DataMaskingAction.MaskRequest second = FlowAES256TestData.maskRequest(new List<SObject>{ c }, new List<String>{ 'Phone' });

        List<FlowAES256DataMaskingAction.MaskResult> results = FlowAES256DataMaskingAction.processRecords(
            new List<FlowAES256DataMaskingAction.MaskRequest>{ first, second });

        System.assert(results[0].isSuccess, results[0].message);
        System.assert(!results[1].isSuccess);
        System.assert(results[1].message.contains('included in another request'), results[1].message);
        Contact masked = FlowAES256TestData.requeryContact(c.Id);
        System.assertEquals(null, masked.Email);
        System.assertNotEquals(null, masked.Phone);
    }

    @IsTest
    static void testDatabaseErrorRollsBackOnlyTheAllOrNoneRequest() {
        FlowAES256TestData.useNewKey();
        List<Lead> leads = FlowAES256TestData.insertLeads(4);

        // A converted lead can still be queried but not updated, so its save fails in the database
        Database.LeadConvert convert = new Database.LeadConvert();
        convert.setLeadId(leads[0].Id);
        convert.setConvertedStatus([SELECT MasterLabel FROM LeadStatus WHERE IsConverted = true LIMIT 1].MasterLabel);
        convert.setDoNotCreateOpportunity(true);
        Database.convertLead(convert);

        List<String> fields = new List<String>{ 'Email' };
        FlowAES256DataMaskingAction.MaskRequest strict = FlowAES256TestData.maskRequest(new List<SObject>{ leads[0], leads[1] }, fields);
        FlowAES256DataMaskingAction.MaskRequest lenient = FlowAES256TestData.maskRequest(new List<SObject>{ leads[2] }, fields);
        lenient.allOrNone = false;
        FlowAES256DataMaskingAction.MaskRequest other = FlowAES256TestData.maskRequest(new List<SObject>{ leads[3] }, fields);

        List<FlowAES256DataMaskingAction.MaskResult> results = FlowAES256DataMaskingAction.processRecords(
            new List<FlowAES256DataMaskingAction.MaskRequest>{ strict, lenient, other });

        System.assert(!results[0].isSuccess);
        System.assert(results[0].message.startsWith('ERROR: No records changed because 1 records failed'), results[0].message);
        System.assertEquals(new List<String>{ leads[0].Id }, results[0].failedRecordIds);
        System.assertEquals('alan@example.com', FlowAES256TestData.requeryLead(leads[1].Id).Email, 'Rolled back with its request');

        System.assert(results[1].isSuccess, results[1].message);
        System.assert(results[2].isSuccess, results[2].message);
        System.assertEquals(null, FlowAES256TestData.requeryLead(leads[2].Id).Email);
        System.assertEquals(null, FlowAES256TestData.requeryLead(leads[3].Id).Email);
    }
}
