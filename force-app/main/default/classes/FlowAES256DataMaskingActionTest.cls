@IsTest
private class FlowAES256DataMaskingActionTest {

    @IsTest
    static void testMasksTextPostcodeDateAndCheckboxFields() {
        FlowAES256TestData.useNewKey();
        Contact c = FlowAES256TestData.insertContacts(1)[0];

        Test.startTest();
        FlowAES256DataMaskingAction.MaskResult res = FlowAES256TestData.mask(new List<SObject>{ c }, FlowAES256TestData.CONTACT_FIELDS);
        Test.stopTest();

        System.assert(res.isSuccess, res.message);
        System.assertEquals('SUCCESS: Processed 1 records.', res.message);
        System.assertEquals(1, res.processedCount);
        System.assertEquals(0, res.skippedCount);
        System.assertEquals(0, res.failedCount);
        System.assert(res.failedRecordIds.isEmpty());

        Contact masked = FlowAES256TestData.requeryContact(c.Id);
        System.assertEquals(null, masked.MailingPostalCode);
        System.assertEquals(null, masked.MailingStreet);
        System.assertEquals(null, masked.Email);
        System.assertEquals(null, masked.Phone);
        System.assertEquals(null, masked.Birthdate);
        System.assertEquals(FlowAES256Util.MASK_PLACEHOLDER, masked.LastName, 'Required text fields get the placeholder');
        System.assertEquals(false, masked.HasOptedOutOfEmail);
        System.assertEquals(true, masked.DoNotCall, 'Status checkbox is ticked');

        System.assert(masked.Description.startsWith('#key: Default_Key\n'), 'Log names the key: ' + masked.Description);
        System.assert(masked.Description.contains('MailingPostalCode: '), masked.Description);
        System.assert(masked.Description.contains('Birthdate: '), masked.Description);
        System.assert(!masked.Description.contains(FlowAES256TestData.POSTCODE), 'Postcode must not appear in clear text');
        System.assert(!masked.Description.contains(FlowAES256TestData.EMAIL), 'Email must not appear in clear text');
        System.assert(!masked.Description.contains('MailingState:'), 'Empty fields are not logged');
    }

    @IsTest
    static void testMasksNumberAndCurrencyFields() {
        FlowAES256TestData.useNewKey();
        Lead l = FlowAES256TestData.insertLead();

        FlowAES256DataMaskingAction.MaskResult res = FlowAES256TestData.mask(
            new List<SObject>{ l }, new List<String>{ 'NumberOfEmployees', 'AnnualRevenue', 'PostalCode' });

        System.assert(res.isSuccess, res.message);
        Lead masked = FlowAES256TestData.requeryLead(l.Id);
        System.assertEquals(null, masked.NumberOfEmployees);
        System.assertEquals(null, masked.AnnualRevenue);
        System.assertEquals(null, masked.PostalCode);
        System.assertEquals(4, FlowAES256Util.splitLogLines(masked.Description).size(), 'Key header plus three fields');
    }

    @IsTest
    static void testFieldNamesAreTrimmedCaseInsensitiveAndDeduplicated() {
        FlowAES256TestData.useNewKey();
        Contact c = FlowAES256TestData.insertContacts(1)[0];

        FlowAES256DataMaskingAction.MaskResult res = FlowAES256TestData.mask(
            new List<SObject>{ c }, new List<String>{ ' email ', 'EMAIL', 'mailingpostalcode', '', null });

        System.assert(res.isSuccess, res.message);
        Contact masked = FlowAES256TestData.requeryContact(c.Id);
        System.assertEquals(null, masked.Email);
        System.assertEquals(null, masked.MailingPostalCode);
        System.assertEquals(1, masked.Description.countMatches('Email: '), masked.Description);
    }

    @IsTest
    static void testSkipsAlreadyMaskedRecordsSoNoDataIsLost() {
        FlowAES256TestData.useNewKey();
        Contact c = FlowAES256TestData.insertContacts(1)[0];

        FlowAES256TestData.mask(new List<SObject>{ c }, FlowAES256TestData.CONTACT_FIELDS);
        String firstLog = FlowAES256TestData.requeryContact(c.Id).Description;

        FlowAES256DataMaskingAction.MaskResult second = FlowAES256TestData.mask(new List<SObject>{ c }, FlowAES256TestData.CONTACT_FIELDS);

        System.assert(second.isSuccess, second.message);
        System.assertEquals('SUCCESS: Processed 0 records. Skipped 1 already masked records.', second.message);
        System.assertEquals(0, second.processedCount);
        System.assertEquals(1, second.skippedCount);
        System.assertEquals(firstLog, FlowAES256TestData.requeryContact(c.Id).Description, 'The original log must be kept');
    }

    @IsTest
    static void testRejectsUnknownFieldWithoutChangingData() {
        FlowAES256TestData.useNewKey();
        Contact c = FlowAES256TestData.insertContacts(1)[0];

        FlowAES256DataMaskingAction.MaskResult res = FlowAES256TestData.mask(
            new List<SObject>{ c }, new List<String>{ 'Email', 'Shoe_Size__c' });

        System.assert(!res.isSuccess);
        System.assert(res.message.contains('Shoe_Size__c does not exist on Contact'), res.message);
        assertContactUnchanged(c.Id);
    }

    @IsTest
    static void testRejectsRequiredNonTextField() {
        FlowAES256TestData.useNewKey();
        Lead l = FlowAES256TestData.insertLead();

        // Lead.Status is a required picklist: it can be neither blanked nor given the placeholder
        FlowAES256DataMaskingAction.MaskResult res = FlowAES256TestData.mask(
            new List<SObject>{ l }, new List<String>{ 'NumberOfEmployees', 'Status' });

        System.assert(!res.isSuccess);
        System.assert(res.message.contains('Status is a required'), res.message);
        Lead unchanged = FlowAES256TestData.requeryLead(l.Id);
        System.assertEquals(250, unchanged.NumberOfEmployees);
        System.assertEquals(false, unchanged.DoNotCall);
    }

    @IsTest
    static void testRejectsReadOnlyCompoundAndLogFields() {
        FlowAES256TestData.useNewKey();
        Contact c = FlowAES256TestData.insertContacts(1)[0];

        FlowAES256DataMaskingAction.MaskResult res = FlowAES256TestData.mask(
            new List<SObject>{ c }, new List<String>{ 'Name', 'Description' });

        System.assert(!res.isSuccess);
        System.assert(res.message.contains('Name is not editable'), res.message);
        System.assert(res.message.contains('Description is the log or checkbox field'), res.message);
        assertContactUnchanged(c.Id);
    }

    @IsTest
    static void testRejectsWrongLogAndStatusFieldTypes() {
        FlowAES256TestData.useNewKey();
        Contact c = FlowAES256TestData.insertContacts(1)[0];

        FlowAES256DataMaskingAction.MaskRequest req = new FlowAES256DataMaskingAction.MaskRequest();
        req.recordsToMask = new List<SObject>{ c };
        req.fieldNamesCollection = new List<String>{ 'Email' };
        req.encryptedLogFieldName = FlowAES256TestData.LOG_FIELD;
        req.statusCheckboxFieldName = 'Birthdate';

        FlowAES256DataMaskingAction.MaskRequest missingLog = new FlowAES256DataMaskingAction.MaskRequest();
        missingLog.recordsToMask = new List<SObject>{ c };
        missingLog.fieldNamesCollection = new List<String>{ 'Email' };
        missingLog.encryptedLogFieldName = 'Audit_Log__x';
        missingLog.statusCheckboxFieldName = FlowAES256TestData.STATUS_FIELD;

        List<FlowAES256DataMaskingAction.MaskResult> results = FlowAES256DataMaskingAction.processRecords(
            new List<FlowAES256DataMaskingAction.MaskRequest>{ req, missingLog });

        System.assert(!results[0].isSuccess);
        System.assert(results[0].message.contains('expected a checkbox'), results[0].message);
        System.assert(!results[1].isSuccess);
        System.assert(results[1].message.contains('Audit_Log__x" does not exist'), results[1].message);
        assertContactUnchanged(c.Id);
    }

    @IsTest
    static void testEmptyRecordAndFieldCollections() {
        FlowAES256TestData.useNewKey();
        Contact c = FlowAES256TestData.insertContacts(1)[0];

        FlowAES256DataMaskingAction.MaskResult noRecords = FlowAES256TestData.mask(new List<SObject>(), FlowAES256TestData.CONTACT_FIELDS);
        FlowAES256DataMaskingAction.MaskResult noFields = FlowAES256TestData.mask(new List<SObject>{ c }, new List<String>());

        System.assert(!noRecords.isSuccess);
        System.assertEquals('ERROR: No records provided in the collection.', noRecords.message);
        System.assert(!noFields.isSuccess);
        System.assertEquals('ERROR: No fields provided to mask.', noFields.message);
    }

    @IsTest
    static void testMissingOrInvalidKeyFailsEveryRequest() {
        Contact c = FlowAES256TestData.insertContacts(1)[0];

        FlowAES256Util.setTestKey(null, '');
        FlowAES256DataMaskingAction.MaskResult missing = FlowAES256TestData.mask(new List<SObject>{ c }, FlowAES256TestData.CONTACT_FIELDS);

        FlowAES256Util.setTestKey(null, EncodingUtil.base64Encode(Crypto.generateAesKey(128)));
        FlowAES256DataMaskingAction.MaskResult tooShort = FlowAES256TestData.mask(new List<SObject>{ c }, FlowAES256TestData.CONTACT_FIELDS);

        System.assert(!missing.isSuccess);
        System.assert(missing.message.contains('missing or blank'), missing.message);
        System.assertEquals(1, missing.failedCount, 'Every record of a rejected request is reported as failed');
        System.assertEquals(new List<String>{ c.Id }, missing.failedRecordIds);
        System.assert(!tooShort.isSuccess);
        System.assert(tooShort.message.contains('32 bytes'), tooShort.message);
        assertContactUnchanged(c.Id);
    }

    @IsTest
    static void testBulkMasking() {
        FlowAES256TestData.useNewKey();
        List<Contact> contacts = FlowAES256TestData.insertContacts(200);

        Test.startTest();
        FlowAES256DataMaskingAction.MaskResult res = FlowAES256TestData.mask(contacts, FlowAES256TestData.CONTACT_FIELDS);
        Test.stopTest();

        System.assert(res.isSuccess, res.message);
        System.assertEquals('SUCCESS: Processed 200 records.', res.message);
        System.assertEquals(200, [SELECT COUNT() FROM Contact WHERE DoNotCall = true AND Email = null]);
    }

    @IsTest
    static void testCustomPlaceholderAndKeyName() {
        FlowAES256TestData.useNewKey();
        FlowAES256TestData.useNewKey('HR_Key');
        Contact c = FlowAES256TestData.insertContacts(1)[0];

        FlowAES256DataMaskingAction.MaskRequest req = FlowAES256TestData.maskRequest(
            new List<SObject>{ c }, new List<String>{ 'LastName', 'Email' });
        req.maskPlaceholder = 'REDACTED';
        req.keyName = 'HR_Key';
        FlowAES256DataMaskingAction.MaskResult res = FlowAES256TestData.mask(req);

        System.assert(res.isSuccess, res.message);
        Contact masked = FlowAES256TestData.requeryContact(c.Id);
        System.assertEquals('REDACTED', masked.LastName);
        System.assertEquals(null, masked.Email, 'Optional fields are still blanked');
        System.assert(masked.Description.startsWith('#key: HR_Key\n'), masked.Description);

        // The value is encrypted with HR_Key, not the default key
        String emailCipher = masked.Description.substringAfter('Email: ').substringBefore('\n').trim();
        System.assertEquals(FlowAES256TestData.EMAIL, FlowAES256Util.decrypt(FlowAES256Util.getKey('HR_Key'), emailCipher));
    }

    @IsTest
    static void testUnknownKeyNameRejectsRequest() {
        FlowAES256TestData.useNewKey();
        Contact c = FlowAES256TestData.insertContacts(1)[0];

        FlowAES256DataMaskingAction.MaskRequest req = FlowAES256TestData.maskRequest(new List<SObject>{ c }, new List<String>{ 'Email' });
        req.keyName = 'No_Such_Key';
        FlowAES256DataMaskingAction.MaskResult res = FlowAES256TestData.mask(req);

        System.assert(!res.isSuccess);
        System.assert(res.message.contains('(No_Such_Key) missing or blank'), res.message);
        assertContactUnchanged(c.Id);
    }

    @IsTest
    static void testLogTooLongFailsRecord() {
        FlowAES256TestData.useNewKey();
        Contact c = FlowAES256TestData.insertContacts(1)[0];

        // Contact.Title holds 128 characters: far too small for an encrypted log
        FlowAES256DataMaskingAction.MaskRequest req = FlowAES256TestData.maskRequest(
            new List<SObject>{ c }, new List<String>{ 'Email', 'MailingStreet', 'Phone' });
        req.encryptedLogFieldName = 'Title';
        FlowAES256DataMaskingAction.MaskResult res = FlowAES256TestData.mask(req);

        System.assert(!res.isSuccess);
        System.assert(res.message.contains('holds 128'), res.message);
        System.assertEquals(new List<String>{ c.Id }, res.failedRecordIds);
        assertContactUnchanged(c.Id);
    }

    @IsTest
    static void testRecordsNotFoundAreReported() {
        FlowAES256TestData.useNewKey();
        List<Contact> contacts = FlowAES256TestData.insertContacts(2);
        Id deletedId = contacts[1].Id;
        delete contacts[1];

        FlowAES256DataMaskingAction.MaskRequest strict = FlowAES256TestData.maskRequest(contacts, new List<String>{ 'Email' });
        FlowAES256DataMaskingAction.MaskResult strictRes = FlowAES256TestData.mask(strict);

        System.assert(!strictRes.isSuccess);
        System.assert(strictRes.message.startsWith('ERROR: No records changed because 1 records failed'), strictRes.message);
        System.assert(strictRes.message.contains('record not found'), strictRes.message);
        assertContactUnchanged(contacts[0].Id);

        FlowAES256DataMaskingAction.MaskRequest lenient = FlowAES256TestData.maskRequest(contacts, new List<String>{ 'Email' });
        lenient.allOrNone = false;
        FlowAES256DataMaskingAction.MaskResult lenientRes = FlowAES256TestData.mask(lenient);

        System.assert(!lenientRes.isSuccess, 'A failed record still makes the request unsuccessful');
        System.assertEquals(1, lenientRes.processedCount);
        System.assertEquals(1, lenientRes.failedCount);
        System.assertEquals(new List<String>{ deletedId }, lenientRes.failedRecordIds);
        System.assertEquals(null, FlowAES256TestData.requeryContact(contacts[0].Id).Email, 'The valid record is masked');
    }

    @IsTest
    static void testMixedObjectsInOneCollectionAreRejected() {
        FlowAES256TestData.useNewKey();
        Contact c = FlowAES256TestData.insertContacts(1)[0];
        Lead l = FlowAES256TestData.insertLead();

        FlowAES256DataMaskingAction.MaskResult res = FlowAES256TestData.mask(new List<SObject>{ c, l }, new List<String>{ 'Email' });

        System.assert(!res.isSuccess);
        System.assert(res.message.contains('same object'), res.message);
        assertContactUnchanged(c.Id);
    }

    private static void assertContactUnchanged(Id contactId) {
        Contact c = FlowAES256TestData.requeryContact(contactId);
        System.assertEquals(FlowAES256TestData.EMAIL, c.Email);
        System.assertEquals(FlowAES256TestData.POSTCODE, c.MailingPostalCode);
        System.assertEquals(false, c.DoNotCall);
        System.assertEquals(null, c.Description);
    }
}
