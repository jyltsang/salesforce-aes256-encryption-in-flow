@IsTest
private class FlowAES256DataUnmaskingActionTest {

    @IsTest
    static void testRoundTripRestoresTextPostcodeDateAndCheckboxFields() {
        FlowAES256TestData.useNewKey();
        Contact original = FlowAES256TestData.requeryContact(FlowAES256TestData.insertContacts(1)[0].Id);
        FlowAES256TestData.mask(new List<SObject>{ original }, FlowAES256TestData.CONTACT_FIELDS);

        Test.startTest();
        FlowAES256DataUnmaskingAction.UnmaskResult res = FlowAES256TestData.unmask(new List<SObject>{ original });
        Test.stopTest();

        System.assert(res.isSuccess, res.message);
        System.assertEquals('SUCCESS: Unmasked 1 records.', res.message);

        Contact restored = FlowAES256TestData.requeryContact(original.Id);
        System.assertEquals(original.LastName, restored.LastName);
        System.assertEquals(FlowAES256TestData.EMAIL, restored.Email);
        System.assertEquals(original.Phone, restored.Phone);
        System.assertEquals(FlowAES256TestData.BIRTHDATE, restored.Birthdate);
        System.assertEquals(FlowAES256TestData.STREET, restored.MailingStreet, 'Multi-line values are restored intact');
        System.assertEquals('London', restored.MailingCity);
        System.assertEquals(FlowAES256TestData.POSTCODE, restored.MailingPostalCode);
        System.assertEquals(true, restored.HasOptedOutOfEmail);
        System.assertEquals(null, restored.Description, 'Log is cleared');
        System.assertEquals(false, restored.DoNotCall, 'Status checkbox is reset');
    }

    @IsTest
    static void testRoundTripRestoresNumberAndCurrencyFields() {
        FlowAES256TestData.useNewKey();
        Lead l = FlowAES256TestData.insertLead();
        FlowAES256TestData.mask(new List<SObject>{ l }, new List<String>{ 'NumberOfEmployees', 'AnnualRevenue', 'PostalCode', 'Email' });

        FlowAES256DataUnmaskingAction.UnmaskResult res = FlowAES256TestData.unmask(new List<SObject>{ l });

        System.assert(res.isSuccess, res.message);
        Lead restored = FlowAES256TestData.requeryLead(l.Id);
        System.assertEquals(250, restored.NumberOfEmployees);
        System.assertEquals(1234567.89, restored.AnnualRevenue);
        System.assertEquals('01234', restored.PostalCode, 'Leading zeros in a postcode are kept');
        System.assertEquals('alan@example.com', restored.Email);
        System.assertEquals(null, restored.Description);
        System.assertEquals(false, restored.DoNotCall);
    }

    @IsTest
    static void testRestoresLogStoredInRichTextFormat() {
        FlowAES256TestData.useNewKey();
        Blob key = FlowAES256Util.getKey();
        Lead l = FlowAES256TestData.insertLead();

        // A Rich Text Area may wrap each line in HTML
        l.Description = '<p>NumberOfEmployees: ' + FlowAES256Util.encrypt(key, '42') + '</p>'
            + '<p>postalcode: ' + FlowAES256Util.encrypt(key, 'EC1A 1BB') + '<br></p>';
        l.NumberOfEmployees = null;
        l.PostalCode = null;
        l.DoNotCall = true;
        update l;

        FlowAES256DataUnmaskingAction.UnmaskResult res = FlowAES256TestData.unmask(new List<SObject>{ l });

        System.assert(res.isSuccess, res.message);
        Lead restored = FlowAES256TestData.requeryLead(l.Id);
        System.assertEquals(42, restored.NumberOfEmployees);
        System.assertEquals('EC1A 1BB', restored.PostalCode);
    }

    @IsTest
    static void testWrongKeyLeavesRecordMaskedWithLogIntact() {
        FlowAES256TestData.useNewKey();
        Contact c = FlowAES256TestData.insertContacts(1)[0];
        FlowAES256TestData.mask(new List<SObject>{ c }, FlowAES256TestData.CONTACT_FIELDS);
        String log = FlowAES256TestData.requeryContact(c.Id).Description;

        FlowAES256TestData.useNewKey();
        FlowAES256DataUnmaskingAction.UnmaskResult res = FlowAES256TestData.unmask(new List<SObject>{ c });

        System.assert(!res.isSuccess);
        System.assert(res.message.contains('1 records were left masked'), res.message);
        System.assert(res.message.contains('could not decrypt'), res.message);
        assertStillMasked(c.Id, log);
    }

    @IsTest
    static void testTamperedOrUnknownLogLinesLeaveRecordMasked() {
        FlowAES256TestData.useNewKey();
        Blob key = FlowAES256Util.getKey();
        List<Contact> contacts = FlowAES256TestData.insertContacts(3);
        contacts[0].Description = 'Email: not-a-valid-cipher-text';
        contacts[1].Description = 'Shoe_Size__c: ' + FlowAES256Util.encrypt(key, '9');
        contacts[2].Description = 'this line has no separator';
        for (Contact c : contacts) {
            c.Email = null;
            c.DoNotCall = true;
        }
        update contacts;

        FlowAES256DataUnmaskingAction.UnmaskResult res = FlowAES256TestData.unmask(contacts);

        System.assert(!res.isSuccess);
        System.assert(res.message.startsWith('ERROR: Unmasked 0 records. 3 records were left masked'), res.message);
        System.assert(res.message.contains('Shoe_Size__c does not exist'), res.message);
        System.assert(res.message.contains('unreadable log line'), res.message);
        for (Contact c : contacts) {
            assertStillMasked(c.Id, c.Description);
        }
    }

    @IsTest
    static void testWrongValueTypeInLogLeavesRecordMasked() {
        FlowAES256TestData.useNewKey();
        Blob key = FlowAES256Util.getKey();
        Lead l = FlowAES256TestData.insertLead();
        l.Description = 'NumberOfEmployees: ' + FlowAES256Util.encrypt(key, 'two hundred');
        l.DoNotCall = true;
        update l;

        FlowAES256DataUnmaskingAction.UnmaskResult res = FlowAES256TestData.unmask(new List<SObject>{ l });

        System.assert(!res.isSuccess);
        System.assert(res.message.contains('could not restore NumberOfEmployees'), res.message);
        System.assertEquals(l.Description, FlowAES256TestData.requeryLead(l.Id).Description);
    }

    @IsTest
    static void testPartialFailureRestoresTheValidRecords() {
        FlowAES256TestData.useNewKey();
        List<Contact> contacts = FlowAES256TestData.insertContacts(2);
        FlowAES256TestData.mask(contacts, FlowAES256TestData.CONTACT_FIELDS);

        Contact tampered = new Contact(Id = contacts[1].Id, Description = 'Email: AAAA');
        update tampered;

        FlowAES256DataUnmaskingAction.UnmaskResult res = FlowAES256TestData.unmask(contacts);

        System.assert(!res.isSuccess);
        System.assert(res.message.startsWith('ERROR: Unmasked 1 records. 1 records were left masked'), res.message);
        System.assertEquals(FlowAES256TestData.EMAIL, FlowAES256TestData.requeryContact(contacts[0].Id).Email);
        assertStillMasked(contacts[1].Id, 'Email: AAAA');
    }

    @IsTest
    static void testBlankLogResetsStatusOnly() {
        FlowAES256TestData.useNewKey();
        Contact c = FlowAES256TestData.insertContacts(1)[0];
        c.Email = null;
        c.DoNotCall = true;
        update c;

        FlowAES256DataUnmaskingAction.UnmaskResult res = FlowAES256TestData.unmask(new List<SObject>{ c });

        System.assert(res.isSuccess, res.message);
        Contact updated = FlowAES256TestData.requeryContact(c.Id);
        System.assertEquals(false, updated.DoNotCall);
        System.assertEquals(null, updated.Email);
    }

    @IsTest
    static void testNothingToUnmask() {
        FlowAES256TestData.useNewKey();
        Contact c = FlowAES256TestData.insertContacts(1)[0];

        FlowAES256DataUnmaskingAction.UnmaskResult res = FlowAES256TestData.unmask(new List<SObject>{ c });
        FlowAES256DataUnmaskingAction.UnmaskResult empty = FlowAES256TestData.unmask(new List<SObject>());

        System.assert(!res.isSuccess);
        System.assertEquals('No valid encrypted logs found to decrypt.', res.message);
        System.assert(!empty.isSuccess);
        System.assertEquals('No records provided in the collection.', empty.message);
    }

    @IsTest
    static void testMissingKeyAndWrongStatusField() {
        Contact c = FlowAES256TestData.insertContacts(1)[0];

        FlowAES256Util.keyOverride = '';
        FlowAES256DataUnmaskingAction.UnmaskResult missingKey = FlowAES256TestData.unmask(new List<SObject>{ c });

        FlowAES256TestData.useNewKey();
        FlowAES256DataUnmaskingAction.UnmaskRequest req = new FlowAES256DataUnmaskingAction.UnmaskRequest();
        req.recordsToUnmask = new List<SObject>{ c };
        req.encryptedLogFieldName = FlowAES256TestData.LOG_FIELD;
        req.statusCheckboxFieldName = 'Email';
        FlowAES256DataUnmaskingAction.UnmaskResult wrongStatus = FlowAES256DataUnmaskingAction.processRecords(
            new List<FlowAES256DataUnmaskingAction.UnmaskRequest>{ req })[0];

        System.assert(!missingKey.isSuccess);
        System.assert(missingKey.message.contains('missing or blank'), missingKey.message);
        System.assert(!wrongStatus.isSuccess);
        System.assert(wrongStatus.message.contains('expected a checkbox'), wrongStatus.message);
    }

    @IsTest
    static void testBulkRoundTrip() {
        FlowAES256TestData.useNewKey();
        List<Contact> contacts = FlowAES256TestData.insertContacts(200);
        FlowAES256TestData.mask(contacts, FlowAES256TestData.CONTACT_FIELDS);

        Test.startTest();
        FlowAES256DataUnmaskingAction.UnmaskResult res = FlowAES256TestData.unmask(contacts);
        Test.stopTest();

        System.assert(res.isSuccess, res.message);
        System.assertEquals('SUCCESS: Unmasked 200 records.', res.message);
        System.assertEquals(200, [
            SELECT COUNT() FROM Contact
            WHERE DoNotCall = false AND Email = :FlowAES256TestData.EMAIL AND MailingPostalCode = :FlowAES256TestData.POSTCODE
        ]);
    }

    private static void assertStillMasked(Id contactId, String expectedLog) {
        Contact c = FlowAES256TestData.requeryContact(contactId);
        System.assertEquals(expectedLog, c.Description, 'Log must be kept so the data can still be recovered');
        System.assertEquals(true, c.DoNotCall);
        System.assertEquals(null, c.Email);
    }
}
