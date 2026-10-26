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
        System.assertEquals(1, res.processedCount);
        System.assertEquals(0, res.failedCount);

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
    static void testLogStillDecryptsAfterDefaultKeyIsRotated() {
        FlowAES256TestData.useNewKey();
        FlowAES256TestData.useNewKey('Key_2025');
        Contact c = FlowAES256TestData.insertContacts(1)[0];

        FlowAES256DataMaskingAction.MaskRequest req = FlowAES256TestData.maskRequest(new List<SObject>{ c }, new List<String>{ 'Email' });
        req.keyName = 'Key_2025';
        FlowAES256TestData.mask(req);

        // A new default key does not matter: the log names the key it was written with
        FlowAES256TestData.useNewKey();
        FlowAES256DataUnmaskingAction.UnmaskResult res = FlowAES256TestData.unmask(new List<SObject>{ c });

        System.assert(res.isSuccess, res.message);
        System.assertEquals(FlowAES256TestData.EMAIL, FlowAES256TestData.requeryContact(c.Id).Email);
    }

    @IsTest
    static void testLegacyLogWithoutHeaderUsesKeyNameInput() {
        FlowAES256TestData.useNewKey();
        FlowAES256TestData.useNewKey('Legacy_Key');
        Lead l = FlowAES256TestData.insertLead();

        // Logs written before key names were recorded have no '#key' line
        l.Description = 'PostalCode: ' + FlowAES256Util.encrypt(FlowAES256Util.getKey('Legacy_Key'), 'EC1A 1BB');
        l.PostalCode = null;
        l.DoNotCall = true;
        update l;

        FlowAES256DataUnmaskingAction.UnmaskResult withDefault = FlowAES256TestData.unmask(new List<SObject>{ l });
        System.assert(!withDefault.isSuccess, 'Default_Key cannot decrypt it');
        System.assert(withDefault.message.contains('with key Default_Key'), withDefault.message);

        FlowAES256DataUnmaskingAction.UnmaskRequest req = FlowAES256TestData.unmaskRequest(new List<SObject>{ l });
        req.keyName = 'Legacy_Key';
        FlowAES256DataUnmaskingAction.UnmaskResult withLegacy = FlowAES256TestData.unmask(req);

        System.assert(withLegacy.isSuccess, withLegacy.message);
        System.assertEquals('EC1A 1BB', FlowAES256TestData.requeryLead(l.Id).PostalCode);
    }

    @IsTest
    static void testRestoresLogStoredInRichTextFormat() {
        FlowAES256TestData.useNewKey();
        Blob key = FlowAES256Util.getKey();
        Lead l = FlowAES256TestData.insertLead();

        // A Rich Text Area may wrap each line in HTML
        l.Description = '<p>#key: Default_Key</p><p>NumberOfEmployees: ' + FlowAES256Util.encrypt(key, '42') + '</p>'
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
        System.assert(res.message.contains('could not decrypt'), res.message);
        System.assertEquals(new List<String>{ c.Id }, res.failedRecordIds);
        assertStillMasked(c.Id, log);
    }

    @IsTest
    static void testTamperedOrUnknownLogLinesLeaveRecordsMasked() {
        FlowAES256TestData.useNewKey();
        Blob key = FlowAES256Util.getKey();
        List<Contact> contacts = FlowAES256TestData.insertContacts(4);
        contacts[0].Description = 'Email: not-a-valid-cipher-text';
        contacts[1].Description = 'Shoe_Size__c: ' + FlowAES256Util.encrypt(key, '9');
        contacts[2].Description = 'this line has no separator';
        contacts[3].Description = '#key: Missing_Key\nEmail: ' + FlowAES256Util.encrypt(key, 'x@example.com');
        for (Contact c : contacts) {
            c.Email = null;
            c.DoNotCall = true;
        }
        update contacts;

        FlowAES256DataUnmaskingAction.UnmaskRequest req = FlowAES256TestData.unmaskRequest(contacts);
        req.allOrNone = false;
        FlowAES256DataUnmaskingAction.UnmaskResult res = FlowAES256TestData.unmask(req);

        System.assert(!res.isSuccess);
        System.assertEquals(4, res.failedCount);
        System.assertEquals(0, res.processedCount);
        System.assert(res.message.contains('could not decrypt Email'), res.message);
        System.assert(res.message.contains('Shoe_Size__c does not exist'), res.message);
        System.assert(res.message.contains('unreadable log line'), res.message);
        System.assert(res.message.contains('(Missing_Key) missing or blank'), res.message);
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
    static void testAllOrNoneControlsPartialFailure() {
        FlowAES256TestData.useNewKey();
        List<Contact> contacts = FlowAES256TestData.insertContacts(2);
        FlowAES256TestData.mask(contacts, FlowAES256TestData.CONTACT_FIELDS);
        String goodLog = FlowAES256TestData.requeryContact(contacts[0].Id).Description;
        update new Contact(Id = contacts[1].Id, Description = 'Email: AAAA');

        // Default: one bad record means nothing is restored
        FlowAES256DataUnmaskingAction.UnmaskResult strict = FlowAES256TestData.unmask(contacts);
        System.assert(!strict.isSuccess);
        System.assert(strict.message.startsWith('ERROR: No records changed because 1 records failed'), strict.message);
        System.assertEquals(0, strict.processedCount);
        System.assertEquals(new List<String>{ contacts[1].Id }, strict.failedRecordIds);
        assertStillMasked(contacts[0].Id, goodLog);

        // All or None off: the valid record is restored, the bad one is reported
        FlowAES256DataUnmaskingAction.UnmaskRequest req = FlowAES256TestData.unmaskRequest(contacts);
        req.allOrNone = false;
        FlowAES256DataUnmaskingAction.UnmaskResult lenient = FlowAES256TestData.unmask(req);

        System.assert(!lenient.isSuccess);
        System.assert(lenient.message.startsWith('ERROR: Unmasked 1 records. Failed 1 records'), lenient.message);
        System.assertEquals(1, lenient.processedCount);
        System.assertEquals(new List<String>{ contacts[1].Id }, lenient.failedRecordIds);
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
        System.assertEquals(1, res.skippedCount);
        System.assert(!empty.isSuccess);
        System.assertEquals('ERROR: No records provided in the collection.', empty.message);
    }

    @IsTest
    static void testMissingKeyAndWrongStatusField() {
        Contact c = FlowAES256TestData.insertContacts(1)[0];
        c.Description = 'Email: AAAA';
        c.DoNotCall = true;
        update c;

        FlowAES256Util.setTestKey(null, '');
        FlowAES256DataUnmaskingAction.UnmaskResult missingKey = FlowAES256TestData.unmask(new List<SObject>{ c });

        FlowAES256TestData.useNewKey();
        FlowAES256DataUnmaskingAction.UnmaskRequest req = FlowAES256TestData.unmaskRequest(new List<SObject>{ c });
        req.statusCheckboxFieldName = 'Email';
        FlowAES256DataUnmaskingAction.UnmaskResult wrongStatus = FlowAES256TestData.unmask(req);

        System.assert(!missingKey.isSuccess);
        System.assert(missingKey.message.contains('missing or blank'), missingKey.message);
        System.assert(!wrongStatus.isSuccess);
        System.assert(wrongStatus.message.contains('expected a checkbox'), wrongStatus.message);
        System.assertEquals(new List<String>{ c.Id }, wrongStatus.failedRecordIds);
    }

    private static void assertStillMasked(Id contactId, String expectedLog) {
        Contact c = FlowAES256TestData.requeryContact(contactId);
        System.assertEquals(expectedLog, c.Description, 'Log must be kept so the data can still be recovered');
        System.assertEquals(true, c.DoNotCall);
        System.assertEquals(null, c.Email);
    }
}
