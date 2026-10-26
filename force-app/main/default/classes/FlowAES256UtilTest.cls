@IsTest
private class FlowAES256UtilTest {

    private static Object roundTrip(Object value, Schema.DisplayType fieldType) {
        return FlowAES256Util.toFieldValue(FlowAES256Util.toText(value, fieldType), fieldType);
    }

    @IsTest
    static void testNumberValuesRoundTrip() {
        System.assertEquals(250, roundTrip(250, Schema.DisplayType.INTEGER));
        System.assertEquals(9876543210L, roundTrip(9876543210L, Schema.DisplayType.LONG));
        System.assertEquals(1234567.89, roundTrip(1234567.89, Schema.DisplayType.CURRENCY));
        System.assertEquals(45.5, roundTrip(45.5, Schema.DisplayType.PERCENT));
        System.assertEquals(-0.000125, roundTrip(-0.000125, Schema.DisplayType.DOUBLE));
        Decimal large = (Decimal) roundTrip(Double.valueOf('1.5E10'), Schema.DisplayType.DOUBLE);
        System.assert(large == 15000000000L, 'Got ' + large);
    }

    @IsTest
    static void testNumbersAreLoggedWithoutScientificNotation() {
        System.assertEquals('15000000000', FlowAES256Util.toText(Double.valueOf('1.5E10'), Schema.DisplayType.DOUBLE).substringBefore('.'));
        System.assertEquals('1234567.89', FlowAES256Util.toText(1234567.89, Schema.DisplayType.CURRENCY));
    }

    @IsTest
    static void testDateAndTimeValuesRoundTrip() {
        Date birthday = Date.newInstance(1815, 12, 10);
        Datetime meeting = Datetime.newInstanceGmt(2024, 3, 31, 23, 45, 12);
        Time lunch = Time.newInstance(12, 30, 15, 250);

        System.assertEquals('1815-12-10', FlowAES256Util.toText(birthday, Schema.DisplayType.DATE));
        System.assertEquals(birthday, roundTrip(birthday, Schema.DisplayType.DATE));
        System.assertEquals(meeting, roundTrip(meeting, Schema.DisplayType.DATETIME));
        System.assertEquals(lunch, roundTrip(lunch, Schema.DisplayType.TIME));
    }

    @IsTest
    static void testLegacyLogFormatsAreStillAccepted() {
        // Formats produced by String.valueOf in the original implementation
        System.assertEquals(Date.newInstance(2024, 1, 15), FlowAES256Util.toFieldValue('2024-01-15 00:00:00', Schema.DisplayType.DATE));
        System.assertEquals(Datetime.valueOf('2024-01-15 10:20:30'), FlowAES256Util.toFieldValue('2024-01-15 10:20:30', Schema.DisplayType.DATETIME));
        System.assertEquals(Time.newInstance(9, 5, 0, 0), FlowAES256Util.toFieldValue('09:05', Schema.DisplayType.TIME));
    }

    @IsTest
    static void testTextBooleanAndIdValuesRoundTrip() {
        String multiline = '  Flat 3\n12 St James\'s Square ';
        System.assertEquals(multiline, roundTrip(multiline, Schema.DisplayType.TEXTAREA), 'Text keeps its whitespace');
        System.assertEquals('Zoë 東京', roundTrip('Zoë 東京', Schema.DisplayType.STRING));
        System.assertEquals('SW1A 1AA', roundTrip('SW1A 1AA', Schema.DisplayType.STRING));
        System.assertEquals('01234', roundTrip('01234', Schema.DisplayType.STRING), 'Leading zeros in a postcode are kept');
        System.assertEquals(true, roundTrip(true, Schema.DisplayType.BOOLEAN));
        System.assertEquals(false, roundTrip(false, Schema.DisplayType.BOOLEAN));

        Id userId = UserInfo.getUserId();
        System.assertEquals(userId, roundTrip(userId, Schema.DisplayType.REFERENCE));
        System.assertEquals(null, FlowAES256Util.toText(null, Schema.DisplayType.CURRENCY));
        System.assertEquals(null, FlowAES256Util.toFieldValue(null, Schema.DisplayType.CURRENCY));
    }

    @IsTest
    static void testEncryptDecryptRoundTrip() {
        Blob key = Crypto.generateAesKey(256);
        String cipherText = FlowAES256Util.encrypt(key, 'SW1A 1AA');

        System.assertNotEquals('SW1A 1AA', cipherText);
        System.assertEquals('SW1A 1AA', FlowAES256Util.decrypt(key, cipherText));
        System.assertNotEquals(cipherText, FlowAES256Util.encrypt(key, 'SW1A 1AA'), 'A fresh IV is used each time');
    }

    @IsTest
    static void testDecryptWithWrongKeyFails() {
        String cipherText = FlowAES256Util.encrypt(Crypto.generateAesKey(256), 'secret');
        Boolean failed = false;
        try {
            String plain = FlowAES256Util.decrypt(Crypto.generateAesKey(256), cipherText);
            failed = plain != 'secret';
        } catch (Exception e) {
            failed = true;
        }
        System.assert(failed, 'Decrypting with another key must not return the original value');
    }

    @IsTest
    static void testGetKeyValidatesKey() {
        Blob key = Crypto.generateAesKey(256);
        FlowAES256Util.setTestKey(null, ' ' + EncodingUtil.base64Encode(key) + ' ');
        System.assertEquals(EncodingUtil.base64Encode(key), EncodingUtil.base64Encode(FlowAES256Util.getKey()));
        System.assertEquals(EncodingUtil.base64Encode(key), EncodingUtil.base64Encode(FlowAES256Util.getKey('  ')),
            'A blank key name means Default_Key');

        assertKeyRejected('', 'missing or blank');
        assertKeyRejected(EncodingUtil.base64Encode(Crypto.generateAesKey(128)), '32 bytes');
    }

    @IsTest
    static void testNamedKeysAreSeparateAndCached() {
        String defaultKey = FlowAES256TestData.useNewKey();
        String regionKey = FlowAES256TestData.useNewKey('EU_Key');

        System.assertEquals(defaultKey, EncodingUtil.base64Encode(FlowAES256Util.getKey()));
        System.assertEquals(regionKey, EncodingUtil.base64Encode(FlowAES256Util.getKey(' EU_Key ')));

        try {
            FlowAES256Util.getKey('Unknown_Key');
            System.assert(false, 'Expected an unknown key name to be rejected');
        } catch (FlowAES256Util.AES256Exception e) {
            System.assert(e.getMessage().contains('(Unknown_Key) missing or blank'), e.getMessage());
        }

        Integer queriesBefore = Limits.getQueries();
        for (Integer i = 0; i < 200; i++) {
            FlowAES256Util.getKey('EU_Key');
        }
        System.assertEquals(queriesBefore, Limits.getQueries(), 'Key look-ups must not use SOQL');
    }

    @IsTest
    static void testLogHeaderNamesTheKey() {
        String log = FlowAES256Util.buildLog(null, new List<String>{ 'Email: abc' });
        List<String> lines = FlowAES256Util.splitLogLines(log);

        System.assertEquals('#key: Default_Key\nEmail: abc', log);
        System.assertEquals('Default_Key', FlowAES256Util.readKeyName(lines));
        System.assertEquals('EU_Key', FlowAES256Util.readKeyName(FlowAES256Util.splitLogLines(FlowAES256Util.buildLog('EU_Key', new List<String>()))));
        System.assertEquals(null, FlowAES256Util.readKeyName(new List<String>{ 'Email: abc' }), 'Logs from earlier versions have no header');
        System.assertEquals(null, FlowAES256Util.readKeyName(new List<String>()));
    }

    @IsTest
    static void testCustomPlaceholderIsCutToFieldLength() {
        Schema.DescribeFieldResult lastName = Contact.LastName.getDescribe();
        System.assertEquals('REDACTED', FlowAES256Util.maskValueFor(lastName, 'REDACTED'));
        System.assertEquals(FlowAES256Util.MASK_PLACEHOLDER, FlowAES256Util.maskValueFor(lastName, ' '));
        System.assertEquals(lastName.getLength(), ((String) FlowAES256Util.maskValueFor(lastName, 'x'.repeat(500))).length());
        System.assertEquals(null, FlowAES256Util.maskValueFor(Contact.Email.getDescribe(), 'REDACTED'), 'Optional fields are still blanked');
    }

    private static void assertKeyRejected(String encodedKey, String expectedMessage) {
        FlowAES256Util.setTestKey(null, encodedKey);
        try {
            FlowAES256Util.getKey();
            System.assert(false, 'Expected key "' + encodedKey + '" to be rejected');
        } catch (FlowAES256Util.AES256Exception e) {
            System.assert(e.getMessage().contains(expectedMessage), e.getMessage());
        }
    }

    @IsTest
    static void testSplitLogLinesHandlesPlainAndRichText() {
        System.assertEquals(new List<String>{ 'A: x', 'B: y' }, FlowAES256Util.splitLogLines('A: x\nB: y'));
        System.assertEquals(new List<String>{ 'A: x', 'B: y' }, FlowAES256Util.splitLogLines('A: x\r\n\r\nB: y\n'));
        System.assertEquals(new List<String>{ 'A: x', 'B: y' }, FlowAES256Util.splitLogLines('<p>A: x</p><p>B: y</p>'));
        System.assertEquals(new List<String>{ 'A: x+/=', 'B: y' }, FlowAES256Util.splitLogLines('A: x&#43;&#x2F;&#61;<br>B: y<br/>'));
        System.assertEquals(0, FlowAES256Util.splitLogLines(null).size());
    }

    @IsTest
    static void testMaskValueDependsOnFieldDefinition() {
        Schema.DescribeFieldResult lastName = Contact.LastName.getDescribe();
        Schema.DescribeFieldResult email = Contact.Email.getDescribe();
        Schema.DescribeFieldResult optOut = Contact.HasOptedOutOfEmail.getDescribe();
        Schema.DescribeFieldResult leadStatus = Lead.Status.getDescribe();

        System.assertEquals(FlowAES256Util.MASK_PLACEHOLDER, FlowAES256Util.maskValueFor(lastName), 'Required text gets the placeholder');
        System.assertEquals(null, FlowAES256Util.maskValueFor(email), 'Optional fields are blanked');
        System.assertEquals(false, FlowAES256Util.maskValueFor(optOut), 'Checkboxes cannot be null');
        System.assert(!FlowAES256Util.canMask(leadStatus), 'A required picklist cannot be blanked');
        System.assert(!FlowAES256Util.isSupportedType(Schema.DisplayType.ADDRESS));
    }

    @IsTest
    static void testRequireFieldRejectsMissingAndWrongTypes() {
        Map<String, Schema.SObjectField> fieldMap = Schema.SObjectType.Contact.fields.getMap();

        System.assertEquals('Description', FlowAES256Util.requireField(
            fieldMap, ' description ', 'Contact', 'Log field', FlowAES256Util.LOG_FIELD_TYPES, 'a text area field').getName());

        try {
            FlowAES256Util.requireField(fieldMap, 'Shoe_Size__c', 'Contact', 'Log field', FlowAES256Util.LOG_FIELD_TYPES, 'a text area field');
            System.assert(false, 'Expected a missing field to be rejected');
        } catch (FlowAES256Util.AES256Exception e) {
            System.assert(e.getMessage().contains('does not exist'), e.getMessage());
        }

        try {
            FlowAES256Util.requireField(fieldMap, 'Email', 'Contact', 'Checkbox field', FlowAES256Util.STATUS_FIELD_TYPES, 'a checkbox');
            System.assert(false, 'Expected a non-checkbox status field to be rejected');
        } catch (FlowAES256Util.AES256Exception e) {
            System.assert(e.getMessage().contains('expected a checkbox'), e.getMessage());
        }
    }
}
