@IsTest
private class FlowAES256ValueActionsTest {

    private static FlowAES256EncryptValueAction.EncryptResult encrypt(String plainText, List<String> plainTexts, String keyName) {
        FlowAES256EncryptValueAction.EncryptRequest req = new FlowAES256EncryptValueAction.EncryptRequest();
        req.plainText = plainText;
        req.plainTexts = plainTexts;
        req.keyName = keyName;
        return FlowAES256EncryptValueAction.encrypt(new List<FlowAES256EncryptValueAction.EncryptRequest>{ req })[0];
    }

    private static FlowAES256DecryptValueAction.DecryptResult decrypt(String encryptedText, List<String> encryptedTexts, String keyName) {
        FlowAES256DecryptValueAction.DecryptRequest req = new FlowAES256DecryptValueAction.DecryptRequest();
        req.encryptedText = encryptedText;
        req.encryptedTexts = encryptedTexts;
        req.keyName = keyName;
        return FlowAES256DecryptValueAction.decrypt(new List<FlowAES256DecryptValueAction.DecryptRequest>{ req })[0];
    }

    @IsTest
    static void testSingleValueRoundTrip() {
        FlowAES256TestData.useNewKey();

        FlowAES256EncryptValueAction.EncryptResult encrypted = encrypt('SW1A 1AA', null, null);
        System.assert(encrypted.isSuccess, encrypted.message);
        System.assertNotEquals('SW1A 1AA', encrypted.encryptedText);
        System.assertEquals(null, encrypted.encryptedTexts);

        FlowAES256DecryptValueAction.DecryptResult decrypted = decrypt(encrypted.encryptedText, null, null);
        System.assert(decrypted.isSuccess, decrypted.message);
        System.assertEquals('SW1A 1AA', decrypted.plainText);
    }

    @IsTest
    static void testCollectionRoundTripKeepsOrderAndBlanks() {
        FlowAES256TestData.useNewKey('Screen_Key');
        List<String> values = new List<String>{ '01234', '', null, 'Zoë 東京', '1234567.89' };

        FlowAES256EncryptValueAction.EncryptResult encrypted = encrypt(null, values, 'Screen_Key');
        System.assert(encrypted.isSuccess, encrypted.message);
        System.assertEquals(null, encrypted.encryptedText);
        System.assertEquals(5, encrypted.encryptedTexts.size());
        System.assertEquals(null, encrypted.encryptedTexts[1], 'Blank values stay blank');
        System.assertEquals(null, encrypted.encryptedTexts[2]);

        FlowAES256DecryptValueAction.DecryptResult decrypted = decrypt(null, encrypted.encryptedTexts, 'Screen_Key');
        System.assert(decrypted.isSuccess, decrypted.message);
        System.assertEquals(new List<String>{ '01234', null, null, 'Zoë 東京', '1234567.89' }, decrypted.plainTexts);
    }

    @IsTest
    static void testBadValueIsReportedWithoutStoppingOthers() {
        FlowAES256TestData.useNewKey();
        String good = encrypt('alpha', null, null).encryptedText;

        FlowAES256DecryptValueAction.DecryptResult res = decrypt(null, new List<String>{ good, 'AAAA', good }, null);

        System.assert(!res.isSuccess);
        System.assert(res.message.contains('item 2'), res.message);
        System.assertEquals(new List<String>{ 'alpha', null, 'alpha' }, res.plainTexts);
    }

    @IsTest
    static void testWrongOrMissingKey() {
        FlowAES256TestData.useNewKey();
        FlowAES256TestData.useNewKey('Other_Key');
        String cipher = encrypt('secret', null, null).encryptedText;

        FlowAES256DecryptValueAction.DecryptResult wrongKey = decrypt(cipher, null, 'Other_Key');
        System.assert(!wrongKey.isSuccess);
        System.assertEquals(null, wrongKey.plainText);

        FlowAES256EncryptValueAction.EncryptResult missingKey = encrypt('secret', null, 'No_Such_Key');
        System.assert(!missingKey.isSuccess);
        System.assert(missingKey.message.contains('(No_Such_Key) missing or blank'), missingKey.message);
        System.assertEquals(null, missingKey.encryptedText);
    }

    @IsTest
    static void testBulkRequestsUseNoQueriesOrDml() {
        FlowAES256TestData.useNewKey();
        List<FlowAES256EncryptValueAction.EncryptRequest> requests = new List<FlowAES256EncryptValueAction.EncryptRequest>();
        for (Integer i = 0; i < 200; i++) {
            FlowAES256EncryptValueAction.EncryptRequest req = new FlowAES256EncryptValueAction.EncryptRequest();
            req.plainText = 'value ' + i;
            requests.add(req);
        }

        Test.startTest();
        List<FlowAES256EncryptValueAction.EncryptResult> results = FlowAES256EncryptValueAction.encrypt(requests);
        System.assertEquals(0, Limits.getQueries());
        System.assertEquals(0, Limits.getDmlStatements());
        Test.stopTest();

        System.assertEquals(200, results.size());
        for (FlowAES256EncryptValueAction.EncryptResult res : results) {
            System.assert(res.isSuccess, res.message);
        }
    }
}
