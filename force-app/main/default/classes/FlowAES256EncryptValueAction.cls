/**
 * Encrypts text values with a Symmetric Key Config record, for use anywhere in a Flow
 * (screen inputs, other objects, outbound messages) without masking a record.
 */
public with sharing class FlowAES256EncryptValueAction {

    public class EncryptRequest {
        @InvocableVariable(label='Text to Encrypt' description='Optional. A single text value to encrypt.')
        public String plainText;

        @InvocableVariable(label='Texts to Encrypt' description='Optional. A collection of text values to encrypt, returned in the same order.')
        public List<String> plainTexts;

        @InvocableVariable(label='Key Name' description='Optional. Name of the Symmetric Key Config record to encrypt with. Defaults to Default_Key.')
        public String keyName;
    }

    public class EncryptResult {
        @InvocableVariable(label='Success Flag')
        public Boolean isSuccess;

        @InvocableVariable(label='Message')
        public String message;

        @InvocableVariable(label='Encrypted Text' description='Base64 cipher text of Text to Encrypt; blank when the input is blank')
        public String encryptedText;

        @InvocableVariable(label='Encrypted Texts' description='Base64 cipher texts of Texts to Encrypt, in the same order')
        public List<String> encryptedTexts;
    }

    @InvocableMethod(label='AES256 Encrypt Text' description='Encrypts text values using a Custom Metadata AES key and returns Base64 cipher text.')
    public static List<EncryptResult> encrypt(List<EncryptRequest> requests) {
        List<EncryptResult> results = new List<EncryptResult>();

        for (EncryptRequest req : requests) {
            EncryptResult res = new EncryptResult();
            try {
                Blob key = FlowAES256Util.getKey(req.keyName);
                res.encryptedText = encryptOne(key, req.plainText);
                if (req.plainTexts != null) {
                    res.encryptedTexts = new List<String>();
                    for (String plainText : req.plainTexts) {
                        res.encryptedTexts.add(encryptOne(key, plainText));
                    }
                }
                res.isSuccess = true;
                res.message = 'SUCCESS: Encrypted with key ' + FlowAES256Util.resolveKeyName(req.keyName) + '.';
            } catch (Exception e) {
                res.isSuccess = false;
                res.message = 'ERROR: ' + e.getMessage();
            }
            results.add(res);
        }
        return results;
    }

    // Empty values stay empty, so a blank Flow variable does not turn into cipher text
    private static String encryptOne(Blob key, String plainText) {
        return String.isEmpty(plainText) ? null : FlowAES256Util.encrypt(key, plainText);
    }
}
