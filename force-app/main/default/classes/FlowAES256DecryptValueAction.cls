/**
 * Decrypts Base64 cipher text produced by FlowAES256EncryptValueAction (or found in a masking log)
 * back into text, for use anywhere in a Flow.
 */
public with sharing class FlowAES256DecryptValueAction {

    public class DecryptRequest {
        @InvocableVariable(label='Text to Decrypt' description='Optional. A single Base64 cipher text to decrypt.')
        public String encryptedText;

        @InvocableVariable(label='Texts to Decrypt' description='Optional. A collection of Base64 cipher texts to decrypt, returned in the same order.')
        public List<String> encryptedTexts;

        @InvocableVariable(label='Key Name' description='Optional. Name of the Symmetric Key Config record the values were encrypted with. Defaults to Default_Key.')
        public String keyName;
    }

    public class DecryptResult {
        @InvocableVariable(label='Success Flag')
        public Boolean isSuccess;

        @InvocableVariable(label='Message')
        public String message;

        @InvocableVariable(label='Decrypted Text' description='Plain text of Text to Decrypt; blank when the input is blank or cannot be decrypted')
        public String plainText;

        @InvocableVariable(label='Decrypted Texts' description='Plain texts of Texts to Decrypt, in the same order; blank where a value cannot be decrypted')
        public List<String> plainTexts;
    }

    @InvocableMethod(label='AES256 Decrypt Text' description='Decrypts Base64 cipher text using a Custom Metadata AES key.')
    public static List<DecryptResult> decrypt(List<DecryptRequest> requests) {
        List<DecryptResult> results = new List<DecryptResult>();

        for (DecryptRequest req : requests) {
            DecryptResult res = new DecryptResult();
            try {
                Blob key = FlowAES256Util.getKey(req.keyName);
                List<String> problems = new List<String>();

                res.plainText = decryptOne(key, req.encryptedText, 'Text to Decrypt', problems);
                if (req.encryptedTexts != null) {
                    res.plainTexts = new List<String>();
                    for (Integer i = 0; i < req.encryptedTexts.size(); i++) {
                        res.plainTexts.add(decryptOne(key, req.encryptedTexts[i], 'item ' + (i + 1), problems));
                    }
                }

                res.isSuccess = problems.isEmpty();
                res.message = problems.isEmpty()
                    ? 'SUCCESS: Decrypted with key ' + FlowAES256Util.resolveKeyName(req.keyName) + '.'
                    : 'ERROR: Could not decrypt ' + String.join(problems, ', ')
                        + '; the value may have been altered or encrypted with another key.';
            } catch (Exception e) {
                res.isSuccess = false;
                res.message = 'ERROR: ' + e.getMessage();
            }
            results.add(res);
        }
        return results;
    }

    // One bad value does not stop the rest; it comes back blank and is named in the message
    private static String decryptOne(Blob key, String encryptedText, String label, List<String> problems) {
        if (String.isBlank(encryptedText)) return null;
        try {
            return FlowAES256Util.decrypt(key, encryptedText.trim());
        } catch (Exception e) {
            problems.add(label);
            return null;
        }
    }
}
