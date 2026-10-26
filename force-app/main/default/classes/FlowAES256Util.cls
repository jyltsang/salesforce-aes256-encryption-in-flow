/**
 * Shared helpers for FlowAES256DataMaskingAction and FlowAES256DataUnmaskingAction:
 * key retrieval, encryption, field validation and type-safe conversion of field values
 * to and from the plain text that is encrypted into the audit log.
 */
public inherited sharing class FlowAES256Util {

    public class AES256Exception extends Exception {}

    public static final String KEY_RECORD_NAME = 'Default_Key';
    public static final String LOG_SEPARATOR = ': ';
    public static final String MASK_PLACEHOLDER = '*****';

    private static final String ALGORITHM = 'AES256';
    private static final Integer KEY_BYTES = 32;
    private static final String ISO_DATETIME_FORMAT = 'yyyy-MM-dd\'T\'HH:mm:ss.SSS\'Z\'';

    // Field types that can hold the placeholder when a required field cannot be blanked
    private static final Set<Schema.DisplayType> TEXT_TYPES = new Set<Schema.DisplayType>{
        Schema.DisplayType.STRING,
        Schema.DisplayType.TEXTAREA,
        Schema.DisplayType.PHONE,
        Schema.DisplayType.URL,
        Schema.DisplayType.ENCRYPTEDSTRING
    };

    // Compound or binary field types that cannot be written back from a single text value
    private static final Set<Schema.DisplayType> UNSUPPORTED_TYPES = new Set<Schema.DisplayType>{
        Schema.DisplayType.ADDRESS,
        Schema.DisplayType.LOCATION,
        Schema.DisplayType.BASE64
    };

    public static final Set<Schema.DisplayType> LOG_FIELD_TYPES = new Set<Schema.DisplayType>{
        Schema.DisplayType.STRING,
        Schema.DisplayType.TEXTAREA
    };

    public static final Set<Schema.DisplayType> STATUS_FIELD_TYPES = new Set<Schema.DisplayType>{
        Schema.DisplayType.BOOLEAN
    };

    // Lets unit tests supply a key, as Custom Metadata records cannot be inserted in tests
    @TestVisible
    private static String keyOverride;

    public static Blob getKey() {
        String encodedKey;
        if (keyOverride != null) {
            encodedKey = keyOverride;
        } else {
            Symmetric_Key_Config__mdt config = Symmetric_Key_Config__mdt.getInstance(KEY_RECORD_NAME);
            encodedKey = config?.AES_Key__c;
        }

        if (String.isBlank(encodedKey)) {
            throw new AES256Exception('Symmetric Key Custom Metadata record (' + KEY_RECORD_NAME + ') missing or blank.');
        }

        Blob key;
        try {
            key = EncodingUtil.base64Decode(encodedKey.trim());
        } catch (Exception e) {
            throw new AES256Exception('AES key in ' + KEY_RECORD_NAME + ' is not valid Base64.');
        }
        if (key == null || key.size() != KEY_BYTES) {
            throw new AES256Exception('AES key in ' + KEY_RECORD_NAME + ' must decode to exactly ' + KEY_BYTES
                + ' bytes. Generate one with: openssl rand -base64 32');
        }
        return key;
    }

    public static String encrypt(Blob key, String plainText) {
        return EncodingUtil.base64Encode(Crypto.encryptWithManagedIV(ALGORITHM, key, Blob.valueOf(plainText)));
    }

    public static String decrypt(Blob key, String base64CipherText) {
        return Crypto.decryptWithManagedIV(ALGORITHM, key, EncodingUtil.base64Decode(base64CipherText)).toString();
    }

    public static Schema.DescribeFieldResult describeField(Map<String, Schema.SObjectField> fieldMap, String fieldName) {
        if (String.isBlank(fieldName)) return null;
        Schema.SObjectField field = fieldMap.get(fieldName.trim().toLowerCase());
        return field == null ? null : field.getDescribe();
    }

    // Describes the log or status field, throwing a readable error if it is missing, read-only or the wrong type
    public static Schema.DescribeFieldResult requireField(
        Map<String, Schema.SObjectField> fieldMap,
        String fieldName,
        String objectName,
        String role,
        Set<Schema.DisplayType> allowedTypes,
        String expectedType
    ) {
        Schema.DescribeFieldResult field = describeField(fieldMap, fieldName);
        if (field == null) {
            throw new AES256Exception(role + ' "' + fieldName + '" does not exist on ' + objectName + '.');
        }
        if (!allowedTypes.contains(field.getType())) {
            throw new AES256Exception(role + ' ' + field.getName() + ' is a ' + field.getType()
                + ' field; expected ' + expectedType + '.');
        }
        if (!field.isUpdateable()) {
            throw new AES256Exception(role + ' ' + field.getName() + ' is not editable by the running user.');
        }
        return field;
    }

    public static Boolean isSupportedType(Schema.DisplayType fieldType) {
        return !UNSUPPORTED_TYPES.contains(fieldType);
    }

    // A field can be masked when it can be blanked, or when it is text and can hold the placeholder
    public static Boolean canMask(Schema.DescribeFieldResult field) {
        return field.getType() == Schema.DisplayType.BOOLEAN
            || field.isNillable()
            || TEXT_TYPES.contains(field.getType());
    }

    public static Object maskValueFor(Schema.DescribeFieldResult field) {
        if (field.getType() == Schema.DisplayType.BOOLEAN) return false;
        if (field.isNillable()) return null;
        if (TEXT_TYPES.contains(field.getType())) return MASK_PLACEHOLDER.left(Math.max(field.getLength(), 1));
        throw new AES256Exception(field.getName() + ' is required and cannot be masked.');
    }

    // Converts a field value into a stable text form that toFieldValue can turn back into the same value
    public static String toText(Object value, Schema.DisplayType fieldType) {
        if (value == null) return null;
        if (fieldType == Schema.DisplayType.DATETIME) {
            return ((Datetime) value).formatGmt(ISO_DATETIME_FORMAT);
        }
        if (fieldType == Schema.DisplayType.DATE) {
            Date d = (Date) value;
            return Datetime.newInstanceGmt(d.year(), d.month(), d.day()).formatGmt('yyyy-MM-dd');
        }
        if (fieldType == Schema.DisplayType.DOUBLE
            || fieldType == Schema.DisplayType.CURRENCY
            || fieldType == Schema.DisplayType.PERCENT) {
            return Decimal.valueOf(String.valueOf(value)).toPlainString();
        }
        return String.valueOf(value);
    }

    // Converts decrypted text back into the Apex type the field expects, so SObject.put does not fail
    public static Object toFieldValue(String text, Schema.DisplayType fieldType) {
        if (text == null) return null;
        String value = text.trim();
        if (fieldType == Schema.DisplayType.INTEGER) return Integer.valueOf(value);
        if (fieldType == Schema.DisplayType.LONG) return Long.valueOf(value);
        if (fieldType == Schema.DisplayType.DOUBLE
            || fieldType == Schema.DisplayType.CURRENCY
            || fieldType == Schema.DisplayType.PERCENT) {
            return Decimal.valueOf(value);
        }
        // left(10) also accepts the 'yyyy-MM-dd 00:00:00' form written by earlier versions
        if (fieldType == Schema.DisplayType.DATE) return Date.valueOf(value.left(10));
        if (fieldType == Schema.DisplayType.DATETIME) return parseDatetime(value);
        if (fieldType == Schema.DisplayType.TIME) return parseTime(value);
        if (fieldType == Schema.DisplayType.BOOLEAN) return Boolean.valueOf(value);
        if (fieldType == Schema.DisplayType.ID || fieldType == Schema.DisplayType.REFERENCE) return Id.valueOf(value);
        // Text keeps its original whitespace
        return text;
    }

    private static Datetime parseDatetime(String value) {
        if (value.contains('T')) {
            return (Datetime) JSON.deserialize('"' + value + '"', Datetime.class);
        }
        // 'yyyy-MM-dd HH:mm:ss' in the running user's time zone, as written by earlier versions
        return Datetime.valueOf(value);
    }

    // Parses 'HH:mm', 'HH:mm:ss' or 'HH:mm:ss.SSS', with or without a trailing 'Z'
    private static Time parseTime(String value) {
        List<String> parts = value.removeEnd('Z').split(':');
        Integer seconds = 0;
        Integer milliseconds = 0;
        if (parts.size() > 2) {
            List<String> secondParts = parts[2].split('\\.');
            seconds = Integer.valueOf(secondParts[0]);
            if (secondParts.size() > 1) milliseconds = Integer.valueOf(secondParts[1]);
        }
        return Time.newInstance(Integer.valueOf(parts[0]), Integer.valueOf(parts[1]), seconds, milliseconds);
    }

    // Splits the log into lines, tolerating the HTML a Rich Text Area adds around plain text
    public static List<String> splitLogLines(String log) {
        List<String> lines = new List<String>();
        if (String.isBlank(log)) return lines;

        String text = log;
        if (text.contains('<')) {
            text = text.replaceAll('(?i)<br\\s*/?>|</p>|</div>', '\n').replaceAll('<[^>]*>', '');
        }
        text = text.unescapeHtml4();

        for (String line : text.split('\r?\n')) {
            if (String.isNotBlank(line)) lines.add(line.trim());
        }
        return lines;
    }
}
