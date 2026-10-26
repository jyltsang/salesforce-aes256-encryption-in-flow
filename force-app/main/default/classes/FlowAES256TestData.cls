/**
 * Test fixtures for the AES256 Flow actions. Uses only standard fields so the tests run in any org:
 * Description stands in for the encrypted log field and DoNotCall for the status checkbox.
 */
@IsTest
public class FlowAES256TestData {

    public static final String LOG_FIELD = 'Description';
    public static final String STATUS_FIELD = 'DoNotCall';

    public static final String STREET = '12 St James\'s Square\nFlat 3';
    public static final String POSTCODE = 'SW1Y 4JH';
    public static final String EMAIL = 'ada@example.com';
    public static final Date BIRTHDATE = Date.newInstance(1815, 12, 10);

    public static final List<String> CONTACT_FIELDS = new List<String>{
        'MailingAddress', 'Email', 'Birthdate', 'LastName', 'HasOptedOutOfEmail', 'Phone'
    };

    public static String useNewKey() {
        String encodedKey = EncodingUtil.base64Encode(Crypto.generateAesKey(256));
        FlowAES256Util.keyOverride = encodedKey;
        return encodedKey;
    }

    public static List<Contact> insertContacts(Integer count) {
        List<Contact> contacts = new List<Contact>();
        for (Integer i = 0; i < count; i++) {
            contacts.add(new Contact(
                FirstName = 'Ada',
                LastName = 'Lovelace ' + i,
                Email = EMAIL,
                Phone = '+44 20 7946 0000',
                Birthdate = BIRTHDATE,
                MailingStreet = STREET,
                MailingCity = 'London',
                MailingPostalCode = POSTCODE,
                HasOptedOutOfEmail = true
            ));
        }
        insert contacts;
        return contacts;
    }

    public static Lead insertLead() {
        Lead l = new Lead(
            LastName = 'Turing',
            Company = 'Bletchley Ltd',
            NumberOfEmployees = 250,
            AnnualRevenue = 1234567.89,
            PostalCode = '01234',
            Email = 'alan@example.com'
        );
        insert l;
        return l;
    }

    public static Contact requeryContact(Id contactId) {
        return [
            SELECT LastName, Email, Phone, Birthdate, MailingStreet, MailingCity, MailingPostalCode,
                   HasOptedOutOfEmail, Description, DoNotCall
            FROM Contact WHERE Id = :contactId
        ];
    }

    public static Lead requeryLead(Id leadId) {
        return [
            SELECT NumberOfEmployees, AnnualRevenue, PostalCode, Email, Status, Description, DoNotCall
            FROM Lead WHERE Id = :leadId
        ];
    }

    public static FlowAES256DataMaskingAction.MaskResult mask(List<SObject> records, List<String> fieldNames) {
        FlowAES256DataMaskingAction.MaskRequest req = new FlowAES256DataMaskingAction.MaskRequest();
        req.recordsToMask = records;
        req.fieldNamesCollection = fieldNames;
        req.encryptedLogFieldName = LOG_FIELD;
        req.statusCheckboxFieldName = STATUS_FIELD;
        return FlowAES256DataMaskingAction.processRecords(new List<FlowAES256DataMaskingAction.MaskRequest>{ req })[0];
    }

    public static FlowAES256DataUnmaskingAction.UnmaskResult unmask(List<SObject> records) {
        FlowAES256DataUnmaskingAction.UnmaskRequest req = new FlowAES256DataUnmaskingAction.UnmaskRequest();
        req.recordsToUnmask = records;
        req.encryptedLogFieldName = LOG_FIELD;
        req.statusCheckboxFieldName = STATUS_FIELD;
        return FlowAES256DataUnmaskingAction.processRecords(new List<FlowAES256DataUnmaskingAction.UnmaskRequest>{ req })[0];
    }
}
