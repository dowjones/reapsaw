BugBar is designed to normalize vulnerabilities across all the tools to the single format:
* `Vulnerabilities name`,
* `Risk Rating`,
* `Priority`,
* `Description`,
* `Recommendation`

# Bug Bar structure
Please find BugBar sample by the link [Reapsaw](https://github.com/dowjones/sast/blob/develop/bugbar/bugbar.json)

> Bug Bar is configurable

<details><summary>JSON report</summary>
<p>

```json
{
  "Cross-Site Request Forgery (CSRF)": {
    "is_issue": "",
    "risk_rating": "Medium",
    "jira_priority": "Major",
    "grouped": "",
    "description": {},
    "recommendation": {},
    "cxsast": "XSRF"
  },
  "SQL Injection": {
    "is_issue": "",
    "risk_rating": "Critical",
    "jira_priority": "Major",
    "grouped": "",
    "description": {},
    "recommendation": {},
    "cxsast": "SQL Injection in Content Provider;SQL_Injection"
  },
  "Sensitive Information Disclosure": {
    "is_issue": "",
    "risk_rating": "High",
    "jira_priority": "Major",
    "grouped": "",
    "description": {},
    "recommendation": {},
    "cxsast": "Sensitive Information Disclosure;Client_Password_In_Comment;Client_Password_Weak_Encryption;CPP_Insecure_Credential_Storage;HardcodedCredentials;Hardcoded_Connection_String;Hardcoded_Password;Hardcoded_password_in_Connection_String;Hardcoded_Password_In_Gradle;Hardcoded_Session_Secret_Token;Hard_Coded_Cryptography_Key;Insufficiently_Protected_Credentials;Kony_Hardcoded_EncryptionKey;Missing_Password_Field_Masking;Password_In_Comment;Password_in_Configuration_File;Password_misuse;Plaintext_Storage_of_a_Password;Storing_Passwords_in_a_Recoverable_Format;Use_of_Hardcoded_Cryptographic_Key;Use_Of_Hardcoded_Password;Use_of_Hardcoded_Password;Use_of_Hard_coded_Cryptographic_Key;Use_of_Hard_coded_Security_Constants"
  },
  "Vulnerable Software": {
    "is_issue": "",
    "risk_rating": "High",
    "jira_priority": "Major",
    "grouped": "",
    "description": {},
    "recommendation": {},
    "cxsast": "Obsolete WordPress version;Client_Use_Of_JQuery_Outdated_Version;Client_JQuery_Deprecated_Symbols;Vulnerable Software Version"
  }
}
```
</p>
</details>

## Features
* Grouping mechanism
* Mark issues as `No Defect`
* Set `Severity` for specific Vulnerability
* Set `Priority` for specific Vulnerability
* Set `Description` for specific Vulnerability and language
* Set `Recommendation` for specific Vulnerability and language
