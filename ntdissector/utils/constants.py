NAME_TO_INTERNAL = {
    "RDN": "ATTm589825",  # name
    "Pek-List": "ATTk590689",
    "Attribute-ID": "ATTc131102",
    "Attribute-Name-LDAP": "ATTm131532",  # LDAP-Display-Name (of attributes)
    "Attribute-Name-CN": "ATTm3",  # Common-Name
    "Attribute-Name-DN": "ATTb49",  # Distinguished-Name
    "msDS-IntId": "ATTj591540",  # for specific attribute ids (exchange...)
    "sAMAccountType": "ATTj590126",
    "userAccountControl": "ATTj589832",
    # "name": "ATTm3",
    "Governs-ID": "ATTc131094",  # for Class-Schema records
    "Object-Class": "ATTc0",
    "Link-ID": "ATTj131122",
    "isDeleted": "ATTi131120",
}

SAM_ACCOUNT_TYPE = {
    "SAM_DOMAIN_OBJECT": 0x0,
    "SAM_GROUP_OBJECT": 0x10000000,
    "SAM_NON_SECURITY_GROUP_OBJECT": 0x10000001,
    "SAM_ALIAS_OBJECT": 0x20000000,
    "SAM_NON_SECURITY_ALIAS_OBJECT": 0x20000001,
    "SAM_USER_OBJECT": 0x30000000,
    "SAM_NORMAL_USER_ACCOUNT": 0x30000000,
    "SAM_MACHINE_ACCOUNT": 0x30000001,
    "SAM_TRUST_ACCOUNT": 0x30000002,
    "SAM_APP_BASIC_GROUP": 0x40000000,
    "SAM_APP_QUERY_GROUP": 0x40000001,
    "SAM_ACCOUNT_TYPE_MAX": 0x7FFFFFFF,
}

USER_ACCOUNT_CONTROL = {
    "SCRIPT": 0x0001,
    "ACCOUNTDISABLE": 0x0002,
    "HOMEDIR_REQUIRED": 0x0008,
    "LOCKOUT": 0x0010,
    "PASSWD_NOTREQD": 0x0020,
    "PASSWD_CANT_CHANGE": 0x0040,
    "ENCRYPTED_TEXT_PWD_ALLOWED": 0x0080,
    "TEMP_DUPLICATE_ACCOUNT": 0x0100,
    "NORMAL_ACCOUNT": 0x0200,
    "INTERDOMAIN_TRUST_ACCOUNT": 0x0800,
    "WORKSTATION_TRUST_ACCOUNT": 0x1000,
    "SERVER_TRUST_ACCOUNT": 0x2000,
    "DONT_EXPIRE_PASSWORD": 0x10000,
    "MNS_LOGON_ACCOUNT": 0x20000,
    "SMARTCARD_REQUIRED": 0x40000,
    "TRUSTED_FOR_DELEGATION": 0x80000,
    "NOT_DELEGATED": 0x100000,
    "USE_DES_KEY_ONLY": 0x200000,
    "DONT_REQ_PREAUTH": 0x400000,
    "PASSWORD_EXPIRED": 0x800000,
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,
    "PARTIAL_SECRETS_ACCOUNT": 0x04000000,
}

UUID_FIELDS = ["objectGUID", "currentValue", "msFVE-RecoveryGuid", "msFVE-VolumeGuid"]

DATETIME_FIELDS = ["dSCorePropagationData", "whenChanged", "whenCreated"]

FILETIME_FIELDS = [
    "badPasswordTime",
    "lastLogon",
    "lastLogoff",
    "lastLogonTimestamp",
    "pwdLastSet",
    "accountExpires",
    "lockoutTime",
    "priorSetTime",
    "lastSetTime",
    "msKds-CreateTime",
    "msKds-UseStartTime"
]

# fieldName: (isHistory, hasDES)
ENCRYPTED_FIELDS = {
    "unicodePwd": (0, 1),
    "dBCSPwd": (0, 1),
    "ntPwdHistory": (1, 1),
    "lmPwdHistory": (1, 1),
    "currentValue": (0, 0),
    "trustAuthIncoming": (0, 0),
    "trustAuthOutgoing": (0, 0),
}

KERBEROS_TYPE = {
    1: "dec-cbc-crc",
    3: "des-cbc-md5",
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    0xFFFFFF74: "rc4_hmac",
}
