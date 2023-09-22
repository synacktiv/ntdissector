NAME_TO_INTERNAL = {
    "RDN": "ATTm589825",  # name
    "Pek-List": "ATTk590689",
    "Attribute-ID": "ATTc131102",
    "Attribute-Name-LDAP": "ATTm131532",  # LDAP-Display-Name (of attributes)
    "Attribute-Name-CN": "ATTm3",  # Common-Name
    "Attribute-Name-DN": "ATTb49",  # Distinguished-Name
    "msDS-IntId": "ATTj591540",  # for specific attribute ids (exchange...)
    "sAMAccountType": "ATTj590126",
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

UUID_FIELDS = ["objectGUID", "currentValue"]

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
