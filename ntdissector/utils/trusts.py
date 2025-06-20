from binascii import hexlify
from impacket.krb5.crypto import string_to_key
from impacket.structure import Structure
from Cryptodome.Hash import MD4
from . import fileTimeToDateTime
from .constants import KERBEROS_TYPE


# 6.1.6.9.1 trustAuthInfo Attributes
class TRUST_AUTH_INFO(Structure):
    structure = (
        ("Count", "<L=0"),
        ("AuthenticationInformationOffSet", "<L=0"),
        ("PreviousAuthenticationInformationOffSet", "<L=0"),
        (
            "_AuthenticationInformationData",
            "_-AuthenticationInformationData",
            'self["PreviousAuthenticationInformationOffSet"] - self["AuthenticationInformationOffSet"]',
        ),
        ("AuthenticationInformationData", ":"),
        ("PreviousAuthenticationInformationData", ":"),
    )

    def __init__(self, data, domain, trust_partner, trust_direction):
        Structure.__init__(self, data)

        self["AuthenticationInformation"] = []
        self["PreviousAuthenticationInformation"] = []

        for aif in ["AuthenticationInformation", "PreviousAuthenticationInformation"]:
            self[aif].append(LSAPR_AUTH_INFORMATION(self[f"{aif}Data"], domain, trust_partner, trust_direction))

            while len(self[aif][-1]["Remaining"]) > 0:
                self[aif].append(LSAPR_AUTH_INFORMATION(self[aif][-1]["Remaining"], domain, trust_partner, trust_direction))

    def _toJson(self):
        obj = {"count": self["Count"]}
        obj["authInfo"] = [x._toJson() for x in self["AuthenticationInformation"]]
        obj["previousAuthInfo"] = [x._toJson() for x in self["PreviousAuthenticationInformation"]]
        return obj


# 6.1.6.9.1.1 LSAPR_AUTH_INFORMATION
class LSAPR_AUTH_INFORMATION(Structure):
    structure = (
        ("LastUpdateTime", "<Q=0"),
        ("AuthType", "<L=0"),
        ("AuthInfoLength", "<L=0"),
        ("_AuthInfo", "_-AuthInfo", 'self["AuthInfoLength"]'),
        ("AuthInfo", ":"),
        ("_Padding", "_-Padding", "self['AuthInfoLength'] % 4"),
        ("Padding", ":"),
        ("Remaining", ":"),
    )

    __LSA_AUTH_INFORMATION_AUTH_TYPES = {
        0: "TRUST_AUTH_TYPE_NONE",
        1: "TRUST_AUTH_TYPE_NT4OWF",
        2: "TRUST_AUTH_TYPE_CLEAR",
        3: "TRUST_AUTH_TYPE_VERSION",
    }

    def __init__(self, data, domain, trust_partner, trust_direction):
        Structure.__init__(self, data)

        self["AuthType"] = self.__LSA_AUTH_INFORMATION_AUTH_TYPES[self["AuthType"]]

        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/cd20fbd1-eabe-4da2-bba3-31ab3036d019
        if self["AuthType"] == "TRUST_AUTH_TYPE_CLEAR":
            # derive RC4 key
            self["AuthInfo_RC4_HMAC"] = MD4.new(self["AuthInfo"]).digest()

            # derive AES keys
            if trust_direction == "trustAuthIncoming":
                salt = f"{domain.upper()}krbtgt{trust_partner.upper()}".encode("utf-8")
            else:  # trustAuthOutgoing
                salt = f"{trust_partner.upper()}krbtgt{domain.upper()}".encode("utf-8")

            password = self["AuthInfo"].decode("utf-16-le", "replace").encode("utf-8", "replace")

            aes_etypes = {k: v.upper() for k, v in KERBEROS_TYPE.items() if "aes" in v}
            for etype_dec, etype_name in aes_etypes.items():
                key = string_to_key(etype_dec, password, salt, None)
                self[f"AuthInfo_{etype_name}"] = hexlify(key.contents).decode("utf-8")

            # to:do ? DES-CBC / DEC-CRC
        elif self["AuthType"] == "TRUST_AUTH_TYPE_NT4OWF":
            self["AuthInfo_RC4_HMAC"] = self["AuthInfo"]

    def _toJson(self):
        obj = {"lastUpdateTime": fileTimeToDateTime(self["LastUpdateTime"]), "authType": self["AuthType"], "authInfo": self["AuthInfo"]}
        supported_etypes = [v.upper() for v in KERBEROS_TYPE.values() if "aes" in v or "rc4" in v]
        for etype in supported_etypes:
            if f"AuthInfo_{etype}" in self.fields:
                obj[f"authInfo_{etype}"] = self[f"AuthInfo_{etype}"]
        return obj
