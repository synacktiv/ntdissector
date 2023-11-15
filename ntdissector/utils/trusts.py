from binascii import hexlify
from impacket.structure import Structure
from Cryptodome.Hash import MD4
from . import fileTimeToDateTime


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

    def __init__(self, data):
        Structure.__init__(self, data)

        self["AuthenticationInformation"] = []
        self["PreviousAuthenticationInformation"] = []

        for aif in ["AuthenticationInformation", "PreviousAuthenticationInformation"]:
            self[aif].append(LSAPR_AUTH_INFORMATION(self[f"{aif}Data"]))

            while len(self[aif][-1]["Remaining"]) > 0:
                self[aif].append(LSAPR_AUTH_INFORMATION(self[aif][-1]["Remaining"]))

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

    def __init__(self, data):
        Structure.__init__(self, data)

        self["AuthType"] = self.__LSA_AUTH_INFORMATION_AUTH_TYPES[self["AuthType"]]

        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/cd20fbd1-eabe-4da2-bba3-31ab3036d019
        if self["AuthType"] == "TRUST_AUTH_TYPE_CLEAR":
            # derive RC4 key
            self["AuthInfo_RC4-HMAC"] = MD4.new(self["AuthInfo"]).digest()
            # to:do ? DES-CBC / DEC-CRC
        elif self["AuthType"] == "TRUST_AUTH_TYPE_NT4OWF":
            self["AuthInfo_RC4-HMAC"] = self["AuthInfo"]

    def _toJson(self):
        obj = {"lastUpdateTime": fileTimeToDateTime(self["LastUpdateTime"]), "authType": self["AuthType"], "authInfo": self["AuthInfo"]}
        if "AuthInfo_RC4-HMAC" in self.fields:
            obj["authInfo_RC4-HMAC"] = self["AuthInfo_RC4-HMAC"]
        return obj
