import logging
from binascii import hexlify
from base64 import b64encode
from struct import unpack
from impacket.structure import Structure


class PVK_FILE_HDR(Structure):
    structure = (
        ("dwMagic", "<L=0"),
        ("dwVersion", "<L=0"),
        ("dwKeySpec", "<L=0"),
        ("dwEncryptType", "<L=0"),
        ("cbEncryptData", "<L=0"),
        ("cbPvk", "<L=0"),
    )


class BACKUP_KEY(Structure):
    # P_BACKUP_KEY : legacy key
    structure_v1 = (
        ("Version", "<L=0"),
        ("Data", ":"),
    )

    # PREFERRED_BACKUP_KEY
    structure_v2 = (
        ("Version", "<L=0"),
        ("KeyLength", "<L=0"),
        ("CertificateLength", "<L=0"),
        ("Data", ":"),
    )

    def __init__(self, data):
        version = unpack("<L", data[:4])[0]

        if version == 1:
            self.structure = self.structure_v1
        elif version == 2:
            self.structure = self.structure_v2

        else:
            logging.error("Unkown BACKUP_KEY Version {%d}" % version)
            raise ValueError

        Structure.__init__(self, data)

        if version == 1:
            self["legacyKey"] = hexlify(self["Data"]).decode("latin-1")
        elif version == 2:
            self["cert"] = b64encode(self["Data"][self["KeyLength"] : self["KeyLength"] + self["CertificateLength"]]).decode("latin-1")

            header = PVK_FILE_HDR()
            header["dwMagic"] = 0xB0B5F11E
            header["dwVersion"] = 0
            header["dwKeySpec"] = 1
            header["dwEncryptType"] = 0
            header["cbEncryptData"] = 0
            header["cbPvk"] = self["KeyLength"]
            self["pvk"] = b64encode(header.getData() + self["Data"][: self["KeyLength"]]).decode("latin-1")

    def _toJson(self):
        if self["Version"] == 1:
            return {"legacyKey": self["legacyKey"]}
        elif self["Version"] == 2:
            return {"pvk": self["pvk"], "cert": self["cert"]}
