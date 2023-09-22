from impacket.structure import Structure
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc5652
from binascii import unhexlify
from Cryptodome.Cipher import AES
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from .gkdi import GKDI, KDFParameter, FFCDHParameter
from ntdissector.utils import GUID, create_sd


class KeyIdentifier(Structure):
    structure = (
        ("Version", "<L=0"),
        ("Magic", "<L=0"), # 0x4B44534B
        ("Flags", "<L=0"),
        ("L0Index", "<L=0"),
        ("L1Index", "<L=0"),
        ("L2Index", "<L=0"),
        ("RootKeyIdentifier", "16s=b"),
        ("KeyInfoLength", "<L=0"),
        ("DomainNameLength", "<L=0"),
        ("ForestNameLength", "<L=0"),
        ("_KeyInfo", "_-KeyInfo", 'self["KeyInfoLength"]'),
        ("KeyInfo", ":"),
        ("_Domain", "_-Domain", 'self["DomainNameLength"]'),
        ("DomainName", ":"),
        ("_Forest", "_-Forest", 'self["ForestNameLength"]'),
        ("ForestName", ":"),
    )


# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/b6ea7b78-64da-48d3-87cb-2cff378e4597
class LAPSEncryptedPasswordBlob(Structure):
    structure = (
        ("PasswordUpdateTimestamp", "<Q=0"),
        ("EncryptedPasswordSize", "<L=0"),
        ("_Reserved", "<L=0"),  # not used
        ("CMSBlob", ":"),  # Cryptographic Message Syntax (CMS)
    )

    def __init__(self, data):
        Structure.__init__(self, data)
        cms_data, self["EncryptedPassword"] = decoder.decode(self["CMSBlob"], asn1Spec=rfc5652.ContentInfo())
        envelopped_data, _ = decoder.decode(cms_data["content"], asn1Spec=rfc5652.EnvelopedData())
        # del self["CMSBlob"]
        recipient_infos = envelopped_data["recipientInfos"]
        kek_recipient_info = recipient_infos[0]["kekri"]
        kek_identifier = kek_recipient_info["kekid"]
        self["keyIdentifier"] = KeyIdentifier(bytes(kek_identifier["keyIdentifier"]))
        # key_id.dump()
        self["keySID"] = decoder.decode(kek_identifier["other"]["keyAttr"])[0]["field-1"][0][0][1].asOctets().decode("utf-8")
        self["keyIdentifier"]["RootKeyGUID"] = GUID(self["keyIdentifier"]["RootKeyIdentifier"]).formatCanonical()
        self["encryptedKey"] = bytes(kek_recipient_info["encryptedKey"])
        enc_content_parameter = bytes(envelopped_data["encryptedContentInfo"]["contentEncryptionAlgorithm"]["parameters"])
        self["IV"] = bytes(decoder.decode(enc_content_parameter)[0][0])


class LAPSv2:
    def __init__(self, laps_cipher, kds_pvk=None):
        self.laps_enc_pwd = LAPSEncryptedPasswordBlob(laps_cipher)
        # self.laps_enc_pwd.dump()

        self.key_sd = create_sd(self.getKeySID())

        # either a single object or a list of objects (ldap naming is expected here for the column names)
        self.kds_pvk = kds_pvk

    def getRootKeyID(self):
        return self.laps_enc_pwd["keyIdentifier"]["RootKeyGUID"]

    def getKeySID(self):
        return self.laps_enc_pwd["keySID"]

    def getKeyId(self, field=None):
        kid = self.laps_enc_pwd["keyIdentifier"]
        if field is None:
            return kid
        return kid[field]

    def setKdsPvk(self, pvk):
        self.kds_pvk = pvk

        self.kds_pvk_kdfparam = KDFParameter(unhexlify(pvk["msKds-KDFParam"]))
        # self.kds_pvk_kdfparam.dump()

        self.kds_pvk_secret_agreement_algo = pvk["msKds-SecretAgreementAlgorithmID"]
        self.kds_pvk_ffcdhparam = FFCDHParameter(unhexlify(pvk["msKds-SecretAgreementParam"]))
        # self.kds_pvk_ffcdhparam.dump()

        self.kds_pvk_root_key_data = unhexlify(pvk["msKds-RootKeyData"])

        self.kds_pvk_private_key_length = int(pvk["msKds-PrivateKeyLength"])

    def loadCEK(self):
        if isinstance(self.kds_pvk, dict) and self.kds_pvk["cn"] != self.getRootKeyID():
            raise RuntimeError("Provied KDS ProvRootKey has the wrong GUID")
        elif isinstance(self.kds_pvk, list):
            # search for the right pvk
            for pvk in self.kds_pvk:
                if pvk["cn"] == self.getRootKeyID():
                    self.setKdsPvk(pvk)
        elif not hasattr(self, "kds_pvk_root_key_data"):
            self.setKdsPvk(self.pvk)
        else:
            raise RuntimeError("Wrong KDS ProvRootKey object")

        gkdi = GKDI(
            self.kds_pvk_kdfparam.hash_algo,
            self.getKeyId("RootKeyIdentifier"),
            self.kds_pvk_root_key_data,
            self.getKeyId("L0Index"),
            self.getKeyId("L1Index"),
            self.getKeyId("L2Index"),
            self.key_sd.getData(),
        )

        is_public = self.getKeyId()["Flags"] & 1

        gkdi.genPrivKey(is_public, self.kds_pvk_secret_agreement_algo, self.kds_pvk_private_key_length, self.getKeyId("KeyInfo"))

        self.kek = gkdi.kek

        self.cek = aes_key_unwrap(gkdi.kek, self.laps_enc_pwd["encryptedKey"])

    def decrypt(self):
        if not hasattr(self, "kek"):
            self.loadCEK()

        aes = AES.new(self.cek, AES.MODE_GCM, nonce=self.laps_enc_pwd["IV"])
        self.plaintext = aes.decrypt(self.laps_enc_pwd["EncryptedPassword"])[:-18].decode("utf-16-le")
        return self.plaintext
