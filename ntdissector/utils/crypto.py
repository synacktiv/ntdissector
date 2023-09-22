import logging
import hashlib
from struct import pack, unpack
from impacket.structure import Structure
from binascii import hexlify, unhexlify, Error as binascii_Error
from impacket.crypto import transformKey
from Cryptodome.Cipher import AES
from Crypto.Util.Padding import unpad
from Cryptodome.Cipher import DES, ARC4
from OpenSSL import crypto as openssl_crypto


def format_asn1_to_pem(data: bytes):
    try:  # is it hex encoded?
        cert = openssl_crypto.load_certificate(openssl_crypto.FILETYPE_ASN1, unhexlify(data))
    except binascii_Error:  # or raw bytes?
        cert = openssl_crypto.load_certificate(openssl_crypto.FILETYPE_ASN1, data)
    return openssl_crypto.dump_certificate(openssl_crypto.FILETYPE_PEM, cert).decode()


def deriveKey(baseKey):
    key = pack("<L", baseKey)
    key1 = [key[0], key[1], key[2], key[3], key[0], key[1], key[2]]
    key2 = [key[3], key[0], key[1], key[2], key[3], key[0], key[1]]

    return transformKey(bytes(key1)), transformKey(bytes(key2))


def decryptAES(key, value, iv=b"\x00" * 16):
    plainText = b""
    if iv != b"\x00" * 16:
        aes256 = AES.new(key, AES.MODE_CBC, iv)

    for index in range(0, len(value), 16):
        if iv == b"\x00" * 16:
            aes256 = AES.new(key, AES.MODE_CBC, iv)
        cipherBuffer = value[index : index + 16]
        # Pad buffer to 16 bytes
        if len(cipherBuffer) < 16:
            cipherBuffer += b"\x00" * (16 - len(cipherBuffer))
        plainText += aes256.decrypt(cipherBuffer)
    try:
        return unpad(plainText, 16)
    except ValueError as e:
        # data is certainly unpadded
        return plainText


class PEKLIST_ENC(Structure):
    structure = (
        ("Header", '8s=b""'),
        ("KeyMaterial", '16s=b""'),
        ("EncryptedPek", ":"),
    )


class PEKLIST_PLAIN(Structure):
    structure = (
        ("Header", '32s=b""'),
        ("DecryptedPek", ":"),
    )


class PEK_KEY(Structure):
    structure = (
        ("Header", '1s=b""'),
        ("Padding", '3s=b""'),
        ("Key", '16s=b""'),
    )


class ENC_SECRET(Structure):
    """
    // Blob structure Win2k:   Algorithm ID (2B), Flags (2B), PEK ID (4B), Salt (16B), Encrypted secret (rest)
    // EncryptedDataOffsetDES := 2 * 2 + 4 + SaltSize
    // Blob structure Win2016: Algorithm ID (2B), Flags (2B), PEK ID (4B), Salt (16B), Secret Length (4B), Encrypted secret (rest)
    // const int EncryptedDataOffsetAES = 2 * sizeof(short) + SaltSize + sizeof(ulong);
    """

    SECRET_ENCRYPTION_ALGORITHMS = {"DB_RC4": 0x10, "DB_RC4_SALT": 0x11, "REP_RC4_SALT": 0x12, "DB_AES": 0x13}

    structure_win16 = (
        ("AlgorithmID", "<h=0"),
        ("Flags", "<h=0"),
        ("PekID", "<L=0"),
        ("Salt", '16s=b""'),
        ("SecretLength", "<L=0"),
        ("EncryptedData", ":"),
    )

    structure_win2k = (
        ("AlgorithmID", "<h=0"),
        ("Flags", "<h=0"),
        ("PekID", "<L=0"),
        ("Salt", '16s=b""'),  # salt
        ("EncryptedData", ":"),
    )

    def __init__(self, data):
        algorithmID = unpack("<h", data[:2])[0]

        if algorithmID == self.SECRET_ENCRYPTION_ALGORITHMS["DB_AES"]:
            self.structure = self.structure_win16
            self.algo_type = [k for (k, v) in self.SECRET_ENCRYPTION_ALGORITHMS.items() if v == algorithmID][0]
            self.is_aes = True
        elif algorithmID in (
            self.SECRET_ENCRYPTION_ALGORITHMS["DB_RC4"],
            self.SECRET_ENCRYPTION_ALGORITHMS["DB_RC4_SALT"],
            self.SECRET_ENCRYPTION_ALGORITHMS["REP_RC4_SALT"],
        ):
            self.structure = self.structure_win2k
            self.algo_type = [k for (k, v) in self.SECRET_ENCRYPTION_ALGORITHMS.items() if v == algorithmID][0]
            self.is_rc4 = True
        else:
            logging.error("Unkown algorithm ID {%d} in secret" % algorithmID)
            raise ValueError

        # logging.debug("ENC_SECRET(algo_id={})".format(self.algo_type))
        Structure.__init__(self, data)


class PEK_LIST:
    def __init__(self, rawEncPekList: bytes, bootKey: bytes):
        self.__encryptedPekList = PEKLIST_ENC(rawEncPekList)
        self.__decryptedPekList = None
        self.__bootKey = bootKey
        self.plainPekList = list()

        if self.__encryptedPekList["Header"][:4] == b"\x02\x00\x00\x00":
            # Up to Windows 2012 R2 looks like header starts this way
            md5 = hashlib.new("md5")
            md5.update(self.__bootKey)
            for i in range(1000):
                md5.update(self.__encryptedPekList["KeyMaterial"])
            tmpKey = md5.digest()
            rc4 = ARC4.new(tmpKey)
            self.__decryptedPekList = PEKLIST_PLAIN(rc4.encrypt(self.__encryptedPekList["EncryptedPek"]))
            pek_len = len(PEK_KEY())
            for i in range(len(self.__decryptedPekList["DecryptedPek"]) // pek_len):
                cursor = i * pek_len
                pek = PEK_KEY(self.__decryptedPekList["DecryptedPek"][cursor : cursor + pek_len])
                logging.info("PEK # %d found and decrypted: %s", i, hexlify(pek["Key"]).decode("utf-8"))
                self.plainPekList.append(pek["Key"])

        elif self.__encryptedPekList["Header"][:4] == b"\x03\x00\x00\x00":
            # Windows 2016 TP4 header starts this way
            # Encrypted PEK Key seems to be different, but actually similar to decrypting LSA Secrets.
            # using AES:
            # Key: the bootKey
            # CipherText: PEKLIST_ENC['EncryptedPek']
            # IV: PEKLIST_ENC['KeyMaterial']
            self.__decryptedPekList = PEKLIST_PLAIN(
                decryptAES(self.__bootKey, self.__encryptedPekList["EncryptedPek"], self.__encryptedPekList["KeyMaterial"])
            )

            # PEK list entries take the form:
            #   index (4 byte LE int), PEK (16 byte key)
            # the entries are in ascending order, and the list is terminated
            # by an entry with a non-sequential index (08080808 observed)
            pos, cur_index = 0, 0
            while True:
                pek_entry = self.__decryptedPekList["DecryptedPek"][pos : pos + 20]
                if len(pek_entry) < 20:
                    break  # if list truncated, should not happen
                index, pek = unpack("<L16s", pek_entry)
                if index != cur_index:
                    break  # break on non-sequential index
                self.plainPekList.append(pek)
                logging.info("PEK # %d found and decrypted: %s", index, hexlify(pek).decode("utf-8"))
                cur_index += 1
                pos += 20

    def removeRC4Layer(self, encSecret: ENC_SECRET) -> str:
        md5 = hashlib.new("md5")
        md5.update(self.plainPekList[int(encSecret["PekID"])])
        md5.update(encSecret["Salt"])
        tmpKey = md5.digest()
        rc4 = ARC4.new(tmpKey)
        plainText = rc4.encrypt(encSecret["EncryptedData"])
        return plainText

    def __removeDESLayer(self, cipher: bytes, rid: str) -> str:
        Key1, Key2 = deriveKey(int(rid))
        Crypt1 = DES.new(Key1, DES.MODE_ECB)
        Crypt2 = DES.new(Key2, DES.MODE_ECB)
        plainText = Crypt1.decrypt(cipher[:8]) + Crypt2.decrypt(cipher[8:])
        return plainText

    def decryptSecret(self, rawSecret: bytes, rid: bytes = b"", isHistory: bool = False, hasDES: bool = True, isADAM: bool = False) -> str:
        try:
            encSecret = ENC_SECRET(rawSecret)
        except ValueError as e:
            logging.error(e)
            return "DEC_ERROR_INIT"
        except Exception as e:
            logging.error(e)
            return "DEC_ERROR_UNK"
        if hasattr(encSecret, "is_rc4"):
            tmpPlain = self.removeRC4Layer(encSecret)
            # need the rid too
            # TO:DO test this
            # return "TO:DO:RC4:PASS:RID"
        elif hasattr(encSecret, "is_aes"):
            # encSecret.dump()
            tmpPlain = decryptAES(self.plainPekList[int(encSecret["PekID"])], encSecret["EncryptedData"], encSecret["Salt"])

        if isADAM:
            if isHistory and rid:
                history = list()
                (count,) = unpack("<i", tmpPlain[:4])
                for i in range(0, count):
                    history.append(hexlify(tmpPlain[4 + 4 * (i + 1) + i * 16 : 4 + 4 * (i + 1) + (i + 1) * 16]).decode("utf-8"))
                return history
            elif rid:
                return hexlify(tmpPlain).decode("utf-8")
            else:
                return "MISSING_RID_" + hexlify(tmpPlain).decode("utf-8")

        # has DES layer ??
        if hasDES:
            if isHistory and rid:
                history = list()
                for i in range(0, len(tmpPlain) // 16):
                    history.append(hexlify(self.__removeDESLayer(tmpPlain[i * 16 : (i + 1) * 16], rid)).decode("utf-8"))
                return history
            elif rid:
                return hexlify(self.__removeDESLayer(tmpPlain, rid)).decode("utf-8")
            else:
                return "MISSING_RID_" + hexlify(tmpPlain).decode("utf-8")
        return tmpPlain
