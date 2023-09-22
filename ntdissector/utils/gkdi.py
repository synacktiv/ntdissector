from impacket.structure import Structure
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.asymmetric import ec
from math import ceil, floor

# offline MS-GKDI


# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/9946aeff-a914-45e9-b9e5-6cb5b4059187
class KDFParameter(Structure):
    structure = (
        ("Unknown1", "<L=0"),  # 0x00000000
        ("Unknown2", "<L=0"),  # 0x01000000
        ("HashNameLen", "<L=0"),
        ("Unknown3", "<L=0"),  # 0x00000000
        ("_HashAlgorithmName", "_-HashAlgorithmName", 'self["HashNameLen"]'),
        ("HashAlgorithmName", ":"),  # utf-16-le
    )

    def __init__(self, data):
        Structure.__init__(self, data)

        hash_name = self["HashAlgorithmName"].decode("utf-16-le")[:-1]
        if str(hash_name) in ["SHA1", "SHA256", "SHA384", "SHA512"]:
            self.hash_algo = hashes.__getattribute__(hash_name)()
        else:
            raise NotImplementedError(f"Unsupported hash algorithm {hash_name}")


# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/e15ae269-ee21-446a-a480-de3ea243db5f
class FFCDHParameter(Structure):
    structure = (
        ("Length", "<L=0"),
        ("Magic", '4s=b""'),
        ("KeyLength", "<L=0"),
        ("_FieldOrder", "_-FieldOrder", 'self["KeyLength"]'),
        ("FieldOrder", ":"),
        ("_Generator", "_-Generator", 'self["KeyLength"]'),
        ("Generator", ":"),
    )

    def __init__(self, data):
        Structure.__init__(self, data)

        if self["Magic"] != b"DHPM":
            raise ValueError("Magic bytes are wrong")


# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/f8770f01-036d-4bf6-a4cf-1bd0e3913404
class FFCDHKey(Structure):
    structure = (
        ("Magic", '4s=b""'),
        ("KeyLength", "<L=0"),
        ("_FieldOrder", "_-FieldOrder", 'self["KeyLength"]'),
        ("FieldOrder", ":"),
        ("_Generator", "_-Generator", 'self["KeyLength"]'),
        ("Generator", ":"),
        ("_PublicKey", "_-PublicKey", 'self["KeyLength"]'),
        ("PublicKey", ":"),
    )

    def __init__(self, data):
        Structure.__init__(self, data)
        self.p = int.from_bytes(self["FieldOrder"], byteorder="big")
        self.g = int.from_bytes(self["Generator"], byteorder="big")
        self.y = int.from_bytes(self["PublicKey"], byteorder="big")


# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/24876a37-9a92-4187-9052-222bb6f85d4a
class ECDHKey(Structure):
    structure = (
        ("Magic", '4s=b""'),
        ("KeyLength", "<L=0"),
        ("_X", "_-X", 'self["KeyLength"]'),
        ("X", ":"),
        ("_Y", "_-Y", 'self["KeyLength"]'),
        ("Y", ":"),
    )

    def __init__(self, data):
        Structure.__init__(self, data)

        if self["Magic"] == b"1KCE":
            self["CurveName"] = "P-256"
            self.curve_algo = ec.SECP256R1()
            self.hash_algo = hashes.SHA256()

        elif self["Magic"] == b"3KCE":
            self["CurveName"] = "P-384"
            self.curve_algo = ec.SECP384R1()
            self.hash_algo = hashes.SHA384()

        elif self["Magic"] == b"5KCE":
            self["CurveName"] = "P-521"
            self.curve_algo = ec.SECP521R1()
            self.hash_algo = hashes.SHA512()
        else:
            raise ValueError("Magic bytes are wrong")

        self.x = int.from_bytes(self["X"], byteorder="big")
        self.y = int.from_bytes(self["Y"], byteorder="big")


# kdscli.dll
def GenerateKDFContext(guid: bytes, l0: int, l1: int, l2: int, sd: bytes = b""):
    return guid + l0.to_bytes(4, byteorder="little") + l1.to_bytes(4, byteorder="little") + l2.to_bytes(4, byteorder="little") + sd


class GKDI:
    KDS_SERVICE_LABEL = "KDS service\0".encode("utf-16-le")
    KDS_PUBKEY_LABEL = "KDS public key\0".encode("utf-16le")
    SHA512_LABEL = "SHA512\0".encode("utf-16le")

    def __init__(
        self, hash_algo: str, root_key_id: bytes, root_key_data: bytes, l0_index: int, l1_index: int, l2_index: int, security_descriptor: bytes
    ):
        self.root_key_id = root_key_id
        self.root_key_data = root_key_data

        self.l0_index = l0_index
        self.l0_seed_key = b""
        self.l1_index = l1_index
        self.l1_seed_key = b""
        self.l2_index = l2_index
        self.l2_seed_key = b""

        self.sd = security_descriptor

        self.hash_algo = hash_algo

        self.genGroupKey()

    def kdf(self, secret, label, context, size):
        kdf = KBKDFHMAC(
            algorithm=self.hash_algo,
            mode=Mode.CounterMode,
            length=size,
            rlen=4,
            llen=4,
            location=CounterLocation.BeforeFixed,
            label=label,
            context=context,
            fixed=None,
        )

        return kdf.derive(secret)

    def genGroupKey(self):
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/5d373568-dd68-499b-bd06-a3ce16ca7117
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/4a004c52-f652-4c99-ad81-0c390fcc1341

        # derive L0 seed key
        l0_ctx = GenerateKDFContext(self.root_key_id, self.l0_index, 0xFFFFFFFF, 0xFFFFFFFF)
        self.l0_seed_key = self.kdf(self.root_key_data, self.KDS_SERVICE_LABEL, l0_ctx, 64)

        # derive L1 seed key
        l1_ctx = GenerateKDFContext(self.root_key_id, self.l0_index, 31, 0xFFFFFFFF, self.sd)
        l1_seed_key = self.kdf(self.l0_seed_key, self.KDS_SERVICE_LABEL, l1_ctx, 64)
        l1_idx = 31
        while l1_idx > self.l1_index:
            l1_idx -= 1
            l1_ctx = GenerateKDFContext(self.root_key_id, self.l0_index, l1_idx, 0xFFFFFFFF)
            l1_seed_key = self.kdf(l1_seed_key, self.KDS_SERVICE_LABEL, l1_ctx, 64)

        # derive L2 seed key
        self.l2_seed_key = l1_seed_key
        l2_idx = 32
        while l2_idx > self.l2_index:
            l2_idx -= 1
            l2_ctx = GenerateKDFContext(
                self.root_key_id,
                self.l0_index,
                self.l1_index,
                l2_idx,
            )
            self.l2_seed_key = self.kdf(self.l2_seed_key, self.KDS_SERVICE_LABEL, l2_ctx, 64)

        return self.l0_seed_key, self.l1_seed_key, self.l2_seed_key

    def genPrivKey(self, is_public: bool, secret_algorithm_id: str, private_key_length: int, key_material: bytes):
        if is_public:
            # 3.1.4.1.2 Generating a Group Key
            # PrivKey(SD, RK, L0, L1, L2) = KDF(HashAlg, Key(SD, RK, L0, L1, L2), "KDS service", RK.msKds-SecretAgreement-AlgorithmID, RK.msKds-PrivateKey-Length)
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/5d373568-dd68-499b-bd06-a3ce16ca7117
            priv_key = self.kdf(
                self.l2_seed_key,
                self.KDS_SERVICE_LABEL,
                (secret_algorithm_id + "\0").encode("utf-16-le"),
                ceil(private_key_length / 8),
            )
            priv_key = int.from_bytes(priv_key, byteorder="big")

            if secret_algorithm_id == "DH":
                # 5.7.1.1 Finite Field Cryptography Diffie-Hellman (FFC DH) Primitive
                # https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-56ar2.pdf
                ffcdh_key = FFCDHKey(key_material)

                # Z = y**x mod p
                z = pow(ffcdh_key.y, priv_key, ffcdh_key.p)
                shared_secret = z.to_bytes(floor((z.bit_length() + 7) / 8), byteorder="big")

            elif secret_algorithm_id == "ECDH_P":
                # ECDH_P256, ECDH_P384, ECDH_P521
                echdh_key = ECDHKey(key_material)
                ecdh_pub_key = ec.EllipticCurvePublicNumbers(echdh_key.x, echdh_key.y, echdh_key.curve_algo).public_key()
                ecdh_priv_key = ec.derive_private_key(int.from_bytes(priv_key, byteorder="big"))
                shared_secret = ecdh_priv_key.exchange(ec.ECDH(), ecdh_pub_key)
                raise NotImplementedError("ECDH algorithms aren't implemented")
            else:
                raise NotImplementedError("Unknown secret agreement algorithm")

            secret = ConcatKDFHash(
                algorithm=hashes.SHA256(),
                length=32,
                otherinfo=self.SHA512_LABEL + self.KDS_PUBKEY_LABEL + self.KDS_SERVICE_LABEL,
            ).derive(shared_secret)
            self.kek = self.kdf(secret, self.KDS_SERVICE_LABEL, self.KDS_PUBKEY_LABEL, 32)
        else:
            self.kek = self.kdf(self.l2_seed_key, self.KDS_SERVICE_LABEL, key_material, 32)
