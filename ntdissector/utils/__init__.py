from impacket.structure import Structure
from struct import unpack
from datetime import datetime
from dateutil import tz
from json import JSONEncoder, dumps
from binascii import hexlify
from impacket.ldap import ldaptypes


class ByteEncoder(JSONEncoder):
    def default(self, x):
        return hexlify(x).decode("utf-8") if isinstance(x, bytes) else super().default(x)
        # return b64encode(x).decode("utf-8") if isinstance(x, bytes) else super().default(x)


def json_dumps(json):
    return dumps(json, ensure_ascii=False, cls=ByteEncoder)


def formatDateTime(t) -> str:
    if isinstance(t, list):
        return list(
            datetime.fromtimestamp(x - 11644473600, tz=tz.gettz("UTC"))
            .isoformat(timespec="microseconds")
            .replace("Z", "+00:00")
            .replace(".000000", "")
            for x in t
        )
    else:
        return (
            datetime.fromtimestamp(t - 11644473600, tz=tz.gettz("UTC"))
            .isoformat(timespec="microseconds")
            .replace("Z", "+00:00")
            .replace(".000000", "")
        )


def fileTimeToDateTime(t):
    return formatDateTime((t / 10**7))


class NTDS_SID_IDENTIFIER_AUTHORITY(Structure):
    structure = (("Value", "6s"),)


class NTDS_SID(Structure):
    structure = (
        ("Revision", "<B"),
        ("SubAuthorityCount", "<B"),
        ("IdentifierAuthority", ":", NTDS_SID_IDENTIFIER_AUTHORITY),
        ("SubLen", "_-SubAuthority", 'self["SubAuthorityCount"]*4'),
        ("SubAuthority", ":"),
    )

    def formatCanonical(self):
        ans = "S-%d-%d" % (self["Revision"], ord(self["IdentifierAuthority"]["Value"][5:6]))
        for i in range(self["SubAuthorityCount"]):
            if i != self["SubAuthorityCount"] - 1:
                format = "<L"
            else:
                # last part is B-E
                format = ">L"
            ans += "-%d" % (unpack(format, self["SubAuthority"][i * 4 : i * 4 + 4])[0])
        return ans

    def getRID(self):
        return self.formatCanonical().split("-")[-1]


class GUID(Structure):
    # P1(4B/LE)-P2(2b/LE)-P3(2b/LE)-P4(2b/BE)-P5(6b/BE)
    structure = (
        ("P1", "<L"),
        ("P2", "<H"),
        ("P3", "<H"),
        ("P4", ">H"),
        ("P5", ">6s"),
    )

    def formatCanonical(self) -> str:
        return "%08x-%04x-%04x-%04x-%s" % (
            self["P1"],
            self["P2"],
            self["P3"],
            self["P4"],
            self["P5"].hex(),
        )


def create_ace(sid, mask):
    nace = ldaptypes.ACE()
    nace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    nace["AceFlags"] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata["Mask"] = ldaptypes.ACCESS_MASK()
    acedata["Mask"]["Mask"] = mask
    acedata["Sid"] = ldaptypes.LDAP_SID()
    acedata["Sid"].fromCanonical(sid)
    nace["Ace"] = acedata
    return nace


def create_sd(sid):
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 32772
    sd["OwnerSid"] = ldaptypes.LDAP_SID()
    sd["OwnerSid"].fromCanonical("S-1-5-18")
    sd["GroupSid"] = ldaptypes.LDAP_SID()
    sd["GroupSid"].fromCanonical("S-1-5-18")
    sd["Sacl"] = b""

    acl = ldaptypes.ACL()
    acl["AclRevision"] = 2
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = [create_ace(sid, 3), create_ace("S-1-1-0", 2)]
    sd["Dacl"] = acl
    return sd
