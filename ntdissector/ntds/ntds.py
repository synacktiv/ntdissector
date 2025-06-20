import logging
from dissect.esedb.esedb import EseDB
from dissect.esedb.record import Record
from dissect.esedb.page import Page
from impacket.dcerpc.v5.samr import (
    USER_PROPERTIES,
    USER_PROPERTY,
    KERB_STORED_CREDENTIAL_NEW,
    KERB_KEY_DATA_NEW,
    KERB_STORED_CREDENTIAL,
    KERB_KEY_DATA,
    WDIGEST_CREDENTIALS,
)
from sys import __stdout__, __stderr__
from termcolor import colored
from impacket import winregistry
from pathlib import Path
from six import b
from hashlib import md5
from textwrap import dedent
from os import path
from json import loads
from tqdm import tqdm
import multiprocessing as mp
from binascii import hexlify, unhexlify
from base64 import b64encode
from ntdissector.utils.crypto import PEK_LIST, format_asn1_to_pem
from ntdissector.utils.sddl import parse_ntSecurityDescriptor
from ntdissector.utils.trusts import TRUST_AUTH_INFO
from ntdissector.utils import NTDS_SID, GUID, fileTimeToDateTime, formatDateTime, json_dumps
from ntdissector.utils.constants import (
    SAM_ACCOUNT_TYPE,
    USER_ACCOUNT_CONTROL,
    UUID_FIELDS,
    DATETIME_FIELDS,
    FILETIME_FIELDS,
    ENCRYPTED_FIELDS,
    KERBEROS_TYPE,
    NAME_TO_INTERNAL,
)
from ntdissector.utils.dpapi import BACKUP_KEY

from ntdissector.utils.lapsv2 import LAPSv2


class NTDS:
    defaultdir = f"{Path.home()}/.ntdissector"

    def __init__(self, ntdsFile, options=None) -> None:
        self.__dt_records_count = -1
        self.__nfo = [ntdsFile, md5(b(ntdsFile)).hexdigest(), self.__dt_records_count]
        self.__db = EseDB(open(ntdsFile, "rb"))
        self.__datatable = self.__db.table("datatable")
        self.__linktable = self.__db.table("link_table")
        self.__sdtable = self.__db.table("sd_table")

        self.bootKey = None

        self.__dt_cols = self.__datatable.column_names
        # short mapping of numeric IDS => to full ATT... names
        self.datatable_columns_mapping = {int(v[4:]): v for v in self.__dt_cols if v.startswith("ATT")}

        # for resolving columns, built automatically from NTDS and cached
        self.objectClassSchema = {"ldap": dict(), "cn": dict(), "resolve": dict()}
        self.attributeSchema = {"ldap": dict(), "cn": dict(), "resolve": dict(), "links": dict(), "unresolved": dict()}

        # for links between objects
        # stored as tuples (dn, link_base)
        self.links = {"to": dict(), "from": dict()}
        self.dnt_to_dn = dict()

        self.securityDescriptors = dict()

        self.pekList = None
        self.rawEncPekList = None
        self.ldap_naming = options.ldap_naming

        self.__persistCache = options.saveCache  # defaults to true
        self.__cacheLoaded = False
        self.__dryRun = options.dryRun  # defaults to false
        self.__isADAM = False  # AD LDS format
        self.__skipDel = options.keepDel == False

        self.workers = options.workers

        self.__cachedir = path.join(f"{options.cachedir}" if options.cachedir else self.defaultdir, f".cache/{self.__nfo[1]}")
        self.__outdir = path.join(f"{options.outputdir}" if options.outputdir else self.defaultdir, f"out/{self.__nfo[1]}")

        self.__KDSRootKeys = list()

        self.__cacheFiles = {
            "objectClassSchema": f"{self.__cachedir}/__objectClassSchema.json",
            "attributeSchema": f"{self.__cachedir}/__attributeSchema.json",
            "rawEncPekList": f"{self.__cachedir}/__pekList.json",
            "securityDescriptors": f"{self.__cachedir}/_securityDescriptors.json",
            "links": f"{self.__cachedir}/_links.json",
            "dnt_to_dn": f"{self.__cachedir}/_dnt_to_dn.json",
            "__nfo": f"{self.__cachedir}/.nfo",
            "bootKey": f"{self.__cachedir}/bootKey.json",
            "__isADAM": f"{self.__cachedir}/ADAM.json",
            "__KDSRootKeys": f"{self.__cachedir}/__KDSRootKeys.json",
            # "datatable_columns_mapping": f"{self.__cachedir}/__datatable_columns_mapping.json",
        }

        # For ADAM
        self.__schemaPekList = None
        self.__rootPekList = None

        if not self.__dryRun:
            self.__loadCache()
            self.__dt_records_count = self.__nfo[2]

        if self.__dryRun or not self.__cacheLoaded:
            self.__getBootKey(options.bootKey, options.system)
            self.__buildSchemas()
            if self.__persistCache:
                self.__saveCache()
        else:
            self.__getBootKey(options.bootKey, options.system)

        self.__decryptPekList()

        logging.debug("Cache directory : %s" % self.__cachedir)
        logging.debug("Output directory : %s" % self.__outdir)
        logging.debug("NTDS debug stats" + self.__stats())

    def __stats(self):
        out = dedent(
            """
            >>> ESEDB Tables
            {}

            >>>> datatable
            {}

            >>> NTDS
            {}
            """
        ).format(
            "\n".join("* %s" % table.name for table in self.__db.tables()),
            "* columns={}\n* data_tree_root_page={}\n* lv_tree_root_page={}".format(
                len(self.__dt_cols), self.__datatable.root_page, self.__datatable.lv_page.num
            ),
            "* Hash: {}\n* isADAM: {}\n* Object Class Schema: {}\n* Resolved Columns: {}/{}\n* Total Records: {}\n* Encrypted Pek List: {}\n* System Boot Key: {}\n* Decrypted Pek List: {}".format(
                self.__nfo[1],
                self.__isADAM,
                len(self.objectClassSchema["resolve"]),
                len(self.attributeSchema["resolve"]),
                len(self.datatable_columns_mapping),
                self.__dt_records_count,
                self.rawEncPekList,
                hexlify(self.bootKey).decode() if self.bootKey is not None else None,
                [hexlify(key).decode() for key in self.pekList.plainPekList] if self.pekList else None,
            ),
        )
        return out

    def __getBootKey(self, bootKey=None, systemHive=None):
        if self.bootKey is not None:
            try:
                self.bootKey = unhexlify(self.bootKey)
            except:
                pass
        elif bootKey is not None:
            try:
                self.bootKey = unhexlify(bootKey)
                logging.debug("Loaded static bootkey from provided hex value %s" % bootKey)
            except TypeError:
                logging.error("Couldn't load bootkey, should be a hex string")
        elif systemHive is not None:
            if Path(systemHive).is_file():
                try:
                    winreg = winregistry.Registry(systemHive)
                except: 
                    logging.error(f"Couldn't parse the SYSTEM hive file, wrong file ? {systemHive}")
                else:
                    self.bootKey = b""
                    tmpKey = b""
                    currentControlSet = "ControlSet%03d" % (winreg.getValue("\\Select\\Current")[1])
                    for key in ["JD", "Skew1", "GBG", "Data"]:
                        ans = winreg.getClass("\\%s\\Control\\Lsa\\%s" % (currentControlSet, key))
                        digit = ans[:16].decode("utf-16le")
                        tmpKey = tmpKey + b(digit)

                    transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]

                    tmpKey = unhexlify(tmpKey)

                    for i in range(len(tmpKey)):
                        self.bootKey += tmpKey[transforms[i] : transforms[i] + 1]

                    logging.debug("Retrieved system bootKey from hive: %s" % hexlify(self.bootKey).decode("utf-8"))
            else:
                logging.error(f"Couldn't load bootkey, file not found : {systemHive}")

        elif self.__isADAM:
            if self.__rootPekList is None or self.__schemaPekList is None:
                self.bootKey = None
                logging.warning("ADAM_NTDS : No system bootKey")
            else:
                root_permutation = [2, 4, 25, 9, 7, 27, 5, 11]
                schema_permutation = [37, 2, 17, 36, 20, 11, 22, 7]
                print(self.__schemaPekList[2])
                self.bootKey = b"".join(
                    [self.__rootPekList[i].to_bytes(1, "little") for i in root_permutation]
                    + [self.__schemaPekList[i].to_bytes(1, "little") for i in schema_permutation]
                )
                logging.debug("ADAM_NTDS: computer system bootKey from : %s" % hexlify(self.bootKey).decode("utf-8"))

        else:
            self.bootKey = None
            logging.warning("No system bootKey")

    def __loadCache(self) -> None:
        for k, p in self.__cacheFiles.items():
            try:
                self.__setattr__(f"_{self.__class__.__name__}{k}" if k.startswith("__") else k, loads(open(p, "r", encoding='utf-8').read()))
                logging.debug("Loaded cache file %s into %s" % (p, k))
            except Exception as e:
                logging.error("Couldn't load cache file %s -> %s" % (p, e))
                self.__cacheLoaded = False
                return
        self.__cacheLoaded = True

    def __saveCache(self):
        Path(self.__cachedir).mkdir(parents=True, exist_ok=True)
        for k, v in self.__cacheFiles.items():
            logging.debug("Saving %s into cache file %s" % (k, v))
            open(v, "w", encoding='utf-8').write(json_dumps(self.__getattribute__(f"_{self.__class__.__name__}{k}" if k.startswith("__") else k)))

    def __buildSchemas(self) -> None:
        if self.__cacheLoaded and len(self.objectClassSchema["resolve"]) and len(self.attributeSchema["resolve"]) and self.rawEncPekList is not None:
            logging.debug("Skipping the schema build, pekList, objectClassSchema and attributeSchema are already loaded from cache file")
            return
        logging.info("Building the schemas, please wait...")

        def printProgress(stats):
            __stdout__.write("%s\r" % colored("[?] Progress " + stats, "yellow", attrs=["bold"]))
            __stdout__.write("\033[2K\033[1G")

        def getStats():
            s1 = f"objectClassSchema={len(self.objectClassSchema['resolve'])}"
            s2 = f"attributeSchema={len(self.attributeSchema['resolve'])}"
            s3 = "pekList={}".format("x" if self.rawEncPekList is None else "Found")
            return f"[ {s1} | {s2} | {s3} | seen={seen}]"

        def updateAttributeSchema(aid: int, cn_name: str, ldap_name: str):
            self.attributeSchema["resolve"][self.datatable_columns_mapping.get(aid)] = (cn_name, ldap_name)
            self.attributeSchema["cn"][cn_name] = self.datatable_columns_mapping.get(aid)
            self.attributeSchema["ldap"][ldap_name] = self.datatable_columns_mapping.get(aid)

        seen = 0
        OCLID_classSchema = 196621
        OCLID_attributeSchema = 196622
        OCLID_domainDNS = 655427
        OCLID_dMD = 196617
        OCLID_top = 65536
        OCLID_configuration = 655372
        # MS-GKDI
        OCLID_KDSProvRootKey = 655638

        logging.debug("Parsing the sdtable")
        for record in self.__sdtable.records():
            try:
                self.securityDescriptors[str(record.get("sd_id"))] = record.get("sd_value")
            except Exception as e:
                logging.error("Failed to parse SD of record with sd_id=%s - %s" % (record.get("sd_id"), repr(e)))

        logging.debug("Parsing the link_table")
        for record in self.__linktable.records():
            _b_DNT = str(record.get("backlink_DNT"))
            if _b_DNT not in self.links["to"]:
                self.links["to"][_b_DNT] = []
            self.links["to"][_b_DNT].append((record.get("link_DNT"), record.get("link_base"), record.get("link_deltime"), record.get("link_deactivetime"), record.get("link_data")))

            _l_DNT = str(record.get("link_DNT"))
            if _l_DNT not in self.links["from"]:
                self.links["from"][_l_DNT] = []
            self.links["from"][_l_DNT].append((record.get("backlink_DNT"), record.get("link_base"), record.get("link_deltime"), record.get("link_deactivetime"), record.get("link_data")))

        logging.debug("Parsing the datatable")
        for record in self.__datatable.records():
            printProgress(getStats())
            seen += 1

            if record is None:
                break

            elif OCLID_classSchema in self.__getObjectClass(record):
                id = str(record.get(NAME_TO_INTERNAL["Governs-ID"]))
                ldap_name = record.get(NAME_TO_INTERNAL["Attribute-Name-LDAP"])
                cn_name = record.get(NAME_TO_INTERNAL["Attribute-Name-CN"])
                self.objectClassSchema["resolve"][id] = (cn_name, ldap_name)
                self.objectClassSchema["ldap"][ldap_name] = id
                self.objectClassSchema["cn"][cn_name] = id

            elif OCLID_attributeSchema in self.__getObjectClass(record):
                attId = record.get(NAME_TO_INTERNAL["Attribute-ID"])
                msdsId = record.get(NAME_TO_INTERNAL["msDS-IntId"])
                ldap_name = record.get(NAME_TO_INTERNAL["Attribute-Name-LDAP"])
                cn_name = record.get(NAME_TO_INTERNAL["Attribute-Name-CN"])
                lid = record.get(NAME_TO_INTERNAL["Link-ID"])

                if isinstance(lid, int):
                    self.attributeSchema["links"][str(lid)] = (cn_name, ldap_name)

                if attId in self.datatable_columns_mapping:
                    updateAttributeSchema(attId, cn_name, ldap_name)
                elif msdsId in self.datatable_columns_mapping:
                    updateAttributeSchema(msdsId, cn_name, ldap_name)
                else:
                    self.attributeSchema["unresolved"][ldap_name] = (
                        self.datatable_columns_mapping.get(attId, attId),
                        self.datatable_columns_mapping.get(msdsId, msdsId),
                        cn_name,
                    )
            elif not self.rawEncPekList and (
                OCLID_domainDNS in self.__getObjectClass(record) and record.get(NAME_TO_INTERNAL["Pek-List"]) is not None
            ):
                self.__isADAM = False
                self.rawEncPekList = hexlify(record.get(NAME_TO_INTERNAL["Pek-List"])).decode()
                logging.debug("Found Pek-List")
            elif [OCLID_top] == self.__getObjectClass(record) and record.get(NAME_TO_INTERNAL["Pek-List"]) is not None:
                self.__isADAM = True
                self.__rootPekList = record.get(NAME_TO_INTERNAL["Pek-List"])
                logging.debug("ADAM_NTDS : Found rootPekList (len:%s)" % len(self.__rootPekList))
            elif OCLID_dMD in self.__getObjectClass(record) and record.get(NAME_TO_INTERNAL["Pek-List"]) is not None:
                self.__isADAM = True
                self.__schemaPekList = record.get(NAME_TO_INTERNAL["Pek-List"])
                logging.debug("ADAM_NTDS : Found schemaPekList (len:%s)" % len(self.__schemaPekList))
            elif OCLID_configuration in self.__getObjectClass(record) and record.get(NAME_TO_INTERNAL["Pek-List"]) is not None:
                self.__isADAM = True
                self.rawEncPekList = hexlify(record.get(NAME_TO_INTERNAL["Pek-List"])).decode()
                logging.debug("ADAM_NTDS : Found Pek-List")
            elif OCLID_KDSProvRootKey in self.__getObjectClass(record):
                self.__KDSRootKeys.append(self.__serializeRecord(record))
                logging.debug("Found a RootKey for MS-GKDI")

        logging.debug("Building distinguished names...")

        def __buildDNs(iterator, remaining=list()):
            for record in iterator:
                # ID to DN
                if record.get(NAME_TO_INTERNAL["RDN"]) is not None and record.get("PDNT_col"):
                    parent_dn = self.dnt_to_dn.get(str(record.get("PDNT_col")), None)

                    # Keep it for the second round
                    if parent_dn is None:
                        remaining.append(record)
                        pass

                    rdn_type = self.attributeSchema["resolve"].get(
                        f"ATTm{record.get('RDNtyp_col')}",
                        ["Common-Name", "cn"],
                    )[self.ldap_naming]

                    tdn = f"{rdn_type.upper()}={str(record.get(NAME_TO_INTERNAL['RDN']))}"
                    self.dnt_to_dn[str(record.get("DNT_col"))] = ",".join([tdn] if parent_dn is None else [tdn, parent_dn])

        remaining = list()
        __buildDNs(self.__datatable.records(), remaining)
        # Second loop to fix unresolved parent DNs
        if len(remaining):
            logging.debug(f"Processing {len(remaining)} unresolved DNs")
            __buildDNs(remaining)

        self.__dt_records_count = seen
        self.__nfo[2] = seen
        logging.debug("Schemas built successfully : %s" % getStats())

    def __decryptPekList(self) -> None:
        if self.rawEncPekList is not None and self.bootKey is not None:
            self.pekList = PEK_LIST(unhexlify(self.rawEncPekList), self.bootKey)
            logging.debug("Decrypted pekList")

    def __serializeRecord(self, record: Record, filter: list = []) -> dict:
        tmp_res = record.as_dict()
        columns_with_values = dict()
        resolver = self.attributeSchema["resolve"]
        for col_name, value in tmp_res.items():
            if col_name in resolver:
                if not len(filter) or (col_name != "null" and resolver[col_name][self.ldap_naming] in filter):
                    columns_with_values[resolver[col_name][self.ldap_naming]] = hexlify(value).decode() if isinstance(value, bytes) else value
        return columns_with_values

    def __formatTimestamps(self, obj: dict) -> dict:
        for field in FILETIME_FIELDS:
            try:
                obj[field] = fileTimeToDateTime(obj[field])
            except Exception as e:
                # logging.error("Error on fileTimeToDateTime(%s) - %s" % (field, e))
                pass
        for field in DATETIME_FIELDS:
            try:
                obj[field] = formatDateTime(obj[field])
            except Exception as e:
                # logging.error("Error on fileTimeToDateTime(%s) - %s" % (field, e))
                pass

    def __formatSamAccountType(self, obj: dict, as_string: bool = False) -> None:
        res = list()
        if "sAMAccountType" in obj:
            for t, v in SAM_ACCOUNT_TYPE.items():
                if v & int(obj["sAMAccountType"]):
                    res.append(t)
            obj["sAMAccountType"] = " | ".join(res) if as_string else res

    def __formatUserAccountControl(self, obj: dict, as_string: bool = False) -> None:
        res = list()
        if "userAccountControl" in obj:
            for t, v in USER_ACCOUNT_CONTROL.items():
                if v & int(obj["userAccountControl"]):
                    res.append(t)
            obj["userAccountControl"] = " | ".join(res) if as_string else res

    def __formatObjectClass(self, obj: dict, as_string: bool = False) -> None:
        if "objectClass" in obj:
            res = list()
            if isinstance(obj["objectClass"], list):
                for v in obj["objectClass"]:
                    oid = str(v)
                    res.append(self.objectClassSchema["resolve"].get(oid, [oid, oid])[self.ldap_naming])
                obj["objectClass"] = " | ".join(res) if as_string else res
            elif isinstance(obj["objectClass"], int):
                oid = str(obj["objectClass"])
                obj["objectClass"] = self.objectClassSchema["resolve"].get(oid, [oid, oid])[self.ldap_naming]

    def __formatUID(self, obj: dict) -> None:
        for field in UUID_FIELDS:
            if field not in obj or (field == "currentValue" and obj["cn"] not in ["BCKUPKEY_P Secret", "BCKUPKEY_PREFERRED Secret"]):
                pass
            else:
                try:
                    guid = GUID(unhexlify(obj[field]) if isinstance(obj[field], str) else obj[field]).formatCanonical()
                    obj[field] = guid
                except Exception as e:
                    logging.error("Failed to parse UUID field - %s - %s" % (e, obj[field]))
                    # raise e

    def __formatSupplementalCredentialsInfo(self, obj: dict) -> None:
        if not isinstance(self.pekList, PEK_LIST):
            return
        res = dict()
        if "supplementalCredentials" in obj:
            creds = self.pekList.decryptSecret(unhexlify(obj["supplementalCredentials"]), hasDES=False)
            if self.__isADAM:
                # Undocumented structure for AD LDS: [Unknown - 0100000001000000e80100000600000001000000e0010000] + [Primary:WDigest - WDIGEST_CREDENTIALS]
                res["Primary:WDigest"] = list()
                try:
                    wDigestCreds = WDIGEST_CREDENTIALS(creds.split(unhexlify("0100000001000000e80100000600000001000000e0010000"))[1])
                except:
                    logging.error("__formatSupplementalCredentialsInfo (ADAM) : %s" % e)
                    return
                for j in range(wDigestCreds["NumberOfHashes"]):
                    res["Primary:WDigest"].append(hexlify(wDigestCreds["Hash%d" % (j + 1)]).decode("utf-8"))
            else:
                try:
                    uProperties = USER_PROPERTIES(creds)
                except:
                    return
                propertiesData = uProperties["UserProperties"]
                for i in range(uProperties["PropertyCount"]):
                    try:
                        uProperty = USER_PROPERTY(propertiesData)
                    except:
                        continue
                    # uProperty.dump()
                    propertiesData = propertiesData[len(uProperty) :]
                    try:
                        pName = uProperty["PropertyName"].decode("utf-16-le")
                    except Exception as e:
                        logging.error("__formatSupplementalCredentialsInfo : %s" % e)
                        break
                    res[pName] = list()

                    if "Primary:Kerberos" in pName:
                        if pName == "Primary:Kerberos-Newer-Keys":
                            kerbCreds = (
                                KERB_STORED_CREDENTIAL_NEW(unhexlify(uProperty["PropertyValue"]))
                                if pName == "Primary:Kerberos-Newer-Keys"
                                else KERB_STORED_CREDENTIAL(unhexlify(uProperty["PropertyValue"]))
                            )
                            kerbCredsData = kerbCreds["Buffer"]
                            for j in range(kerbCreds["CredentialCount"]):
                                kerbKeyData = (
                                    KERB_KEY_DATA_NEW(kerbCredsData) if pName == "Primary:Kerberos-Newer-Keys" else KERB_KEY_DATA(kerbCredsData)
                                )
                                kerbCredsData = kerbCredsData[len(kerbKeyData) :]
                                keyValue = unhexlify(uProperty["PropertyValue"])[kerbKeyData["KeyOffset"] :][: kerbKeyData["KeyLength"]]
                                res[pName].append(
                                    "%s:%s"
                                    % (
                                        KERBEROS_TYPE[kerbKeyData["KeyType"]] if kerbKeyData["KeyType"] in KERBEROS_TYPE else kerbKeyData["KeyType"],
                                        hexlify(keyValue).decode("utf-8"),
                                    )
                                )

                    elif "Primary:CLEARTEXT" in pName:
                        try:
                            res[pName].append(unhexlify(uProperty["PropertyValue"]).decode("utf-16-le"))
                        except UnicodeDecodeError:
                            res[pName].append(uProperty["PropertyValue"].decode("utf-8"))
                    elif "Primary:WDigest" in pName:
                        wDigestCreds = WDIGEST_CREDENTIALS(unhexlify(uProperty["PropertyValue"]))
                        # wDigestCreds.dump()
                        for j in range(wDigestCreds["NumberOfHashes"]):
                            res[pName].append(hexlify(wDigestCreds["Hash%d" % (j + 1)]).decode("utf-8"))
                    elif "Packages" in pName:
                        res[pName] = unhexlify(uProperty["PropertyValue"]).decode("utf-16-le").split("\x00")
                    else:
                        res[pName].append(hexlify(uProperty["PropertyValue"]).decode("utf-8"))

        if len(res):
            obj["supplementalCredentials"] = res

    def __formatSecrets(self, obj: dict) -> None:
        if not isinstance(self.pekList, PEK_LIST):
            return
        rid = 0 if not "objectSid" in obj else obj["objectSid"].split("-")[-1]
        for field, (isHistory, hasDES) in ENCRYPTED_FIELDS.items():
            if field in obj:
                try:
                    res = self.pekList.decryptSecret(unhexlify(obj[field]), rid, isHistory, hasDES, self.__isADAM)
                    obj[field] = res[:32] if field in ["unicodePwd"] else res
                except Exception as e:
                    logging.error("__formatSecrets : %s" % e)

    def __formatSID(self, obj: dict) -> None:
        if "objectSid" in obj:
            obj["objectSid"] = NTDS_SID(unhexlify(obj["objectSid"])).formatCanonical()

    def __formatDN(self, obj: dict) -> None:
        dn = obj.get("distinguishedName")
        if dn is not None and str(dn) in self.dnt_to_dn:
            obj["distinguishedName"] = self.dnt_to_dn[str(dn)]

        # known columns that contain a reference a DN value
        dn_fields = ["showInAddressBook", "rIDSetReferences", "objectCategory", "msKds-DomainID"]
        for dnf in dn_fields:
            if dnf in obj:
                if isinstance(obj[dnf], list):
                    obj[dnf] = [self.dnt_to_dn.get(str(i), "UNKNOWN DN %d" % i) for i in obj[dnf]]
                else:
                    obj[dnf] = self.dnt_to_dn.get(str(obj[dnf]), "UNKNOWN DN %d" % obj[dnf])

    def __formatLinks(self, obj: dict) -> None:
        dn = obj.get("distinguishedName")
        if dn is not None:
            for (_dn, _link_base, _link_deltime, _link_deactivetime, _link_data), _link_direction in [(x, 1) for x in self.links["to"].get(str(dn), ())] + [
                (y, 0) for y in self.links["from"].get(str(dn), ())
            ]:
                link_attribute_name = self.attributeSchema["links"].get(
                    str(int(_link_base) * 2 + _link_direction), [f"UNKNOWN LINK BASE FOR {_link_base}"] * 2
                )[self.ldap_naming]
                if link_attribute_name not in obj:
                    obj[link_attribute_name] = list()
                if _link_data is None:
                    resolved_dn = self.dnt_to_dn.get(str(_dn), f"UNKNOWN CN FOR DN {_dn}")
                    if (_link_deltime is not None or _link_deltime is not None) and self.__skipDel:
                        continue
                    else:
                        if _link_deltime is not None:
                            resolved_dn = f"__DELETED-{_link_deltime}__{resolved_dn}"
                        if _link_deactivetime is not None :
                            resolved_dn = f"__DEACTIVE-{_link_deactivetime}__{resolved_dn}"
                    obj[link_attribute_name].append(resolved_dn)
                else:
                    obj[link_attribute_name].append(_link_data)

    def __formatDPAPI(self, obj: dict) -> None:
        if "secret" in obj["objectClass"] and "currentValue" in obj and isinstance(obj["currentValue"], bytes):
            try:
                key = BACKUP_KEY(obj["currentValue"])
                # key.dump()
                obj["currentValue"] = key._toJson()
            except Exception as e:
                logging.error("__formatDPAPI : %s" % e)

    def __formatKeyCredentialLink(self, obj: dict) -> None:
        if "msDS-KeyCredentialLink-BL" in obj and "msDS-KeyCredentialLink" in obj:
            tmp = list()
            for kcl in obj["msDS-KeyCredentialLink"]:
                tmp.append(b64encode(f"B:854:{kcl[-854:]}:{obj['distinguishedName']}".encode()).decode("latin-1"))
            obj["msDS-KeyCredentialLink"] = tmp
            # redundant, unset attr this maybe?
            obj["msDS-KeyCredentialLink-BL"] = tmp

    def __formatAllowedToActOnBehalfOfOtherIdentity(self, obj: dict) -> None:
        if "msDS-AllowedToActOnBehalfOfOtherIdentity" in obj.keys():
            if isinstance(obj["msDS-AllowedToActOnBehalfOfOtherIdentity"], str):
                sd = parse_ntSecurityDescriptor(bytes.fromhex(obj["msDS-AllowedToActOnBehalfOfOtherIdentity"]))
            elif isinstance(obj["msDS-AllowedToActOnBehalfOfOtherIdentity"], bytes):
                sd = parse_ntSecurityDescriptor(obj["msDS-AllowedToActOnBehalfOfOtherIdentity"])
            sids = list()
            for ace in sd["DACL"]["ACEs"]:
                sids.append(ace.get("SID", ""))
            obj["msDS-AllowedToActOnBehalfOfOtherIdentity"] = sids

    def __formatCertificates(self, obj: dict) -> None:
        if "cACertificate" in obj:
            if isinstance(obj["cACertificate"], list):
                obj["cACertificate"] = [format_asn1_to_pem(d) for d in obj["cACertificate"]]
            else:
                obj["cACertificate"] = format_asn1_to_pem(obj["cACertificate"])

    def __formatLAPS(self, obj: dict) -> None:
        if "ms-Mcs-AdmPwd" in obj:
            obj["ms-Mcs-AdmPwd"] = unhexlify(obj["ms-Mcs-AdmPwd"]).decode()
        if "ms-Mcs-AdmPwdExpirationTime" in obj:
            try:
                obj["ms-Mcs-AdmPwdExpirationTime"] = fileTimeToDateTime(obj["ms-Mcs-AdmPwdExpirationTime"])
            except:
                pass

    def __formatLAPSv2(self, obj: dict) -> None:
        if "msLAPS-PasswordExpirationTime" in obj:
            try:
                obj["msLAPS-PasswordExpirationTime"] = fileTimeToDateTime(obj["msLAPS-PasswordExpirationTime"])
            except:
                pass
        for fn in [
            "msLAPS-EncryptedPassword",
            "msLAPS-EncryptedPasswordHistory",
            "msLAPS-EncryptedDSRMPassword",
            "msLAPS-EncryptedDSRMPasswordHistory",
        ]:
            if fn in obj:
                try:
                    if isinstance(obj[f"{fn}"], list):
                        obj[f"{fn}_"] = list()
                        for o in obj[fn]:
                            res = loads(LAPSv2(o, self.__KDSRootKeys).decrypt())
                            res["t"] = fileTimeToDateTime(int(res["t"], 16))
                            obj[f"{fn}_"].append(res)
                    else:
                        res = loads(LAPSv2(unhexlify(obj[fn]), self.__KDSRootKeys).decrypt())
                        res["t"] = fileTimeToDateTime(int(res["t"], 16))
                        obj[f"{fn}_"] = res
                except Exception as e:
                    obj[f"{fn}_"] = f"!ERROR! {e}"

    def __formatSecurityDescriptor(self, obj: dict) -> None:
        sd_fields = ["nTSecurityDescriptor", "msDS-AllowedToActOnBehalfOfOtherIdentity"]
        for sdf in sd_fields:
            if sdf in obj:
                obj[sdf] = self.securityDescriptors.get(
                    str(int.from_bytes(bytes.fromhex(obj[sdf]), byteorder="little")),
                    "!ERROR!",  # re-run with dryRun opt to rebuild cache
                )

    def __formatTrust(self, obj: dict) -> None:
        if "trustedDomain" in obj["objectClass"]:
            domain = obj["distinguishedName"].split("DC=", 1)[-1].replace("DC=", "").replace(",", ".")
            trust_partner = obj["trustPartner"]

            if "securityIdentifier" in obj:
                try:
                    obj["securityIdentifier"] = NTDS_SID(unhexlify(obj["securityIdentifier"])).formatCanonical()
                except:
                    pass
            for attr in ["trustAuthIncoming", "trustAuthOutgoing"]:
                try:
                    obj[attr] = TRUST_AUTH_INFO(obj[attr], domain, trust_partner, attr)._toJson()
                except Exception as e:
                    pass

    def __formatFields(self, obj: dict) -> None:
        self.__formatSID(obj)
        self.__formatSecrets(obj)
        self.__formatSupplementalCredentialsInfo(obj)
        self.__formatTimestamps(obj)
        self.__formatSamAccountType(obj, as_string=True)
        self.__formatUserAccountControl(obj, as_string=True)
        self.__formatObjectClass(obj)
        self.__formatUID(obj)
        self.__formatLinks(obj)
        self.__formatDN(obj)
        self.__formatDPAPI(obj)
        self.__formatKeyCredentialLink(obj)
        self.__formatCertificates(obj)
        self.__formatLAPS(obj)
        self.__formatLAPSv2(obj)
        self.__formatSecurityDescriptor(obj)
        self.__formatAllowedToActOnBehalfOfOtherIdentity(obj)
        self.__formatTrust(obj)

    def __getObjectClass(self, record: Record) -> str or list:
        try:
            rOC = record.get(self.attributeSchema["ldap"]["objectClass"])
        except KeyError:
            # fallback when the schema isn't built
            rOC = record.get(NAME_TO_INTERNAL["Object-Class"])

        if isinstance(rOC, list):
            return rOC
        elif isinstance(rOC, int):
            return [rOC]
        else:
            return list()

    def __getObjectClassResolved(self, record: Record) -> str:
        rOcd = {"objectClass": self.__getObjectClass(record)}
        self.__formatObjectClass(rOcd)
        return rOcd["objectClass"]

    # translate to opposite naming
    def __translate(self, name: str) -> str:
        if isinstance(name, str):
            ocsid = str(self.objectClassSchema["ldap" if self.ldap_naming else "cn"].get(name, -1))
            return self.objectClassSchema["resolve"].get(ocsid, ["", ""])[not self.ldap_naming]
        return name

    # multiprocessing with a queue
    def __dumpObjectWorker(self, workersQ: mp.Queue, workerLock: mp.Lock) -> None:
        wid = mp.current_process().name.split("-")[1]
        results = dict()
        logging.debug(f"Worker-{wid} started ")
        self.__db = EseDB(open(self.__nfo[0], "rb"))
        self.__datatable = self.__db.table("datatable")
        self.__linktable = self.__db.table("link_table")
        while True:
            pickled_record = workersQ.get(block=True)
            if pickled_record is None:
                with workerLock:
                    logging.debug("Lock acquired by Worker-%s, dumping results" % wid)
                    for cName, res in results.items():
                        with open(f"{self.__outdir}/{cName}.json", "a", encoding='utf-8') as outFile:
                            outFile.write("\n".join([json_dumps(r) for r in res]))
                            outFile.write("\n")
                break
            else:
                node = Page(esedb=self.__db, num=pickled_record["page_num"], buf=pickled_record["page_buf"]).node(num=pickled_record["node_num"])
                record = Record(table=self.__datatable, node=node)
                res_obj = self.__serializeRecord(record)
                # logging.debug(res_obj)
                try:
                    self.__formatFields(res_obj)
                except Exception as e:
                    logging.debug(f"Worker-{wid} __formatFields error : {e} ")
                if pickled_record["cName"] not in results:
                    results[pickled_record["cName"]] = list()
                results[pickled_record["cName"]].append(res_obj)

    def dumpObjectsT(self, classList: list = ["all"], limit: int = None) -> None:
        def printStats(stats: dict):
            __stderr__.write(
                "%s\r"
                % (
                    colored(
                        f"[?] {total_records} / {self.__dt_records_count} | " + " ".join([f"{k}={v}" for k, v in stats.items()])[:100],
                        "blue",
                        attrs=["bold"],
                    )
                )
            )

        Path(self.__outdir).mkdir(parents=True, exist_ok=True)
        matches = 0
        total_records = 0
        stats = dict()

        def __reduce(record):
            return {"page_num": record._node.tag.page.num, "page_buf": bytes(record._node.tag.page.buf), "node_num": record._node.num}

        workersQ = mp.Queue()
        workerLock = mp.Lock()
        pool = mp.get_context("fork").Pool(self.workers, self.__dumpObjectWorker, (workersQ, workerLock))
        logging.info("Filtering records with this list of object classes :  %s" % classList)
        if self.__skipDel:
            logging.info("Ignoring records marked as deleted")
        with tqdm(total=self.__dt_records_count, miniters=1, unit="rec.") as pbar:
            for record in self.__datatable.records():
                total_records += 1
                if limit is not None and matches >= limit:
                    break
                if record.get(NAME_TO_INTERNAL["isDeleted"], 0) == 1 and self.__skipDel:
                    pbar.update()
                    continue
                cName = dict(enumerate(self.__getObjectClassResolved(record))).get(0, -1)
                ## translate is used in last resort to check if it matches the opposite naming
                if (cName != -1) and (("all" in classList) or (cName in classList) or (self.__translate(cName) in classList)):
                    if cName not in stats:
                        stats[cName] = 0
                        # create empty file, zeroes out any existing output
                        open(f"{self.__outdir}/{cName}.json", "w", encoding='utf-8').close()
                    a = __reduce(record)
                    a["cName"] = cName
                    workersQ.put(a, block=True)
                    stats[cName] += 1
                    matches += 1
                pbar.update()

        logging.info(f"Finished, matched {matches} records out of {total_records}")

        qsize = workersQ.qsize()
        nTasks = matches if limit is None or (isinstance(limit, int) and matches < limit) else limit

        logging.info(f"Processing {nTasks} serialization tasks")
        with tqdm(
            total=nTasks,
            initial=nTasks - qsize,
            miniters=1,
            unit="rec.",
        ) as pbar_q:
            while True:
                if qsize > 0:
                    qsizen = workersQ.qsize()
                    pbar_q.update(qsize - qsizen)
                    qsize = qsizen
                else:
                    pbar_q.update(nTasks - pbar_q.n)
                    break

        logging.debug("Sending shutdown signal to workers")
        for i in range(self.workers):
            workersQ.put(None)

        try:
            workersQ.close()
            workersQ.join_thread()
            logging.debug("Worker queue closed successfully")
            pool.close()
            pool.join()
            logging.debug("Process pool closed successfully")
        except BrokenPipeError as e:
            logging.error("BrokenPipeError while closing pool - %e" % e)
        except Exception as e:
            logging.error("Error while closing pool - %e" % e)
            raise e

    def getClasses(self) -> list:
        self.__buildSchemas()
        res = list(self.objectClassSchema["ldap" if self.ldap_naming else "cn"].keys())
        res.sort(key=len)
        return res

    def __getstate__(self):
        state = self.__dict__.copy()
        # Don't pickle these fields so multiprocessing in spawn context works
        del state["_NTDS__db"]
        del state["_NTDS__datatable"]
        print("pickle")
        return state
