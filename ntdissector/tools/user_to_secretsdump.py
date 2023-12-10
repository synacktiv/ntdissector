import argparse
import json
import logging

def main():
    parser = argparse.ArgumentParser(
                        prog='JSON NT hashes converter')
    parser.add_argument('files', type=str, nargs='+')
    args = parser.parse_args()

    for fl in args.files:
        with open(fl, 'r', encoding='utf-8') as f:
            for l in f:
                try:
                    j = json.loads(l)
                except:
                    logging.error("Failed to parse %s" % l)
                    continue
                rid = j.get('objectSid', '').split('-')[-1]
                if "userPrincipalName" in j.keys():
                    username = "%s\\%s" % (j.get("userPrincipalName").split("@")[-1], j.get("sAMAccountName"))
                else:
                    username = j.get("sAMAccountName", None)
                    username = username if username is not None else j.get("name") # for ADAM NTDS
                if "cn" in j.keys() and "unicodePwd" in j.keys():
                    if "pwdLastSet" in j.keys():
                        if "ACCOUNTDISABLE" not in j.get('userAccountControl', []):
                            status = "Enabled"
                        else:
                            status = "Disabled"
                        print("%s:%s:%s:%s::: (pwdLastSet=%s) (status=%s)" % (username, rid, j.get("dBCSPwd", "aad3b435b51404eeaad3b435b51404ee"), j["unicodePwd"], j['pwdLastSet'], status))

                if "cn" in j.keys() and "ntPwdHistory" in j.keys():
                    i = 0
                    for h in j["ntPwdHistory"]:
                        if "lmPwdHistory" in j:
                            lm = j["lmPwdHistory"][i] if i < len(j["lmPwdHistory"]) else "aad3b435b51404eeaad3b435b51404ee"
                            lm = lm if "dBCSPwd" in j else "aad3b435b51404eeaad3b435b51404ee"
                        else:
                            lm = "aad3b435b51404eeaad3b435b51404ee"
                        print("%s_history%d:%s:%s:%s" % (username, i, rid, lm, h))
                        i += 1


if __name__ == "__main__":
    main()
