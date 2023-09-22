import logging
import argparse
from impacket.examples import logger
from os.path import basename
from textwrap import dedent
from ntdissector import __version__
from ntdissector.ntds import NTDS


def main():
    parser = argparse.ArgumentParser(add_help=True, description=f"NTDS Dissector v{__version__}", formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("-V", "--version", action="version", version=__version__, help="Display version info")

    dbgroup = parser.add_argument_group("Files")
    dbgroup.add_argument("-system", action="store", help="SYSTEM hive to parse")
    dbgroup.add_argument("-ntds", action="store", required=True, help="NTDS file to parse")
    dbgroup.add_argument("-bootKey", action="store", help="Force bootkey (skips the SYSTEM hive parsing)")
    dbgroup.add_argument("-outputdir", action="store", help=f"Base output directory\n(Default: {NTDS.defaultdir}/out/)")
    dbgroup.add_argument("-cachedir", action="store", help=f"Base cache directory\n(Default: {NTDS.defaultdir}/.cache/)")

    fgroup = parser.add_argument_group("Filter options")
    fgroup.add_argument(
        "-f",
        "--filter",
        action="store",
        type=lambda v: v.split(","),
        default=["user", "secret", "group", "domainDNS"],
        help="""Filter object classes, 'all' to dump everything.\nUse -filters to get a list of available object classes\nDefault: [user, secret, group, domainDNS].\n""",
    )
    fgroup.add_argument("-filters", action="store_true", default=False, help="Print all classes available for filtering")
    fgroup.add_argument("-limit", action="store", default=None, type=int, help="Dump a specific number of objects then stop")

    dgroup = parser.add_argument_group("Display options")
    dgroup.add_argument("-cn", action="store_true", default=False, help="Toggle CN naming output (Default: LDAP naming)")
    dgroup.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")
    dgroup.add_argument("-verbose", action="store_true", help="Turn INFO output ON")
    dgroup.add_argument("-silent", action="store_true", help="Silent")
    dgroup.add_argument("-ts", action="store_true", help="Adds a timestamp to every logging output")
    dgroup.add_argument("-keepDel", action="store_true", default=False, help="Keeps deleted records")

    mgroup = parser.add_argument_group("Miscellaneous")
    mgroup.add_argument("-w", "-workers", dest="workers", action="store", type=int, default=5, help="Number of workers (default: 5)")
    mgroup.add_argument("-nocache", dest="saveCache", action="store_false", default=True, help="Disable cache")
    mgroup.add_argument("-dryRun", action="store_true", help="Launch in dry run mode, ignores cache files")

    parser.epilog = dedent(
        f"""
Examples:

> Dump users, groups and domain backup keys
$ ntdissector -ntds NTDS.dit -system SYSTEM -outputdir /tmp/ntdissector/ -ts -f user,group,secret

> Dump all records from the database
$ ntdissector -ntds NTDS.dit -system SYSTEM -outputdir /tmp/ntdissector/ -ts -f all

> Dump user objects and include deleted records
$ ntdissector -ntds NTDS.dit -system SYSTEM -outputdir /tmp/ntdissector/ -ts -f user -keepDel

> List object classes available to filter records
$ ntdissector -ntds NTDS.dit  -filters
"""
    )

    options = parser.parse_args()

    logger.init(ts=options.ts)
    if options.silent:
        logging.getLogger().setLevel(logging.ERROR)
    elif options.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif options.verbose:
        logging.getLogger().setLevel(logging.INFO)

    if options.cn:
        options.__setattr__("ldap_naming", False)
    else:
        options.__setattr__("ldap_naming", True)

    ntdis = NTDS(options.ntds, options)

    if options.filters:
        logging.info("Available classes")
        print(*ntdis.getClasses(), sep="\n")
        exit(0)

    # ntds.dumpObjects(options.filter, options.limit)

    ntdis.dumpObjectsT(options.filter, options.limit)


if __name__ == "__main__":
    main()
