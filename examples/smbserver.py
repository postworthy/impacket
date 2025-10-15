#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Simple SMB Server example.
#
# Author:
#   Alberto Solino (@agsolino)
#

import sys
import argparse
import logging

from impacket.virtualfs import VirtualFS, add_virtual_share

from impacket.examples import logger
from impacket import smbserver, version
from impacket.ntlm import compute_lmhash, compute_nthash

if __name__ == '__main__':

    # Init the example's logger theme
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "This script will launch a SMB Server and add a "
                                     "share specified as an argument. Usually, you need to be root in order to bind to port 445. "
                                     "For optional authentication, it is possible to specify username and password or the NTLM hash. "
                                     "Example: smbserver.py -comment 'My share' TMP /tmp\n"
                                     "In-memory example: smbserver.py SHARE virtual_root --virtual-json '{\"test\": {\"test.txt\": \"hello world\"}}'\n"
                                     "Test with: smbclient //127.0.0.1/SHARE -N -c 'ls; get test/test.txt -'")

    parser.add_argument('shareName', action='store', help='name of the share to add')
    parser.add_argument('sharePath', action='store', help='path of the share to add')
    parser.add_argument('-comment', action='store', help='share\'s comment to display when asked for shares')
    parser.add_argument('-username', action="store", help='Username to authenticate clients')
    parser.add_argument('-password', action="store", help='Password for the Username')
    parser.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes for the Username, format is LMHASH:NTHASH')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ip', '--interface-address', action='store', default=argparse.SUPPRESS, help='ip address of listening interface ("0.0.0.0" or "::" if omitted)')
    parser.add_argument('-port', action='store', default='445', help='TCP port for listening incoming connections (default 445)')
    parser.add_argument('-dropssp', action='store_true', default=False, help='Disable NTLM ESS/SSP during negotiation')
    parser.add_argument('-6','--ipv6', action='store_true',help='Listen on IPv6')
    parser.add_argument('-smb2support', action='store_true', default=False, help='SMB2 Support (experimental!)')
    parser.add_argument('--virtual-json', action='store', default=None,
                        help='JSON document describing a virtual, in-memory filesystem for this share')
    parser.add_argument('--virtual-json-file', action='store', default=None,
                        help='Load the virtual filesystem description from a JSON file')
    parser.add_argument('-outputfile', action='store', default=None, help='Output file to log smbserver output messages')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    try:
       options = parser.parse_args()
    except Exception as e:
       logging.critical(str(e))
       sys.exit(1)

    logger.init(options.ts, options.debug)

    if options.comment is None:
        comment = ''
    else:
        comment = options.comment

    if 'interface_address' not in options:
        options.interface_address = '::' if options.ipv6 else '0.0.0.0'

    server = smbserver.SimpleSMBServer(listenAddress=options.interface_address, listenPort=int(options.port), ipv6=options.ipv6)

    if options.outputfile:
        logging.info('Switching output to file %s' % options.outputfile)
        server.setLogFile(options.outputfile)

    share_name = options.shareName.upper()
    server.addShare(share_name, options.sharePath, comment)
    server.setSMB2Support(options.smb2support)
    server.setDropSSP(options.dropssp)

    vfs_spec = None
    if options.virtual_json_file:
        try:
            with open(options.virtual_json_file, 'r', encoding='utf-8') as handle:
                vfs_spec = handle.read()
        except OSError as exc:
            logging.error('Unable to read virtual JSON file %s: %s', options.virtual_json_file, exc)
            sys.exit(1)
    elif options.virtual_json:
        vfs_spec = options.virtual_json

    if vfs_spec is not None:
        try:
            vfs = VirtualFS.from_json(vfs_spec)
        except Exception as exc:
            logging.error('Invalid virtual filesystem description: %s', exc)
            sys.exit(1)
        add_virtual_share(options.sharePath, vfs, share_name=share_name)
        logging.info('Registered virtual filesystem for share %s', share_name)

    # If a user was specified, let's add it to the credentials for the SMBServer. If no user is specified, anonymous
    # connections will be allowed
    if options.username is not None:
        # we either need a password or hashes, if not, ask
        if options.password is None and options.hashes is None:
            from getpass import getpass
            password = getpass("Password:")
            # Let's convert to hashes
            lmhash = compute_lmhash(password)
            nthash = compute_nthash(password)
        elif options.password is not None:
            lmhash = compute_lmhash(options.password)
            nthash = compute_nthash(options.password)
        else:
            lmhash, nthash = options.hashes.split(':')

        server.addCredential(options.username, 0, lmhash, nthash)

    # Here you can set a custom SMB challenge in hex format
    # If empty defaults to '4141414141414141'
    # (remember: must be 16 hex bytes long)
    # e.g. server.setSMBChallenge('12345678abcdef00')
    server.setSMBChallenge('')

    # Rock and roll
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nInterrupted, exiting...")
        sys.exit(130)
