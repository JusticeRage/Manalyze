#!/usr/bin/env python3

"""
    This file is part of Manalyze.

    Manalyze is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Manalyze is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Manalyze.  If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import os
import shutil
import tarfile
import zlib
import uuid
import argparse
from parse_clamav import parse_ndb, parse_ldb

try:
    import requests
except ModuleNotFoundError as e:
    print('Please install the requests module to use thie script.')
    print("$> pip3 install requests")
    sys.exit(1)

URL_MAIN = "https://database.clamav.net/main.cvd"
URL_DAILY = "https://database.clamav.net/daily.cvd"


def download_file(url):
    """
    Downloads a file.
    """
    file_name = url.split('/')[-1]
    r = requests.get(url, stream=True, headers={
        'User-Agent': f'CVDUPDATE/0.3.3 ({str(uuid.uuid4())})'
    })
    if r.status_code == 429:
        print(f"The remote server indicates that this IP is rate-limited. Please try again in 12 hours.")
        sys.exit(0)
    elif r.status_code != 200:
        print(f"Could not download {url} (Status: {r.status_code}).")
        sys.exit(1)
    with open(file_name, 'wb') as outfile:
        file_size = r.headers.get('Content-Length')
        if file_size is None:
            outfile.write(r.content)
            return
        
        downloaded = 0
        chunk_size = 8192
        file_size = int(file_size)
        print("Downloading: %s Bytes: %s" % (file_name, file_size))
        for d in r.iter_content(chunk_size):
            downloaded += len(d)
            outfile.write(d)
            status = "\r%10d  [%3.2f%%]" % (downloaded, downloaded * 100. / file_size)
            status += chr(8) * (len(status) + 1)
            print(status, end="")




def zlib_decompress(path, outpath):
    d = zlib.decompressobj(zlib.MAX_WBITS + 16)
    input = open(path, "rb")
    output = open(outpath, "wb")
    if not input or not output:
        print("[!] Error decompressing signatures.")
        sys.exit(-1)

    while True:
        chunk = input.read(2048)
        if not chunk:
            break
        uncompressed = d.decompress(chunk)
        output.write(uncompressed)

    input.close()
    output.close()
    os.remove(path)


def update_signatures(url, download):
    # Download CVD file if necessary
    if download:
        download_file(url)
    file_name = url.split('/')[-1]
    file_basename = file_name.split('.')[-2]

    # Extract signatures
    f = open(file_name, "rb")
    if not f or len(f.read(512)) != 512:  # Skip the CVD header
        print("[!] Error reading main.cvd!")
        sys.exit(-1)

    g = open("%s.tar.gz" % file_basename, "wb")
    if not g:
        f.close()
        print("[!] Error writing to %s.tar.gz!" % file_basename)
        sys.exit(-1)

    # Create a copy of the virus definitions without the ClamAV header (it becomes a valid TGZ file)
    while True:
        data = f.read(2048)
        if not data:
            break
        g.write(data)

    f.close()
    g.close()

    # We need to keep a set of all the signatures seen, because there are duplicates in the ClamAV database and
    # Yara doesn't like that.
    RULES = set()

    # Excract the signatures
    zlib_decompress("%s.tar.gz" % file_basename, "%s.tar" % file_basename)
    tar = tarfile.open("%s.tar" % file_basename)
    tar.extract("%s.ndb" % file_basename)
    os.chmod("%s.ndb" % file_basename, 0o644)
    if "%s.ldb" % file_basename in tar.getnames():
        tar.extract("%s.ldb" % file_basename)
        os.chmod("%s.ldb" % file_basename, 0o644)
    tar.close()
    parse_ndb("%s.ndb" % file_basename, "clamav.yara", file_basename != "main")
    if os.path.exists("%s.ldb" % file_basename):
        parse_ldb("%s.ldb" % file_basename, "clamav.yara", file_basename != "main")
        os.remove("%s.ldb" % file_basename)
    os.remove("%s.tar" % file_basename)
    os.remove("%s.ndb" % file_basename)

# Work in the script's directory
if os.path.dirname(sys.argv[0]) != "":
    os.chdir(os.path.dirname(sys.argv[0]))

parser = argparse.ArgumentParser(description="Updates ClamAV signatures for plugin_clamav.")
parser.add_argument("--main", action="store_true", help="Update ClamAV's main signature file.")
parser.add_argument("--skip-download", dest="skipdownload", action="store_false",
                    help="Work with local copies of ClamAV signature files.")
args = parser.parse_args()

try:
    os.remove("clamav.yara")
except OSError:
    pass

if not os.path.exists("clamav.main.yara"):
    args.main = True

if args.main:
    if os.path.exists("clamav.main.yara"):
        os.remove("clamav.main.yara")
    with open("clamav.yara", "wb") as f:
        f.write(b'import "manape"\n\n')  # Do not forget to import our module.
    update_signatures(URL_MAIN, args.skipdownload)
    shutil.copy("clamav.yara", "clamav.main.yara")  # Keep a copy to which we can append future daily signature files.
else:
    # Use the old clamav.main.yara as a base and append the daily rules to it.
    shutil.copy("clamav.main.yara", "clamav.yara")

update_signatures(URL_DAILY, args.skipdownload)

try:
    os.remove("clamav.yarac")
except OSError:
    pass
os.chmod("clamav.yara", 0o644)

# TODO: Support .hdb & .mdb (hashes of known malwares / sections) - http://resources.infosecinstitute.com/open-source-antivirus-clamav/
# TODO: Support .ldb (logical signatures)? Seems hard :(
