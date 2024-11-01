#!/usr/bin/python3
"""
    Copyright (c) 2024 Penterep Security s.r.o.

    ptmultifinder is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ptmultifinder is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of

    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ptmultifinder.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import os
import socket
import sys; sys.path.append(__file__.rsplit("/", 1)[0])
import json
import requests
import re
import warnings

from typing import List
from _version import __version__

from ptlibs import ptjsonlib, ptmisclib, ptprinthelper, ptnethelper, tldparser, sockets
from ptlibs.threads import ptthreads, printlock

from concurrent.futures import ThreadPoolExecutor, as_completed


class PtMultiFinder:
    def __init__(self, args):
        self.ptjsonlib = ptjsonlib.PtJsonLib()
        self.ptthreads = ptthreads.PtThreads()
        self.headers   = ptnethelper.get_request_headers(args)
        self.use_json  = args.json
        self.timeout   = args.timeout
        self.args      = args
        self.proxies   = {"http": args.proxy, "https": args.proxy}

        try:
            self.domains = ptmisclib.read_file(args.file)
        except FileNotFoundError:
            self.ptjsonlib.end_error(f"File '{args.file}' not found", self.use_json)

        if len(self.domains) > 1 and self.use_json:
            ptprinthelper.ptprint("Error: Cannot test more than 1 domain while --json parameter is present", "ERROR")
            sys.exit(1)


    def run(self, args):
        self.sources = self.get_sources(args.source)
        ptprinthelper.ptprint("Testing domains:", "TITLE", not self.use_json, colortext=True)

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_domain = {executor.submit(self.check_domains, domain): domain for domain in self.domains}

            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    future.result()
                except Exception as e:
                    pass

    def check_domains(self, domain: str):
        """Threaded check domain method"""
        if not re.match(r'^https?://', domain):
            domain = 'https://' + domain

        if self.args.check:
            # Checks status code of non-existing resource
            response = requests.get(f"{domain}/f00.b4r.n0t.f0und/", allow_redirects=False, timeout=self.timeout, proxies=self.proxies, verify=False, headers=self.headers)
            if response.status_code == 200:
                return

        # Test URL for <sources>
        for file_path in self.sources:
            full_url = f"{domain}/{file_path}"
            try:
                response = requests.get(full_url, allow_redirects=False, timeout=self.timeout, proxies=self.proxies, verify=False, headers=self.headers)
                if not response:
                    return

                if response.status_code in self.args.status_code:
                    if self.proxies and "burp" in response.text.lower():
                        return
                    if self.args.string_yes:
                        if any(string in response.text for string in self.args.string_yes):
                            ptprinthelper.ptprint(f"String-Yes: {full_url}", "TEXT", not self.use_json, colortext=True, flush=True)
                    elif self.args.string_no:
                        if not all([self.args.string_no]) in response.text:
                            ptprinthelper.ptprint(f"String-No: {full_url}", "TEXT", not self.use_json, colortext=True, flush=True)
                    else:
                        ptprinthelper.ptprint(f"{domain}/{file_path}", "TEXT", not self.use_json, colortext=True, flush=True)
            except Exception as e:
                return

    def get_sources(self, sources: List[str]):
        """Process sources (file to test)"""
        if len(sources) == 1 and os.path.exists(sources[0]): # Process sources from file
            with open(os.path.abspath(sources[0]), "r") as source_file:
                return [line.strip() for line in source_file.readlines()]
        else: # Process sources from CLI
            return [source for source in sources]

def get_help():
    return [
        {"usage": ["ptmultifinder <options>"]},
        {"usage_example": [
            "ptmultifinder -f domains.txt -s sources.txt",
            "ptmultifinder -f domains.txt -s admin.php .git/ backup/"
        ]},
        {"options": [
            ["-f",       "--file",         "<file>",                        "Specify file with list of domains to test"],
            ["-s",       "--source",       "<source>",                      "Specify file with list of sources to check for (index.php, admin/, .git/HEAD, .svn/entries)"],
            ["-sc",      "--status-code",  "<status-code>",                 "Specify status codes that will be accepted (default 200)"],
            ["-sy",      "--string-yes",   "<string-yes>",                  "Show domain only if it contains specified strings"],
            ["-sn",      "--string-no",    "<string-no>",                   "Show domain only if it does not contain specified strings"],
            ["-ch",      "--check",        "",                              "Skip domain if it responds with a status code of 200 to a non-existent resource."],
            ["-p",       "--proxy",        "<proxy>",                       "Set proxy (e.g. http://127.0.0.1:8080)"],
            ["-a",       "--user-agent",   "<agent>",                       "Set User-Agent"],
            ["-t",       "--threads",      "<threads>",                     "Set threads count"],
            ["-T",       "--timeout",      "<timeout>",                     "Set timeout (default 5s)"],
            ["-H",       "--headers",      "<header:value>",                "Set custom header(s)"],
            ["-v",       "--version",      "",                              "Show script version and exit"],
            ["-h",       "--help",         "",                              "Show this help message and exit"],
            ["-j",       "--json",         "",                              "Output in JSON format"],
        ]
        }]


def parse_args():
    parser = argparse.ArgumentParser(add_help=False, usage=f"{SCRIPTNAME} <options>")
    parser.add_argument("-f",  "--file",        type=str)
    parser.add_argument("-s",  "--source",      type=str, nargs="+")
    parser.add_argument("-sc", "--status-code", type=int, nargs="*", default=[200])
    parser.add_argument("-sy", "--string-yes",  type=str, nargs="+")
    parser.add_argument("-sn", "--string-no",   type=str, nargs="+")
    parser.add_argument("-a",  "--user-agent",  type=str, default="Penterep Tools")
    parser.add_argument("-H",  "--headers",     type=ptmisclib.pairs, nargs="+")
    parser.add_argument("-t",  "--threads",     type=int, default=100)
    parser.add_argument("-T",  "--timeout",     type=int, default=5)
    parser.add_argument("-p",  "--proxy",       type=str)

    parser.add_argument("-j",  "--json",        action="store_true")
    parser.add_argument("-ch", "--check",       action="store_true")
    parser.add_argument("-v",  "--version",     action="version", version=f"%(prog)s {__version__}")

    parser.add_argument("--socket-address",  type=str, default=None)
    parser.add_argument("--socket-port",     type=str, default=None)
    parser.add_argument("--process-ident",   type=str, default=None)

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json, 0)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptmultifinder"
    args = parse_args()
    script = PtMultiFinder(args)
    # Suppress all warnings
    warnings.filterwarnings("ignore")
    script.run(args)

if __name__ == "__main__":
    main()
