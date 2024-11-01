[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


## PTMULTIFINDER - Custom Source Domain Testing Tool

ptmultifinder automates the testing of multiple domains from a provided wordlist. It connects to each domain and checks against specified sources to identify matches. It also verifies the existence of the specified sources. Ideal for bulk domain analysis and discovering specific types of domains.

## Installation
```
pip install ptmultifinder
```

## Adding to PATH
If you're unable to invoke the script from your terminal, it's likely because it's not included in your PATH. You can resolve this issue by executing the following commands, depending on the shell you're using:

For Bash Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

For ZSH Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshrc
source ~/.zshrc
```

## Usage examples
```
ptmultifinder -f domains.txt -s sources.txt
ptmultifinder -f domains.txt -s admin.php .git/ backup/
ptmultifinder -f domains.txt -s sources.txt -ch -t 500 -sy admin
```

## Options
```
-f   --file         <file>          Specify file with list of domains to test
-s   --source       <source>        Specify file with list of sources to check for (index.php, admin/, .git/HEAD, .svn/entries)
-sc  --status-code  <status-code>   Specify status codes that will be accepted (default 200)
-sy  --string-yes   <string-yes>    Show domain only if it contains specified strings
-sn  --string-no    <string-no>     Show domain only if it does not contain specified strings
-ch  --check                        Skip domain if it responds with a status code of 200 to a non-existent resource.
-p   --proxy        <proxy>         Set proxy (e.g. http://127.0.0.1:8080)
-a   --user-agent   <agent>         Set User-Agent
-t   --threads      <threads>       Set threads count
-T   --timeout      <timeout>       Set timeout (default 5s)
-H   --headers      <header:value>  Set custom header(s)
-v   --version                      Show script version and exit
-h   --help                         Show this help message and exit
-j   --json                         Output in JSON format
```

## Dependencies
```
ptlibs
```

## License

Copyright (c) 2024 Penterep Security s.r.o.

ptmultifinder is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

ptmultifinder is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with ptmultifinder. If not, see https://www.gnu.org/licenses/.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!