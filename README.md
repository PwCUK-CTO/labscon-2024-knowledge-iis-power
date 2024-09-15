# Knowledge IIS power - LABScon 2024
Supplemental material for the talk 'Knowledge IIS power' at LABScon 2024 by John Southworth (@BitsOfBinary).

## IoCs
The file `iocs.csv` contains all observed IIS backdoor SHA-256 hashes, along with the relevant backdoor name.

## YARA rules
YARA rules are separated into separate files depending on their purpose in the `yara` folder:
- `backdoor_rules.yar` - backdoor specific YARA rules
- `heuristic_rules.yar` - heuristic rules to capture multiple observations/techniques used in IIS malware
- `iis_module_identification_rules.yar` - heuristics to identify IIS modules (note: these will pick up benign samples as well)
- `other_rules.yar` - rules for IIS malware that isn't neatly categorised as per the other entries
- `redirector_rules.yar` - redirector specific YARA rules

## IIS backdoors
Below is a table of the discussed IIS backdoors in the talk:
| IIS Backdoor | First Observed | IIS Type | MITRE | Aliases | Description |
| ------------ | -------------- | -------- | ----- | ------- | ----------- |
| SpiderExecute | Q3 2024 | Managed | T1505.004, T1071.001, T1059.003, T1090.002 | n/a | Executing Windows shell commands, or performing SEO poisoning by redirecting traffic from web crawlers to harcoded URL paths. |
| ZeroOneCookie | Q2 2024 | Managed | T1505.004, T1071.001, T1059.003, T1059.001 | n/a | Will load in commands from Cookie values, and can either execute them via cmd.exe or PowerShell. |
| reGeorgIIS | Q2 2024 | Native | T1071.001, T1059.003, T1505.004, T1090.002, T1090.001, T1105 | n/a | IIS implementation of reGeorg tunnel tool, which can also drop files to disk, exfiltrate files to the operator, and execute shell commands. |
| ReviseIIS | Q1 2024 | Managed | T1071.001, T1505.004, T1059.001, T1059.003, T1047, T1003.004 | n/a | Designed to be installed on Exchange servers. On top of execute shell commands, it can also run PowerShell commands for Web Services for Management (WSMan) and in the Exchange Management Shell to remotely administer the Exchange server, as well as dumping LSA secrets. |
| Detele | Q2 2023 | Managed | T1562.002, T1562.001, T1071.001, T1105, T1082, T1057, T1083, T1055, T1059.003, T1059.001, T1505.004 | n/a | Executes a variety of commands (either built-in or via the command shell, PowerShell or .NET), as well as evading detection through capabilities to patch ETW/AMSI. |
| SessionsIIS | Q1 2023 | Native | T1059.003, T1505.004, T1071.001, T1132.001, T1106 | n/a | Lightweight shell access to an infected server, supporting multiple formats for executing shell commands. |
| TigerIIS | Q1 2023 | Native | T1071.001, T1059.003, T1105, T1027.007, T1505.004, T1036 | n/a | IIS module variant of the Andariel backdoor/loader known as TigerDownloader. Can execute shell commands, and download/upload files to a C2. |
| LightHandIIS | Q1 2023 | Native | T1105, T1059.003, T1505.004, T1071.001, T1036 | n/a | IIS module implementation of the LightHand backdoor, used by Andariel/Onyx Sleet (a sub-group of Lazarus Group). Can execute shell commands and drop files. |
| Frebniis | Q1 2023 | Native | T1505.004, T1071.001, T1106, T1055, T1574 | n/a | Will inject code into the legitimate IIS module iisfreb.dll, and listen for specific HTTP requests to decrypt and load a further .NET backdoor to either proxy traffic or execute further .NET code. |
| CookieHash | Q1 2023 | Native | T1505.004, T1071.001, T1059.003, T1083, T1057, T1082, T1070.004, T1105 | IISCook (Kaspersky) | Receives commands through hashed cookie values. Can perform a variety of functions, including file management, system/process information gathering, and executing further commands. |
| MethedLoader | Q4 2022 | Native | T1505.004, T1071.001, T1574, T1140 | n/a | Designed to intercept HTTP GET requests made to other (legitimate) IIS modules, searching for encoded payloads in those intercepted requests, and decrypting, loading and executing a PE file from them. |
| NoSuch | Q3 2022 | Native | T1505.004, T1059.003, T1071.001, T1036 | n/a | Limited functionality of uploading/downloading files and executing shell commands via named pipes. |
| SessionManager | Q3 2021 | Native | T1505.004, T1059.003, T1071.001, T1090.001, T1070.004, T1105, T1036 | n/a | Likely associated with GELSEMIUM. It can do basic file managemt (upload/download/delete), execute commands, and proxy traffic. |
| RainOwa | Q3 2021 | Managed | T1505.004, T1071.001, T1059.003, T1480, T1036 | n/a | Capability to execute shell commands, but it applies execution guardrails based on both a password and expected requestor IP address, which are obtained from values hardcoded in a registry key (which would have to be set prior to the module installation). |
| DoorMe | Q3 2021 | Native | T1505.004, T1071.001, T1059.003, T1082, T1057, T1083, T1105, T1070.006, T1027.007, T1027, T1036 | n/a | Used by a threat actor known as ChamelGang/CamoFei. Usually obfuscated, with functionality of being able to execute further code and gather basic system information. |
| XCookie | Q2 2021 | Native | T1505.004, T1059.003, T1071.001, T1132.001 | Group 3 (ESET) | Only functionality is to execute shell commands. |
| Owowa | Q2 2021 | Managed | T1071.001, T1505.004, T1059.001, T1070.004, T1056.003, T1557, T1036 | n/a | Backdoor/stealer designed to log and encrypt details associated with successful OWA logins on an infected web server. Can exfiltrate these RSA encrypted logs, delete the log file itself, and also execute PowerShell commands. |
| FakeImage | Q3 2020 | Native | T1059.003, T1505.004, T1071.001, T1105, T1082, T1083, T1135, T1033, T1070.004, T1070.006 | Group 7 (ESET) | Has a variety of features, such as file management (including exfiltrating/dropping files), system information gathering, network share mounting, and executing shell commands. |
| DeployFilterIIS | Q3 2020 | Managed | T1071.001, T1505.004, T1082, T1083, T1105, T1070.004, T1070.006, T1059.003, T1213, T1036 | n/a | Implementation of the DeployFilter webshell, which is based on China Chopper. Can execute shell commands, gather system information, perform file management (downloading, uploading, deleting, copying) and run SQL commands for connected databases. |
| IIS-Raid | Q1 2020 | Native | T1505.004, T1059.003, T1055, T1071.001, T1036 | Group 1 (ESET) | Open source backdoor with multiple commands supported. Variants observed changing up default strings to evade detection. |
| LimitedCookie | Q3 2019 | Managed | T1071.001, T1505.004, T1059.001, T1059.003, T1055, T1105 | IIS_Backdoor (Backdoor author) | Open source managed IIS backdoor which can execute commands either via cmd.exe or PowerShell, drop files to disk, or inject shellcode into a newly spawned process. |
| ThreeTrack | Q1 2019 | Native | T1505.004, T1059.003, T1071.001, T1059.005, T1036 | n/a | Can execute shell commands via cscript and cmd.exe, and also drop files to disk. The backdoor is likely related to the Yellow Maero backdoor RGDoor. |
| BlackMould | Q4 2018 | Native | T1071.001, T1505.004, T1059.003, T1070.004, T1082, T1105 | n/a | Likely based on China Chopper, used by Red Moros (a.k.a. Granite Typhoon, Alloy Taurus). Can execute shell commands, drop further files to disk, and gather basic system information like drive info. |
| TripleRIIS | 2018 | Native | T1505.004, T1105, T1059.003, T1071.001 | Group 2 (ESET) | Characterised by the use of the Crypto++ library, can execute shell commands, and download/upload further files. |
| GoodDownload | 2018 | Native | T1505.004, T1071.001, T1082, T1033, T1105 | Group 8 (ESET) | Can execute processes and shellcode, as well as dropping files to disk and gathering system information. |
| ExOwa | 2017 | Managed | T1071.001, T1505.004, T1105, T1056.002, T1557, T1059.003, T1083, T1070.004, T1036 | n/a | Designed to be installed on OWA servers, with the main purpose of intecepting OWA auth attempts and saving off data (username, password, IP address, user agent and timestamp). Can also execute shell commands, and perform file management (uploading, downloading, deleting). Seen being used in the DeadRinger campaigns, likely by a China-based threat actor. |
| RGDoor | 2016 | Native | T1071.001, T1059.003, T1105, T1505.004 | Group 4 (ESET) | Used by Yellow Maero (a.k.a. OilRig). Can run shell commands and download/upload files. |

## IISHelper Plugin
To help automate some parts of native IIS module analysis, the following IDA Pro plugin is available: https://github.com/PwCUK-CTO/iis-helper-plugin

## References
- https://web-assets.esetstatic.com/wls/2021/08/eset_anatomy_native_iis_malware.pdf
- https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/what-iis-that-malware.html
- https://www.microsoft.com/en-us/security/blog/2019/12/12/gallium-targeting-global-telecom/
- https://www.cybereason.com/blog/research/deadringer-exposing-chinese-threat-actors-targeting-major-telcos
- https://unit42.paloaltonetworks.com/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/
- https://symantec-enterprise-blogs.security.com/threat-intelligence/frebniis-malware-iis
- https://securelist.com/the-sessionmanager-iis-backdoor/106868/
- https://securelist.com/owowa-credential-stealer-and-remote-access/105219/
- https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/new-apt-group-chamelgang/
- https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry
- https://www.microsoft.com/en-us/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/
- https://research.checkpoint.com/2024/iranian-malware-attacks-iraqi-government/
- https://blog.talosintelligence.com/dragon-rank-seo-poisoning/