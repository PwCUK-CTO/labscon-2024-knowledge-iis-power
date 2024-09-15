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
| IIS Backdoor | First Observed | IIS Type | MITRE | Aliases |
| ------------ | -------------- | -------- | ----- | ------- |
| SpiderExecute | Q3 2024 | Managed | T1505.004, T1071.001, T1059.003, T1090.002 | n/a |
| ZeroOneCookie | Q2 2024 | Managed | T1505.004, T1071.001, T1059.003, T1059.001 | n/a |
| reGeorgIIS | Q2 2024 | Native | T1071.001, T1059.003, T1505.004, T1090.002, T1090.001, T1105 | n/a |
| ReviseIIS | Q1 2024 | Managed | T1071.001, T1505.004, T1059.001, T1059.003, T1047, T1003.004 | n/a |
| Detele | Q2 2023 | Managed | T1562.002, T1562.001, T1071.001, T1105, T1082, T1057, T1083, T1055, T1059.003, T1059.001, T1505.004 | n/a |
| SessionsIIS | Q1 2023 | Native | T1059.003, T1505.004, T1071.001, T1132.001, T1106 | n/a |
| TigerIIS | Q1 2023 | Native | T1071.001, T1059.003, T1105, T1027.007, T1505.004, T1036 | n/a |
| LightHandIIS | Q1 2023 | Native | T1105, T1059.003, T1505.004, T1071.001, T1036 | n/a |
| Frebniis | Q1 2023 | Native | T1505.004, T1071.001, T1106, T1055, T1574 | n/a |
| CookieHash | Q1 2023 | Native | T1505.004, T1071.001, T1059.003, T1083, T1057, T1082, T1070.004, T1105 | IISCook (Kaspersky) |
| MethedLoader | Q4 2022 | Native | T1505.004, T1071.001, T1574, T1140 | n/a |
| NoSuch | Q3 2022 | Native | T1505.004, T1059.003, T1071.001, T1036 | n/a |
| SessionManager | Q3 2021 | Native | T1505.004, T1059.003, T1071.001, T1090.001, T1070.004, T1105, T1036 | n/a |
| RainOwa | Q3 2021 | Managed | T1505.004, T1071.001, T1059.003, T1480, T1036 | n/a |
| DoorMe | Q3 2021 | Native | T1505.004, T1071.001, T1059.003, T1082, T1057, T1083, T1105, T1070.006, T1027.007, T1027, T1036 | n/a |
| XCookie | Q2 2021 | Native | T1505.004, T1059.003, T1071.001, T1132.001 | Group 3 (ESET) |
| Owowa | Q2 2021 | Managed | T1071.001, T1505.004, T1059.001, T1070.004, T1056.003, T1557, T1036 | n/a |
| FakeImage | Q3 2020 | Native | T1059.003, T1505.004, T1071.001, T1105, T1082, T1083, T1135, T1033, T1070.004, T1070.006 | Group 7 (ESET) |
| DeployFilterIIS | Q3 2020 | Managed | T1071.001, T1505.004, T1082, T1083, T1105, T1070.004, T1070.006, T1059.003, T1213, T1036 | n/a |
| IIS-Raid | Q1 2020 | Native | T1505.004, T1059.003, T1055, T1071.001, T1036 | Group 1 (ESET) |
| LimitedCookie | Q3 2019 | Managed | T1071.001, T1505.004, T1059.001, T1059.003, T1055, T1105 | IIS_Backdoor (Backdoor author) |
| ThreeTrack | Q1 2019 | Native | T1505.004, T1059.003, T1071.001, T1059.005, T1036 | n/a |
| BlackMould | Q4 2018 | Native | T1071.001, T1505.004, T1059.003, T1070.004, T1082, T1105 | n/a |
| TripleRIIS | 2018 | Native | T1505.004, T1105, T1059.003, T1071.001 | Group 2 (ESET) |
| GoodDownload | 2018 | Native | T1505.004, T1071.001, T1082, T1033, T1105 | Group 8 (ESET) |
| ExOwa | 2017 | Managed | T1071.001, T1505.004, T1105, T1056.002, T1557, T1059.003, T1083, T1070.004, T1036 | n/a |
| RGDoor | 2016 | Native | T1071.001, T1059.003, T1105, T1505.004 | Group 4 (ESET) |

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