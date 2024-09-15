import "pe"

rule Malware_IIS_SpiderExecute_Backdoor : Heuristic_and_General
{
    meta:
        description = "Detects the IIS managed module backdoor SpiderExecute, which can execute commands and redirect traffic"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-09-09"
        modified_date = "2024-09-09"
        revision = "0"
        malware_family = "SpiderExecute"
        hash = "86f1dd3da0b36d4d7788788df59a59a26bfddfb67a0628492f454561e40f6f39"

    strings:
        $ = "HandleSpiderHijack"
        $ = "IsSpiderReferer"
        $ = "ExecuteCommandFromHeader"
        $ = "\\RequestMonitor\\"
        $ = "execute-cmd-iis" wide
        
    condition:
        any of them
}

rule Malware_ZeroOneCookie_Backdoor : Heuristic_and_General
{
    meta:
        description = "Detects the managed IIS module backdoor ZeroOneCookie, which can execute shell commands and PowerShell"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-09-09"
        modified_date = "2024-09-09"
        revision = "0"
        malware_family = "ZeroOneCookie"
        hash = "3df107aff6fc2fce3c867b9f44e6c1820f96508f539c468c3a88384e2975d3f6"

    strings:
        $ = "RunPs"
        $ = "RunProcess"
        
    condition:
        filesize < 100KB and all of them
}

rule Malware_IIS_reGeorg_Unique_Strings : Heuristic_and_General
{
    meta:
        description = "Detects implementations of the reGeorg webshells in a native IIS module"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-07-29"
        modified_date = "2024-07-29"
        revision = "0"
        malware_family = "reGeorg"
        hash = "e5f520d95cbad6ac38eb6badbe0ad225f133e0e410af4e6df5a36b06813e451b"
        hash = "0b8b10a2ff68cb2aa3451eedac4a8af4bd147ef9ddc6eb84fc5b01a65fca68fd"
        hash = "535586af127e85c5561199a9a1a3254d554a6cb97200ee139c5ce23e68a932bd"

    strings:
        $ = "Source Response Empty!"
        $ = "GetFromSource: "
        $ = "Source Response Len: "
        $ = "FUNCTION GET: Error"
        $ = "Parse IP failed :"
        $ = "tn7rM2851XVvOFbc"
        $ = "Socks connect error: "
        $ = "Clear Rules Success!"
        $ = "Filepath can not be empty!"
        
    condition:
        any of them
}

rule Malware_IIS_ReviseIIS_Backdoor : Heuristic_and_General
{
    meta:
        description = "Detects the managed module IIS backdoor named ReviseIIS"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-09-02"
        modified_date = "2024-09-02"
        revision = "0"
        malware_family = "ReviseIIS"
        hash = "69ed5280a398c0a09552660a9c6cbce5dc40090ac3410382c26dfc59bb2b5ae7"
        hash = "442a337b83337935b0d360eeca9db8c59745180fcaf97c921a57190f120d4b01"
        hash = "b0ef8eb2ce75bc6d451fa618caf78cc6404e9cd4591a2046d43556f6a4518a4a"

    strings:
        $ = "RunExshell"
        $ = "trafficObfuscation"
        
        $ = {0A 00 3C 00 74 00 64 00 3E 00 3C 00 69 00 6D 00 67 00 20 00 73 00 72 00 63 00 3D 00 22 00 64 00 61 00 74 00 61 00 3A 00 69 00 6D 00 61 00 67 00 65 00 2F 00 70 00 6E 00 67 00 3B 00 62 00 61 00 73 00 65 00 36 00 34 00 2C 00}
        $ = {22 00 3E 00 3C 00 2F 00 74 00 64 00 3E 00 0D 00 0A 00 3C 00 2F 00 62 00 6F 00 64 00 79 00 3E 00 3C 00 2F 00 68 00 74 00 6D 00 6C 00 3E 00}
        
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Malware_IIS_ExOwa_Backdoor : Heuristic_and_General
{
    meta:
        description = "Detects samples of the ExOwa IIS backdoor"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-09-02"
        modified_date = "2024-09-02"
        revision = "0"
        malware_family = "ExOwa"
        hash = "f48811c1b76098344af5d5d20742a9d09f2a85d873de4f495430662dd8926f8e"

    strings:
        $ = "Bin\\Microsoft.Exchange.Common.dll" wide
        $ = "\\EXANG" wide
        $ = "\\~ex.dat" wide
        
    condition:
        any of them
}

rule Malware_IIS_Detele_dotNET_Backdoor_Unique_Strings : Heuristic_and_General
{
    meta:
        description = "Detects the managed module IIS backdoor 'Detele' based on unique strings"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-07-29"
        modified_date = "2024-07-29"
        revision = "0"
        malware_family = "Detele"
        hash = "15db49717a9e9c1e26f5b1745870b028e0133d430ec14d52884cec28ccd3c8ab"
        hash = "8571a354b5cdd9ec3735b84fa207e72c7aea1ab82ea2e4ffea1373335b3e88f4"

    strings:
        $ = "[iis] strCmdValueEncrypted"
        $ = "[-] Cat File Left Content Failed"
        $ = "[-] Cat File 0 size"
        $ = "[-] Cat File Failed"
        $ = "[+] Detele Succeed"
        $ = "[-] Detele Failed"
        $ = "[+] .Net Exec Succeed"
        $ = "[-] .Net Exec Failed"
        $ = "[-] .Net Exec Timeout (>20s). Result Maybe Incomplete"
        
    condition:
        any of them
}

rule SessionsIIS_Backdoor_Unique_Timestamp_Key : Heuristic_and_General
{
    meta:
        description = "Detects SessionsIIS backdoor, based on a unique timestamp used as a key to issue commands"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2023-05-15"
        modified_date = "2023-05-15"
        revision = "0"
        malware_family = "SessionsIIS"
        hash = "577ca702d73f2090ce583c5b1fbfcb3101d3c79722c98b3aa8dc6598296182f4"

    strings:
        $ = "Sat, 29 Oct 2021 19:43:31 GMT"
        
    condition:
        any of them
}

rule SessionsIIS_Backdoor_RTTI_Information : Heuristic_and_General
{
    meta:
        description = "Detects SessionsIIS backdoor, based on unique RTTI information"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2023-05-15"
        modified_date = "2023-05-15"
        revision = "0"
        malware_family = "SessionsIIS"
        hash = "577ca702d73f2090ce583c5b1fbfcb3101d3c79722c98b3aa8dc6598296182f4"

    strings:
        $ = "HostRewriteModule"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule SessionsIIS_Backdoor_PDB : Heuristic_and_General
{
    meta:
        description = "Detects SessionsIIS backdoor, based on a unique PDB path"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2023-05-15"
        modified_date = "2023-05-15"
        revision = "0"
        malware_family = "SessionsIIS"
        hash = "577ca702d73f2090ce583c5b1fbfcb3101d3c79722c98b3aa8dc6598296182f4"

    strings:
        $ = "eNe.pdb" fullword
        
    condition:
        any of them
}

rule SessionsIIS_Backdoor_A : Heuristic_and_General
{
    meta:
        description = "Detects the SessionsIIS backdoor, based on a unique combination of strings"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2023-05-15"
        modified_date = "2023-05-15"
        revision = "0"
        malware_family = "SessionsIIS"
        hash = "577ca702d73f2090ce583c5b1fbfcb3101d3c79722c98b3aa8dc6598296182f4"

    strings:
        $ = "_sessionsID"
        $ = "If-Modified-Since"

    condition:
        pe.exports("RegisterModule") and all of them
}

rule SessionsIIS_Backdoor_Internal_DLL_Name : Heuristic_and_General
{
    meta:
        description = "Detects SessionsIIS backdoor, based on a unique DLL name"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2023-05-15"
        modified_date = "2023-05-15"
        revision = "0"
        malware_family = "SessionsIIS"
        hash = "577ca702d73f2090ce583c5b1fbfcb3101d3c79722c98b3aa8dc6598296182f4"

    condition:
        pe.dll_name == "Rewrite.dll"
}

rule Malware_IIS_TigerIIS_Backdoor : Black_Artemis
{
    meta:
        description = "Detects the IIS backdoor TigerIIS, a variant of TigerDownloader/TigerLite, used by Andariel"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
        hash = "4e8b93fdf8847d411d9596b346405f40ce7fb4c46d74ca4f8aff3aec7684eea2"
        malware_family = "TigerIIS"

    strings:
        $dll_name = "Microsoft Credental.dll"
        $key = "MicrosoftCorporationValidation@#$%^&*()!US"
        
        // movsxd  rbx, ecx
        // movzx   ecx, byte ptr [r8+rbx]
        // mov     [r9], cl
        // mov     [r8+rbx], dl
        // movzx   edx, byte ptr [r9]
        // movzx   ecx, byte ptr [r8+rbx]
        // add     edx, ecx
        $crypto_routine = {4863D9410FB60C1841880941881418410FB611410FB60C1803D1}
        
        $c2_str1 = "198409"
        $c2_str2 = "199703"
        $c2_str3 = "202106"
        $c2_str4 = "201445"
        
    condition:
        pe.exports("RegisterModule") and (
            any of ($dll_name, $key, $crypto_routine) or
            all of ($c2_str*)
        )
}

rule Malware_IIS_LightHandIIS_Backdoor : Black_Artemis
{
    meta:
        description = "Detects an IIS implementation of the LightHand/AndarDoor backdoor called LightHandIIS, used by Andariel/Onyx Sleet. This variant can drop files, and execute shell commands."
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-13"
        modified_date = "2024-08-29"
        revision = "1"
        malware_family = "LightHandIIS"
        reference = "https://www.microsoft.com/en-us/security/blog/2024/07/25/onyx-sleet-uses-array-of-malware-to-gather-intelligence-for-north-korea/"
        reference = "https://asec.ahnlab.com/en/56405/"
        hash = "a8875161709f05c510136eb0071095eabaaabe253cd0bd9f0304900d00bc12b7"
        hash = "661ca6cb6b79a4b99c34994be458fcc9d7193a3b6e02d2650c5a79916d889d26"

    strings:
        $log1 = "Read Body Failed!" ascii wide
        $log2 = "Upload Success!" ascii wide
        $log3 = "Create File Failed!" ascii wide
        
        $pdb_path1 = "\\Backup\\IIS-Backup\\"
        $pdb_path2 = "\\IIS-Backup.pdb"
        $pdb_path3 = "A:\\tool\\Backup\\"
        
        $iis_session = {41 53 50 53 45 53 53 49 4f 4e 49 44 [30-36] 3b 20 70 61 74 68 3d 2f}
        
        $iis_class = "CIISModuleFactory"
    
    condition:
        pe.exports("RegisterModule") and 
        (
            all of ($log*) or
            any of ($pdb_path*, $iis_session, $iis_class)
        )
}

rule Malware_IIS_Frebniis_Patching_Code : Heuristic_and_General
{
    meta:
        description = "Detects the Frebniis IIS backdoor based on code used to patch another IIS process"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-07-29"
        modified_date = "2024-07-29"
        revision = "0"
        malware_family = "Frebniis"
        reference = "https://symantec-enterprise-blogs.security.com/threat-intelligence/frebniis-malware-iis"
        hash = "b81c177c440e84635f22dc97b0411de93a24a983a41af676ffbbb4439487aaef"

    strings:
        // lea     rbx, [rax+1770h]
        // mov     rcx, [rbx]
        // sub     rcx, rax
        // cmp     rcx, 66A8h
        // jz      short loc_180007012
        // lea     rbx, [rax+13C0h]
        // mov     rcx, [rbx]
        // sub     rcx, rax
        // cmp     rcx, 48A0h
        // jz      short loc_180007012
        // lea     rbx, [rax+0C010h]
        // mov     rax, [rbx]
        // sub     rax, rdx
        // cmp     rax, 2480h
        $ = {48 8B 0B 48 2B C8 48 81 F9 A8 66 00 00 74 2B 48 8D 98 ?? ?? ?? ?? 48 8B 0B 48 2B C8 48 81 F9 A0 48 00 00 74 15 48 8D 98 ?? ?? ?? ?? 48 8B 03 48 2B C2 48 3D 80 24 00 00}
        
    condition:
        any of them
}

rule Malware_IIS_CookieHash_Backdoor : Heuristic_and_General
{
    meta:
        description = "Detects samples of the CookieHash IIS backdoor, which uses hashed command strings in a 'cookie' field to issue commands"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        malware_family = "CookieHash"
        hash = "d97987b9a7e63973b49d76f06a58048db172f8584710b1c30e58457c54a4d82c"

    strings:
        $format = "%ld|%ld|%s||"
        $xor_routine = {488B13488BC883E11F420FB60C01300C0248FFC08B4B08483BC172E4}
        $dll_name = "iisc_v1.2.dll"
        
        $hash1 = "ab3b3b1357c29e970336d06a3b76dcf6"
        $hash2 = "a53108f7543b75adbb34afc035d4cdf6"
        $hash3 = "44ba5ca65651b4f36f1927576dd35436"
        $hash4 = "caf9b6b99962bf5c2264824231d7a40c"
        $hash5 = "6865aeb3a9ed28f9a79ec454b259e5d0"
        $hash6 = "8812c36aa5ae336c2a77bf63211d899a"
        $hash7 = "76ee3de97a1b8b903319b7c013d8c877"
        $hash8 = "fd456406745d816a45cae554c788e754"
        $hash9 = "d67f249b90615ca158b1258712c3a9fc"
        $hash10 = "9c95319bf274672d6eae7eb97c3dfda5"
        $hash11 = "534735884d341071762ede7af01c53e8"
        $hash12 = "2360dc7a3b0658bc85dd8e53a235b80f"
        $hash13 = "008fe471b782da239ae8607bfb20e366"
        $hash14 = "c3f9e67fe33f14547545e3a07f3d5db7"
        
    condition:
        any of ($format, $xor_routine, $dll_name) or 11 of ($hash*)
}

rule Malware_IIS_Methed_Loader : Heuristic_and_General
{
    meta:
        description = "Detects a malicious IIS module, used to decrypt, load and execute payloads from malicious HTTP requests"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "30e70931a7b18eca5821748f6e7d24ef182792d2c5ebabbee649b19eb266c1f6"
        hash = "750bb8ed4ebb000de9923f03eb61168b5e8a1a7836fbea0165c4b0293e9e412b"
        hash = "68fea78646599c81bcac6f1c07992167c6dd4daa786f774a89c422f0dffe880b"
        hash = "343aa1f9f7bc720b5317276d4c5f8835ab6980c0c2de3d2bf3f3ea768374ab25"
        hash = "f551b50b6b2a17c2196e12bf81240031a0dd7de1fbd2a417b68bbbe1e27cfeb6"
        hash = "259d7c07a0bdf2e846393ffc9c66c331da77f9fe0f8acb102ed5430d95e9285a"
        malware_family = "MethedLoader"

    strings:
        $ = "Ope#2Rx@Lq"
        $ = {C1 EA 05 8D 0C 92 C1 E1 03 2B C1 8B 8D ?? ?? ?? ?? 0F B6 04 38}
        
    condition:
        any of them
}

rule Malware_IIS_NoSuch_Backdoor : Heuristic_and_General
{
    meta:
        description = "Detects the NoSuch IIS backdoor, based on unique strings. The backdoor can execute shell commands, and download/upload files."
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        malware_family = "NoSuch"
        hash = "6a6bd8b772bbe54d7b425161cf7505fa3739a24b411d70dc9364cfd79b2e7b75"

    strings:
        $ = "NoSuchHeaderError"
        $ = "WaitForSingleObject for cmd subprocess failed."
        $ = "Failed to set the STDOUT's read handle information."
        $ = "getFile: offset exceeds file size"
        $ = "qNfn3mYyasd75Adne"
        $ = "HttpLib final buffer size different than expected"
        $ = "Upload File - empty buffer."
        $ = "Upload File - empty destFilePath string."
        $ = "Uploader: CreateFile failed."
        $ = "Uploader: WriteFile failed."
        
    condition:
        any of them
}

rule Malware_IIS_SessionManager_Internal_Class_Name : Heuristic_and_General
{
    meta:
        description = "Detects the SessionManager IIS backdoor, based on the unique class name 'SessionManagerModule'"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-09"
        modified_date = "2024-08-09"
        revision = "0"
        malware_family = "SessionManager"
        reference = "https://securelist.com/the-sessionmanager-iis-backdoor/106868/"
        reference = "https://unit42.paloaltonetworks.com/rare-possible-gelsemium-attack-targets-se-asia/"
        hash = "4464dc2f9b7c5b022725277b0c665b62c5f5321b49f4b8c76942a2418bd1b934"
        hash = "a86502e763c3394e291391d4437b44ff8112cad51ff44ac1b9d5f46f2586e687"
        hash = "ae64ed75ca773a9d751c0fbdb31265a7fd2a17f7bf173de2d88d07b17a9f1a24"
        hash = "1a63259345f9012f71739ed6c571246676cc24191ede91328b98f2285688988e"
        hash = "1183e96c80d784049426b57d4c6f8d19958f91695dd1d493a7c332fdfe85c40f"

    strings:
        $ = "SessionManagerModuleFactory"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_SessionManager_Unique_Strings : Heuristic_and_General
{
    meta:
        description = "Detects the SessionManager IIS backdoor, based on unique strings"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-09"
        modified_date = "2024-08-09"
        revision = "0"
        malware_family = "SessionManager"
        reference = "https://securelist.com/the-sessionmanager-iis-backdoor/106868/"
        reference = "https://unit42.paloaltonetworks.com/rare-possible-gelsemium-attack-targets-se-asia/"
        hash = "ae64ed75ca773a9d751c0fbdb31265a7fd2a17f7bf173de2d88d07b17a9f1a24"
        hash = "4464dc2f9b7c5b022725277b0c665b62c5f5321b49f4b8c76942a2418bd1b934"
        hash = "a86502e763c3394e291391d4437b44ff8112cad51ff44ac1b9d5f46f2586e687"

    strings:
        $ = "Session Manager Works OK"
        $ = "error to open file for read"
        $ = "error to open file for write"
        $ = "attachment; filename = \"cool.html\""
        $ = "Complete Write To File :"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_RainOwa_Backdoor : Heuristic_and_General
{
    meta:
        description = "Detects the managed IIS module backdoor RainOwa, which can execute shell commands, and implements guardrails based on an installed key/IP address"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-09-02"
        modified_date = "2024-09-02"
        revision = "0"
        malware_family = "RainOwa"
        hash = "4c640b1248d0b6cad2acf29b5d9df40d4ee6e640926d7dbe15e759ea4ad40989"

    strings:
        $ = "c:\\users\\dadmin\\"
        
        $ = "RainFL84CA7GHhauPb1y"
        $ = "WzqmDOBOV0NZgThdGFnl"
        $ = "dVrvZ9U36rhmD4diJW7C"
        $ = "CPhJdep7SrcG5tQvui2V"
        $ = "bnw7Nfvhf0PofeN38URz"
        
        $ = {1108178D2D00000125161F3A9D6F2B00000A13091109130A2B00110A2A}
        
    condition:
        any of them
}

rule DoorMe_IIS_Backdoor_Strings : Heuristic_and_General
{
    meta:
        description = "Detects variants of the DoorMe IIS backdoor, based on unique strings"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2023-04-24"
        modified_date = "2023-04-24"
        revision = "0"
        malware_family = "DoorMe"
        hash = "c283ceb230c6796d8c4d180d51f30e764ec82cfca0dfaa80ee17bb4fdf89c3e0"
        hash = "96b226e1dcfb8ea2155c2fa508125472c8c767569d009a881ab4c39453e4fe7f"
        hash = "fadbb46a64086b9329667608d32c1e8c5fe8a4d28ab3066439580bd49a262a91"
        hash = "38a164643d0a5a55325d7500ff51f7293dd97bd20faba67fd9443ab39c2ae943"
        reference = "https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry"
        reference = "https://www.elastic.co/security-labs/update-to-the-REF2924-intrusion-set-and-related-campaigns"

    strings:
        $internal_name = "IISBeacon.dll"
        $doorme = "AVDoorme@@"
        $tag = "BCcD;= " wide fullword
        
    condition:
        any of them
}

rule Malware_IIS_XCookie_Backdoor : Heuristic_and_General
{
    meta:
        description = "Detects the XCookie IIS module backdoor (which ESET calls 'Group 3')"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-27"
        modified_date = "2024-08-27"
        revision = "0"
        malware_family = "XCookie"
        reference = "https://web-assets.esetstatic.com/wls/2021/08/eset_anatomy_native_iis_malware.pdf"
        hash = "f8eeb8a8e336eaa8723d483fd3dec802c504a7121976477a3a1d6baf44f19a12"

    strings:
        $ = "BackdoorHttpModuleFactory"
        
    condition:
        any of them or pe.imphash() == "f730313c2ac071e1485eafac3f58b7fe"
}

rule Malware_IIS_Owowa_Backdoor : Heuristic_and_General
{
    meta:
        description = "Detects samples of the Owowa IIS backdoor"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-09-02"
        modified_date = "2024-09-02"
        revision = "0"
        malware_family = "Owowa"
        reference = "https://securelist.com/owowa-credential-stealer-and-remote-access/105219/"
        hash = "8e1e0ddeb249b9f8331b1562498d2cbd9138ec5e00c55a521d489e65b7ef447d"
        hash = "e19d8585ce66eb8f34b495819c9d2a73a26a54830b7437ccfdcdfaaac4398d5b"
        hash = "3897e7d173564cb3c348edef48ff2e125f59ea4465e975f4e3f0e495782c28ff"

    strings:
        $debug = "C:\\Users\\S3crt\\"
        
        $obf_str1 = "dEUM3jZXaDiob8BrqSy2PQO1" wide
        $obf_str2 = "Fb8v91c6tHiKsWzrulCeqO" wide
        $obf_str3 = "jFuLIXpzRdateYHoVwMlfc" wide
        
        $guid = "$6801b573-4cdb-4307-8d4a-3d1e2842f09f"
        
        $func1 = "PreSend_RequestContent"
        $func2 = "RunCommand"
        
    condition:
        uint16(0) == 0x5A4D and (
            any of ($debug, $obf_str*, $guid) or 
            all of ($func*)
        )
}

rule Malware_IIS_FakeImage_Backdoor : Heuristic_and_General
{
    meta:
        description = "Detects the FakeImage IIS backdoor (also referred to as ESET as Group 7)"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        malware_family = "FakeImage"
        hash = "819500f6d820bffd4290b172eb84721eee9f4d3a5814d58a65d5a321ce3e51ab"
        reference = "https://web-assets.esetstatic.com/wls/2021/08/eset_anatomy_native_iis_malware.pdf"

    strings:
        $ = "%.8s%.8s=%.8s%.16s%.8s%.16s"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_DeployFilter_Backdoor_IIS_Variant : Heuristic_and_General
{
    meta:
        description = "Detects an IIS variant of the DeployFilter backdoor"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-09-02"
        modified_date = "2024-09-02"
        revision = "0"
        malware_family = "DeployFilter"
        hash = "39e84372c81e79112a6d35c39e893983dfd8d1b38248b2ac9b34a66f5b364636"
        reference = "https://www.cybereason.com/blog/research/deadringer-exposing-chinese-threat-actors-targeting-major-telcos"

    strings:
        $ = "This Function can not use now." wide
        $ = "ChopperApi_"
        
    condition:
        any of them
}

rule Heuristic_IIS_Raid_Memory_Allocation : Heuristic_and_General
{
    meta:
        description = "Detects samples of the open source IIS-Raid backdoor, based on unique values used to allocate memory"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-06"
        modified_date = "2024-08-06"
        revision = "0"
        malware_family = "IIS-Raid"
        hash = "03340365d1a4ce340bdc4b83369196354bcaa7cdcba57222c04ad82226c65ad6"
        hash = "19364ae4376e8c6208d84af04c9c56bf2487817e502610bd3ce5870513313368"
        hash = "aae78b772f08fabdcd55a936f31a12a55e6610f9e447db75d153fe9cea87e0b3"
        reference = "https://github.com/0x09AL/IIS-Raid"

    strings:
        // 40 9C - hardcoded value of 40000 for MAX_DATA in IIS-Raid
        // 00 30 - MEM_COMMIT | MEM_RESERVE
        // 00 40 - MEM_DECOMMIT
        $virtualalloc_protect_proximity = {(40 9C [2-4] 00 30 | 00 30 [2-4] 40 9C) [2-400] (40 9C [2-4] 00 40 | 00 40 [2-4] 40 9C)}
        
    condition:
        pe.exports("RegisterModule") and 
        pe.imports("kernel32.dll", "VirtualAlloc") and 
        pe.imports("kernel32.dll", "VirtualFree") and
        for any section in pe.sections : (
            section.characteristics & pe.SECTION_MEM_EXECUTE and
            $virtualalloc_protect_proximity in (section.raw_data_offset .. section.raw_data_offset + section.raw_data_size)
        )
}

rule Malware_IIS_Raid_Backdoor_Generic : Heuristic_and_General {

    meta:
        description = "Detects samples of the open source IIS-Raid backdoor, used to target IIS servers"
        TLP = "WHITE"
        author = "Copyright PwCIL 2024 (C) :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2021-03-10"
        modified_date = "2021-03-10"
        revision = "0"
        reference = "https://www.welivesecurity.com/2021/03/10/exchange-servers-under-siege-10-apt-groups/"
        malware_family = "IIS-Raid"
        hash = "a11626d55ee9c958d86e8c77dfe19f66cdf545fbd8743126081f46dc24446767"

    strings:
        $timestamp = "%02d/%02d/%04d %02d:%02d:%02d | %s"

        $filepath1 = "C:\\Windows\\Temp\\creds.db"
        $filepath2 = "C:\\Windows\\Temp\\log.tmp"
        
        $no_creds = "No Creds Found"

        $unique = "X-FFEServer"

        $control_command1 = "CMD|"
        $control_command2 = "PIN|"
        $control_command3 = "INJ|"
        $control_command4 = "DMP|"

        $invalid = "INVALID COMMAND"
        
    condition:
        uint16(0) == 0x5A4D and filesize < 3MB and (
            2 of ($timestamp, $filepath*, $no_creds, $invalid) or 
            all of ($control_command*) or
            (2 of ($control_command*) and $invalid) or
            $unique
        )
}

rule Malware_IIS_Raid_Default_Command_Strs : Heuristic_and_General
{
    meta:
        description = "Detects samples of the IIS-Raid backdoor based on the default command strings that can be executed"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-06"
        modified_date = "2024-08-06"
        revision = "0"
        malware_family = "IIS-Raid"
        hash = "03340365d1a4ce340bdc4b83369196354bcaa7cdcba57222c04ad82226c65ad6"
        hash = "ea123701145cb0c4025614535ef29f3b862f7bc38383c305beeafd2f489f3012"
        hash = "b44457d39e768a9127467c664ca354153e28e2d575c4fa10062d4f55e559c9d1"
        reference = "https://github.com/0x09AL/IIS-Raid"

    strings:
        $ = "CMD|"
        $ = "PIN|"
        $ = "INJ|"
        $ = "DMP|"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_Raid_Default_GitHub_Path : Heuristic_and_General
{
    meta:
        description = "Detects samples of the IIS-Raid backdoor based on the default GitHub path name"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-06"
        modified_date = "2024-08-06"
        revision = "0"
        malware_family = "IIS-Raid"
        hash = "19364ae4376e8c6208d84af04c9c56bf2487817e502610bd3ce5870513313368"
        hash = "ae94b9528965e76b0a3c5f34849fe7fc81ad503bccfaa2e25c8dfacc193bdbad"
        hash = "b44457d39e768a9127467c664ca354153e28e2d575c4fa10062d4f55e559c9d1"
        reference = "https://github.com/0x09AL/IIS-Raid"

    strings:
        $ = "IIS-Raid"
        $ = "IIS-Backdoor"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_Raid_Default_Header_Strings : Heuristic_and_General
{
    meta:
        description = "Detects samples of the IIS-Raid backdoor based on default header strings"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-06"
        modified_date = "2024-08-06"
        revision = "0"
        malware_family = "IIS-Raid"
        hash = "b44457d39e768a9127467c664ca354153e28e2d575c4fa10062d4f55e559c9d1"
        hash = "9b3095e1729c82e6556cb146381b53b9212722de459ae4609598e7e9fb9d4c9c"
        hash = "b2725369e302f6f2172221c004f7e9e8184171be1d69099023782fab2a4a77e0"
        reference = "https://github.com/0x09AL/IIS-Raid"

    strings:
        $ = "X-Chrome-Variations"
        $ = "SIMPLEPASS"
        
    condition:
        pe.exports("RegisterModule") and all of them
}

rule Malware_IIS_Raid_Default_Invalid_Command_Str : Heuristic_and_General
{
    meta:
        description = "Detects samples of IIS-Raid backdoor based on a default error string used"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-06"
        modified_date = "2024-08-06"
        revision = "0"
        malware_family = "IIS-Raid"
        hash = "ea123701145cb0c4025614535ef29f3b862f7bc38383c305beeafd2f489f3012"
        hash = "b44457d39e768a9127467c664ca354153e28e2d575c4fa10062d4f55e559c9d1"
        reference = "https://github.com/0x09AL/IIS-Raid"

    strings:
        $invalid = "INVALID COMMAND"
        
    condition:
        pe.exports("RegisterModule") and 
        for any section in pe.sections : (
            section.name == ".rdata" and
            $invalid in (section.raw_data_offset .. section.raw_data_offset + section.raw_data_size)
        )
}

rule Malware_IIS_LimitedCookie_Backdoor : Heuristic_and_General
{
    meta:
        description = "Detects the open source managed IIS backdoor which we call LimitedCookie (and which is referred to in the open source project simply as 'IIS_Backdoor')"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-09-02"
        modified_date = "2024-09-02"
        revision = "0"
        malware_family = "LimitedCookie"
        reference = "https://github.com/WBGlIl/IIS_backdoor/tree/master"
        hash = "0d5e50a7207854b6e481985d7576a6ffb80622dae024601bd758395ceffe98e0"
        hash = "6bc80e628f3eacdc0a8cb6a76a975954f3d9a9e4761844a717ace4cf004c228d"
        hash = "582c24a9b3d699623b9837f065f441e04bd04675f912d6dbd119c16b14453854"

    strings:
        $ = "!Target requires"
        $ = "Runpscmd"
        $ = "IIS_backdoor_dll"
        
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Malware_IIS_ThreeTrack_Backdoor : Heuristic_and_General
{
    meta:
        description = "Detects the IIS backdoor 'ThreeTrack', which can execute commands and drop files"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-13"
        modified_date = "2024-08-13"
        revision = "0"
        malware_family = "ThreeTrack"
        hash = "29b753f0ca1e3db12fa2e3f66047e0253309b93a4081ce5c2afd5a27fd6e6b32"
        hash = "b0e881d7a6eca08529ecf789941607e811be81edd86c31d799e6fb1e7faaf64f"
        hash = "697cd1d45bfaaa22f91fdf18c3489354bab0f2214b1233ee497281293664d410"
        hash = "373183adc90251f62c5d559b7773400b19e1f12dc3e840e4e53757d602493a02"

    strings:
        $ = "C:\\Users\\T\\Desktop\\er\\"
        $ = "\\StripHeaders-1.0.5\\"
        $ = "\\x64\\Release\\w3trc.pdb"
        $ = "c:\\windows\\temp\\adobeproducttemp\\"
        $ = "w3trcModule.dll"
        
    condition:
        any of them
}

rule Malware_IIS_BlackMould_Backdoor : Red_Moros {

    meta:
        description = "Detects BlackMould China Chopper executable used by GALLIUM"
        TLP = "WHITE"
        author = "Copyright PwCIL 2024 (C) :: @BitsOfBinary"
        copyright = "Copyright PwC UK 2024 (C)"
        created_date = "2020-01-03"
        modified_date = "2020-01-03"
        revision = "0"
        hash = "a370e47cb97b35f1ae6590d14ada7561d22b4a73be0cb6df7e851d85054b1ac3"

    strings:
        $unique1 = "0628182016134805143312"
        $unique2 = "[CheckValue]:"
        $unique3 = "recv OK!"
        $unique4 = "hello!!!"
        $unique5 = "Rename File Fail."
        $unique6 = "srvhttp.log" wide
        
        $logging1 = "[ERROR]:Please run exe as administrator ..."
        $logging2 = "[ERROR]:Parameter error, please input 'install' or 'unstall'..."
        $logging3 = "Install Filter start..."
        $logging4 = "system is AMD64 or IA64..."
        $logging5 = "[ERROR]:CreateFile to %ws(%s) error..."
        $logging6 = "CreateFile %ws(%s) OK..."
        $logging7 = "To configure ApplicationHost.config file OK..."
        $logging8 = "[ERROR]:To configure ApplicationHost.config file FAIL..."
        $logging9 = "install finished..."
        $logging10 = "-unstall"
        $logging11 = "Unstall Filter start..."
        $logging12 = "Remove configure from ApplicationHost.config file OK..."
        $logging13 = "[ERROR]:Remove configure from ApplicationHost.config file FAIL..."
        $logging14 = "Remove %ws OK..."
        $logging15 = "[ERROR]Remove %ws FAIL..."
        $logging16 = "unstall finished..."
        $logging17 = "[ERROR]:%s"
        
    condition:
        pe.imphash() == "c0ee015bd83e01c351f2e3e6c3a04481" or (
        uint16(0) == 0x5A4D and (
                (2 of ($unique*)) or
                (12 of ($logging*))
            )
    )
}

rule Malware_IIS_TripleRIIS_Strings : Heuristic_and_General
{
    meta:
        description = "Detects samples of the TripleRIIS IIS backdoor (which ESET calls 'Group 2'), based on unique strings"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-27"
        modified_date = "2024-08-27"
        revision = "0"
        malware_family = "TripleRIIS"
        reference = "https://web-assets.esetstatic.com/wls/2021/08/eset_anatomy_native_iis_malware.pdf"
        hash = "cfaec2a27dc9667443bc5be81b66e01c42ad5d83a90393e4dffc396e46f99ee7"
        hash = "b4aab2c535978cb2a914e1bbdef19ab05326b3c2cc86a0b955b12e6a69e6c0aa"

    strings:
        $ = "294A1FC8FA5255E704F3A53F04056C91"
        $ = "([\\w+%]+)=([^!]*)"
        $ = ".?AVmyModuleFactory@@"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_TripleRIIS_RSA_DER_Key : Heuristic_and_General
{
    meta:
        description = "Detects samples the IIS backdoor TripleRIIS based on an RSA DER encoded key used in samples"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-09"
        modified_date = "2024-08-09"
        revision = "0"
        hash = "b4aab2c535978cb2a914e1bbdef19ab05326b3c2cc86a0b955b12e6a69e6c0aa"
        hash = "97589aca5d66b44a3056e23155506aeb71ada52e4bcb4939584d22b213d12b11"
        malware_family = "TripleRIIS"

    strings:
        $ = "MIICdgIBADA"

    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_GoodDownload_Backdoor : Heuristic_and_General
{
    meta:
        description = "Detects the GoodDownloader IIS module backdoor (which ESET calls 'Group 8')"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-27"
        modified_date = "2024-08-27"
        revision = "0"
        malware_family = "GoodDownloader"
        reference = "https://web-assets.esetstatic.com/wls/2021/08/eset_anatomy_native_iis_malware.pdf"
        hash = "4fbda60f74a4003bc93e75acffbd55520c99236052b527f920c67c18673e6bbb"
        hash = "052ea3e132ecc8bee3744856867b12a13477750a4ee99fb713cd20a7bcd98b46"
        hash = "610ee35688bcbca206d83c96b782254cec3be304f257e21a6bdbf31db95a6286"

    strings:
        $ = "Realy path : %s"
        $ = "Good!Download OK!"
        $ = "Shit!Download False!"
        $ = "Good!Run OK!"
        $ = "Shit!Run False!"
        $ = "Logged On Users : %d"
        $ = "Current process bits :  %s"
        $ = "[X86](WOW64)"
        
        $ = {436F6E6E656374204F4B210D0A596F7520617265206675636B6564210D0A00}
        $ = {53686974214572726F720D0A57686572652069732074686520476F6421210D0A00}
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_RGDoor_Backdoor_Strings : Yellow_Maero
{
    meta:
        description = "Detects samples of RGDoor (and the likely related malware family ThreeTrack) based on unique command codes and error strings"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-13"
        modified_date = "2024-08-13"
        revision = "0"
        malware_family = "RGDoor"
        malware_family = "ThreeTrack"
        hash = "a9c92b29ee05c1522715c7a2f9c543740b60e36373cb47b5620b1f3d8ad96bfa"
        hash = "29b753f0ca1e3db12fa2e3f66047e0253309b93a4081ce5c2afd5a27fd6e6b32"
        reference = "https://unit42.paloaltonetworks.com/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/"

    strings:
        // failed\r\n
        $error1 = {6661696C65640D0A00}
        
        // write done \r\n
        $error2 = {777269746520646F6E65200D0A00}
        
        // can't open file: 
        $error3 = {63616E2774206F70656E2066696C65203A2000}
        
        $cmd1 = "cmd$"
        $cmd2 = "upload$"
        $cmd3 = "download$"
        
    condition:
        pe.exports("RegisterModule") and (
            2 of ($error*) or
            2 of ($cmd*)
        )
}