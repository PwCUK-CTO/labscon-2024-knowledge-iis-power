import "pe"

rule Heuristic_IIS_Module_dotNET_Loading : Heuristic_and_General
{
    meta:
        description = "Detects IIS modules that have the capability to load .NET code, seen across multiple backdoors/injectors (Detele, IISInjectorPlus, Frebniis)"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-16"
        modified_date = "2024-08-16"
        revision = "0"
        hash = "a9ea32cf9dd8a2969c931c4062a67ad503dc37d5ce11c0adf5f74f543b9ac65e"
        hash = "b81c177c440e84635f22dc97b0411de93a24a983a41af676ffbbb4439487aaef"
        hash = "8571a354b5cdd9ec3735b84fa207e72c7aea1ab82ea2e4ffea1373335b3e88f4"
        hash = "aa7a3bf407fbc034570c4b1009ea1c381e30ab4b5ef7355a65916e44ea07ac76"
        malware_family = "Detele"
        malware_family = "IISInjectorPlus"
        malware_family = "Frebniis"
        reference = "https://gist.github.com/xpn/e95a62c6afcf06ede52568fcd8187cc2"

    strings:
        $subscribed = "This module subscribed to event"
        $override = "but did not override the method in its"
        $module1 = "CHttpModule"
        $module2 = "CGlobalModule"

    condition:
        pe.exports("RegisterModule") and
        (
            for any export in pe.export_details : (
                export.name == "RegisterModule" and
                export.ordinal == 1
            )
            or
            any of them
        ) and 
        pe.imports("mscoree.dll", "CLRCreateInstance")
}

rule Heuristic_IIS_Popen_Error_Message : Heuristic_and_General
{
    meta:
        description = "Detects samples of IIS modules using a 'popen' error message, seen in a couple of backdoors including SessionsIIS and TripleRIIS"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-09"
        modified_date = "2024-08-09"
        revision = "0"
        hash = "b4aab2c535978cb2a914e1bbdef19ab05326b3c2cc86a0b955b12e6a69e6c0aa"
        hash = "97589aca5d66b44a3056e23155506aeb71ada52e4bcb4939584d22b213d12b11"
        hash = "577ca702d73f2090ce583c5b1fbfcb3101d3c79722c98b3aa8dc6598296182f4"
        malware_family = "SessionsIIS"
        malware_family = "TripleRIIS"

    strings:
        $ = "popen() failed!"
        $ = "popen failed!"

    condition:
        pe.exports("RegisterModule") and any of them
}

rule Heuristic_IIS_w3wp_Stack_String : Heuristic_and_General
{
    meta:
        description = "Detects the stack string 'w3wp.exe' seen in malicious IIS modules"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-07-29"
        modified_date = "2024-07-29"
        revision = "0"
        reference = "https://symantec-enterprise-blogs.security.com/threat-intelligence/frebniis-malware-iis"
        hash = "b81c177c440e84635f22dc97b0411de93a24a983a41af676ffbbb4439487aaef"

    strings:
        $ = {77 33 77 70 [1-4] 2E 65 78 65}
        
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Heuristic_IIS_Module_Embedded_Public_RSA_DER_Key : Heuristic_and_General
{
    meta:
        description = "Detects IIS modules with an embedded public RSA key (DER format), a technique seen used in backdoors such as TripleRIIS"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-09"
        modified_date = "2024-08-09"
        revision = "0"
        malware_family = "TripleRIIS"
        hash = "97589aca5d66b44a3056e23155506aeb71ada52e4bcb4939584d22b213d12b11"
        hash = "b4aab2c535978cb2a914e1bbdef19ab05326b3c2cc86a0b955b12e6a69e6c0aa"

    strings:
        $ = "MIGfMA0GC"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Heuristic_IIS_Module_Unsigned_MyHttpModule : Heuristic_and_General
{
    meta:
        description = "Detects IIS modules using the class name 'MyHttpModule'. While this string has been seen in a variety of IIS malware families, there are some false positives - however, the false positives are mostly on security solutions, so will be easier to distinguish."
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "a35f810ed9ffd884d0599aa391d0043ad955e821f8144089116b15f01b8a932b"
        hash = "c75a9a104e340473b72140127f3039a08f99a334887afc100d09cffa3c4c8e24"
        hash = "9afef39b7b81083360e69f9788c45c8b972eb6668bbcbb49715d5e1c5ac8e155"

    strings:
        $ = "MyHttpModuleFactory"
        
    condition:
        pe.exports("RegisterModule") and pe.number_of_signatures == 0 and any of them
}

rule Heuristic_IIS_Multi_Byte_XOR_Routine : Heuristic_and_General
{
    meta:
        description = "Detects native IIS modules using a multi-byte XOR routine"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-06"
        modified_date = "2024-08-12"
        revision = "1"
        hash = "1c870ee30042b1f6387cda8527c2a9cf6791195e63c5126d786f807239bd0ddc"
        hash = "4f4832f457a798e8601d325477a1cbc5087c27a87ea8323bba49c2a26f368876"
        hash = "2acc0d456b1b22fa0d17cb6e5984917a2464e67cf02921415b5f86ff6d7420ff"
        hash = "8bc6efea989fbdb0b12e69f5ff33aa1aa5b32195948ffb28515e80c26290a62c"
        hash = "aec4d671250bfed54735cf8294d7cb5edd3388d26cf335738b45bc5affb6c401"

    strings:
        $xor = {80 30 ?? 80 70 01 ?? 80 70 02 ?? 80 70 03}
        
    condition:
        pe.exports("RegisterModule") and #xor >= 3
}

rule Heuristic_IIS_F_IIS_DLL_Name : Heuristic_and_General
{
    meta:
        description = "Detects samples of malicious IIS modules with an internal DLL name of 'F*ckIIS'"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-27"
        modified_date = "2024-08-27"
        revision = "0"
        hash = "d22ec1ab7d8a56d3b3f09fd2726e91472d1b1e37f1c01783efd2cab0d2017551"
        hash = "66b6cfd1546192f39ecedebf4b53b383ba69fc58c2c67c5b4ce8122029e09c41"
        hash = "9727b02ae01b2cbdf9900d9c9af6e7fd41a0bb84bf89b7513fa480e2c6488fdb"

    strings:
        $ = "FuckIIS.dll"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Heuristic_Unsigned_IIS_Module_Webcrawler_Strings : Heuristic_and_General
{
    meta:
        description = "Detects IIS modules with multiple strings referencing web crawlers, seen in modules performing SEO or redirecting"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "ee6288fa8e5f111571475211b15522bc987da8421e9687a8089d1edef1df14a2"
        hash = "ffceed66dd9935c92ff7922bd5fdfde08e9a2ff78dd3a76dc65a200305779b9c"
        hash = "a35f810ed9ffd884d0599aa391d0043ad955e821f8144089116b15f01b8a932b"

    strings:
        $ = "360Spider"
        $ = "Baidu.com"
        $ = "Baiduspider"
        $ = "Sm.cn"
        $ = "Sogou web spider"
        $ = "Sogou.com"
        $ = "Soso.com"
        $ = "Sosospider"
        $ = "Uc.cn"
        $ = "YisouSpider"
        $ = "Bingbot"
        $ = "Googlebot"
        $ = "Sogou Pic Spider"
        $ = "Sogou web spider"
        $ = "YandexBot"
        $ = "Bingbot"
        $ = "Sogou wap spider"
        $ = "Yisou"
        $ = "Sogouspider"
        $ = "Bytespider"
        $ = "360spider"
        $ = "baidu.com"
        $ = "baiduspider"
        $ = "sm.cn"
        $ = "sogou web spider"
        $ = "sogou.com"
        $ = "soso.com"
        $ = "sosospider"
        $ = "uc.cn"
        $ = "yisouspider"
        $ = "bingbot"
        $ = "googlebot"
        $ = "sogou pic spider"
        $ = "sogou web spider"
        $ = "yandexbot"
        $ = "bingbot"
        $ = "sogou wap spider"
        $ = "yisou"
        $ = "sogouspider"
        $ = "bytespider"
        
    condition:
        pe.exports("RegisterModule") and pe.number_of_signatures == 0 and filesize < 4MB and 4 of them
}