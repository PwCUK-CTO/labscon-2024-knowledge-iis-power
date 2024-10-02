import "pe"

rule Malware_IIS_IISInjectorPlus_IISBackDoorPlus : Heuristic_and_General
{
    meta:
        description = "Detects an IIS injector, which we call 'IISInjectorPlus', and .NET webshell likely based on ChinaChopper, both of which are self labelled as 'IISBackDoorPlus'"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwC International Limited 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-07-29"
        modified_date = "2024-07-29"
        revision = "0"
        malware_family = "IISInjectorPlus"
        hash = "a9ea32cf9dd8a2969c931c4062a67ad503dc37d5ce11c0adf5f74f543b9ac65e"
        hash = "aa7a3bf407fbc034570c4b1009ea1c381e30ab4b5ef7355a65916e44ea07ac76"

    strings:
        $ = "IISBackDoorPlus"
        $ = "c21Ffc565eb86fec" ascii wide
        
    condition:
        any of them
}

rule Malware_IIS_IISInjectorPlus_RTTI_Info : Heuristic_and_General
{
    meta:
        description = "Detects IIS code injectors, called 'IISInjectorPlus', based on unique RTTI information"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwC International Limited 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-16"
        modified_date = "2024-08-16"
        revision = "0"
        malware_family = "IISInjectorPlus"
        hash = "ab47afed1adb06279fd3a30224cffe324bb943cadb4aa403d83031ea1d160a91"
        hash = "d263e99bc4f228b70b20a5885b06e431d6e329a52cac17bb5b7865b89ad57288"
        hash = "ff78c6a8dd3e245ae6a0be34aeb3b59c978c8ea03b836ae8ccb532f74606ae9f"
        hash = "9c83302ba38097c3ba64ec6d1cb04e386919491043bd889ed7aa36d674108c85"

    strings:
        $ = "MyHttpModuleRegistrationInfo"
        $ = "MyWpfSettings"
        
    condition:
        any of them
}

rule Heuristic_IIS_Custom_Seo_Module : Heuristic_and_General
{
    meta:
        description = "Detects IIS modules, self-labelled as 'IIS_Seo', likely performing some form of search engine optimisation based on intercepted requests"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwC International Limited 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-09"
        modified_date = "2024-08-09"
        revision = "0"
        hash = "1a265cc1c7394be8da5a4e9b339b3f030238d60652eb49c3bc9a435db1033dc9"

    strings:
        $ = "CIIS_SeoFactory"
        $ = "httpdata.url:%s"
        $ = "httpdata.types:%s"
        $ = "httpdata.dic:%s"
        $ = "httpdata.keyword:%s"
        $ = "httpdata.formt:%s"
        $ = "httpdata.ua:%s"
        $ = "httpdata.ref:%s"
        
    condition:
        any of them
}

rule Heuristic_IIS_Module_HelloWorldFactory : Heuristic_and_General
{
    meta:
        description = "Detects IIS modules using an internal class named 'HelloWorld'. While this is a common programming term used, this specific class name has been observed in a variety of IIS malware"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwC International Limited 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "f747b857f0b43d854a2b175b7b772c11fa509a7ae9efab2089051dfabe1dc903"
        hash = "b8626f0c45c68f6176540a64e2f8c6d5ac8b942a5ec030b590870a6eaffb931f"
        hash = "1e17d5080ec3a4674158468752b034d7f5e8b04b186fe04e2ed6cfdd3acb611b"

    strings:
        $ = "CHelloWorldFactory"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Heuristic_IIS_Embedded_HTML_Script_Header : Heuristic_and_General
{
    meta:
        description = "Detects IIS modules with an embedded HTML script header, seen in IIS redirector modules"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwC International Limited 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-09"
        modified_date = "2024-08-09"
        revision = "0"
        hash = "2d61594850f23fb3b4e52bc408b00712575de54c72d66924796f6bf13a04c512"
        hash = "9dca44bad71b38694d76b8822295f8c036b213aa1a40e45d2e30e06aedb35311"

    strings:
        $ = "<!DOCTYPE html><html><body><script src=\""

    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_OneCmd_Proxy_Module : Heuristic_and_General
{
    meta:
        description = "Detects samples of what we call 'OneCmd' (which ESET calls 'Group 11'), which is a proxy module that can conduct SEO fraud and drop files to an infected web server"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwC International Limited 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-27"
        modified_date = "2024-08-27"
        revision = "0"
        malware_family = "OneCmd"
        reference = "https://web-assets.esetstatic.com/wls/2021/08/eset_anatomy_native_iis_malware.pdf"
        hash = "fb07c5b6e8f0ae482d9c571611f5868179227938e1e23de3d09dcbcb14fb7972"

    strings:
        $sub_2_routine = {80E902880A488D52010FB6020FB6C884C075ED}
        $one_php_cmdout_sub_minus_2 = "30rjrAeofqwv?"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_Dongtai_Module : Heuristic_and_General
{
    meta:
        description = "Detects an IIS module, self-labelled as 'Dongtai', which can perform multiple functions on intercepted HTTP requests"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwC International Limited 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "64d0a4703ec976b0e0db4e193b9ccdf4ef6f34d24c32274579ee028a67bfa3a9"
        hash = "4d830c72085eba2af24141048f204ec42f1196d7a5e9f226f3fc4781c95df3a2"
        hash = "e7446f56826b0ba9f03b15062bf67e37df57309b7d1fdd00f1eb7ff5727fdf76"

    strings:
        $ = "\\LMIISModule-main\\"
        $ = "\\Release\\Dongtai.pdb"
        
    condition:
        any of them
}

rule Malware_IIS_Module_CRM_Payment_Card_Stealer : Heuristic_and_General
{
    meta:
        description = "Detect IIS modules designed to be run on a CRM server, to intercept and stealer payment card information"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwC International Limited 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "223665fafdd5aee940dc383f0ab2fe626ee4346c478957c1c2fb30db31aa0b19"

    strings:
        $ = "%s%s_%04d%02d%02d_.tmp" wide
        
        // mov     rax, [rsp+38h+var_30]
        // movsx   eax, byte ptr [rax]
        // mov     [rsp+38h+var_28], eax
        // mov     eax, [rsp+38h+var_38]
        // cdq
        // idiv    [rsp+38h+var_24]
        // mov     eax, edx
        // cdqe
        // movsx   eax, [rsp+rax+38h+var_20]
        // mov     ecx, [rsp+38h+var_28]
        // xor     ecx, eax
        // mov     eax, ecx
        // mov     rcx, [rsp+38h+var_30]
        // mov     [rcx], al
        $xor_routine = {48 8B 44 24 ?? 0F BE 00 89 44 24 ?? 8B 04 24 99 F7 7C 24 ?? 8B C2 48 98 0F BE 44 04}
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_Checkout_Stealer : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS module which saves/steals HTTP responses to specific checkout URLs"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwC International Limited 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "d52ebfa1ea0366ffbce967a652190e3eb0206e47319a19df630d37443e7d0d69"

    strings:
        $ = "X-IIS-Data"
        $ = "SoUnRCxgREXMu9bM9Zr1Z78OkgaXj1Xr"
        $ = "C:\\Windows\\Temp\\cache.txt"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_IISniff_Infostealer : Heuristic_and_General
{
    meta:
        description = "Detects samples of the IIS infostealer known as IISniff/ISN"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwC International Limited 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        malware_family = "IISniff"
        reference = "https://web-assets.esetstatic.com/wls/2021/08/eset_anatomy_native_iis_malware.pdf"
        reference = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/the-curious-case-of-the-malicious-iis-module/"
        hash = "157174f0b9be66e3c9090c95efdd1dd23b19e42aa671758ebac5540a173f760c"

    strings:
        // get POST failed %d\r\n--------\r\n
        $ = {67657420504F5354206661696C65642025640D0A2D2D2D2D2D2D2D2D0D0A00}
        $ = "isn_getlog"
        $ = "isn_logpath"
        $ = "isn_logdel"
        $ = "isn7 config reloaded"
        $ = "isn7 config NOT reloaded, not found or empty"
        $ = "isn7 log deleted"
        $ = "isn7 log not deleted, ERROR 0x%X"
        $ = "isn7 log NOT found"
        $ = "\\isn7\\Release\\isn7.pdb"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_Seo_Client_Debug_Strings : Heuristic_and_General
{
    meta:
        description = "Detects an IIS module, self-labelled as 'seo-client', likely performing SEO to requests made to the infected web server"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwC International Limited 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "6a9901acf191e5400e0e9ebc323c42cfe57fe001fdcdb07f9caabd484d3005f4"
        hash = "8e4cb4e0749d4c26e349e2f62b3135e089cd1f239c24301da11e1d6e899bfb4f"

    strings:
        $ = "seo-client-iis.dll"
        $ = "seo-client-iis.pdb"
        $ = "\\seo-client-iis\\"
        
    condition:
        any of them
}

rule Malware_IIS_SatanicFilter : Heuristic_and_General
{
    meta:
        description = "Detects a self-labelled 'SatanicFilter' IIS module, designed to scrape specific requests made to an eCommerce platforms URLs and save them to disk"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwC International Limited 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-06"
        modified_date = "2024-08-06"
        revision = "0"
        malware_family = "SatanicFilter"
        hash = "0b0c1ec7c4048e6833e21260740226907b19ed73e953152da00daef2663be5ca"

    strings:
        $unique1 = "SataticFilterModule"
        $unique2 = "_Defender_Antivirus.log"
        
        $card1 = "Qoo10Card"
        $card2 = "QPGPayByCard"
        $card3 = "ProceedChangePayment"
        
    condition:
        any of ($unique*) or all of ($card*)
}