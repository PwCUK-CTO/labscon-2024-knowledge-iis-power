import "pe"

rule Heuristic_IIS_Infector_Redirector_Pipe_Strings : Heuristic_and_General
{
    meta:
        description = "Heuristic rule for likely malicious IIS modules which have infected a server to force redirect users, based on observed pipe strings (i.e. strings separated with '|') in known modules"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-07-31"
        modified_date = "2024-08-12"
        revision = "1"
        hash = "c345ef226485f8491d560e06ad87bcae67425a7b4ce0cc834dd463541ff96c6c"
        hash = "ca1bc4a8dd0e71d374772b5e1d446b68d2147c4b77f2b82a3a7fc7c5f609a152"
        hash = "21a61777b0f725dd0dbdb2ecd0dd66e952012e94894e71c306059990c2afe377"

    strings:
        $ = "|gods|" ascii wide
        $ = "|king|" ascii wide
        $ = "|Fennec|" ascii wide
        $ = "|ios|" ascii wide
        $ = "|Sm.cn|" ascii wide
        $ = "|gougou|" ascii wide
        $ = "|mahj|" ascii wide
        $ = "|mvm|" ascii wide
        $ = "|add|" ascii wide
        $ = "|wOSBrowser|" ascii wide
        $ = "|youdao|" ascii wide
        $ = "|gov|" ascii wide
        $ = "|Dabong|" ascii wide
        $ = "|fru|" ascii wide
        $ = "|gam|" ascii wide
        $ = "|baidu|" ascii wide
        $ = "|bea|" ascii wide
        $ = "|pac|" ascii wide
        $ = "|biz|" ascii wide
        $ = "|youle|" ascii wide
        $ = "|baidu.com|" ascii wide
        $ = "|fish|" ascii wide
        $ = "|browser|" ascii wide
        $ = "|vna|" ascii wide
        $ = "|qzone|" ascii wide
        $ = "|oppo|" ascii wide
        $ = "|xwt|" ascii wide
        $ = "|MQQBrowser|" ascii wide
        $ = "|you|" ascii wide
        $ = "|QQBrowser|" ascii wide
        $ = "|WebOS|" ascii wide
        $ = "|nohu|" ascii wide
        $ = "|wzwen|" ascii wide
        $ = "|phone|" ascii wide
        $ = "|doc|" ascii wide
        $ = "|Nohu|" ascii wide
        $ = "|Windows Phone|" ascii wide
        $ = "|yahoo|" ascii wide
        $ = "|coccoc|" ascii wide
        $ = "|Yisou|" ascii wide
        $ = "|coccoc.com|" ascii wide
        $ = "|toutiao|" ascii wide
        $ = "|sbb|" ascii wide
        $ = "|or|" ascii wide
        $ = "|doca|" ascii wide
        $ = "|soft|" ascii wide
        $ = "|xin|" ascii wide
        $ = "|vid|" ascii wide
        $ = "|naver.com|" ascii wide
        $ = "|Googlebot|" ascii wide
        $ = "|gambling|" ascii wide
        $ = "|xinws|" ascii wide
        $ = "|tuugo|" ascii wide
        $ = "|360spider|" ascii wide
        $ = "|slo|" ascii wide
        $ = "|lsitt|" ascii wide
        $ = "|poker|" ascii wide
        $ = "|octher|" ascii wide
        $ = "|rna|" ascii wide
        $ = "|2021|" ascii wide
        $ = "|wzw|" ascii wide
        $ = "|muv|" ascii wide
        $ = "|JUC|" ascii wide
        $ = "|sogou|" ascii wide
        $ = "|ios2|" ascii wide
        $ = "|slots|" ascii wide
        $ = "|cash|" ascii wide
        $ = "|so.com|" ascii wide
        $ = "|googlebot|" ascii wide
        $ = "|subr|" ascii wide
        $ = "|sooule|" ascii wide
        $ = "|android|" ascii wide
        $ = "|Sogou wap spider|" ascii wide
        $ = "|YisouSpider|" ascii wide
        $ = "|BlackBerry|" ascii wide
        $ = "|lsi|" ascii wide
        $ = "|Video|" ascii wide
        $ = "|vido|" ascii wide
        $ = "|xoso|" ascii wide
        $ = "|vn|" ascii wide
        $ = "|yii|" ascii wide
        $ = "|Android|" ascii wide
        $ = "|coccocbot|" ascii wide
        $ = "|ser|" ascii wide
        $ = "|bingo|" ascii wide
        $ = "|xsn|" ascii wide
        $ = "|bull|" ascii wide
        $ = "|Baiduspider|" ascii wide
        $ = "|sm.cn|" ascii wide
        $ = "|pat|" ascii wide
        $ = "|360Spider|" ascii wide
        $ = "|serrevice|" ascii wide
        $ = "|bsbb|" ascii wide
        $ = "|yisou|" ascii wide
        $ = "|bing.com|" ascii wide
        $ = "|bmw|" ascii wide
        $ = "|comp|" ascii wide
        $ = "|Mobile|" ascii wide
        $ = "|BaiduSpider|" ascii wide
        $ = "|Baidu|" ascii wide
        $ = "|ucbrowser|" ascii wide
        $ = "|www|" ascii wide
        $ = "|timkhap|" ascii wide
        $ = "|2022|" ascii wide
        $ = "|sitemap|" ascii wide
        $ = "|dic|" ascii wide
        $ = "|iPad|" ascii wide
        $ = "|apk|" ascii wide
        $ = "|adc|" ascii wide
        $ = "|mussic|" ascii wide
        $ = "|silk|" ascii wide
        $ = "|register|" ascii wide
        $ = "|sm|" ascii wide
        $ = "|bizhi|" ascii wide
        $ = "|and2|" ascii wide
        $ = "|app|" ascii wide
        $ = "|UCWEB|" ascii wide
        $ = "|sofft|" ascii wide
        $ = "|world|" ascii wide
        $ = "|yiiyu|" ascii wide
        $ = "|abc|" ascii wide
        $ = "|thnews|" ascii wide
        $ = "|news|" ascii wide
        $ = "|zop|" ascii wide
        $ = "|cmp|" ascii wide
        $ = "|deposit|" ascii wide
        $ = "|360|" ascii wide
        $ = "|byte|" ascii wide
        $ = "|tian|" ascii wide
        $ = "|qzo|" ascii wide
        $ = "|xwtp|" ascii wide
        $ = "|pad|" ascii wide
        $ = "|wei|" ascii wide
        $ = "|edu|" ascii wide
        $ = "|uc|" ascii wide
        $ = "|bing|" ascii wide
        $ = "|sub|" ascii wide
        $ = "|com|" ascii wide
        $ = "|nes|" ascii wide
        $ = "|Sogou web spider|" ascii wide
        $ = "|spo|" ascii wide
        $ = "|dabong|" ascii wide
        $ = "|google|" ascii wide
        $ = "|wap|" ascii wide
        $ = "|fishing|" ascii wide
        $ = "|Casino|" ascii wide
        $ = "|wor|" ascii wide
        $ = "|article|" ascii wide
        $ = "|Yeti|" ascii wide
        $ = "|sto|" ascii wide
        $ = "|sof|" ascii wide
        $ = "|xor|" ascii wide
        $ = "|spins|" ascii wide
        $ = "|patt|" ascii wide
        $ = "|mul|" ascii wide
        $ = "|abcout|" ascii wide
        $ = "|bet|" ascii wide
        $ = "|118114|" ascii wide
        $ = "|card|" ascii wide
        $ = "|tig|" ascii wide
        $ = "|ivc|" ascii wide
        $ = "|iPod|" ascii wide
        $ = "|qsj|" ascii wide
        $ = "|sports|" ascii wide
        $ = "|iPhone|" ascii wide
        $ = "|HUAWEI|" ascii wide
        $ = "|cassinos|" ascii wide
        $ = "|games|" ascii wide
        $ = "|Sosospider|" ascii wide
        $ = "|sptv|" ascii wide
        $ = "|Sogou|" ascii wide
        $ = "|bac|" ascii wide
        $ = "|video|" ascii wide
        $ = "|iOS|" ascii wide
        $ = "|pod|" ascii wide
        $ = "|daum.net|" ascii wide
        $ = "|tee|" ascii wide
        $ = "|BrowserNG|" ascii wide
        $ = "|bsb|" ascii wide
        $ = "|yisouspider|" ascii wide
        $ = "|and|" ascii wide
        $ = "|Haosou|" ascii wide
        $ = "|Vn|" ascii wide
        $ = "|bingbot|" ascii wide
        $ = "|viet|" ascii wide
        $ = "|xiazai|" ascii wide
        $ = "|poc|" ascii wide
        $ = "|hot|" ascii wide
        $ = "|div|" ascii wide
        $ = "|dowms|" ascii wide
        $ = "|mrxw|" ascii wide
        $ = "|dow|" ascii wide
        $ = "|zywj|" ascii wide
        $ = "|fis|" ascii wide
        $ = "|mvmx|" ascii wide
        $ = "|nesws|" ascii wide
        $ = "|xxxxxx.com|" ascii wide
        $ = "|game|" ascii wide
        $ = "|ifeng|" ascii wide
        $ = "|iphone|" ascii wide
        $ = "|adapp|" ascii wide
        $ = "|zxzx|" ascii wide
        $ = "|google.com|" ascii wide
        $ = "|Xoso|" ascii wide
        $ = "|biso|" ascii wide
        $ = "|oct|" ascii wide
        $ = "|betting|" ascii wide
        $ = "|Sogouspider|" ascii wide
        $ = "|Sogou spider|" ascii wide
        $ = "|casino|" ascii wide
        $ = "|down|" ascii wide
        $ = "|mus|" ascii wide
        $ = "|bonus|" ascii wide
        $ = "|vod|" ascii wide
        $ = "|daum|" ascii wide
        $ = "|sho|" ascii wide
        $ = "|poli|" ascii wide
        $ = "|casinos|" ascii wide
        $ = "|Sogou inst spider|" ascii wide
        $ = "|gamse|" ascii wide
        $ = "|divr|" ascii wide
        $ = "|Symbian|" ascii wide
        $ = "|naver|" ascii wide
        $ = "|mobile|" ascii wide
        $ = "|IEMobile|" ascii wide
        $ = "|sogou.com|" ascii wide
        $ = "|prefetcht1|" ascii wide
        $ = "|prefetcht2|" ascii wide
        $ = "|prefetchnta|" ascii wide
        $ = "|prefetcht3|" ascii wide
        $ = "|prefetcht0|" ascii wide
        $ = "|.aspx|" ascii wide
        $ = "|.cshtml|" ascii wide
        $ = "|.shtm|" ascii wide
        $ = "|.asp|" ascii wide
        $ = "|.htm|" ascii wide
        $ = "|.php|" ascii wide
        $ = "|.html|" ascii wide
        $ = "|.shtml|" ascii wide
        $ = "|.svg|" ascii wide
        $ = "|.cs|" ascii wide
        $ = "|.png|" ascii wide
        $ = "|.webp|" ascii wide
        $ = "|.otf|" ascii wide
        $ = "|.jpeg|" ascii wide
        $ = "|.json|" ascii wide
        $ = "|.bmp|" ascii wide
        $ = "|jpg|" ascii wide
        $ = "|.txt|" ascii wide
        $ = "|.map|" ascii wide
        $ = "|.tiff|" ascii wide
        $ = "|.svgz|" ascii wide
        $ = "|.ico|" ascii wide
        $ = "|.woff|" ascii wide
        $ = "|.tif|" ascii wide
        $ = "|.ttf|" ascii wide
        $ = "|.gif|" ascii wide
        $ = "|.woff2|" ascii wide
        $ = "|.pict|" ascii wide
        $ = "|.ejs|" ascii wide
        $ = "|.swf|" ascii wide
        $ = "|.jpg|" ascii wide
        $ = "|.eot|" ascii wide
        $ = "|.dll|" ascii wide
        $ = "|.eps|" ascii wide
        $ = "|.css|" ascii wide
        $ = "|.class|" ascii wide
        $ = "|.js|" ascii wide
        $ = "|thnewsinfo|" ascii wide
        $ = "|androids|" ascii wide
        $ = "|showinfo|" ascii wide
        $ = "|covidnews|" ascii wide
        $ = "|blognewsj|" ascii wide
        $ = "|enventer|" ascii wide
        $ = "|movie|" ascii wide
        $ = "|dvd|" ascii wide
        $ = "|film|" ascii wide
        $ = "|tv|" ascii wide
        $ = "|watch|" ascii wide
        $ = "|dabo|" ascii wide
        $ = "|xxm|" ascii wide
        $ = "|images|" ascii wide
        $ = "|lingdu|" ascii wide
        $ = "|vsod|" ascii wide
        $ = "|snce|" ascii wide
        $ = "|adot|" ascii wide
        $ = "|grds|" ascii wide

    condition:
        pe.exports("RegisterModule") and 4 of them
}

rule Malware_IIS_HotNews_Redirector : Heuristic_and_General
{
    meta:
        description = "Detects a managed IIS module redirector, which we call HotNews, which redirects traffic to '/news' and '/hot' URL paths to a malicious server to return a different response"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-09-02"
        modified_date = "2024-09-02"
        revision = "0"
        malware_family = "HotNews"
        hash = "a056fa033e4bc469d89054f2d2af373c7975b555d833bd66d209df8367fe3d33"
        hash = "9605c78cdd209e34080857fd62b04688b562450c9911ffd697462a56fee1459b"

    strings:
        $ = {071204281900000A1B6F1A00000A2C101204281B00000A07281C00000A0C}
        $ = "InputCacheModule"
        
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Malware_IIS_Infector_Redirector_A : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-07-29"
        modified_date = "2024-07-29"
        revision = "0"
        hash = "3adcd5e8954bb0bacf84579dedc2543acf8848984f3fb139ceec26b1701f696f"
        hash = "b6a933fa55e13b9ea31af18c878de5ced82c787f7c4eb482ab0615cbed76921b"
        hash = "6fee8dbc89df7bd9fbe67df340d10bc054415cfc4d4b5b39542b8d359e4e712a"

    strings:
        $ = "<html><head><title>The resource cannot be found.</title><script>window.location="
        
    condition:
        any of them
}

rule Malware_IIS_Infector_Redirector_B : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-07-29"
        modified_date = "2024-07-29"
        revision = "0"
        hash = "fc31ad54698c37f4808567c081e4c26af08cc34746fcf4f6b07ddc7ff2d1e4cd"
        hash = "288b96399995df2b46256742753a1f1bdd044d4cf4a7f8e23821b392344d9d84"
        hash = "a2285070960e634e6cdd0bffa113b78b7457a00d99b4e2373ff81a27e5f89ff4"

    strings:
        $ = "tee|pat|and|app|poker|gam|sto|vid|bea|slo|fis|bac|pac|tig|bmw|fru|bull|card|gods|fish|mahj"
        $ = "bingbot|Googlebot|Yeti"
        $ = "iPhone|iPad|iPod|iOS|Android|uc|BlackBerry|HUAWEI"
        $ = ".js|.css|.jpg|.jpeg|.png|.gif|.bmp|.ico|.svg|.tif|.pict|.tiff|.swf|.eps|.ejs|.woff|.woff2|.eot|.otf|.svg|.svgz|.ttf|.webp|.json|.class|.map|.txt"
        
    condition:
        any of them
}

rule Malware_IIS_Infector_Redirector_C : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-07-29"
        modified_date = "2024-07-29"
        revision = "0"
        hash = "c45c8220a5abc6463e77d69e1fc057631e7abe3d95379ab0216505e78a2346f4"
        hash = "ca1bc4a8dd0e71d374772b5e1d446b68d2147c4b77f2b82a3a7fc7c5f609a152"
        hash = "878a3befccade4f047c5a81c091b23e26678281d8eb76640942cb81deea1e6fe"

    strings:
        $ = "?ding=1&tt=1"
        $ = "?ding=2&tt=2"
        $ = "IISRESPONSE"
        $ = "?ding=1&zz=1"
        $ = "?ding=2&zz=1"
        $ = "adot|vsod|snce|grds"
        $ = "iPhone|iPod|iPad|Android|mobile|QQBrowser|ucbrowser|Symbian|WebOS"
        $ = ".xml|.doc|.ppt|.xls|.csv|.pdf"
        $ = "baidu|sogou|yisouspider"
        
    condition:
        any of them
}

rule Malware_IIS_Infector_Redirector_D : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-07-29"
        modified_date = "2024-07-29"
        revision = "0"
        hash = "61913e0a38282a42b26aff578da17dab60ac0fbee819fa42db5497cc5cf55760"
        hash = "65967f471440449d2f1b615ff1338b8082b0481b617eda4d9f21a9f102b98859"
        hash = "e3c73f76f7b08ab6e223918a5b961201f60934ec95e5362529a42c1655395443"

    strings:
        $ = "----WebKitFormBoundaryBHNkQBGxcQrf7zY1"
        
    condition:
        any of them
}

rule Malware_IIS_Infector_Redirector_E : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-06"
        modified_date = "2024-08-06"
        revision = "0"
        hash = "a34132d7965318b23186fd13feab8f7ef54524afdbe4b73a705ad91dfaf63d29"
        hash = "3f1b6dd16f4e0634ef39d00a42db71a47191df14cab69cb2520623c12e3da3a2"
        hash = "00ee3aac381f606731573eb8b755229701c8f2ff6875af2455d94ef415fc7e3d"

    strings:
        $ = "&dqwz="
        $ = "C:\\Users\\gaqia\\"
        $ = "\\Desktop\\daima\\"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_Infector_Redirector_F : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-06"
        modified_date = "2024-08-06"
        revision = "0"
        hash = "0dbc7d0d16d2783ac54be4e880a25eb6acd2da607659d115f11f244aa94573df"
        hash = "20937833da23e7435400773da12115c374a39cb7b8efde4014400a755254d966"

    strings:
        $ = "/iis.php?host="
        $ = {476F6F676C65626F7400000042696E67626F74005961686F6F00}
        $ = {2E706870000000002E617370000000002E68746D000000002E617370780000002E68746D6C0000002E7368746D6C00}
        $ = {61707000616E640076696400706F6B0074656500}
        
    condition:
        any of them
}

rule Malware_IIS_Infector_Redirector_G : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-06"
        modified_date = "2024-08-06"
        revision = "0"
        hash = "89fe879c3cda5c98f219462d3a639fc93edd9144556a715116a5b5cc22e8357e"
        hash = "97c4134692bfd252f68cb5d03f50abf3daf56dd9562786a63c015876e501e700"
        hash = "2dbe07c555f9cd24e101a79611b80dccf501b0d3cc848ebc6efdcd8f07648a12"

    strings:
        $ = "&ipzz1="
        $ = "&ipzz2="
        $ = "(^/index|^/default)\\.(asp$|htm$|html$|shtm$|shtml$|aspx$|php$)"
        $ = {2675353D000000002675343D000000002675333D000000002675323D000000002F3F753D00}
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_Infector_Redirector_H : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-06"
        modified_date = "2024-08-06"
        revision = "0"
        hash = "22a9e1675bd8b8d64516bd4be1f07754c8f4ad6c59a965d0e009cbeaca6147a7"
        hash = "e2e00fd57d177e4c90c1e6a973cae488782f73378224f54cf1284d69a88b6805"
        hash = "1c870ee30042b1f6387cda8527c2a9cf6791195e63c5126d786f807239bd0ddc"

    strings:
        $ = "chongxiede"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_Infector_Redirector_I : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-09"
        modified_date = "2024-08-09"
        revision = "0"
        hash = "e2e39e7abd477b26760f335d85d6f4030982b39efc3a4e4c8125a846dbf02fa7"
        hash = "099d40f7d17b587d02c1aab1bf1d79ef6b48c1540a01e5508e03c5773237e298"
        hash = "7e1553acb98272a5bbfbb6aa184cc27608c4fd4f814f0e001f08d717bd17c12b"

    strings:
        $log = "d:\\zlog\\1.log"
        
        $b64_1 = "MzYwU3BpZGVy"
        $b64_2 = "U29zb3NwaWRlcg=="
        $b64_3 = "U29nb3VzcGlkZXI="
        $b64_4 = "WWlzb3VTcGlkZXI="
        $b64_5 = "U29nb3Ugd2ViIHNwaWRlcg=="
        $b64_6 = "U29nb3U="
        
    condition:
        $log or all of ($b64_*)
}

rule Malware_IIS_Infector_Redirector_J : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-09"
        modified_date = "2024-08-09"
        revision = "0"
        hash = "2d61594850f23fb3b4e52bc408b00712575de54c72d66924796f6bf13a04c512"
        hash = "9dca44bad71b38694d76b8822295f8c036b213aa1a40e45d2e30e06aedb35311"

    strings:
        $ = "Baidu"
        $ = "baidu"
        $ = "sogou"
        $ = "Sogou"
        $ = "sm.cn"
        $ = "Sm.cn"
        $ = "Yisou"
        $ = "yisou"
        $ = "Baiduspider"
        $ = "baiduspider"
        
    condition:
        pe.exports("RegisterModule") and all of them
}

rule Malware_IIS_Infector_Redirector_K : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "706adf153a8de475b811baa432fb1048e8f28d2abb58dcd52ebf0f263d81f71c"
        hash = "f71ae6112de5618e5f48d8013411abf05b7303d890591a1cb5836d5ecc4975bb"
        hash = "916b6def6fcbe82336dc1216bbf3c2dcd25a9fa293140f9ac88905ef5f9c1940"

    strings:
        $ = "CF5XFFHttpModuleFactory"
        
    condition:
        any of them
}

rule Malware_IIS_Infector_Redirector_L : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "aec4d671250bfed54735cf8294d7cb5edd3388d26cf335738b45bc5affb6c401"
        hash = "8bc6efea989fbdb0b12e69f5ff33aa1aa5b32195948ffb28515e80c26290a62c"
        hash = "2acc0d456b1b22fa0d17cb6e5984917a2464e67cf02921415b5f86ff6d7420ff"

    strings:
        $ = "C:\\inetpub\\temp\\IIS Temporary Compressed Files\\"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_Infector_Redirector_M : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "25a14c9a1d16f7d07312ac17b4f4b510a66df0b2e19cc4ee6cad95ab3bd551cf"

    strings:
        $urltest = "UrlTest"
        
        $upper1 = "Baidu"
        $upper2 = "Sogou"
        $upper3 = "Sm.cn"
        $upper4 = "Yisou"
        $upper5 = "Baiduspider"
        $upper6 = "360spider"
        $upper7 = "Sosospider"
        $upper8 = "Sogouspider"
        $upper9 = "YisouSpider"
        $upper10 = "Sogou web spider"
        $upper11 = "Bytespider"
        
        $lower1 = "baidu"
        $lower2 = "sogou"
        $lower3 = "sm.cn"
        $lower4 = "yisou"
        $lower5 = "baiduspider"
        $lower6 = "sosospider"
        $lower7 = "sogouspider"
        $lower8 = "yisouSpider"
        $lower9 = "sogou web spider"
        $lower10 = "bytespider"

    condition:
        pe.exports("RegisterModule") and $urltest and 
        (
            2 of ($upper*) or
            2 of ($lower*)
        )
}

rule Malware_IIS_Infector_Redirector_N : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "25a77986340d36e56320856bcc826c24fe1365223f0511b8e751424a1fd17945"
        hash = "4dbe5afb939670fb05e3f48b97af547ccdbfa6706f7f66fbae5cf14cd7fc79dc"
        hash = "4c34a8e1aa0af03c2953d58a880238e440b85fda835c48d4e4e2ad52c16c0c58"
        hash = "22fdecc0e5c4f8d6da7bdbdfb18addfe1276d4827b7899b6c720d3f44e6fa81f"

    strings:
        $ = "/sitemap.php?host='" wide
        $ = "/index.php?type=3&host=" wide
        $ = "^\\/(xoso|slot|casino|baccarat|Nohu|banca)\\/[a-z]*-[a-z]*-[a-z]*"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_Infector_Redirector_O : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "8dbbe0fbc74c8781467e19107251c27585d32597c9ab227cf860aa9085f5b487"
        hash = "22760fdcfa825cf41c0d3f303ceaad2168786c8e930caa0c5f729941d202e702"
        hash = "3a56df4ad6619c86cfe40103aec2742d9d09b28f3954b75503bf109c23d6fe39"

    strings:
        $ = "IISFilter32.pdb"
        $ = "CHttpFilter::OnSendResponse"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_Infector_Redirector_P : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "20935d19164e18310829d7fd9aa0533f04fd16717e890dccad8df8f17cdad0bf"
        hash = "2873d1404a7112860da2934b57d3afd426997099d1ee3c94a64bc512cd4826d5"
        hash = "6b8013f9e7cf6d46616a9385b23818950dcce634603f68580399862f9f64cf07"

    strings:
        $ = "?prefix=/amp/&host="
        $ = "\\IIS_Dirs-main\\"
        $ = "\\IIS_Dirs.pdb"
        
    condition:
        any of them
}

rule Malware_IIS_Infector_Redirector_Q : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "839b8532681df355271cd5fdbf0c0d09bef9c8cbbfa98d3fe9727afa670c30e7"
        hash = "74063aeff534b824ad3f505431e56875c1fd73dfd95be7972defaf0719120406"
        hash = "7dd1307fd65599600a5056ae867c373333ae265f6fa29dc02ec697916159ed84"

    strings:
        $ = "\\HttpModRespDLLx64.pdb"
        $ = "\\HttpModRespDLL\\"
        $ = "HttpModDLL.dll"
        
    condition:
        any of them
}

rule Malware_IIS_Infector_Redirector_R : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "06a923b250ae256a3660f8d21c53c4b03e1099d509b892daf72215d4534fabba"
        hash = "344800d4222bbd10234943bb0e49bf19a58b713c059abfdb0b6df100e4744297"

    strings:
        $ = "\\IIS7NativeModuleSample-libcurl\\"
        $ = "\\IIS7NativeModule.pdb"
        $ = " = crs tpircs<"
        $ = ">tpircs/<>\"tpircsavaj/txet\"=epyt"
        
    condition:
        any of them
}

rule Malware_IIS_Infector_Redirector_S : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "318c66ec2c5055697a8fee95ec41a8ed6d8a9ac85c9751b332b1e07f7a3c7d82"
        hash = "8dace1c9c434c2c957d640735ef762472c4e10b7d3d061367f5be89be916484c"
        hash = "5a9be53b371136c62f73113c13f3f5deee978a595191c3361a0db90d691b777b"

    strings:
        // mov     [rdi], rax
        // mov     r10, [r12]
        // xor     r9d, r9d
        // mov     r8d, 20000001h
        // mov     rdx, rdi
        // mov     rcx, r12
        // call    qword ptr [r10+10h]
        // mov     ebx, eax
        // test    eax, eax
        $ = {4889074D8B14244533C941B801000020488BD7498BCC41FF52108BD885C0}
        
    condition:
        any of them
}

rule Malware_IIS_Infector_Redirector_T : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "052ea3e132ecc8bee3744856867b12a13477750a4ee99fb713cd20a7bcd98b46"
        hash = "610ee35688bcbca206d83c96b782254cec3be304f257e21a6bdbf31db95a6286"

    strings:
        $ = "FliterSecurity.dll"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_Infector_Redirector_U : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "b7f6589b83b30ef1617bfe731e60e1a062e2d5924ca6c2cbb068a8f9dc8a2c2d"

    strings:
        $ = "agent-self: %s"
        $ = "agent-file: %s"
        $ = "agent-ip: %s"
        $ = "D:\\soures\\"
        $ = "\\urlresol.pdb"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_Infector_Redirector_V : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "aa34ecb2922ce8a8066358a1d0ce0ff632297037f8b528e3a37cd53477877e47"
        hash = "dfda34edb9bd9335c00580745b7f94a416531ae763b7992b6d15fe525e447982"

    strings:
        $ = "SecurityHttpModuleFactory"
        $ = "onlyMobileSpider : "
        $ = "loadConfigMessage : "
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Malware_IIS_Infector_Redirector_W : Heuristic_and_General
{
    meta:
        description = "Detects malicious IIS modules which have infected a server to force redirect users"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-12"
        modified_date = "2024-08-12"
        revision = "0"
        hash = "56715f3e15e8d39125e0b8cb46aaac1788fa46df4eed6881ddc5beb805679506"

    strings:
        $ = "\\Desktop\\Module for IIS 7.0\\"
        $ = "<title>(.*?)title(.*?)>"
        $ = "<meta(.*?)name(.*?)=(.*?)keywords(.*?)>"
        $ = "<meta(.*?)name(.*?)=(.*?)description(.*?)>"
        
    condition:
        pe.exports("RegisterModule") and any of them
}

rule Heuristic_Managed_IIS_Module_Webcrawler_Strings : Heuristic_and_General
{
    meta:
        description = "Detects IIS modules with multiple strings referencing web crawlers, seen in modules performing SEO or redirecting"
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-09-09"
        modified_date = "2024-09-09"
        revision = "0"

    strings:
        $web1 = "360Spider"
        $web2 = "Baidu.com"
        $web3 = "Baiduspider"
        $web4 = "Sm.cn"
        $web5 = "Sogou web spider"
        $web6 = "Sogou.com"
        $web7 = "Soso.com"
        $web8 = "Sosospider"
        $web9 = "Uc.cn"
        $web10 = "YisouSpider"
        $web11 = "Bingbot"
        $web12 = "Googlebot"
        $web13 = "Sogou Pic Spider"
        $web14 = "Sogou web spider"
        $web15 = "YandexBot"
        $web16 = "Bingbot"
        $web17 = "Sogou wap spider"
        $web18 = "Yisou"
        $web19 = "Sogouspider"
        $web20 = "Bytespider"
        $web21 = "360spider"
        $web22 = "baidu.com"
        $web23 = "baiduspider"
        $web24 = "sm.cn"
        $web25 = "sogou web spider"
        $web26 = "sogou.com"
        $web27 = "soso.com"
        $web28 = "sosospider"
        $web29 = "uc.cn"
        $web30 = "yisouspider"
        $web31 = "bingbot"
        $web32 = "googlebot"
        $web33 = "sogou pic spider"
        $web34 = "sogou web spider"
        $web35 = "yandexbot"
        $web36 = "bingbot"
        $web37 = "sogou wap spider"
        $web38 = "yisou"
        $web39 = "sogouspider"
        $web40 = "bytespider"
        $module = "IHttpModule"
        $dispose = "Dispose"
        
        $method1 = "AcquireRequestState"
        $method2 = "AuthenticateRequest"
        $method3 = "AuthorizeRequest"
        $method4 = "BeginRequest"
        $method5 = "EndRequest"
        $method6 = "LogRequest"
        $method7 = "MapRequestHandler"
        $method8 = "PostAcquireRequestState"
        $method9 = "PostAuthenticateRequest"
        $method10 = "PostAuthorizeRequest"
        $method11 = "PostLogRequest"
        $method12 = "PostMapRequestHandler"
        $method13 = "PostReleaseRequestState"
        $method14 = "PostRequestHandlerExecute"
        $method15 = "PostResolveRequestCache"
        $method16 = "PostUpdateRequestCache"
        $method17 = "PreRequestHandlerExecute"
        $method18 = "PreSendRequestContent"
        $method19 = "PreSendRequestHeaders"
        $method20 = "ReleaseRequestState"
        $method21 = "RequestCompleted"
        $method22 = "ResolveRequestCache"
        $method23 = "UpdateRequestCache"
        
    condition:
        pe.is_dll() and 
        $module and 
        $dispose and
        any of ($method*)
        and filesize < 1MB and 
        4 of ($web*)
}

rule Malware_IIS_LamyFilter_HTTP_Redirector : Heuristic_and_General
{
    meta:
        description = "Detects variants of IIS modules used to redirect requests made to IIS servers to a hardcoded IP address, and return a new response. Named 'LamyFilter' based on observed PDB paths."
        TLP = "WHITE"
        author = "PwC Threat Intelligence :: @BitsOfBinary"
        copyright = "Copyright PwCIL 2024 (C)"
        license = "Apache License 2.0"
        created_date = "2024-08-09"
        modified_date = "2024-08-09"
        revision = "0"
        malware_family = "LamyFilter"
        hash = "492ff42581db27d067f6f3c87ff5e53e1669e1b4050727fcbb5c7f3b13819522"
        hash = "ced21d8ead6a72345a6425898ef0ecd696a85faa00b15800a31eec287b944218"
        hash = "cfa7bebd2482201fed8918f8bf911dd222e79ff286a62a7a4cdfec2ae20283c7"

    strings:
        $ = "C:\\Users\\lamy\\source\\repos\\loader\\"
        $ = "CKMFactory"
        
    condition:
        any of them
}