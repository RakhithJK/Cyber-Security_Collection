# PenetrationTesting


[English Version](https://github.com/xrkk/awesome-cyber-security/blob/master/Readme_en.md)

Github的Readme显示不会超过4000行，而此Repo添加的工具和文章近万行，默认显示不全。当前页面是减配版：工具星数少于200且500天内没更新的不在此文档中显示。
点击这里查看完整版：[中文-完整版](https://github.com/xrkk/awesome-cyber-security/blob/master/Readme_full.md)


# 目录
- [工具](#94ca60d12e210fdd7fd9e387339b293e)
    - [新添加的](#9eee96404f868f372a6cbc6769ccb7f8)
        - [(854) 新添加的](#31185b925d5152c7469b963809ceb22d)
        - [未分类](#f34b4da04f2a77a185729b5af752efc5)
    - [人工智能&&机器学习&&深度学习&&神经网络](#cc80626cfd1f8411b968373eb73bc4ea)
        - [(21) 未分类-AI](#19dd474da6b715024ff44d27484d528a)
        - [收集](#bab8f2640d6c5eb981003b3fd1ecc042)
    - [收集&&集合](#a4ee2f4d4a944b54b2246c72c037cd2e)
        - [(156) 未分类](#e97d183e67fa3f530e7d0e7e8c33ee62)
        - [(9) 混合型收集](#664ff1dbdafefd7d856c88112948a65b)
        - [(12) 无工具类收集](#67acc04b20c99f87ee625b073330d8c2)
        - [(1) 收集类的收集](#24707dd322098f73c7e450d6b1eddf12)
        - [(5) 教育资源&&课程&&教程&&书籍](#9101434a896f20263d09c25ace65f398)
        - [笔记&&Tips&&Tricks&&Talk&&Conference](#8088e46fc533286d88b945f1d472bf57)
            - [(11) 未分类](#f57ccaab4279b60c17a03f90d96b815c)
            - [(1) blog](#0476f6b97e87176da0a0d7328f8747e7)
    - [移动&&Mobile](#06fccfcc4faa7da54d572c10ef29b42e)
        - [(76) Android](#fe88ee8c0df10870b44c2dedcd86d3d3)
        - [(16) 未分类-Mobile](#4a64f5e8fdbd531a8c95d94b28c6c2c1)
        - [(58) iOS&&MacOS&&iPhone&&iPad&&iWatch](#dbde77352aac39ee710d3150a921bcad)
    - [CTF&&HTB](#c7f35432806520669b15a28161a4d26a)
        - [(110) 未分类-CTF&&HTB](#c0fea206256a42e41fd5092cecf54d3e)
        - [(6) 收集](#30c4df38bcd1abaaaac13ffda7d206c6)
        - [(1) HTB](#0d871dfb0d2544d6952c04f69a763059)
        - [CTF](#e64cedb2d91d06b3eeac5ea414e12b27)
            - [(25) Writeup](#0591f47788c6926c482f385b1d71efec)
            - [(71) 未分类-CTF](#e8853f1153694b24db203d960e394827)
            - [收集](#dc89088263fc944901fd7a58197a5f6d)
    - [漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing](#683b645c2162a1fce5f24ac2abfa1973)
        - [(212) 未分类-Vul](#9d1ce4a40c660c0ce15aec6daf7f56dd)
        - [漏洞开发](#605b1b2b6eeb5138cb4bc273a30b28a5)
            - [(5) 未分类-VulDev](#68a64028eb1f015025d6f5a6ee6f6810)
            - [(20) ROP](#019cf10dbc7415d93a8d22ef163407ff)
        - [漏洞扫描&&挖掘&&发现](#c0bec2b143739028ff4ec439e077aa63)
            - [未分类](#5d02822c22d815c94c58cdaed79d6482)
            - [漏洞扫描](#661f41705ac69ad4392372bd4bd02f01)
                - [(111) 未分类](#0ed7e90d216a8a5be1dafebaf9eaeb5d)
                - [Web漏洞](#d22e52bd9f47349df896ca85675d1e5c)
                - [系统漏洞](#060dd7b419423ee644794fccd67c22a8)
                - [App漏洞](#67939d66cf2a9d9373cc0a877a8c72c2)
                - [移动平台漏洞](#2076af46c7104737d06dbe29eb7c9d3a)
            - [Fuzzing](#382aaa11dea4036c5b6d4a8b06f8f786)
                - [(2) 资源收集](#a9a8b68c32ede78eee0939cf16128300)
                - [(8) Fuzzer](#ff703caa7c3f7b197608abaa76b1a263)
                - [(315) 未分类-Fuzz](#1c2903ee7afb903ccfaa26f766924385)
        - [漏洞利用](#41ae40ed61ab2b61f2971fea3ec26e7c)
            - [(119) 漏洞利用](#c83f77f27ccf5f26c8b596979d7151c3)
            - [(299) Exp&&PoC](#5c1af335b32e43dba993fceb66c470bc)
        - [XSS&&XXE](#5d7191f01544a12bdaf1315c3e986dff)
            - [(6) 收集](#493e36d0ceda2fb286210a27d617c44d)
            - [(134) 未分类-XSS](#648e49b631ea4ba7c128b53764328c39)
        - [知名漏洞&&CVE&&特定产品](#f799ff186643edfcf7ac1e94f08ba018)
            - [(248) 未分类](#309751ccaee413cbf35491452d80480f)
            - [(1) CVE](#33386e1e125e0653f7a3c8b8aa75c921)
            - [(17) Spectre&&Meltdown](#67f7ce74d12e16cdee4e52c459afcba2)
            - [(7) BlueKeep](#10baba9b8e7a2041ad6c55939cf9691f)
            - [(4) Heartbleed](#a6ebcba5cc1b4d2e3a72509b47b84ade)
            - [(9) DirtyCow](#d84e7914572f626b338beeb03ea613de)
            - [(3) Blueborne](#dacdbd68d9ca31cee9688d6972698f63)
        - [(42) 资源收集](#750f4c05b5ab059ce4405f450b56d720)
        - [(21) CSRF](#79ed781159b7865dc49ffb5fe2211d87)
        - [(22) 容器&&Docker](#edbf1e5f4d570ed44080b30bc782c350)
        - [(2) 漏洞管理](#9f068ea97c2e8865fac21d6fc50f86b3)
        - [(2) 漏洞数据库](#4c80728d087c2f08c6012afd2377d544)
        - [(1) CORS](#13fb2b7d1617dd6e0f503f52b95ba86b)
        - [漏洞分析](#0af37d7feada6cb8ccd0c81097d0f115)
    - [特定目标](#7e840ca27f1ff222fd25bc61a79b07ba)
        - [未分类-XxTarget](#eb2d1ffb231cee014ed24d59ca987da2)
        - [(89) AWS](#c71ad1932bbf9c908af83917fe1fd5da)
        - [(1) Phoenix](#88716f4591b1df2149c2b7778d15d04e)
        - [(2) Kubernetes](#4fd96686a470ff4e9e974f1503d735a2)
        - [(1) Azure](#786201db0bcc40fdf486cee406fdad31)
        - [(1) Nginx](#40dbffa18ec695a618eef96d6fd09176)
        - [(1) ELK](#6b90a3993f9846922396ec85713dc760)
    - [物联网(IoT)&&嵌入式设备&&路由器&&交换机&&智能设备&&打印机](#d55d9dfd081aa2a02e636b97ca1bad0b)
        - [(44) 未分类-IoT](#cda63179d132f43441f8844c5df10024)
        - [(1) 打印机 ](#72bffacc109d51ea286797a7d5079392)
        - [(4) 路由器&&交换机](#c9fd442ecac4e22d142731165b06b3fe)
        - [(1) 嵌入式设备](#3d345feb9fee1c101aea3838da8cbaca)
    - [通信&&代理&&反向代理&&隧道](#1a9934198e37d6d06b881705b863afc8)
        - [(233) 未分类-Proxy](#56acb7c49c828d4715dce57410d490d1)
        - [翻墙&&GFW](#837c9f22a3e1bb2ce29a0fb2bcd90b8f)
            - [(1) 未分类](#fe72fb9498defbdbb98448511cd1eaca)
            - [(3) 翻墙](#6e28befd418dc5b22fb3fd234db322d3)
            - [(9) GFW](#e9cc4e00d5851a7430a9b28d74f297db)
        - [(6) 代理](#21cbd08576a3ead42f60963cdbfb8599)
        - [(13) 反向代理&&穿透](#a136c15727e341b9427b6570910a3a1f)
        - [(8) 隧道](#e996f5ff54050629de0d9d5e68fcb630)
        - [(2) 代理爬取&&代理池](#b2241c68725526c88e69f1d71405c6b2)
        - [匿名网络](#b03a7c05fd5b154ad593b6327578718b)
            - [未分类](#f0979cd783d1d455cb5e3207d574aa1e)
            - [(47) Tor&&&Onion&&洋葱](#e99ba5f3de02f68412b13ca718a0afb6)
        - [(84) Socks&&ShadowSocksXx](#f932418b594acb6facfc35c1ec414188)
        - [(17) V2Ray](#dbc310300d300ae45b04779281fe6ec8)
        - [(2) VPN](#891b953fda837ead9eff17ff2626b20a)
    - [渗透&&offensive&&渗透框架&&后渗透框架](#1233584261c0cd5224b6e90a98cc9a94)
        - [(285) 未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e)
        - [无线&&WiFi&&AP&&802.11](#39931e776c23e80229368dfc6fd54770)
            - [(172) 未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c)
            - [(7) WPS&&WPA&&WPA2](#8d233e2d068cce2b36fd0cf44d10f5d8)
            - [(2) 802.11](#8863b7ba27658d687a85585e43b23245)
        - [Payload&&远控&&RAT](#80301821d0f5d8ec2dd3754ebb1b4b10)
            - [(86) 未分类-payload](#6602e118e0245c83b13ff0db872c3723)
            - [(20) Payload收集](#b5d99a78ddb383c208aae474fc2cb002)
            - [(32) 远控&&RAT](#b318465d0d415e35fc0883e9894261d1)
            - [(57) Payload生成](#ad92f6b801a18934f1971e2512f5ae4f)
            - [(30) Botnet&&僵尸网络](#c45a90ab810d536a889e4e2dd45132f8)
            - [(70) 后门&&添加后门](#b6efee85bca01cde45faa45a92ece37f)
            - [(1) 混淆器&&Obfuscate](#85bb0c28850ffa2b4fd44f70816db306)
            - [(1) Payload管理](#78d0ac450a56c542e109c07a3b0225ae)
            - [(31) 勒索软件](#d08b7bd562a4bf18275c63ffe7d8fc91)
            - [(14) 键盘记录器](#82f546c7277db7919986ecf47f3c9495)
            - [(13) Meterpreter](#8f99087478f596139922cd1ad9ec961b)
            - [(6) Payload投递](#63e0393e375e008af46651a3515072d8)
        - [(13) 渗透多合一&&渗透框架](#2051fd9e171f2698d8e7486e3dd35d87)
        - [后渗透](#a9494547a9359c60f09aea89f96a2c83)
            - [(36) 未分类-post-exp](#12abc279c69d1fcf10692b9cb89bcdf7)
            - [(51) 提权&&PrivilegeEscalation](#4c2095e7e192ac56f6ae17c8fc045c51)
            - [Windows](#caab36bba7fa8bb931a9133e37d397f6)
                - [(19) UAC](#58f3044f11a31d0371daa91486d3694e)
                - [(5) 未分类](#7ed8ee71c4a733d5e5e5d239f0e8b9e0)
                - [(3) AppLocker](#b84c84a853416b37582c3b7f13eabb51)
                - [(1) ActiveDirectory](#e3c4c83dfed529ceee65040e565003c4)
                - [域渗透](#25697cca32bd8c9492b8e2c8a3a93bfe)
            - [(9) 驻留&&Persistence](#2dd40db455d3c6f1f53f8a9c25bbe63e)
        - [(4) 自动化](#fc8737aef0f59c3952d11749fe582dac)
        - [(4) 收集](#9081db81f6f4b78d5c263723a3f7bd6d)
        - [Burp](#39e9a0fe929fffe5721f7d7bb2dae547)
            - [(2) 收集](#6366edc293f25b57bf688570b11d6584)
            - [(324) 未分类-Burp](#5b761419863bc686be12c76451f49532)
        - [(3) 数据渗透](#3ae4408f4ab03f99bab9ef9ee69642a8)
        - [Metasploit](#8e7a6a74ff322cbf2bad59092598de77)
            - [(127) 未分类-metasploit](#01be61d5bb9f6f7199208ff0fba86b5d)
        - [横向渗透](#adfa06d452147ebacd35981ce56f916b)
        - [(25) 免杀&&躲避AV检测](#b1161d6c4cb520d0cd574347cd18342e)
        - [(23) C&C](#98a851c8e6744850efcb27b8e93dff73)
        - [(43) DDOS](#a0897294e74a0863ea8b83d11994fad6)
        - [(129) Kali](#7667f6a0381b6cded2014a0d279b5722)
        - [(44) OWASP](#8e1069b2bce90b87eea762ee3d0935d8)
        - [(40) CobaltStrike](#0b8e79b79094082d0906153445d6ef9a)
    - [扫描器&&安全扫描&&App扫描&&漏洞扫描](#8f92ead9997a4b68d06a9acf9b01ef63)
        - [(283) 未分类-Scanner](#de63a029bda6a7e429af272f291bb769)
        - [(18) 隐私&&Secret&&Privacy扫描](#58d8b993ffc34f7ded7f4a0077129eb2)
        - [隐私存储](#1927ed0a77ff4f176b0b7f7abc551e4a)
            - [(1) 未分类](#1af1c4f9dba1db2a4137be9c441778b8)
            - [(23) 隐写](#362dfd9c1f530dd20f922fd4e0faf0e3)
    - [侦察&&信息收集&&子域名发现与枚举&&OSINT](#a76463feb91d09b3d024fae798b92be6)
        - [(177) 未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99)
        - [(71) 子域名枚举&&爆破](#e945721056c78a53003e01c3d2f3b8fe)
        - [(69) 信息收集&&侦查&&Recon&&InfoGather](#375a8baa06f24de1b67398c1ac74ed24)
        - [(43) 指纹&&Fingerprinting](#016bb6bd00f1e0f8451f779fe09766db)
        - [(1) 收集](#6ea9006a5325dd21d246359329a3ede2)
        - [社交网络](#dc74ad2dd53aa8c8bf3a3097ad1f12b7)
            - [(2) Twitter](#de93515e77c0ca100bbf92c83f82dc2a)
            - [(4) 其他](#6d36e9623aadaf40085ef5af89c8d698)
            - [(11) Github](#8d1ae776898748b8249132e822f6c919)
        - [(55) DNS](#a695111d8e30d645354c414cb27b7843)
        - [(33) Shodan](#18c7c1df2e6ae5e9135dfa2e4eb1d4db)
        - [(119) nmap](#94c01f488096fafc194b9a07f065594c)
    - [数据库&&SQL攻击&&SQL注入](#969212c047f97652ceb9c789e4d8dae5)
        - [(5) 未分类-Database](#e8d5cfc417b84fa90eff2e02c3231ed1)
        - [SQL](#3157bf5ee97c32454d99fd4a9fa3f04a)
            - [(6) SQL注入](#0519846509746aa50a04abd3ccf2f1d5)
            - [(41) 未分类-SQL](#1cfe1b2a2c88cd92a414f81605c8d8e7)
            - [(2) SQL漏洞](#5a7451cdff13bc6709da7c943dda967f)
        - [NoSQL](#ca6f4bd198f3712db7f24383e8544dfd)
            - [(2) 未分类-NoSQL](#af0aaaf233cdff3a88d04556dc5871e0)
            - [(11) MongoDB](#54d36c89712652a7064db6179faa7e8c)
    - [审计&&安全审计&&代码审计](#df8a5514775570707cce56bb36ca32c8)
        - [(15) 未分类-Audit](#6a5e7dd060e57d9fdb3fed8635d61bc7)
        - [(53) 代码审计](#34569a6fdce10845eae5fbb029cd8dfa)
    - [社工(SET)&&钓鱼&&鱼叉攻击](#546f4fe70faa2236c0fbc2d486a83391)
        - [(11) 未分类-SET](#ce734598055ad3885d45d0b35d2bf0d7)
        - [(2) 社工](#f30507893511f89b19934e082a54023e)
        - [(137) 钓鱼&&Phish](#290e9ae48108d21d6d8b9ea9e74d077d)
        - [鱼叉攻击](#ab3e6e6526d058e35c7091d8801ebf3a)
    - [硬件设备&&USB&树莓派](#04102345243a4bcaec83f703afff6cb3)
        - [(12) 未分类-Hardware](#ff462a6d508ef20aa41052b1cc8ad044)
        - [(57) USB](#48c53d1304b1335d9addf45b959b7d8a)
        - [(62) 树莓派&&RaspberryPi](#77c39a0ad266ad42ab8157ba4b3d874a)
        - [(11) 车&&汽车&&Vehicle](#da75af123f2f0f85a4c8ecc08a8aa848)
    - [环境配置&&分析系统](#dc89c90b80529c1f62f413288bca89c4)
        - [(10) 未分类-Env](#f5a7a43f964b2c50825f3e2fee5078c8)
        - [(5) Linux-Distro](#cf07b04dd2db1deedcf9ea18c05c83e0)
        - [(3) 环境自动配置&&自动安装](#4709b10a8bb691204c0564a3067a0004)
    - [靶机&&漏洞环境&&漏洞App](#761a373e2ec1c58c9cd205cd7a03e8a8)
        - [(107) 未分类-VulnerableMachine](#3e751670de79d2649ba62b177bd3e4ef)
        - [(12) WebApp](#a6a2bb02c730fc1e1f88129d4c2b3d2e)
        - [(4) 靶机生成](#60b4d03a0cff6efc4b9b998a4a1a79d6)
        - [(2) 收集](#383ad9174d3f7399660d36cd6e0b2c00)
        - [(5) MobileApp](#aa60e957e4da03301643a7abe4c1938a)
    - [浏览嗅探&&流量拦截&&流量分析&&中间人](#79499aeece9a2a9f64af6f61ee18cbea)
        - [(152) 未分类-Network](#99398a5a8aaf99228829dadff48fb6a7)
        - [(135) 中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36)
        - [(7) 流量嗅探&&监控](#c09843b4d4190dea0bf9773f8114300a)
        - [(9) pcap数据包](#dde87061175108fc66b00ef665b1e7d0)
        - [劫持&&TCP/HTTP/流量劫持](#1692d675f0fc7d190e0a33315f4abae8)
        - [(1) 协议分析&&流量分析](#3c28b67524f117ed555daed9cc99e35e)
    - [密码&&凭证](#c49aef477cf3397f97f8b72185c3d100)
        - [(47) 未分类-Password](#20bf2e2fefd6de7aadbf0774f4921824)
        - [(43) 密码](#86dc226ae8a71db10e4136f4b82ccd06)
    - [(3) 古老的&&有新的替代版本的](#d5e869a870d6e2c14911de2bc527a6ef)
    - [(2) Windows](#983f763457e9599b885b13ea49682130)
    - [webshell](#bad06ceb38098c26b1b8b46104f98d25)
        - [(4) 收集](#e08366dcf7aa021c6973d9e2a8944dff)
        - [(65) 未分类-webshell](#faa91844951d2c29b7b571c6e8a3eb54)
    - [辅助周边](#43b0310ac54c147a62c545a2b0f4bce2)
        - [(11) 未分类](#569887799ee0148230cc5d7bf98e96d0)
        - [(5) TLS&&SSL&&HTTPS](#86d5daccb4ed597e85a0ec9c87f3c66f)
    - [事件响应&&取证&&内存取证&&数字取证](#e1fc1d87056438f82268742dc2ba08f5)
        - [(55) 事件响应&&IncidentResponse](#d0f59814394c5823210aa04a8fcd1220)
        - [(124) 取证&&Forensics&&数字取证&&内存取证](#1fc5d3621bb13d878f337c8031396484)
        - [(4) 未分类-Forensics](#65f1e9dc3e08dff9fcda9d2ee245764e)
        - [(28) Volatility](#4d2a33083a894d6e6ef01b360929f30a)
    - [密罐&&Honeypot](#a2df15c7819a024c2f5c4a7489285597)
        - [(142) 密罐](#d20acdc34ca7c084eb52ca1c14f71957)
        - [(1) 收集](#efde8c850d8d09e7c94aa65a1ab92acf)
        - [(13) SSH&&Telnet](#c8f749888134d57b5fb32382c78ef2d1)
        - [(41) 未分类-Honeypot](#2af349669891f54649a577b357aa81a6)
        - [TCP&&UDP](#356be393f6fb9215c14799e5cd723fca)
        - [(1) HTTP&&Web](#577fc2158ab223b65442fb0fd4eb8c3e)
        - [(1) ActiveDirectory](#35c6098cbdc5202bf7f60979a76a5691)
        - [(1) SMTP](#7ac08f6ae5c88efe2cd5b47a4d391e7e)
        - [(1) 打印机](#8c58c819e0ba0442ae90d8555876d465)
        - [(1) Elasticsearch](#1a6b81fd9550736d681d6d0e99ae69e3)
        - [(1) ADB](#57356b67511a9dc7497b64b007047ee7)
        - [(15) 蓝牙&&Bluetooth ](#c5b6762b3dc783a11d72dea648755435)
        - [其他类型](#2a77601ce72f944679b8c5650d50148d)
            - [(2) Wordpress](#1d0819697e6bc533f564383d0b98b386)
    - [威胁情报](#f56806b5b229bdf6c118f5fb1092e141)
        - [(60) 未分类-ThreatIntelligence](#8fd1f0cfde78168c88fc448af9c6f20f)
        - [(2) 收集](#91dc39dc492ee8ef573e1199117bc191)
        - [IOC](#3e10f389acfbd56b79f52ab4765e11bf)
            - [(15) 未分类](#c94be209c558a65c5e281a36667fc27a)
            - [(2) IOC集合](#20a019435f1c5cc75e574294c01f3fee)
            - [(3) IOC提取](#1b1aa1dfcff3054bc20674230ee52cfe)
            - [(27) IOC获取](#9bcb156b2e3b7800c42d5461c0062c02)
    - [防护&&Defense](#946d766c6a0fb23b480ff59d4029ec71)
        - [(41) WAF](#784ea32a3f4edde1cd424b58b17e7269)
        - [(33) 防火墙&&FireWall](#ce6532938f729d4c9d66a5c75d1676d3)
        - [(37) IDS&&IPS](#ff3e0b52a1477704b5f6a94ccf784b9a)
        - [(8) 未分类-Defense](#7a277f8b0e75533e0b50d93c902fb351)
    - [(1) 爬虫](#785ad72c95e857273dce41842f5e8873)
    - [wordlist](#609214b7c4d2f9bb574e2099313533a2)
        - [(20) 未分类-wordlist](#af1d71122d601229dc4aa9d08f4e3e15)
        - [(2) 收集](#3202d8212db5699ea5e6021833bf3fa2)
        - [(2) Wordlist生成](#f2c76d99a0b1fda124d210bd1bbc8f3f)
    - [(2) 泄漏&&Breach&&Leak](#96171a80e158b8752595329dd42e8bcf)
    - [(172) 破解&&Crack&&爆破&&BruteForce](#de81f9dd79c219c876c1313cd97852ce)
    - [(30) OSCP](#13d067316e9894cc40fe55178ee40f24)
    - [(23) MitreATT&CK](#249c9d207ed6743e412c8c8bcd8a2927)
    - [(21) 浏览器&&browser](#76df273beb09f6732b37a6420649179c)
    - [(3) 蓝牙&&Bluetooth](#ceb90405292daed9bb32ac20836c219a)
    - [(3) REST_API&&RESTFUL ](#7d5d2d22121ed8456f0c79098f5012bb)
    - [(12) 恶意代码&&Malware&&APT](#8cb1c42a29fa3e8825a0f8fca780c481)


# <a id="94ca60d12e210fdd7fd9e387339b293e"></a>工具


***


## <a id="9eee96404f868f372a6cbc6769ccb7f8"></a>新添加的


### <a id="31185b925d5152c7469b963809ceb22d"></a>新添加的


- [**3527**星][2m] [PowerShell] [bloodhoundad/bloodhound](https://github.com/BloodHoundAD/BloodHound) 
- [**1992**星][2m] [C++] [darthton/blackbone](https://github.com/darthton/blackbone) 
- [**1879**星][19d] [C] [chipsec/chipsec](https://github.com/chipsec/chipsec) 
- [**1859**星][1y] [C++] [y-vladimir/smartdeblur](https://github.com/y-vladimir/smartdeblur) 
- [**1773**星][5m] [Py] [veil-framework/veil](https://github.com/veil-framework/veil) 
- [**1560**星][1m] [Shell] [internetwache/gittools](https://github.com/internetwache/gittools) 
- [**1400**星][4m] [C] [ettercap/ettercap](https://github.com/ettercap/ettercap) 
- [**1384**星][1y] [Go] [filosottile/whosthere](https://github.com/filosottile/whosthere) 
- [**1339**星][20d] [XSLT] [lolbas-project/lolbas](https://github.com/lolbas-project/lolbas) 
- [**1328**星][12m] [XSLT] [api0cradle/lolbas](https://github.com/api0cradle/lolbas) 
- [**1314**星][1y] [mortenoir1/virtualbox_e1000_0day](https://github.com/mortenoir1/virtualbox_e1000_0day) 
- [**1298**星][2m] [PowerShell] [peewpw/invoke-psimage](https://github.com/peewpw/invoke-psimage) 
- [**1272**星][1y] [JS] [sakurity/securelogin](https://github.com/sakurity/securelogin) 
- [**1218**星][1y] [Go] [cloudflare/redoctober](https://github.com/cloudflare/redoctober) 
- [**1209**星][1m] [Go] [google/martian](https://github.com/google/martian) 
- [**1136**星][3m] [C] [dgiese/dustcloud](https://github.com/dgiese/dustcloud) 
- [**1128**星][2m] [HTML] [cure53/httpleaks](https://github.com/cure53/httpleaks) 
- [**1105**星][2m] [Py] [thoughtfuldev/eagleeye](https://github.com/thoughtfuldev/eagleeye) 
- [**1073**星][14d] [Go] [looterz/grimd](https://github.com/looterz/grimd) 
- [**1052**星][1m] [PHP] [nbs-system/php-malware-finder](https://github.com/nbs-system/php-malware-finder) 
- [**1023**星][13d] [Py] [yelp/detect-secrets](https://github.com/yelp/detect-secrets) 
- [**967**星][25d] [HTML] [n0tr00t/sreg](https://github.com/n0tr00t/sreg) 可对使用者通过输入email、phone、username的返回用户注册的所有互联网护照信息。
- [**923**星][7m] [Py] [osirislab/hack-night](https://github.com/osirislab/Hack-Night) 
- [**904**星][26d] [Ruby] [david942j/one_gadget](https://github.com/david942j/one_gadget) 
- [**903**星][12m] [C++] [miek/inspectrum](https://github.com/miek/inspectrum) 
- [**902**星][3m] [Go] [dominicbreuker/pspy](https://github.com/dominicbreuker/pspy) 
- [**894**星][25d] [C] [arm-software/arm-trusted-firmware](https://github.com/arm-software/arm-trusted-firmware) 
- [**885**星][1m] [C#] [google/sandbox-attacksurface-analysis-tools](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) 沙箱攻击面（Attack Surface）分析工具，用于测试 Windows 上沙箱的各种属性
- [**874**星][4m] [JS] [dpnishant/appmon](https://github.com/dpnishant/appmon) 
- [**873**星][4m] [bugcrowd/bugcrowd_university](https://github.com/bugcrowd/bugcrowd_university) 
- [**852**星][20d] [Py] [shmilylty/oneforall](https://github.com/shmilylty/oneforall) 子域收集工具
- [**850**星][3m] [CSS] [outflanknl/redelk](https://github.com/outflanknl/redelk) 
- [**838**星][13d] [Py] [circl/ail-framework](https://github.com/circl/ail-framework) 
- [**835**星][13d] [Roff] [slimm609/checksec.sh](https://github.com/slimm609/checksec.sh) checksec.sh: 检查可执行文件(PIE, RELRO, PaX, Canaries, ASLR, Fortify Source)属性的 bash 脚本
- [**832**星][7m] [JS] [serpicoproject/serpico](https://github.com/serpicoproject/serpico) 
- [**819**星][10m] [Shell] [thelinuxchoice/userrecon](https://github.com/thelinuxchoice/userrecon) 
- [**818**星][21d] [C#] [borntoberoot/networkmanager](https://github.com/borntoberoot/networkmanager) 
- [**814**星][9m] [Py] [ietf-wg-acme/acme](https://github.com/ietf-wg-acme/acme) 
- [**814**星][16d] [Py] [lylemi/learn-web-hacking](https://github.com/lylemi/learn-web-hacking) 
- [**812**星][14d] [Java] [lamster2018/easyprotector](https://github.com/lamster2018/easyprotector) 
- [**807**星][8m] [Py] [nccgroup/featherduster](https://github.com/nccgroup/featherduster) 
- [**802**星][6m] [Py] [corelan/mona](https://github.com/corelan/mona) 
- [**797**星][2m] [JS] [sindresorhus/is-online](https://github.com/sindresorhus/is-online) 
- [**793**星][1m] [Py] [hellman/xortool](https://github.com/hellman/xortool) 
- [**769**星][1m] [Go] [dreddsa5dies/gohacktools](https://github.com/dreddsa5dies/gohacktools) 
- [**765**星][12m] [PowerShell] [kevin-robertson/invoke-thehash](https://github.com/kevin-robertson/invoke-thehash) 
- [**761**星][24d] [C++] [shekyan/slowhttptest](https://github.com/shekyan/slowhttptest) 
- [**757**星][9m] [Py] [hlldz/spookflare](https://github.com/hlldz/spookflare) 
- [**757**星][4m] [TSQL] [threathunterx/nebula](https://github.com/threathunterx/nebula) 
- [**746**星][1y] [Py] [greatsct/greatsct](https://github.com/greatsct/greatsct) 
- [**745**星][1m] [Go] [bishopfox/sliver](https://github.com/bishopfox/sliver) 
- [**739**星][1m] [PHP] [symfony/security-csrf](https://github.com/symfony/security-csrf) 
- [**738**星][2m] [C++] [snort3/snort3](https://github.com/snort3/snort3) 
- [**735**星][7m] [Py] [ricterz/genpass](https://github.com/ricterz/genpass) 
- [**734**星][5m] [Go] [talkingdata/owl](https://github.com/talkingdata/owl) 企业级分布式监控告警系
- [**731**星][1m] [HTML] [m4cs/babysploit](https://github.com/m4cs/babysploit) 
- [**729**星][1y] [C#] [eladshamir/internal-monologue](https://github.com/eladshamir/internal-monologue) 
- [**719**星][5m] [Go] [anshumanbh/git-all-secrets](https://github.com/anshumanbh/git-all-secrets) 结合多个开源 git 搜索工具实现的代码审计工具
- [**711**星][3m] [Py] [f-secure/see](https://github.com/f-secure/see) 
- [**709**星][24d] [Py] [globaleaks/globaleaks](https://github.com/globaleaks/globaleaks) The Open-Source Whistleblowing Software
- [**708**星][5m] [Py] [adamlaurie/rfidiot](https://github.com/adamlaurie/rfidiot) 
- [**707**星][1m] [Perl] [gouveaheitor/nipe](https://github.com/GouveaHeitor/nipe) 
- [**706**星][4m] [aleenzz/cobalt_strike_wiki](https://github.com/aleenzz/cobalt_strike_wiki) 
- [**706**星][1y] [C#] [p3nt4/powershdll](https://github.com/p3nt4/powershdll) 
- [**706**星][1m] [Py] [shawndevans/smbmap](https://github.com/shawndevans/smbmap) 
- [**698**星][13d] [C] [iaik/zombieload](https://github.com/iaik/zombieload) 
- [**692**星][3m] [netflix/security-bulletins](https://github.com/netflix/security-bulletins) 
- [**687**星][5m] [C++] [google/certificate-transparency](https://github.com/google/certificate-transparency) 
- [**687**星][7m] [C] [hfiref0x/tdl](https://github.com/hfiref0x/tdl) 
- [**684**星][2m] [Py] [mjg59/python-broadlink](https://github.com/mjg59/python-broadlink) 
- [**684**星][25d] [streaak/keyhacks](https://github.com/streaak/keyhacks) 
- [**682**星][12d] [Java] [peergos/peergos](https://github.com/peergos/peergos) 
- [**673**星][7m] [Py] [mr-un1k0d3r/powerlessshell](https://github.com/mr-un1k0d3r/powerlessshell) 
- [**665**星][1y] [Py] [endgameinc/rta](https://github.com/endgameinc/rta) 
- [**665**星][12m] [PowerShell] [arvanaghi/sessiongopher](https://github.com/Arvanaghi/SessionGopher) 
- [**664**星][2m] [Py] [skelsec/pypykatz](https://github.com/skelsec/pypykatz) 纯Python实现的Mimikatz
- [**662**星][2m] [Go] [pquerna/otp](https://github.com/pquerna/otp) 
- [**658**星][5m] [Py] [golismero/golismero](https://github.com/golismero/golismero) 
- [**654**星][1y] [Py] [deepzec/bad-pdf](https://github.com/deepzec/bad-pdf) create malicious PDF file to steal NTLM(NTLMv1/NTLMv2) Hashes from windows machines
- [**651**星][4m] [C#] [outflanknl/evilclippy](https://github.com/outflanknl/evilclippy) 
- [**650**星][12d] [ptresearch/attackdetection](https://github.com/ptresearch/attackdetection) 
- [**647**星][8m] [C] [samdenty/wi-pwn](https://github.com/samdenty/Wi-PWN)  performs deauth attacks on cheap Arduino boards
- [**642**星][11m] [C#] [wwillv/godofhacker](https://github.com/wwillv/godofhacker) 
- [**637**星][3m] [C#] [ghostpack/rubeus](https://github.com/ghostpack/rubeus) 
- [**631**星][2m] [Py] [gquere/pwn_jenkins](https://github.com/gquere/pwn_jenkins) 
- [**628**星][5m] [PHP] [l3m0n/bypass_disable_functions_shell](https://github.com/l3m0n/bypass_disable_functions_shell) 
- [**615**星][10m] [Py] [dirkjanm/privexchange](https://github.com/dirkjanm/privexchange) 
- [**606**星][1y] [Shell] [wireghoul/htshells](https://github.com/wireghoul/htshells) 
- [**602**星][2m] [JS] [evilsocket/arc](https://github.com/evilsocket/arc) 可用于管理私密数据的工具. 后端是 Go 语言编写的 RESTful 服务器,  前台是Html + JavaScript
- [**592**星][2m] [PHP] [hongrisec/php-audit-labs](https://github.com/hongrisec/php-audit-labs) 
- [**592**星][1m] [PowerShell] [ramblingcookiemonster/powershell](https://github.com/ramblingcookiemonster/powershell) 
- [**589**星][3m] [Py] [webrecorder/pywb](https://github.com/webrecorder/pywb) 
- [**584**星][16d] [YARA] [didierstevens/didierstevenssuite](https://github.com/didierstevens/didierstevenssuite) 
- [**575**星][8m] [C#] [0xbadjuju/tokenvator](https://github.com/0xbadjuju/tokenvator) 
- [**575**星][9m] [Py] [romanz/amodem](https://github.com/romanz/amodem) transmit a file between 2 computers, using a simple headset, allowing true air-gapped communication (via a speaker and a microphone), or an audio cable (for higher transmission speed)
- [**574**星][8m] [C] [mrexodia/titanhide](https://github.com/mrexodia/titanhide) 
- [**567**星][1y] [C#] [tyranid/dotnettojscript](https://github.com/tyranid/dotnettojscript) 
- [**561**星][1y] [Solidity] [trailofbits/not-so-smart-contracts](https://github.com/crytic/not-so-smart-contracts) 
- [**558**星][5m] [Py] [nidem/kerberoast](https://github.com/nidem/kerberoast)  a series of tools for attacking MS Kerberos implementations
- [**550**星][10m] [C] [justinsteven/dostackbufferoverflowgood](https://github.com/justinsteven/dostackbufferoverflowgood) 
- [**545**星][1y] [Go] [cw1997/natbypass](https://github.com/cw1997/natbypass) 内网穿透，端口转发工具
- [**545**星][3m] [Py] [its-a-feature/apfell](https://github.com/its-a-feature/apfell) 
- [**543**星][1m] [Go] [shopify/kubeaudit](https://github.com/shopify/kubeaudit) 
- [**536**星][8m] [C] [hfiref0x/upgdsed](https://github.com/hfiref0x/upgdsed) 
- [**536**星][2m] [C] [vanhauser-thc/thc-ipv6](https://github.com/vanhauser-thc/thc-ipv6) 
- [**533**星][1m] [Go] [yggdrasil-network/yggdrasil-go](https://github.com/yggdrasil-network/yggdrasil-go) 
- [**530**星][5m] [HCL] [coalfire-research/red-baron](https://github.com/coalfire-research/red-baron) 
- [**530**星][2m] [C] [eliasoenal/multimon-ng](https://github.com/EliasOenal/multimon-ng) 
- [**526**星][28d] [Ruby] [hdm/mac-ages](https://github.com/hdm/mac-ages) 
- [**524**星][1y] [Py] [n00py/wpforce](https://github.com/n00py/wpforce) 
- [**523**星][1y] [C#] [ghostpack/safetykatz](https://github.com/ghostpack/safetykatz) 
- [**515**星][11m] [PowerShell] [a-min3/winspect](https://github.com/a-min3/winspect) 
- [**513**星][1m] [Shell] [trailofbits/twa](https://github.com/trailofbits/twa) 
- [**509**星][11m] [Go] [mthbernardes/gtrs](https://github.com/mthbernardes/gtrs) Google Translator Reverse Shell
- [**507**星][1m] [JS] [mr-un1k0d3r/thundershell](https://github.com/mr-un1k0d3r/thundershell) 
- [**505**星][7m] [Visual Basic] [mr-un1k0d3r/maliciousmacrogenerator](https://github.com/mr-un1k0d3r/maliciousmacrogenerator) 
- [**501**星][24d] [Go] [sensepost/gowitness](https://github.com/sensepost/gowitness) Go 语言编写的网站快照工具
- [**489**星][2m] [PHP] [nzedb/nzedb](https://github.com/nzedb/nzedb) a fork of nnplus(2011) | NNTP / Usenet / Newsgroup indexer.
- [**485**星][2m] [Go] [gen2brain/cam2ip](https://github.com/gen2brain/cam2ip) 将任何网络摄像头转换为IP 摄像机
- [**480**星][1y] [Java] [continuumsecurity/bdd-security](https://github.com/continuumsecurity/bdd-security) 
- [**479**星][11m] [Go] [evanmiller/hecate](https://github.com/evanmiller/hecate) The Hex Editor From Hell
- [**475**星][1m] [C] [m0nad/diamorphine](https://github.com/m0nad/diamorphine) 
- [**474**星][10m] [Shell] [craigz28/firmwalker](https://github.com/craigz28/firmwalker) 
- [**474**星][2m] [Go] [gorilla/csrf](https://github.com/gorilla/csrf) 
- [**468**星][2m] [Py] [bashfuscator/bashfuscator](https://github.com/bashfuscator/bashfuscator) 
- [**465**星][18d] [Py] [aoii103/darknet_chinesetrading](https://github.com/aoii103/darknet_chinesetrading) 
- [**457**星][21d] [LLVM] [jonathansalwan/tigress_protection](https://github.com/jonathansalwan/tigress_protection) 
- [**456**星][12m] [Py] [mehulj94/radium](https://github.com/mehulj94/Radium) 
- [**454**星][5m] [C] [phoenhex/files](https://github.com/phoenhex/files) 
- [**453**星][27d] [Go] [gen0cide/gscript](https://github.com/gen0cide/gscript) 基于运行时参数，动态安装恶意软件
- [**449**星][3m] [C++] [omerya/invisi-shell](https://github.com/omerya/invisi-shell) 
- [**448**星][2m] [Py] [bit4woo/teemo](https://github.com/bit4woo/teemo) 
- [**448**星][2m] [PowerShell] [rvrsh3ll/misc-powershell-scripts](https://github.com/rvrsh3ll/misc-powershell-scripts) 
- [**445**星][13d] [Shell] [wireghoul/graudit](https://github.com/wireghoul/graudit) 简单的脚本和签名集，进行源代码审计
- [**444**星][9m] [C] [martinmarinov/tempestsdr](https://github.com/martinmarinov/tempestsdr) 
- [**443**星][2m] [Py] [portantier/habu](https://github.com/portantier/habu) Python 编写的网络工具工具包，主要用于教学/理解网络攻击中的一些概念
- [**443**星][1y] [JS] [simonepri/upash](https://github.com/simonepri/upash) 
- [**437**星][6m] [PHP] [flozz/p0wny-shell](https://github.com/flozz/p0wny-shell) 
- [**432**星][1m] [PowerShell] [mr-un1k0d3r/redteampowershellscripts](https://github.com/mr-un1k0d3r/redteampowershellscripts) 
- [**428**星][6m] [Pascal] [mojtabatajik/robber](https://github.com/mojtabatajik/robber) 
- [**426**星][6m] [Py] [stamparm/fetch-some-proxies](https://github.com/stamparm/fetch-some-proxies) 
- [**423**星][28d] [Py] [super-l/superl-url](https://github.com/super-l/superl-url) 根据关键词，对搜索引擎内容检索结果的网址内容进行采集的一款轻量级软程序。 程序主要运用于安全渗透测试项目，以及批量评估各类CMS系统0DAY的影响程度，同时也是批量采集自己获取感兴趣的网站的一个小程序~~ 可自动从搜索引擎采集相关网站的真实地址与标题等信息，可保存为文件，自动去除重复URL。同时，也可以自定义忽略多条域名等。
- [**421**星][10m] [Py] [d4vinci/cuteit](https://github.com/d4vinci/cuteit) 
- [**408**星][10m] [Py] [powerscript/katanaframework](https://github.com/powerscript/katanaframework) 
- [**404**星][2m] [C++] [hoshimin/kernel-bridge](https://github.com/hoshimin/kernel-bridge) 
- [**401**星][5m] [Py] [ytisf/pyexfil](https://github.com/ytisf/pyexfil) 
- [**396**星][2m] [HTML] [w3c/webappsec](https://github.com/w3c/webappsec) 
- [**387**星][1y] [C#] [squalr/squalr](https://github.com/squalr/squalr) 
- [**378**星][1y] [JS] [empireproject/empire-gui](https://github.com/empireproject/empire-gui) 
- [**376**星][1m] [JS] [nccgroup/tracy](https://github.com/nccgroup/tracy) tracy: 查找web app中所有的sinks and sources, 并以易于理解的方式显示这些结果
- [**375**星][13d] [C++] [simsong/bulk_extractor](https://github.com/simsong/bulk_extractor) 
- [**375**星][8m] [Java] [tiagorlampert/saint](https://github.com/tiagorlampert/saint) a Spyware Generator for Windows systems written in Java
- [**372**星][8m] [Py] [k4m4/onioff](https://github.com/k4m4/onioff) onioff：url检测器，深度检测网页链接
- [**365**星][1m] [C++] [crypto2011/idr](https://github.com/crypto2011/idr) 
- [**362**星][17d] [C#] [bloodhoundad/sharphound](https://github.com/bloodhoundad/sharphound) 
- [**361**星][20d] [Py] [emtunc/slackpirate](https://github.com/emtunc/slackpirate) 
- [**360**星][26d] [Ruby] [david942j/seccomp-tools](https://github.com/david942j/seccomp-tools) 
- [**360**星][4m] [Shell] [trimstray/otseca](https://github.com/trimstray/otseca) otseca: 安全审计工具, 搜索并转储系统配置
- [**354**星][2m] [Py] [fox-it/bloodhound.py](https://github.com/fox-it/bloodhound.py) 
- [**351**星][6m] [Py] [tidesec/tidefinger](https://github.com/tidesec/tidefinger) 
- [**350**星][10m] [Py] [secynic/ipwhois](https://github.com/secynic/ipwhois) 
- [**348**星][2m] [Py] [lockgit/hacking](https://github.com/lockgit/hacking) 
- [**342**星][30d] [Ruby] [sunitparekh/data-anonymization](https://github.com/sunitparekh/data-anonymization) 
- [**339**星][1m] [C] [nccgroup/phantap](https://github.com/nccgroup/phantap) 
- [**338**星][1y] [Ruby] [srcclr/commit-watcher](https://github.com/srcclr/commit-watcher) 
- [**336**星][4m] [Perl] [keydet89/regripper2.8](https://github.com/keydet89/regripper2.8) 
- [**331**星][12m] [Assembly] [egebalci/amber](https://github.com/egebalci/amber) 
- [**328**星][8m] [Py] [dirkjanm/ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) 
- [**327**星][28d] [PowerShell] [joelgmsec/autordpwn](https://github.com/joelgmsec/autordpwn) 
- [**327**星][1y] [Py] [leapsecurity/inspy](https://github.com/leapsecurity/InSpy) 
- [**325**星][10m] [C#] [ghostpack/sharpdump](https://github.com/ghostpack/sharpdump) 
- [**322**星][1y] [Shell] [1n3/goohak](https://github.com/1n3/goohak) 
- [**318**星][22d] [Py] [codingo/interlace](https://github.com/codingo/interlace) 
- [**317**星][1y] [JS] [nccgroup/wssip](https://github.com/nccgroup/wssip) 服务器和客户端之间通信时自定义 WebSocket 数据的捕获、修改和发送。
- [**316**星][1m] [JS] [meituan-dianping/lyrebird](https://github.com/meituan-dianping/lyrebird) 
- [**316**星][1y] [Java] [ysrc/liudao](https://github.com/ysrc/liudao) 
- [**314**星][1y] [Go] [benjojo/bgp-battleships](https://github.com/benjojo/bgp-battleships) 
- [**312**星][2m] [Py] [circl/lookyloo](https://github.com/circl/lookyloo) 
- [**312**星][11m] [crazywa1ker/darthsidious-chinese](https://github.com/crazywa1ker/darthsidious-chinese) 从0开始你的域渗透之旅
- [**311**星][12d] [C] [vanhauser-thc/aflplusplus](https://github.com/vanhauser-thc/aflplusplus) 
- [**310**星][5m] [YARA] [needmorecowbell/hamburglar](https://github.com/needmorecowbell/hamburglar)  collect useful information from urls, directories, and files
- [**307**星][1m] [Go] [wangyihang/platypus](https://github.com/wangyihang/platypus)  A modern multiple reverse shell sessions/clients manager via terminal written in go
- [**306**星][3m] [PowerShell] [enigma0x3/misc-powershell-stuff](https://github.com/enigma0x3/misc-powershell-stuff) 
- [**304**星][2m] [Py] [coalfire-research/slackor](https://github.com/coalfire-research/slackor) 
- [**304**星][6m] [C] [pmem/syscall_intercept](https://github.com/pmem/syscall_intercept) Linux系统调用拦截框架，通过 hotpatching 进程标准C库的机器码实现。
- [**302**星][7m] [C] [tomac/yersinia](https://github.com/tomac/yersinia) yersinia：layer 2 攻击框架
- [**298**星][26d] [Py] [salls/angrop](https://github.com/salls/angrop) a rop gadget finder and chain builder 
- [**298**星][1m] [Py] [skylined/bugid](https://github.com/skylined/bugid) 
- [**296**星][1y] [PowerShell] [onelogicalmyth/zeroday-powershell](https://github.com/onelogicalmyth/zeroday-powershell) 
- [**295**星][6m] [HTML] [nccgroup/crosssitecontenthijacking](https://github.com/nccgroup/crosssitecontenthijacking) 
- [**295**星][1y] [C++] [nevermoe/unity_metadata_loader](https://github.com/nevermoe/unity_metadata_loader)  load strings and method/class names in global-metadata.dat to IDA
- [**295**星][1y] [JS] [xxxily/fiddler-plus](https://github.com/xxxily/fiddler-plus) 
- [**294**星][27d] [JS] [doyensec/electronegativity](https://github.com/doyensec/electronegativity) 
- [**294**星][13d] [C++] [squalr/squally](https://github.com/squalr/squally) 
- [**290**星][3m] [Shell] [fdiskyou/zines](https://github.com/fdiskyou/zines) 
- [**290**星][1m] [C] [mboehme/aflfast](https://github.com/mboehme/aflfast) 
- [**288**星][2m] [C] [9176324/shark](https://github.com/9176324/shark) 
- [**288**星][3m] [Visual Basic] [itm4n/vba-runpe](https://github.com/itm4n/vba-runpe) 
- [**286**星][8m] [C] [gianlucaborello/libprocesshider](https://github.com/gianlucaborello/libprocesshider) 
- [**286**星][1y] [Java] [webgoat/webgoat-legacy](https://github.com/webgoat/webgoat-legacy) 
- [**285**星][3m] [Py] [apache/incubator-spot](https://github.com/apache/incubator-spot) 
- [**284**星][6m] [C#] [matterpreter/offensivecsharp](https://github.com/matterpreter/offensivecsharp) 
- [**279**星][11m] [Py] [justicerage/ffm](https://github.com/justicerage/ffm) 
- [**278**星][1m] [Go] [cruise-automation/fwanalyzer](https://github.com/cruise-automation/fwanalyzer) 
- [**278**星][3m] [Py] [joxeankoret/pyew](https://github.com/joxeankoret/pyew) 
- [**277**星][1y] [HTML] [google/p0tools](https://github.com/googleprojectzero/p0tools) 
- [**277**星][16d] [Shell] [trimstray/mkchain](https://github.com/trimstray/mkchain) sslmerge: 建立从根证书到最终用户证书的有效的SSL证书链, 修复不完整的证书链并下载所有缺少的CA证书
- [**276**星][4m] [geerlingguy/ansible-role-security](https://github.com/geerlingguy/ansible-role-security) 
- [**276**星][2m] [Go] [mdsecactivebreach/o365-attack-toolkit](https://github.com/mdsecactivebreach/o365-attack-toolkit) 
- [**275**星][4m] [Py] [opsdisk/pagodo](https://github.com/opsdisk/pagodo) 
- [**273**星][3m] [PowerShell] [nullbind/powershellery](https://github.com/nullbind/powershellery) 
- [**272**星][9m] [C++] [anhkgg/superdllhijack](https://github.com/anhkgg/superdllhijack) 
- [**272**星][3m] [Py] [invernizzi/scapy-http](https://github.com/invernizzi/scapy-http) 
- [**271**星][3m] [artsploit/solr-injection](https://github.com/artsploit/solr-injection) 
- [**269**星][6m] [Py] [ropnop/windapsearch](https://github.com/ropnop/windapsearch) 
- [**268**星][4m] [Py] [den1al/jsshell](https://github.com/den1al/jsshell) 
- [**264**星][7m] [s0md3v/mypapers](https://github.com/s0md3v/mypapers) 
- [**264**星][7m] [Py] [s0md3v/breacher](https://github.com/s0md3v/Breacher) 
- [**263**星][1y] [Ruby] [evait-security/envizon](https://github.com/evait-security/envizon) envizon: 网络可视化工具, 在渗透测试中快速识别最可能的目标
- [**261**星][2m] [Shell] [al0ne/linuxcheck](https://github.com/al0ne/linuxcheck) 
- [**260**星][10m] [Py] [ant4g0nist/susanoo](https://github.com/ant4g0nist/susanoo) 
- [**260**星][5m] [C++] [d35ha/callobfuscator](https://github.com/d35ha/callobfuscator) 
- [**260**星][3m] [C] [portcullislabs/linikatz](https://github.com/portcullislabs/linikatz) UNIX版本的Mimikatz
- [**259**星][2m] [C] [eua/wxhexeditor](https://github.com/eua/wxhexeditor) 
- [**258**星][25d] [Py] [frint0/email-enum](https://github.com/frint0/email-enum) 
- [**256**星][1y] [PowerShell] [fox-it/invoke-aclpwn](https://github.com/fox-it/invoke-aclpwn) 
- [**256**星][8m] [C] [landhb/hideprocess](https://github.com/landhb/hideprocess) 
- [**256**星][1y] [Py] [m4ll0k/galileo](https://github.com/m4ll0k/galileo) 
- [**256**星][11m] [Py] [hysnsec/devsecops-studio](https://github.com/hysnsec/DevSecOps-Studio) 
- [**254**星][1m] [Shell] [cytoscape/cytoscape](https://github.com/cytoscape/cytoscape) 
- [**254**星][9m] [C] [p0f/p0f](https://github.com/p0f/p0f) 
- [**253**星][1y] [C] [benjamin-42/trident](https://github.com/benjamin-42/trident) 
- [**253**星][1y] [Java] [jackofmosttrades/gadgetinspector](https://github.com/jackofmosttrades/gadgetinspector) 
- [**252**星][2m] [C++] [poweradminllc/paexec](https://github.com/poweradminllc/paexec) 
- [**251**星][6m] [Go] [lavalamp-/ipv666](https://github.com/lavalamp-/ipv666) ipv666: IPV6地址枚举工具. Go编写
- [**250**星][14d] [C++] [fransbouma/injectablegenericcamerasystem](https://github.com/fransbouma/injectablegenericcamerasystem) 
- [**250**星][2m] [Py] [hacktoolspack/hack-tools](https://github.com/hacktoolspack/hack-tools) 
- [**249**星][6m] [Py] [itskindred/procspy](https://github.com/itskindred/procspy) 
- [**247**星][14d] [Py] [rvrsh3ll/findfrontabledomains](https://github.com/rvrsh3ll/findfrontabledomains) 
- [**246**星][4m] [Py] [redteamoperations/pivotsuite](https://github.com/redteamoperations/pivotsuite) 
- [**244**星][7m] [ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet](https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet) wordpress_plugin_security_testing_cheat_sheet：WordPress插件安全测试备忘录。
- [**243**星][9m] [Py] [wh0ale/src-experience](https://github.com/wh0ale/src-experience) 
- [**239**星][7m] [Py] [openstack/syntribos](https://github.com/openstack/syntribos) 自动化的 API 安全测试工具
- [**236**星][1y] [Py] [matthewclarkmay/geoip-attack-map](https://github.com/matthewclarkmay/geoip-attack-map) 
- [**236**星][8m] [Py] [mazen160/bfac](https://github.com/mazen160/bfac) 自动化 web app 备份文件测试工具，可检测备份文件是否会泄露 web  app 源代码
- [**234**星][15d] [Py] [cisco-config-analysis-tool/ccat](https://github.com/cisco-config-analysis-tool/ccat) 
- [**234**星][3m] [Rust] [hippolot/anevicon](https://github.com/Hippolot/anevicon) 
- [**233**星][2m] [JS] [martinzhou2015/srcms](https://github.com/martinzhou2015/srcms) 
- [**231**星][11m] [xcsh/unity-game-hacking](https://github.com/xcsh/unity-game-hacking) 
- [**230**星][29d] [Py] [timlib/webxray](https://github.com/timlib/webxray) 
- [**226**星][10m] [duoergun0729/2book](https://github.com/duoergun0729/2book) 
- [**226**星][7m] [Shell] [r00t-3xp10it/meterpreter_paranoid_mode-ssl](https://github.com/r00t-3xp10it/meterpreter_paranoid_mode-ssl) 
- [**225**星][1y] [Go] [netxfly/sec_check](https://github.com/netxfly/sec_check) 服务器安全检测的辅助工具
- [**224**星][6m] [JS] [jesusprubio/strong-node](https://github.com/jesusprubio/strong-node) 
- [**222**星][22d] [Py] [webbreacher/whatsmyname](https://github.com/webbreacher/whatsmyname) 
- [**221**星][2m] [Py] [guimaizi/get_domain](https://github.com/guimaizi/get_domain) 域名收集与监测
- [**217**星][6m] [bhdresh/dejavu](https://github.com/bhdresh/dejavu) deception framework which can be used to deploy decoys across the infrastructure
- [**215**星][9m] [Py] [mckinsey666/vocabs](https://github.com/Mckinsey666/vocabs) A lightweight online dictionary integration to the command line
- [**213**星][3m] [JS] [varchashva/letsmapyournetwork](https://github.com/varchashva/letsmapyournetwork) 
- [**212**星][4m] [Shell] [cryptolok/crykex](https://github.com/cryptolok/crykex) 
- [**212**星][1m] [Py] [wazuh/wazuh-ruleset](https://github.com/wazuh/wazuh-ruleset) ruleset is used to detect attacks, intrusions, software misuse, configuration problems, application errors, malware, rootkits, system anomalies or security policy violations.
- [**212**星][8m] [JS] [zhuyingda/veneno](https://github.com/zhuyingda/veneno) 用Node.js编写的Web安全测试框架
- [**209**星][1y] [basilfx/tradfri-hacking](https://github.com/basilfx/tradfri-hacking) 
- [**208**星][5m] [C#] [erfg12/memory.dll](https://github.com/erfg12/memory.dll) 
- [**208**星][2m] [Py] [jordanpotti/cloudscraper](https://github.com/jordanpotti/cloudscraper) Tool to enumerate targets in search of cloud resources. S3 Buckets, Azure Blobs, Digital Ocean Storage Space.
- [**205**星][4m] [PowerShell] [harmj0y/damp](https://github.com/harmj0y/damp) 
- [**205**星][12m] [Py] [orf/xcat](https://github.com/orf/xcat) 辅助盲 Xpath 注入，检索正在由 Xpath 查询处理的整个 XML 文档，读取主机文件系统上的任意文件，并使用出站 HTTP 请求，使服务器将数据直接发送到xcat
- [**205**星][12m] [C#] [tevora-threat/sharpview](https://github.com/tevora-threat/sharpview) 
- [**204**星][8m] [1hack0/facebook-bug-bounty-write-ups](https://github.com/1hack0/facebook-bug-bounty-write-ups) 
- [**203**星][14d] [Py] [seahoh/gotox](https://github.com/seahoh/gotox) 
- [**201**星][12d] [CoffeeScript] [bevry/getmac](https://github.com/bevry/getmac) 
- [**201**星][6m] [JS] [wingleung/save-page-state](https://github.com/wingleung/save-page-state) 
- [**200**星][1m] [Py] [nyxgeek/lyncsmash](https://github.com/nyxgeek/lyncsmash) 


### <a id="f34b4da04f2a77a185729b5af752efc5"></a>未分类






***


## <a id="cc80626cfd1f8411b968373eb73bc4ea"></a>人工智能&&机器学习&&深度学习&&神经网络


### <a id="19dd474da6b715024ff44d27484d528a"></a>未分类-AI


- [**4216**星][25d] [Py] [tensorflow/cleverhans](https://github.com/tensorflow/cleverhans) cleverhans：基准测试（benchmark）机器学习系统的漏洞生成（to）对抗样本（adversarial examples）
- [**3263**星][18d] [jivoi/awesome-ml-for-cybersecurity](https://github.com/jivoi/awesome-ml-for-cybersecurity) 针对网络安全的机器学习资源列表
- [**2480**星][15d] [Py] [evilsocket/pwnagotchi](https://github.com/evilsocket/pwnagotchi) 
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**1049**星][1m] [Py] [13o-bbr-bbq/machine_learning_security](https://github.com/13o-bbr-bbq/machine_learning_security) 
- [**569**星][20d] [404notf0und/ai-for-security-learning](https://github.com/404notf0und/ai-for-security-learning) 
- [**513**星][21d] [Py] [gyoisamurai/gyoithon](https://github.com/gyoisamurai/gyoithon) 使用机器学习的成长型渗透测试工具
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/渗透多合一&&渗透框架](#2051fd9e171f2698d8e7486e3dd35d87) |
- [**445**星][4m] [Py] [cchio/deep-pwning](https://github.com/cchio/deep-pwning) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Metasploit/未分类-metasploit](#01be61d5bb9f6f7199208ff0fba86b5d) |
- [**283**星][1m] [Py] [bishopfox/eyeballer](https://github.com/bishopfox/eyeballer) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |


### <a id="bab8f2640d6c5eb981003b3fd1ecc042"></a>收集






***


## <a id="a4ee2f4d4a944b54b2246c72c037cd2e"></a>收集&&集合


### <a id="e97d183e67fa3f530e7d0e7e8c33ee62"></a>未分类


- [**4097**星][20d] [qazbnm456/awesome-web-security](https://github.com/qazbnm456/awesome-web-security) web 安全资源列表
- [**2778**星][4m] [C] [juliocesarfort/public-pentesting-reports](https://github.com/juliocesarfort/public-pentesting-reports) 
- [**2747**星][2m] [infosecn1nja/red-teaming-toolkit](https://github.com/infosecn1nja/red-teaming-toolkit) 
- [**2592**星][1m] [rmusser01/infosec_reference](https://github.com/rmusser01/infosec_reference) 
- [**2483**星][2m] [kbandla/aptnotes](https://github.com/kbandla/aptnotes) 
- [**2353**星][22d] [Py] [0xinfection/awesome-waf](https://github.com/0xinfection/awesome-waf) 
- [**2253**星][11m] [yeyintminthuhtut/awesome-red-teaming](https://github.com/yeyintminthuhtut/awesome-red-teaming) 
- [**2058**星][3m] [infoslack/awesome-web-hacking](https://github.com/infoslack/awesome-web-hacking) 
- [**2024**星][1y] [bluscreenofjeff/red-team-infrastructure-wiki](https://github.com/bluscreenofjeff/red-team-infrastructure-wiki) 
- [**2008**星][1m] [tanprathan/mobileapp-pentest-cheatsheet](https://github.com/tanprathan/mobileapp-pentest-cheatsheet) 
- [**1897**星][2m] [toolswatch/blackhat-arsenal-tools](https://github.com/toolswatch/blackhat-arsenal-tools) Black Hat 武器库
- [**1767**星][1m] [djadmin/awesome-bug-bounty](https://github.com/djadmin/awesome-bug-bounty) 
- [**1706**星][4m] [ngalongc/bug-bounty-reference](https://github.com/ngalongc/bug-bounty-reference) 
- [**1698**星][1y] [coreb1t/awesome-pentest-cheat-sheets](https://github.com/coreb1t/awesome-pentest-cheat-sheets) 
- [**1602**星][6m] [Py] [w1109790800/penetration](https://github.com/w1109790800/penetration) 
- [**1587**星][6m] [Ruby] [brunofacca/zen-rails-security-checklist](https://github.com/brunofacca/zen-rails-security-checklist) 
- [**1510**星][24d] [emijrp/awesome-awesome](https://github.com/emijrp/awesome-awesome) 
- [**1340**星][19d] [grrrdog/java-deserialization-cheat-sheet](https://github.com/grrrdog/java-deserialization-cheat-sheet) 
- [**1170**星][7m] [joe-shenouda/awesome-cyber-skills](https://github.com/joe-shenouda/awesome-cyber-skills) 
- [**1126**星][2m] [Batchfile] [ckjbug/hacking](https://github.com/ckjbug/hacking) 
- [**1124**星][2m] [m4ll0k/awesome-hacking-tools](https://github.com/m4ll0k/awesome-hacking-tools) 
- [**1095**星][13d] [w00t3k/awesome-cellular-hacking](https://github.com/w00t3k/awesome-cellular-hacking) 
- [**1095**星][1y] [paulsec/awesome-windows-domain-hardening](https://github.com/PaulSec/awesome-windows-domain-hardening) 
- [**1088**星][4m] [zbetcheckin/security_list](https://github.com/zbetcheckin/security_list) 
- [**994**星][1y] [JS] [0xsobky/hackvault](https://github.com/0xsobky/hackvault) 
- [**961**星][4m] [Py] [jekil/awesome-hacking](https://github.com/jekil/awesome-hacking) 
- [**944**星][7m] [0x4d31/awesome-threat-detection](https://github.com/0x4d31/awesome-threat-detection) 
- [**940**星][6m] [sundowndev/hacker-roadmap](https://github.com/sundowndev/hacker-roadmap) 
- [**908**星][9m] [wtsxdev/penetration-testing](https://github.com/wtsxdev/penetration-testing) 
- [**905**星][6m] [PowerShell] [api0cradle/ultimateapplockerbypasslist](https://github.com/api0cradle/ultimateapplockerbypasslist) 
- [**899**星][6m] [cn0xroot/rfsec-toolkit](https://github.com/cn0xroot/rfsec-toolkit) 
- [**894**星][24d] [tom0li/collection-document](https://github.com/tom0li/collection-document) 
- [**862**星][5m] [Shell] [dominicbreuker/stego-toolkit](https://github.com/dominicbreuker/stego-toolkit) 
- [**848**星][13d] [explife0011/awesome-windows-kernel-security-development](https://github.com/explife0011/awesome-windows-kernel-security-development) 
- [**803**星][4m] [Shell] [danielmiessler/robotsdisallowed](https://github.com/danielmiessler/robotsdisallowed) 
- [**762**星][10m] [v2-dev/awesome-social-engineering](https://github.com/v2-dev/awesome-social-engineering) awesome-social-engineering：社会工程学资源集合
- [**761**星][1m] [daviddias/awesome-hacking-locations](https://github.com/daviddias/awesome-hacking-locations) 
- [**723**星][1y] [Py] [averagesecurityguy/scripts](https://github.com/averagesecurityguy/scripts) 
- [**709**星][1y] [snifer/security-cheatsheets](https://github.com/snifer/security-cheatsheets) 
- [**696**星][4m] [bit4woo/python_sec](https://github.com/bit4woo/python_sec) 
- [**685**星][2m] [C#] [harleyqu1nn/aggressorscripts](https://github.com/harleyqu1nn/aggressorscripts) 
- [**681**星][1m] [andrewjkerr/security-cheatsheets](https://github.com/andrewjkerr/security-cheatsheets) 
- [**667**星][8m] [XSLT] [adon90/pentest_compilation](https://github.com/adon90/pentest_compilation) 
    - 重复区段: [工具/OSCP](#13d067316e9894cc40fe55178ee40f24) |
- [**649**星][1y] [dsasmblr/hacking-online-games](https://github.com/dsasmblr/hacking-online-games) 
- [**628**星][9m] [webbreacher/offensiveinterview](https://github.com/webbreacher/offensiveinterview) 
- [**627**星][2m] [redhuntlabs/awesome-asset-discovery](https://github.com/redhuntlabs/awesome-asset-discovery) 
- [**619**星][3m] [3gstudent/pentest-and-development-tips](https://github.com/3gstudent/pentest-and-development-tips) 
- [**603**星][2m] [Shell] [ashishb/osx-and-ios-security-awesome](https://github.com/ashishb/osx-and-ios-security-awesome) 
- [**589**星][1y] [jiangsir404/audit-learning](https://github.com/jiangsir404/audit-learning) 
- [**587**星][11m] [pandazheng/ioshackstudy](https://github.com/pandazheng/ioshackstudy) 
- [**575**星][16d] [Py] [hslatman/awesome-industrial-control-system-security](https://github.com/hslatman/awesome-industrial-control-system-security) awesome-industrial-control-system-security：工控系统安全资源列表
- [**552**星][8m] [guardrailsio/awesome-python-security](https://github.com/guardrailsio/awesome-python-security) 
- [**452**星][8m] [gradiuscypher/infosec_getting_started](https://github.com/gradiuscypher/infosec_getting_started) 
- [**444**星][7m] [jnusimba/miscsecnotes](https://github.com/jnusimba/miscsecnotes) 
- [**426**星][1y] [meitar/awesome-lockpicking](https://github.com/meitar/awesome-lockpicking) awesome-lockpicking：有关锁、保险箱、钥匙的指南、工具及其他资源的列表
- [**404**星][19d] [meitar/awesome-cybersecurity-blueteam](https://github.com/meitar/awesome-cybersecurity-blueteam) 
- [**398**星][21d] [Py] [bl4de/security-tools](https://github.com/bl4de/security-tools) 
- [**394**星][3m] [re4lity/hacking-with-golang](https://github.com/re4lity/hacking-with-golang) 
- [**390**星][6m] [HTML] [gexos/hacking-tools-repository](https://github.com/gexos/hacking-tools-repository) 
- [**384**星][1m] [husnainfareed/awesome-ethical-hacking-resources](https://github.com/husnainfareed/Awesome-Ethical-Hacking-Resources) 
- [**380**星][1m] [dsopas/assessment-mindset](https://github.com/dsopas/assessment-mindset) 安全相关的思维导图, 可用于pentesting, bug bounty, red-teamassessments
- [**350**星][16d] [fkromer/awesome-ros2](https://github.com/fkromer/awesome-ros2) 
- [**331**星][1m] [softwareunderground/awesome-open-geoscience](https://github.com/softwareunderground/awesome-open-geoscience) 
- [**328**星][27d] [PowerShell] [mgeeky/penetration-testing-tools](https://github.com/mgeeky/penetration-testing-tools) 
- [**308**星][16d] [cryptax/confsec](https://github.com/cryptax/confsec) 
- [**303**星][4m] [trimstray/technical-whitepapers](https://github.com/trimstray/technical-whitepapers) 收集：IT白皮书、PPT、PDF、Hacking、Web应用程序安全性、数据库、逆向等
- [**299**星][1m] [HTML] [eugenekolo/sec-tools](https://github.com/eugenekolo/sec-tools) 
- [**289**星][1m] [hongrisec/web-security-attack](https://github.com/hongrisec/web-security-attack) 
- [**265**星][1y] [JS] [ropnop/serverless_toolkit](https://github.com/ropnop/serverless_toolkit) 
- [**260**星][3m] [mattnotmax/cyber-chef-recipes](https://github.com/mattnotmax/cyber-chef-recipes) 
- [**243**星][4m] [zhaoweiho/web-sec-interview](https://github.com/zhaoweiho/web-sec-interview) 
- [**232**星][21d] [pe3zx/my-infosec-awesome](https://github.com/pe3zx/my-infosec-awesome) 
- [**224**星][25d] [euphrat1ca/security_w1k1](https://github.com/euphrat1ca/security_w1k1) 
- [**211**星][5m] [guardrailsio/awesome-dotnet-security](https://github.com/guardrailsio/awesome-dotnet-security) 
- [**207**星][9m] [jeansgit/redteam](https://github.com/jeansgit/redteam) 
- [**205**星][9m] [puresec/awesome-serverless-security](https://github.com/puresec/awesome-serverless-security) 
- [**201**星][1y] [faizann24/resources-for-learning-hacking](https://github.com/faizann24/resources-for-learning-hacking) 
- [**201**星][1y] [sigp/solidity-security-blog](https://github.com/sigp/solidity-security-blog) 


### <a id="664ff1dbdafefd7d856c88112948a65b"></a>混合型收集


- [**24225**星][15d] [trimstray/the-book-of-secret-knowledge](https://github.com/trimstray/the-book-of-secret-knowledge) 
- [**10176**星][17d] [enaqx/awesome-pentest](https://github.com/enaqx/awesome-pentest) 渗透测试资源/工具集
- [**5384**星][8m] [carpedm20/awesome-hacking](https://github.com/carpedm20/awesome-hacking) Hacking教程、工具和资源
- [**4994**星][1m] [sbilly/awesome-security](https://github.com/sbilly/awesome-security) 与安全相关的软件、库、文档、书籍、资源和工具等收集
- [**3116**星][20d] [Rich Text Format] [the-art-of-hacking/h4cker](https://github.com/The-Art-of-Hacking/h4cker) 资源收集：hacking、渗透、数字取证、事件响应、漏洞研究、漏洞开发、逆向
- [**1710**星][20d] [olivierlaflamme/cheatsheet-god](https://github.com/olivierlaflamme/cheatsheet-god) 
    - 重复区段: [工具/OSCP](#13d067316e9894cc40fe55178ee40f24) |
- [**573**星][5m] [d30sa1/rootkits-list-download](https://github.com/d30sa1/rootkits-list-download) Rootkit收集
- [**551**星][17d] [Perl] [bollwarm/sectoolset](https://github.com/bollwarm/sectoolset) 安全项目工具集合


### <a id="67acc04b20c99f87ee625b073330d8c2"></a>无工具类收集


- [**33516**星][1y] [Py] [minimaxir/big-list-of-naughty-strings](https://github.com/minimaxir/big-list-of-naughty-strings) “淘气”的字符串列表，当作为用户输入时很容易引发问题
- [**8929**星][2m] [vitalysim/awesome-hacking-resources](https://github.com/vitalysim/awesome-hacking-resources) 
- [**2935**星][1m] [blacckhathaceekr/pentesting-bible](https://github.com/blacckhathaceekr/pentesting-bible) links reaches 10000 links & 10000 pdf files .Learn Ethical Hacking and penetration testing .hundreds of ethical hacking & penetration testing & red team & cyber security & computer science resources.
- [**2660**星][1m] [secwiki/sec-chart](https://github.com/secwiki/sec-chart) 
- [**2580**星][1y] [HTML] [chybeta/web-security-learning](https://github.com/chybeta/web-security-learning) 
- [**2427**星][1y] [onlurking/awesome-infosec](https://github.com/onlurking/awesome-infosec) 
- [**2306**星][10m] [hack-with-github/free-security-ebooks](https://github.com/hack-with-github/free-security-ebooks) 
- [**2054**星][2m] [yeahhub/hacking-security-ebooks](https://github.com/yeahhub/hacking-security-ebooks) 
- [**1917**星][3m] [Py] [nixawk/pentest-wiki](https://github.com/nixawk/pentest-wiki) 
- [**1434**星][4m] [hmaverickadams/beginner-network-pentesting](https://github.com/hmaverickadams/beginner-network-pentesting) 


### <a id="24707dd322098f73c7e450d6b1eddf12"></a>收集类的收集


- [**32197**星][2m] [hack-with-github/awesome-hacking](https://github.com/hack-with-github/awesome-hacking) 


### <a id="9101434a896f20263d09c25ace65f398"></a>教育资源&&课程&&教程&&书籍


- [**10844**星][1m] [CSS] [hacker0x01/hacker101](https://github.com/hacker0x01/hacker101) 
- [**3897**星][3m] [PHP] [paragonie/awesome-appsec](https://github.com/paragonie/awesome-appsec) 


### <a id="8088e46fc533286d88b945f1d472bf57"></a>笔记&&Tips&&Tricks&&Talk&&Conference


#### <a id="f57ccaab4279b60c17a03f90d96b815c"></a>未分类


- [**2786**星][29d] [paulsec/awesome-sec-talks](https://github.com/paulsec/awesome-sec-talks) 
- [**671**星][2m] [uknowsec/active-directory-pentest-notes](https://github.com/uknowsec/active-directory-pentest-notes) 
- [**540**星][9m] [PowerShell] [threatexpress/red-team-scripts](https://github.com/threatexpress/red-team-scripts) 


#### <a id="0476f6b97e87176da0a0d7328f8747e7"></a>blog


- [**1231**星][5m] [chalker/notes](https://github.com/chalker/notes) 






***


## <a id="06fccfcc4faa7da54d572c10ef29b42e"></a>移动&&Mobile


### <a id="4a64f5e8fdbd531a8c95d94b28c6c2c1"></a>未分类-Mobile


- [**4885**星][14d] [HTML] [owasp/owasp-mstg](https://github.com/owasp/owasp-mstg) 关于移动App安全开发、测试和逆向的相近手册
- [**4785**星][13d] [JS] [mobsf/mobile-security-framework-mobsf](https://github.com/MobSF/Mobile-Security-Framework-MobSF) 
- [**1940**星][20d] [Py] [sensepost/objection](https://github.com/sensepost/objection) objection： runtimemobile exploration
- [**1839**星][6m] [Java] [fuzion24/justtrustme](https://github.com/fuzion24/justtrustme) 
- [**604**星][6m] [JS] [vincentcox/stacoan](https://github.com/vincentcox/stacoan) 
    - 重复区段: [工具/审计&&安全审计&&代码审计/未分类-Audit](#6a5e7dd060e57d9fdb3fed8635d61bc7) |
- [**529**星][17d] [Shell] [owasp/owasp-masvs](https://github.com/owasp/owasp-masvs) OWASP 移动App安全标准
- [**370**星][1y] [CSS] [nowsecure/secure-mobile-development](https://github.com/nowsecure/secure-mobile-development) 
- [**320**星][5m] [Java] [datatheorem/trustkit-android](https://github.com/datatheorem/trustkit-android) 


### <a id="fe88ee8c0df10870b44c2dedcd86d3d3"></a>Android


- [**4221**星][23d] [Shell] [ashishb/android-security-awesome](https://github.com/ashishb/android-security-awesome) 
- [**2294**星][1y] [Java] [csploit/android](https://github.com/csploit/android) 
- [**2089**星][8m] [Py] [linkedin/qark](https://github.com/linkedin/qark) 查找Android App的漏洞, 支持源码或APK文件
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞扫描&&挖掘&&发现/漏洞扫描/未分类](#0ed7e90d216a8a5be1dafebaf9eaeb5d) |
- [**2033**星][9m] [jermic/android-crack-tool](https://github.com/jermic/android-crack-tool) 
- [**1966**星][7m] [Py] [fsecurelabs/drozer](https://github.com/FSecureLABS/drozer) 
- [**1414**星][10m] [Java] [aslody/legend](https://github.com/aslody/legend) (Android)无需Root即可Hook Java方法的框架, 支持Dalvik和Art环境
- [**1393**星][13d] [Java] [chrisk44/hijacker](https://github.com/chrisk44/hijacker) 
- [**1202**星][26d] [Java] [find-sec-bugs/find-sec-bugs](https://github.com/find-sec-bugs/find-sec-bugs) 
- [**1199**星][2m] [Java] [javiersantos/piracychecker](https://github.com/javiersantos/piracychecker) 
- [**781**星][2m] [sh4hin/androl4b](https://github.com/sh4hin/androl4b) 用于评估Android应用程序，逆向工程和恶意软件分析的虚拟机
    - 重复区段: [工具/环境配置&&分析系统/未分类-Env](#f5a7a43f964b2c50825f3e2fee5078c8) |
- [**664**星][17d] [doridori/android-security-reference](https://github.com/doridori/android-security-reference) 
- [**511**星][3m] [JS] [wooyundota/droidsslunpinning](https://github.com/wooyundota/droidsslunpinning) 
- [**462**星][3m] [JS] [lyxhh/lxhtoolhttpdecrypt](https://github.com/lyxhh/lxhtoolhttpdecrypt) 
- [**383**星][1y] [Py] [thehackingsage/hacktronian](https://github.com/thehackingsage/hacktronian) 
- [**372**星][3m] [Java] [megatronking/netbare](https://github.com/megatronking/netbare) 
- [**358**星][4m] [C] [the-cracker-technology/andrax-mobile-pentest](https://github.com/the-cracker-technology/andrax-mobile-pentest) 
- [**348**星][4m] [Makefile] [crifan/android_app_security_crack](https://github.com/crifan/android_app_security_crack) 
- [**341**星][4m] [b3nac/android-reports-and-resources](https://github.com/b3nac/android-reports-and-resources) 
- [**326**星][14d] [TypeScript] [shroudedcode/apk-mitm](https://github.com/shroudedcode/apk-mitm) 
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/未分类-Network](#99398a5a8aaf99228829dadff48fb6a7) |[工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**248**星][9m] [C] [chef-koch/android-vulnerabilities-overview](https://github.com/chef-koch/android-vulnerabilities-overview) 
- [**233**星][1y] [Ruby] [hahwul/droid-hunter](https://github.com/hahwul/droid-hunter) 


### <a id="dbde77352aac39ee710d3150a921bcad"></a>iOS&&MacOS&&iPhone&&iPad&&iWatch


- [**5299**星][5m] [C] [pwn20wndstuff/undecimus](https://github.com/pwn20wndstuff/undecimus) 
- [**5097**星][2m] [Py] [axi0mx/ipwndfu](https://github.com/axi0mx/ipwndfu) 
- [**4143**星][7m] [Objective-C] [alonemonkey/monkeydev](https://github.com/alonemonkey/monkeydev) 
- [**3411**星][6m] [icodesign/potatso](https://github.com/icodesign/Potatso) 
- [**3072**星][9m] [JS] [jipegit/osxauditor](https://github.com/jipegit/osxauditor) 
- [**1685**星][5m] [Py] [yelp/osxcollector](https://github.com/yelp/osxcollector) 
- [**1366**星][6m] [Objective-C] [nabla-c0d3/ssl-kill-switch2](https://github.com/nabla-c0d3/ssl-kill-switch2) 
- [**1259**星][5m] [JS] [feross/spoof](https://github.com/feross/spoof) 
- [**1218**星][5m] [Vue] [chaitin/passionfruit](https://github.com/chaitin/passionfruit) iOSapp 黑盒评估工具。功能丰富，自带基于web的 GUI
- [**1214**星][19d] [C] [datatheorem/trustkit](https://github.com/datatheorem/trustkit) 
- [**1174**星][29d] [YARA] [horsicq/detect-it-easy](https://github.com/horsicq/detect-it-easy) 
- [**1121**星][4m] [JS] [alonemonkey/frida-ios-dump](https://github.com/alonemonkey/frida-ios-dump) 
- [**1094**星][1y] [Objective-C] [neoneggplant/eggshell](https://github.com/neoneggplant/eggshell) 
- [**969**星][1y] [Py] [mwrlabs/needle](https://github.com/FSecureLABS/needle) 
- [**898**星][2m] [Objective-C] [ptoomey3/keychain-dumper](https://github.com/ptoomey3/keychain-dumper) 
- [**577**星][2m] [siguza/ios-resources](https://github.com/siguza/ios-resources) 
- [**475**星][1y] [Swift] [icepa/icepa](https://github.com/icepa/icepa) 
- [**385**星][3m] [ansjdnakjdnajkd/ios](https://github.com/ansjdnakjdnajkd/ios) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |
- [**321**星][30d] [Objective-C] [auth0/simplekeychain](https://github.com/auth0/simplekeychain) 
- [**213**星][10m] [AppleScript] [lifepillar/csvkeychain](https://github.com/lifepillar/csvkeychain) 
- [**204**星][7m] [C] [owasp/igoat](https://github.com/owasp/igoat) 




***


## <a id="c7f35432806520669b15a28161a4d26a"></a>CTF&&HTB


### <a id="c0fea206256a42e41fd5092cecf54d3e"></a>未分类-CTF&&HTB


- [**952**星][2m] [ctfs/resources](https://github.com/ctfs/resources) 
- [**744**星][1m] [Py] [ashutosh1206/crypton](https://github.com/ashutosh1206/crypton) 
- [**634**星][8m] [cryptogenic/exploit-writeups](https://github.com/cryptogenic/exploit-writeups) 
- [**474**星][5m] [PHP] [wonderkun/ctf_web](https://github.com/wonderkun/ctf_web) 
- [**472**星][3m] [PHP] [susers/writeups](https://github.com/susers/writeups) 
- [**450**星][8m] [Py] [christhecoolhut/zeratool](https://github.com/christhecoolhut/zeratool) 
- [**410**星][3m] [ctftraining/ctftraining](https://github.com/ctftraining/ctftraining) 
- [**307**星][5m] [C] [sixstars/ctf](https://github.com/sixstars/ctf) 
- [**294**星][28d] [HTML] [balsn/ctf_writeup](https://github.com/balsn/ctf_writeup) 
- [**290**星][9m] [HTML] [s1gh/ctf-literature](https://github.com/s1gh/ctf-literature) 
- [**283**星][10m] [Shell] [ctf-wiki/ctf-tools](https://github.com/ctf-wiki/ctf-tools) 
- [**260**星][5m] [CSS] [l4wio/ctf-challenges-by-me](https://github.com/l4wio/ctf-challenges-by-me) 
- [**253**星][6m] [Shell] [lieanu/libcsearcher](https://github.com/lieanu/libcsearcher) 
- [**233**星][8m] [harmoc/ctftools](https://github.com/harmoc/ctftools) 
- [**209**星][1y] [Py] [3summer/ctf-rsa-tool](https://github.com/3summer/CTF-RSA-tool) 


### <a id="30c4df38bcd1abaaaac13ffda7d206c6"></a>收集


- [**3857**星][1m] [JS] [apsdehal/awesome-ctf](https://github.com/apsdehal/awesome-ctf) 
- [**3857**星][1m] [JS] [apsdehal/awesome-ctf](https://github.com/apsdehal/awesome-ctf) 
- [**1709**星][1m] [PHP] [orangetw/my-ctf-web-challenges](https://github.com/orangetw/my-ctf-web-challenges) 
- [**945**星][19d] [C] [bt3gl/pentesting-toolkit](https://github.com/bt3gl/Pentesting-Toolkit) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |
- [**358**星][4m] [xtiankisutsa/awesome-mobile-ctf](https://github.com/xtiankisutsa/awesome-mobile-ctf) 
    - 重复区段: [工具/靶机&&漏洞环境&&漏洞App/收集](#383ad9174d3f7399660d36cd6e0b2c00) |


### <a id="0d871dfb0d2544d6952c04f69a763059"></a>HTB


- [**642**星][28d] [hackplayers/hackthebox-writeups](https://github.com/hackplayers/hackthebox-writeups) 


### <a id="e64cedb2d91d06b3eeac5ea414e12b27"></a>CTF


#### <a id="e8853f1153694b24db203d960e394827"></a>未分类-CTF


- [**6102**星][1y] [Hack] [facebook/fbctf](https://github.com/facebook/fbctf) 
- [**5861**星][14d] [Py] [gallopsled/pwntools](https://github.com/gallopsled/pwntools) 
- [**4317**星][1m] [Shell] [zardus/ctf-tools](https://github.com/zardus/ctf-tools) 
- [**2756**星][19d] [HTML] [ctf-wiki/ctf-wiki](https://github.com/ctf-wiki/ctf-wiki) 
- [**2295**星][19d] [Py] [ctfd/ctfd](https://github.com/CTFd/CTFd) 
- [**1531**星][1m] [C] [firmianay/ctf-all-in-one](https://github.com/firmianay/ctf-all-in-one) 
- [**1343**星][4m] [Go] [google/google-ctf](https://github.com/google/google-ctf) 
- [**1340**星][3m] [C] [taviso/ctftool](https://github.com/taviso/ctftool) 
- [**1248**星][11m] [Py] [unapibageek/ctfr](https://github.com/unapibageek/ctfr) 
- [**1244**星][2m] [Py] [ganapati/rsactftool](https://github.com/ganapati/rsactftool) RSA攻击工具，主要用于CTF，从弱公钥和/或uncipher数据中回复私钥
- [**1132**星][16d] [Py] [p4-team/ctf](https://github.com/p4-team/ctf) 
- [**1034**星][2m] [C] [trailofbits/ctf](https://github.com/trailofbits/ctf) 
- [**1013**星][12m] [naetw/ctf-pwn-tips](https://github.com/naetw/ctf-pwn-tips) 
- [**845**星][1m] [Ruby] [w181496/web-ctf-cheatsheet](https://github.com/w181496/web-ctf-cheatsheet) 
- [**824**星][28d] [ignitetechnologies/privilege-escalation](https://github.com/ignitetechnologies/privilege-escalation) 
- [**780**星][2m] [Py] [acmesec/ctfcracktools](https://github.com/Acmesec/CTFCrackTools) 中国国内首个CTF工具框架,旨在帮助CTFer快速攻克难关
- [**609**星][1m] [Shell] [diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration) 
- [**423**星][6m] [HTML] [ctf-wiki/ctf-challenges](https://github.com/ctf-wiki/ctf-challenges) 
- [**397**星][2m] [Py] [j00ru/ctf-tasks](https://github.com/j00ru/ctf-tasks) 
- [**381**星][14d] [Py] [moloch--/rootthebox](https://github.com/moloch--/rootthebox) 
- [**373**星][4m] [C] [hackgnar/ble_ctf](https://github.com/hackgnar/ble_ctf) 
- [**309**星][2m] [PHP] [nakiami/mellivora](https://github.com/nakiami/mellivora) 
- [**302**星][7m] [Py] [screetsec/brutesploit](https://github.com/screetsec/brutesploit) 
- [**292**星][2m] [Py] [christhecoolhut/pinctf](https://github.com/christhecoolhut/pinctf) 
- [**275**星][11m] [Py] [hongrisec/ctf-training](https://github.com/hongrisec/ctf-training) 
- [**252**星][5m] [Shell] [ctfhacker/epictreasure](https://github.com/ctfhacker/EpicTreasure) Batteries included CTF VM
- [**236**星][12m] [Java] [shiltemann/ctf-writeups-public](https://github.com/shiltemann/ctf-writeups-public) 
- [**218**星][2m] [HTML] [sectalks/sectalks](https://github.com/sectalks/sectalks) 
- [**215**星][1m] [C] [david942j/ctf-writeups](https://github.com/david942j/ctf-writeups) 


#### <a id="0591f47788c6926c482f385b1d71efec"></a>Writeup


- [**1813**星][1y] [CSS] [ctfs/write-ups-2015](https://github.com/ctfs/write-ups-2015) 
- [**1763**星][11m] [Py] [ctfs/write-ups-2017](https://github.com/ctfs/write-ups-2017) 
- [**586**星][1m] [Py] [pwning/public-writeup](https://github.com/pwning/public-writeup) 
- [**489**星][8m] [manoelt/50m_ctf_writeup](https://github.com/manoelt/50m_ctf_writeup) 
- [**275**星][7m] [HTML] [bl4de/ctf](https://github.com/bl4de/ctf) 
- [**222**星][1y] [Shell] [ctfs/write-ups-2018](https://github.com/ctfs/write-ups-2018) 


#### <a id="dc89088263fc944901fd7a58197a5f6d"></a>收集








***


## <a id="683b645c2162a1fce5f24ac2abfa1973"></a>漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing


### <a id="9d1ce4a40c660c0ce15aec6daf7f56dd"></a>未分类-Vul


- [**1968**星][12d] [Java] [jeremylong/dependencycheck](https://github.com/jeremylong/dependencycheck) 
- [**1797**星][27d] [TypeScript] [snyk/snyk](https://github.com/snyk/snyk) 
- [**1619**星][18d] [roave/securityadvisories](https://github.com/roave/securityadvisories) ensures that your application doesn't have installed dependencies with known security vulnerabilities
- [**1535**星][1m] [Java] [spotbugs/spotbugs](https://github.com/spotbugs/spotbugs) 
- [**1284**星][12m] [Py] [xyntax/poc-t](https://github.com/xyntax/poc-t) 脚本调用框架，用于渗透测试中 采集|爬虫|爆破|批量PoC 等需要并发的任务
- [**1232**星][30d] [JS] [archerysec/archerysec](https://github.com/archerysec/archerysec) 
- [**1079**星][19d] [Jupyter Notebook] [ibm/adversarial-robustness-toolbox](https://github.com/ibm/adversarial-robustness-toolbox) 
- [**1074**星][1y] [PowerShell] [rasta-mouse/sherlock](https://github.com/rasta-mouse/sherlock) 
- [**1018**星][16d] [HTML] [defectdojo/django-defectdojo](https://github.com/defectdojo/django-defectdojo) 
- [**901**星][19d] [Py] [knownsec/pocsuite3](https://github.com/knownsec/pocsuite3) 远程漏洞测试与PoC开发框架
- [**814**星][6m] [numirias/security](https://github.com/numirias/security) 
- [**813**星][3m] [JS] [creditease-sec/insight](https://github.com/creditease-sec/insight) 
- [**806**星][1y] [Py] [leviathan-framework/leviathan](https://github.com/tearsecurity/leviathan) 多功能审计工具包，包括多种服务发现（FTP、SSH、Talnet、RDP、MYSQL）、爆破、远程命令执行、SQL注入扫描、指定漏洞利用，集成了Masscan、Ncrack、DSSS等工具。
- [**625**星][5m] [Py] [pyupio/safety](https://github.com/pyupio/safety) 检查所有已安装 Python 包, 查找已知的安全漏洞
- [**578**星][7m] [Java] [olacabs/jackhammer](https://github.com/olacabs/jackhammer) 安全漏洞评估和管理工具
- [**567**星][12d] [arkadiyt/bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) 
- [**541**星][1y] [Java] [mr5m1th/poc-collect](https://github.com/Mr5m1th/POC-Collect) 
- [**540**星][10m] [PHP] [zhuifengshaonianhanlu/pikachu](https://github.com/zhuifengshaonianhanlu/pikachu) 
- [**462**星][1m] [Java] [joychou93/java-sec-code](https://github.com/joychou93/java-sec-code) 
- [**430**星][28d] [Py] [google/vulncode-db](https://github.com/google/vulncode-db)  a database for vulnerabilities and their corresponding source code if available
- [**428**星][4m] [Py] [crocs-muni/roca](https://github.com/crocs-muni/roca) 测试公共 RSA 密钥是否存在某些漏洞
- [**409**星][4m] [Java] [nccgroup/freddy](https://github.com/nccgroup/freddy) 自动识别 Java/.NET 应用程序中的反序列化漏洞
- [**395**星][17d] [Go] [cbeuw/cloak](https://github.com/cbeuw/cloak) 
- [**379**星][10m] [skyblueeternal/thinkphp-rce-poc-collection](https://github.com/skyblueeternal/thinkphp-rce-poc-collection) 
- [**372**星][6m] [tidesec/tide](https://github.com/tidesec/tide) 
- [**361**星][12m] [hannob/vulns](https://github.com/hannob/vulns) 
- [**357**星][8m] [C] [vulnreproduction/linuxflaw](https://github.com/vulnreproduction/linuxflaw) 
- [**354**星][6m] [PHP] [fate0/prvd](https://github.com/fate0/prvd) 
- [**351**星][6m] [Py] [orangetw/awesome-jenkins-rce-2019](https://github.com/orangetw/awesome-jenkins-rce-2019) 
- [**342**星][2m] [snyk/zip-slip-vulnerability](https://github.com/snyk/zip-slip-vulnerability) 
- [**335**星][2m] [Java] [denimgroup/threadfix](https://github.com/denimgroup/threadfix) threadfix：软件漏洞汇总和管理系统，可帮助组织汇总漏洞数据，生成虚拟补丁，并与软件缺陷跟踪系统进行交互
- [**314**星][27d] [Java] [sap/vulnerability-assessment-tool](https://github.com/sap/vulnerability-assessment-tool) 
- [**312**星][11m] [cryin/paper](https://github.com/cryin/paper) 
- [**299**星][16d] [Py] [ym2011/poc-exp](https://github.com/ym2011/poc-exp) 
- [**291**星][3m] [Py] [christhecoolhut/firmware_slap](https://github.com/christhecoolhut/firmware_slap) 
- [**286**星][2m] [Py] [fplyth0ner-combie/bug-project-framework](https://github.com/fplyth0ner-combie/bug-project-framework) 
- [**283**星][4m] [C#] [l0ss/grouper2](https://github.com/l0ss/grouper2) 
- [**283**星][7m] [C] [tangsilian/android-vuln](https://github.com/tangsilian/android-vuln) 
- [**271**星][21d] [disclose/disclose](https://github.com/disclose/disclose) 
- [**265**星][1y] [Py] [ucsb-seclab/bootstomp](https://github.com/ucsb-seclab/bootstomp) a bootloader vulnerability finder
- [**263**星][1y] [JS] [portswigger/hackability](https://github.com/portswigger/hackability) 
- [**249**星][5m] [Py] [jcesarstef/dotdotslash](https://github.com/jcesarstef/dotdotslash) Python脚本, 查找目录遍历漏洞
- [**234**星][19d] [HTML] [edoverflow/bugbountyguide](https://github.com/edoverflow/bugbountyguide) 
- [**220**星][2m] [Py] [ismailtasdelen/hackertarget](https://github.com/pyhackertarget/hackertarget) attack surface discovery and identification of security vulnerabilities
- [**211**星][2m] [C++] [atxsinn3r/vulncases](https://github.com/atxsinn3r/VulnCases) 
- [**207**星][6m] [Py] [jas502n/cnvd-c-2019-48814](https://github.com/jas502n/cnvd-c-2019-48814) 
- [**202**星][6m] [Py] [greekn/rce-bug](https://github.com/greekn/rce-bug) 
- [**201**星][2m] [Ruby] [appfolio/gemsurance](https://github.com/appfolio/gemsurance) 
- [**201**星][7m] [C++] [j00ru/kfetch-toolkit](https://github.com/googleprojectzero/bochspwn) 


### <a id="750f4c05b5ab059ce4405f450b56d720"></a>资源收集


- [**3444**星][8m] [C] [rpisec/mbe](https://github.com/rpisec/mbe) 
- [**3429**星][4m] [PHP] [hanc00l/wooyun_public](https://github.com/hanc00l/wooyun_public) 
- [**2954**星][8m] [C] [secwiki/linux-kernel-exploits](https://github.com/secwiki/linux-kernel-exploits) 
- [**2600**星][1m] [xairy/linux-kernel-exploitation](https://github.com/xairy/linux-kernel-exploitation) Linux 内核 Fuzz 和漏洞利用的资源收集
- [**2072**星][14d] [PowerShell] [k8gege/k8tools](https://github.com/k8gege/k8tools) 
- [**1962**星][14d] [qazbnm456/awesome-cve-poc](https://github.com/qazbnm456/awesome-cve-poc) CVE PoC列表
- [**1882**星][1m] [HTML] [gtfobins/gtfobins.github.io](https://github.com/gtfobins/gtfobins.github.io) 
- [**1701**星][3m] [tunz/js-vuln-db](https://github.com/tunz/js-vuln-db) 
- [**1196**星][1y] [felixgr/secure-ios-app-dev](https://github.com/felixgr/secure-ios-app-dev) secure-ios-app-dev：iOSApp 最常见漏洞收集
- [**1093**星][5m] [Py] [coffeehb/some-poc-or-exp](https://github.com/coffeehb/some-poc-or-exp) 
- [**1044**星][14d] [Py] [offensive-security/exploitdb-bin-sploits](https://github.com/offensive-security/exploitdb-bin-sploits) 
- [**1020**星][1m] [C] [xairy/kernel-exploits](https://github.com/xairy/kernel-exploits) 
- [**1006**星][19d] [Py] [thekingofduck/fuzzdicts](https://github.com/thekingofduck/fuzzdicts) 
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞扫描&&挖掘&&发现/Fuzzing/未分类-Fuzz](#1c2903ee7afb903ccfaa26f766924385) |
- [**977**星][10m] [Py] [xiphosresearch/exploits](https://github.com/xiphosresearch/exploits) 
- [**962**星][11m] [PHP] [secwiki/cms-hunter](https://github.com/secwiki/cms-hunter) 
- [**938**星][5m] [C] [dhavalkapil/heap-exploitation](https://github.com/dhavalkapil/heap-exploitation) 
- [**894**星][2m] [Py] [nullsecuritynet/tools](https://github.com/nullsecuritynet/tools) 
- [**672**星][1y] [C] [billy-ellis/exploit-challenges](https://github.com/billy-ellis/exploit-challenges) 
- [**609**星][7m] [yeyintminthuhtut/awesome-advanced-windows-exploitation-references](https://github.com/yeyintminthuhtut/Awesome-Advanced-Windows-Exploitation-References) 
- [**568**星][1y] [C] [externalist/exploit_playground](https://github.com/externalist/exploit_playground) 
- [**483**星][7m] [C] [jiayy/android_vuln_poc-exp](https://github.com/jiayy/android_vuln_poc-exp) 
- [**417**星][9m] [C] [hardenedlinux/linux-exploit-development-tutorial](https://github.com/hardenedlinux/linux-exploit-development-tutorial) 
- [**329**星][1y] [snyk/vulnerabilitydb](https://github.com/snyk/vulnerabilitydb) 
- [**268**星][10m] [Py] [secwiki/office-exploits](https://github.com/secwiki/office-exploits) 
- [**222**星][2m] [Py] [boy-hack/airbug](https://github.com/boy-hack/airbug) 
- [**222**星][1y] [C++] [wnagzihxa1n/browsersecurity](https://github.com/wnagzihxa1n/browsersecurity) 


### <a id="605b1b2b6eeb5138cb4bc273a30b28a5"></a>漏洞开发


#### <a id="68a64028eb1f015025d6f5a6ee6f6810"></a>未分类-VulDev


- [**3705**星][10m] [Py] [longld/peda](https://github.com/longld/peda) Python Exploit Development Assistance for GDB
- [**2488**星][13d] [Py] [hugsy/gef](https://github.com/hugsy/gef) gdb增强工具，使用Python API，用于漏洞开发和逆向分析。
- [**2362**星][22d] [Py] [pwndbg/pwndbg](https://github.com/pwndbg/pwndbg) GDB插件，辅助漏洞开发和逆向
- [**465**星][10m] [Py] [wapiflapi/villoc](https://github.com/wapiflapi/villoc) 


#### <a id="019cf10dbc7415d93a8d22ef163407ff"></a>ROP


- [**2101**星][27d] [Py] [jonathansalwan/ropgadget](https://github.com/jonathansalwan/ropgadget) 
- [**931**星][13d] [Py] [sashs/ropper](https://github.com/sashs/ropper) 
- [**677**星][11m] [HTML] [zhengmin1989/myarticles](https://github.com/zhengmin1989/myarticles) 




### <a id="c0bec2b143739028ff4ec439e077aa63"></a>漏洞扫描&&挖掘&&发现


#### <a id="5d02822c22d815c94c58cdaed79d6482"></a>未分类




#### <a id="661f41705ac69ad4392372bd4bd02f01"></a>漏洞扫描


##### <a id="0ed7e90d216a8a5be1dafebaf9eaeb5d"></a>未分类


- [**6953**星][24d] [Go] [future-architect/vuls](https://github.com/future-architect/vuls) 针对Linux/FreeBSD 编写的漏洞扫描器. Go 语言编写
- [**6516**星][16d] [Java] [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy) 在开发和测试Web App时自动发现安全漏洞
- [**5563**星][17d] [Ruby] [presidentbeef/brakeman](https://github.com/presidentbeef/brakeman) ROR程序的静态分析工具
- [**2904**星][21d] [Py] [andresriancho/w3af](https://github.com/andresriancho/w3af) Web App安全扫描器, 辅助开发者和渗透测试人员识别和利用Web App中的漏洞
    - 重复区段: [工具/扫描器&&安全扫描&&App扫描&&漏洞扫描/未分类-Scanner](#de63a029bda6a7e429af272f291bb769) |
- [**2440**星][6m] [Py] [ysrc/xunfeng](https://github.com/ysrc/xunfeng) 
- [**2403**星][28d] [Go] [knqyf263/trivy](https://github.com/aquasecurity/trivy) 
- [**2089**星][8m] [Py] [linkedin/qark](https://github.com/linkedin/qark) 查找Android App的漏洞, 支持源码或APK文件
    - 重复区段: [工具/移动&&Mobile/Android](#fe88ee8c0df10870b44c2dedcd86d3d3) |
- [**1873**星][1m] [Py] [j3ssie/osmedeus](https://github.com/j3ssie/osmedeus) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/信息收集&&侦查&&Recon&&InfoGather](#375a8baa06f24de1b67398c1ac74ed24) |
- [**1864**星][3m] [Py] [python-security/pyt](https://github.com/python-security/pyt) Python Web App 安全漏洞检测和静态分析工具
- [**1629**星][1y] [Py] [evyatarmeged/raccoon](https://github.com/evyatarmeged/raccoon) 高性能的侦查和漏洞扫描工具
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/信息收集&&侦查&&Recon&&InfoGather](#375a8baa06f24de1b67398c1ac74ed24) |
- [**1370**星][6m] [Py] [almandin/fuxploider](https://github.com/almandin/fuxploider) 文件上传漏洞扫描和利用工具
- [**1339**星][5m] [Py] [s0md3v/striker](https://github.com/s0md3v/Striker) 
- [**1023**星][7m] [Py] [lucifer1993/angelsword](https://github.com/lucifer1993/angelsword) 
- [**932**星][1y] [Java] [google/firing-range](https://github.com/google/firing-range)  a test bed for web application security scanners, providing synthetic, wide coverage for an array of vulnerabilities.
- [**913**星][4m] [threathuntingproject/threathunting](https://github.com/threathuntingproject/threathunting) 
- [**884**星][1m] [Go] [opensec-cn/kunpeng](https://github.com/opensec-cn/kunpeng) Golang编写的开源POC框架/库，以动态链接库的形式提供各种语言调用，通过此项目可快速开发漏洞检测类的系统。
- [**884**星][2m] [Py] [hasecuritysolutions/vulnwhisperer](https://github.com/HASecuritySolutions/VulnWhisperer) 
- [**852**星][3m] [Py] [boy-hack/w9scan](https://github.com/w-digital-scanner/w9scan) 
- [**840**星][3m] [Py] [lijiejie/bbscan](https://github.com/lijiejie/bbscan) 
- [**725**星][10m] [PowerShell] [l0ss/grouper](https://github.com/l0ss/grouper) 
- [**643**星][5m] [Perl] [moham3driahi/xattacker](https://github.com/moham3driahi/xattacker) 
- [**632**星][5m] [PHP] [mattiasgeniar/php-exploit-scripts](https://github.com/mattiasgeniar/php-exploit-scripts) 
- [**602**星][10m] [Dockerfile] [aquasecurity/microscanner](https://github.com/aquasecurity/microscanner) 
- [**539**星][5m] [JS] [seccubus/seccubus](https://github.com/seccubus/seccubus) 
- [**523**星][3m] [Py] [hatboy/struts2-scan](https://github.com/hatboy/struts2-scan) 
- [**513**星][7m] [Py] [wyatu/perun](https://github.com/wyatu/perun) 主要适用于乙方安服、渗透测试人员和甲方RedTeam红队人员的网络资产漏洞扫描器/扫描框架
- [**491**星][14d] [C#] [k8gege/ladon](https://github.com/k8gege/ladon) 
- [**488**星][2m] [Perl 6] [rezasp/joomscan](https://github.com/rezasp/joomscan) Perl语言编写的Joomla CMS漏洞扫描器
- [**452**星][1m] [C] [greenbone/openvas-scanner](https://github.com/greenbone/openvas) 
- [**443**星][5m] [Py] [dr0op/weblogicscan](https://github.com/dr0op/weblogicscan) 
- [**436**星][15d] [Py] [k8gege/k8cscan](https://github.com/k8gege/k8cscan) 大型内网渗透自定义插件化扫描神器，包含信息收集、网络资产、漏洞扫描、密码爆破、漏洞利用，程序采用多线程批量扫描大型内网多个IP段C段主机，目前插件包含: C段旁注扫描、子域名扫描、Ftp密码爆破、Mysql密码爆破、Oracle密码爆破、MSSQL密码爆破、Windows/Linux系统密码爆破、存活主机扫描、端口扫描、Web信息探测、操作系统版本探测、Cisco思科设备扫描等,支持调用任意外部程序或脚本，支持Cobalt Strike联动
- [**375**星][10m] [Py] [hahwul/a2sv](https://github.com/hahwul/a2sv) a2sv：自动扫描并检测常见的和已知的SSL 漏洞
- [**362**星][1m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) 若干快速访问功能, 扫描字符串格式化漏洞
        <details>
        <summary>查看详情</summary>


        ### 功能
        - 快速移除函数返回类型
        - 数据格式(format)快速转换
        - 扫描字符串格式化漏洞
        - 双击跳转vtable函数
        - 快捷键: w/c/v
        </details>


- [**351**星][1m] [C#] [security-code-scan/security-code-scan](https://github.com/security-code-scan/security-code-scan) 
- [**343**星][2m] [Py] [chenjj/corscanner](https://github.com/chenjj/corscanner) 
- [**319**星][3m] [Py] [vulmon/vulmap](https://github.com/vulmon/vulmap) 
- [**318**星][7m] [C#] [yalcinyolalan/wssat](https://github.com/yalcinyolalan/wssat) web service security scanning tool which provides a dynamic environment to add, update or delete vulnerabilities by just editing its configuration files
- [**297**星][4m] [Py] [zhaoweiho/securitymanageframwork](https://github.com/zhaoweiho/securitymanageframwork) 
- [**287**星][1y] [Py] [flipkart-incubator/watchdog](https://github.com/flipkart-incubator/watchdog) 全面的安全扫描和漏洞管理工具
- [**285**星][2m] [Py] [utiso/dorkbot](https://github.com/utiso/dorkbot) dorkbot：扫描谷歌搜索返回的网页，查找网页漏洞
- [**279**星][7m] [Py] [vulscanteam/vulscan](https://github.com/vulscanteam/vulscan) 
- [**276**星][5m] [Perl] [rezasp/vbscan](https://github.com/rezasp/vbscan) 
- [**257**星][2m] [JS] [stono/hawkeye](https://github.com/hawkeyesec/scanner-cli) 
- [**246**星][4m] [Shell] [peterpt/eternal_scanner](https://github.com/peterpt/eternal_scanner) eternal_scanner：永恒之蓝漏洞的网络扫描器
- [**226**星][1y] [Py] [leapsecurity/libssh-scanner](https://github.com/leapsecurity/libssh-scanner) 
- [**222**星][1y] [C++] [ucsb-seclab/dr_checker](https://github.com/ucsb-seclab/dr_checker) 用于Linux 内核驱动程序的漏洞检测工具
- [**218**星][7m] [Py] [skewwg/vulscan](https://github.com/skewwg/vulscan) 
- [**211**星][6m] [Py] [kingkaki/weblogic-scan](https://github.com/kingkaki/weblogic-scan) 
- [**208**星][20d] [Py] [sethsec/celerystalk](https://github.com/sethsec/celerystalk) 


##### <a id="d22e52bd9f47349df896ca85675d1e5c"></a>Web漏洞




##### <a id="060dd7b419423ee644794fccd67c22a8"></a>系统漏洞




##### <a id="67939d66cf2a9d9373cc0a877a8c72c2"></a>App漏洞




##### <a id="2076af46c7104737d06dbe29eb7c9d3a"></a>移动平台漏洞






#### <a id="382aaa11dea4036c5b6d4a8b06f8f786"></a>Fuzzing


##### <a id="1c2903ee7afb903ccfaa26f766924385"></a>未分类-Fuzz


- [**4649**星][29d] [C] [google/oss-fuzz](https://github.com/google/oss-fuzz) oss-fuzz：开源软件fuzzing
- [**3992**星][12d] [Py] [google/clusterfuzz](https://github.com/google/clusterfuzz) 
- [**3169**星][1m] [Go] [dvyukov/go-fuzz](https://github.com/dvyukov/go-fuzz) 
- [**1706**星][1y] [PowerShell] [fuzzysecurity/powershell-suite](https://github.com/fuzzysecurity/powershell-suite) 
- [**1335**星][2m] [C] [googleprojectzero/winafl](https://github.com/googleprojectzero/winafl) 
- [**1107**星][9m] [Py] [openrce/sulley](https://github.com/openrce/sulley) 
- [**1100**星][28d] [bo0om/fuzz.txt](https://github.com/bo0om/fuzz.txt) 
- [**1006**星][19d] [Py] [thekingofduck/fuzzdicts](https://github.com/thekingofduck/fuzzdicts) 
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/资源收集](#750f4c05b5ab059ce4405f450b56d720) |
- [**990**星][28d] [C] [google/fuzzer-test-suite](https://github.com/google/fuzzer-test-suite) 
- [**859**星][18d] [Py] [swisskyrepo/ssrfmap](https://github.com/swisskyrepo/ssrfmap) 
- [**850**星][25d] [Go] [sahilm/fuzzy](https://github.com/sahilm/fuzzy) 
- [**808**星][1m] [C] [rust-fuzz/afl.rs](https://github.com/rust-fuzz/afl.rs) 
- [**788**星][17d] [Swift] [googleprojectzero/fuzzilli](https://github.com/googleprojectzero/fuzzilli) 
- [**748**星][23d] [Py] [jtpereyda/boofuzz](https://github.com/jtpereyda/boofuzz) 网络协议Fuzzing框架, sulley的继任者
- [**736**星][7m] [HTML] [tennc/fuzzdb](https://github.com/tennc/fuzzdb) 
- [**689**星][14d] [Go] [ffuf/ffuf](https://github.com/ffuf/ffuf) 
- [**634**星][28d] [Go] [google/gofuzz](https://github.com/google/gofuzz) 
- [**628**星][4m] [C] [kernelslacker/trinity](https://github.com/kernelslacker/trinity) 
- [**608**星][14d] [C] [google/afl](https://github.com/google/afl) 
- [**588**星][4m] [Py] [nongiach/arm_now](https://github.com/nongiach/arm_now) arm_now: 快速创建并运行不同CPU架构的虚拟机, 用于逆向分析或执行二进制文件. 基于QEMU
- [**569**星][19d] [Py] [1n3/blackwidow](https://github.com/1n3/blackwidow) 
- [**541**星][8m] [Py] [shellphish/fuzzer](https://github.com/shellphish/fuzzer) fuzzer：Americanfuzzy lop 的 Python 版本接口
- [**516**星][2m] [C++] [angorafuzzer/angora](https://github.com/angorafuzzer/angora) 
- [**500**星][12d] [Py] [mozillasecurity/funfuzz](https://github.com/mozillasecurity/funfuzz) 
- [**472**星][1y] [Py] [c0ny1/upload-fuzz-dic-builder](https://github.com/c0ny1/upload-fuzz-dic-builder) 
- [**471**星][16d] [Py] [trailofbits/deepstate](https://github.com/trailofbits/deepstate) 
- [**453**星][1m] [Rust] [rust-fuzz/cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) cargo-fuzz：libFuzzer的wrapper
- [**424**星][2m] [Perl] [wireghoul/dotdotpwn](https://github.com/wireghoul/dotdotpwn) 
- [**404**星][6m] [Ruby] [tidesec/fuzzscanner](https://github.com/tidesec/fuzzscanner) 
- [**398**星][4m] [C] [mykter/afl-training](https://github.com/mykter/afl-training) 
- [**384**星][6m] [C] [coolervoid/0d1n](https://github.com/coolervoid/0d1n) 
- [**379**星][27d] [Haskell] [crytic/echidna](https://github.com/crytic/echidna) echidna: Ethereum fuzz testing framework
- [**378**星][3m] [Rust] [microsoft/lain](https://github.com/microsoft/lain) 
- [**370**星][1m] [TypeScript] [fuzzitdev/jsfuzz](https://github.com/fuzzitdev/jsfuzz) 
- [**364**星][1y] [C] [battelle/afl-unicorn](https://github.com/Battelle/afl-unicorn) 
- [**357**星][3m] [C++] [googleprojectzero/brokentype](https://github.com/googleprojectzero/BrokenType) 
- [**340**星][4m] [Java] [google/graphicsfuzz](https://github.com/google/graphicsfuzz) 
- [**340**星][1m] [C++] [sslab-gatech/qsym](https://github.com/sslab-gatech/qsym) 
- [**337**星][11m] [Py] [joxeankoret/nightmare](https://github.com/joxeankoret/nightmare) 
- [**311**星][3m] [lcatro/source-and-fuzzing](https://github.com/lcatro/Source-and-Fuzzing) 
- [**306**星][5m] [Py] [cisco-talos/mutiny-fuzzer](https://github.com/cisco-talos/mutiny-fuzzer) 
- [**304**星][9m] [Py] [cisco-sas/kitty](https://github.com/cisco-sas/kitty) 
- [**298**星][10m] [Py] [mseclab/pyjfuzz](https://github.com/mseclab/pyjfuzz) 
- [**292**星][5m] [Py] [mozillasecurity/dharma](https://github.com/mozillasecurity/dharma) 
- [**283**星][10m] [C++] [gamozolabs/applepie](https://github.com/gamozolabs/applepie) 
- [**278**星][11m] [Py] [mrash/afl-cov](https://github.com/mrash/afl-cov) 
- [**278**星][10m] [C] [samhocevar/zzuf](https://github.com/samhocevar/zzuf) 
- [**277**星][1m] [Py] [tomato42/tlsfuzzer](https://github.com/tomato42/tlsfuzzer) 
- [**273**星][17d] [HTML] [mozillasecurity/fuzzdata](https://github.com/mozillasecurity/fuzzdata) 
- [**272**星][1y] [C++] [dekimir/ramfuzz](https://github.com/dekimir/ramfuzz) 
- [**268**星][17d] [C] [aflsmart/aflsmart](https://github.com/aflsmart/aflsmart) 
- [**263**星][8m] [Py] [mozillasecurity/peach](https://github.com/mozillasecurity/peach) 
- [**245**星][7m] [C++] [ucsb-seclab/difuze](https://github.com/ucsb-seclab/difuze) difuze: 针对 Linux 内核驱动的 Fuzzer
- [**239**星][5m] [C] [compsec-snu/razzer](https://github.com/compsec-snu/razzer) 
- [**239**星][1y] [Py] [hgascon/pulsar](https://github.com/hgascon/pulsar) pulsar：具有自动学习、模拟协议功能的网络 fuzzer
- [**230**星][4m] [HTML] [rootup/bfuzz](https://github.com/rootup/bfuzz) 
- [**222**星][3m] [C] [pagalaxylab/unifuzzer](https://github.com/PAGalaxyLab/uniFuzzer) 
- [**221**星][3m] [C] [dongdongshe/neuzz](https://github.com/dongdongshe/neuzz) 
- [**214**星][27d] [cpuu/awesome-fuzzing](https://github.com/cpuu/awesome-fuzzing) 
- [**212**星][3m] [C++] [lifting-bits/grr](https://github.com/lifting-bits/grr) 
- [**210**星][4m] [C] [hunter-ht-2018/ptfuzzer](https://github.com/hunter-ht-2018/ptfuzzer) 
- [**207**星][4m] [HTML] [ajinabraham/droid-application-fuzz-framework](https://github.com/ajinabraham/droid-application-fuzz-framework) 
- [**203**星][2m] [Py] [jwilk/python-afl](https://github.com/jwilk/python-afl) 


##### <a id="a9a8b68c32ede78eee0939cf16128300"></a>资源收集


- [**3792**星][1m] [PHP] [fuzzdb-project/fuzzdb](https://github.com/fuzzdb-project/fuzzdb) 通过动态App安全测试来查找App安全漏洞, 算是不带扫描器的漏洞扫描器
- [**2864**星][5m] [secfigo/awesome-fuzzing](https://github.com/secfigo/awesome-fuzzing) 


##### <a id="ff703caa7c3f7b197608abaa76b1a263"></a>Fuzzer


- [**2629**星][17d] [Go] [google/syzkaller](https://github.com/google/syzkaller) 一个unsupervised、以 coverage 为导向的Linux 系统调用fuzzer
- [**2346**星][1m] [Py] [xmendez/wfuzz](https://github.com/xmendez/wfuzz) 
- [**1699**星][21d] [C] [google/honggfuzz](https://github.com/google/honggfuzz) 
- [**1051**星][2m] [Py] [googleprojectzero/domato](https://github.com/googleprojectzero/domato) ProjectZero 开源的 DOM fuzzer






### <a id="41ae40ed61ab2b61f2971fea3ec26e7c"></a>漏洞利用


#### <a id="c83f77f27ccf5f26c8b596979d7151c3"></a>漏洞利用


- [**3933**星][3m] [Py] [nullarray/autosploit](https://github.com/nullarray/autosploit) 
- [**3364**星][1m] [C] [shellphish/how2heap](https://github.com/shellphish/how2heap) how2heap：学习各种堆利用技巧的repo
- [**2175**星][10m] [JS] [secgroundzero/warberry](https://github.com/secgroundzero/warberry) 
- [**1448**星][3m] [Py] [epinna/tplmap](https://github.com/epinna/tplmap) 代码注入和服务器端模板注入（Server-Side Template Injection）漏洞利用，若干沙箱逃逸技巧。
- [**1180**星][15d] [Py] [codingo/nosqlmap](https://github.com/codingo/NoSQLMap) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |[工具/数据库&&SQL攻击&&SQL注入/NoSQL/未分类-NoSQL](#af0aaaf233cdff3a88d04556dc5871e0) |
- [**1080**星][6m] [Go] [sensepost/ruler](https://github.com/sensepost/ruler) ruler：自动化利用Exchange 服务的repo
- [**822**星][1m] [Py] [nil0x42/phpsploit](https://github.com/nil0x42/phpsploit) 
- [**818**星][7m] [Shell] [niklasb/libc-database](https://github.com/niklasb/libc-database) 
- [**797**星][28d] [Ruby] [rastating/wordpress-exploit-framework](https://github.com/rastating/wordpress-exploit-framework) wordpress-exploit-framework：WordPress 漏洞利用框架
- [**792**星][12d] [cveproject/cvelist](https://github.com/cveproject/cvelist) 
- [**665**星][10m] [JS] [theori-io/pwnjs](https://github.com/theori-io/pwnjs) 辅助开发浏览器exploit 的 JS 模块
- [**600**星][5m] [Java] [sigploiter/sigploit](https://github.com/sigploiter/sigploit) Telecom Signaling Exploitation Framework - SS7, GTP, Diameter & SIP
- [**568**星][1y] [Py] [spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop) 内核提权枚举和漏洞利用框架
- [**510**星][8m] [Py] [dark-lbp/isf](https://github.com/dark-lbp/isf) 工控漏洞利用框架，基于Python
- [**474**星][25d] [C] [r0hi7/binexp](https://github.com/r0hi7/binexp) 
- [**449**星][5m] [Py] [shellphish/rex](https://github.com/shellphish/rex) 
- [**429**星][11m] [Py] [neohapsis/bbqsql](https://github.com/neohapsis/bbqsql) 
- [**394**星][20d] [Py] [corkami/collisions](https://github.com/corkami/collisions) 
- [**378**星][2m] [Py] [sab0tag3d/siet](https://github.com/sab0tag3d/siet) 
- [**346**星][9m] [C] [wapiflapi/exrs](https://github.com/wapiflapi/exrs) 
- [**345**星][29d] [JS] [fsecurelabs/dref](https://github.com/FSecureLABS/dref) DNS 重绑定利用框架
- [**315**星][1y] [C] [tharina/blackhoodie-2018-workshop](https://github.com/tharina/blackhoodie-2018-workshop) 
- [**314**星][13d] [Shell] [zmarch/orc](https://github.com/zmarch/orc) 
- [**300**星][4m] [JS] [vngkv123/asiagaming](https://github.com/vngkv123/asiagaming) 
- [**288**星][9m] [Py] [immunit/drupwn](https://github.com/immunit/drupwn) 
- [**284**星][1m] [xairy/vmware-exploitation](https://github.com/xairy/vmware-exploitation) 
- [**282**星][12m] [C] [str8outtaheap/heapwn](https://github.com/str8outtaheap/heapwn) 
- [**280**星][1y] [Py] [novicelive/bintut](https://github.com/novicelive/bintut) 
- [**273**星][12m] [Py] [fox-it/aclpwn.py](https://github.com/fox-it/aclpwn.py) 与BloodHound交互, 识别并利用基于ACL的提权路径
- [**266**星][22d] [Py] [0xinfection/xsrfprobe](https://github.com/0xinfection/xsrfprobe) 
- [**257**星][3m] [HTML] [sp1d3r/swf_json_csrf](https://github.com/sp1d3r/swf_json_csrf) swf_json_csrf：简化基于 SWF的 JSON CSRF exploitation
- [**250**星][7m] [Py] [xairy/easy-linux-pwn](https://github.com/xairy/easy-linux-pwn) 
- [**243**星][26d] [Py] [0xinfection/xsrfprobe](https://github.com/0xInfection/XSRFProbe) 
- [**231**星][10m] [C] [r3x/how2kernel](https://github.com/r3x/how2kernel) 


#### <a id="5c1af335b32e43dba993fceb66c470bc"></a>Exp&&PoC


- [**1363**星][1m] [Py] [bitsadmin/wesng](https://github.com/bitsadmin/wesng) 
- [**1353**星][6m] [Py] [vulnerscom/getsploit](https://github.com/vulnerscom/getsploit) 
- [**1322**星][4m] [Py] [lijiejie/githack](https://github.com/lijiejie/githack) git泄露利用脚本，通过泄露的.git文件夹下的文件，重建还原工程源代码
- [**1120**星][4m] [Py] [qyriad/fusee-launcher](https://github.com/Qyriad/fusee-launcher) NVIDIA Tegra X1处理器Fusée Gelée漏洞exploit的launcher. (Fusée Gelée: 冷启动漏洞，允许在bootROM早期, 通过NVIDIA Tegra系列嵌入式处理器上的Tegra恢复模式(RCM)执行完整、未经验证的任意代码)
- [**930**星][10m] [Shell] [1n3/findsploit](https://github.com/1n3/findsploit) 
- [**918**星][5m] [JS] [reswitched/pegaswitch](https://github.com/reswitched/pegaswitch) 
- [**881**星][3m] [C] [theofficialflow/h-encore](https://github.com/theofficialflow/h-encore) 
- [**711**星][1y] [Py] [rfunix/pompem](https://github.com/rfunix/pompem) 
- [**707**星][11m] [HTML] [juansacco/exploitpack](https://github.com/juansacco/exploitpack) 
- [**703**星][4m] [Py] [rhinosecuritylabs/security-research](https://github.com/rhinosecuritylabs/security-research) 
- [**695**星][6m] [C] [unamer/vmware_escape](https://github.com/unamer/vmware_escape) VMwareWorkStation 12.5.5 之前版本的逃逸 Exploit
- [**681**星][1y] [C] [saelo/pwn2own2018](https://github.com/saelo/pwn2own2018) Pwn2Own 2018 Safari+macOS 漏洞利用链
- [**636**星][4m] [smgorelik/windows-rce-exploits](https://github.com/smgorelik/windows-rce-exploits) 
- [**621**星][4m] [C++] [eliboa/tegrarcmgui](https://github.com/eliboa/tegrarcmgui) 
- [**617**星][4m] [Perl] [jondonas/linux-exploit-suggester-2](https://github.com/jondonas/linux-exploit-suggester-2) 
- [**608**星][3m] [C] [matheus-garbelini/esp32_esp8266_attacks](https://github.com/matheus-garbelini/esp32_esp8266_attacks) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**607**星][8m] [Py] [al-azif/ps4-exploit-host](https://github.com/al-azif/ps4-exploit-host) 
- [**580**星][1y] [JS] [cryptogenic/ps4-5.05-kernel-exploit](https://github.com/cryptogenic/ps4-5.05-kernel-exploit) 
- [**580**星][10m] [mtivadar/windows10_ntfs_crash_dos](https://github.com/mtivadar/windows10_ntfs_crash_dos) Windows NTFS文件系统崩溃漏洞PoC
- [**552**星][9m] [C] [t00sh/rop-tool](https://github.com/t00sh/rop-tool) binary exploits编写辅助脚本
- [**544**星][2m] [Py] [tarunkant/gopherus](https://github.com/tarunkant/gopherus) 
- [**523**星][5m] [Py] [bignerd95/chimay-red](https://github.com/bignerd95/chimay-red) 
- [**489**星][6m] [Py] [danigargu/heap-viewer](https://github.com/danigargu/heap-viewer) 查看glibc堆, 主要用于漏洞开发
- [**489**星][5m] [Py] [metachar/phonesploit](https://github.com/metachar/phonesploit) 
- [**488**星][7m] [Py] [lijiejie/ds_store_exp](https://github.com/lijiejie/ds_store_exp) 
- [**481**星][5m] [PHP] [cfreal/exploits](https://github.com/cfreal/exploits) 
- [**473**星][2m] [JS] [acmesec/pocbox](https://github.com/Acmesec/PoCBox) 赏金猎人的脆弱性测试辅助平台
- [**472**星][9m] [Py] [insecurityofthings/jackit](https://github.com/insecurityofthings/jackit) Exploit Code for Mousejack
- [**435**星][1y] [Py] [jfoote/exploitable](https://github.com/jfoote/exploitable) 
- [**431**星][9m] [Shell] [r00t-3xp10it/fakeimageexploiter](https://github.com/r00t-3xp10it/fakeimageexploiter) 
- [**418**星][11m] [Shell] [nilotpalbiswas/auto-root-exploit](https://github.com/nilotpalbiswas/auto-root-exploit) 
- [**412**星][3m] [Py] [misterch0c/malsploitbase](https://github.com/misterch0c/malsploitbase) 
- [**402**星][1y] [C] [ww9210/linux_kernel_exploits](https://github.com/ww9210/linux_kernel_exploits) 
- [**390**星][7m] [Py] [jm33-m0/massexpconsole](https://github.com/jm33-m0/mec) 
- [**383**星][12m] [JS] [linushenze/webkit-regex-exploit](https://github.com/linushenze/webkit-regex-exploit) 
- [**378**星][12m] [PHP] [bo0om/php_imap_open_exploit](https://github.com/bo0om/php_imap_open_exploit) 
- [**372**星][2m] [PHP] [mm0r1/exploits](https://github.com/mm0r1/exploits) 
- [**349**星][1m] [Shell] [th3xace/sudo_killer](https://github.com/th3xace/sudo_killer) 
- [**348**星][8m] [C] [p0cl4bs/kadimus](https://github.com/p0cl4bs/kadimus) 
- [**339**星][4m] [C] [theofficialflow/trinity](https://github.com/theofficialflow/trinity) 
- [**331**星][6m] [C++] [thezdi/poc](https://github.com/thezdi/poc) 
- [**305**星][1y] [Shell] [jas502n/st2-057](https://github.com/jas502n/st2-057) 
- [**302**星][3m] [PowerShell] [kevin-robertson/powermad](https://github.com/kevin-robertson/powermad) 
- [**300**星][1m] [Py] [admintony/svnexploit](https://github.com/admintony/svnexploit) 
- [**276**星][1m] [C] [0xdea/exploits](https://github.com/0xdea/exploits) 研究员 0xdeadbeef 的公开exploits 收集
- [**275**星][3m] [Shell] [cryptolok/aslray](https://github.com/cryptolok/aslray) 
- [**269**星][1y] [Py] [mwrlabs/wepwnise](https://github.com/FSecureLABS/wePWNise) 
- [**266**星][4m] [Java] [c0ny1/fastjsonexploit](https://github.com/c0ny1/fastjsonexploit) 
- [**263**星][12m] [Py] [c0rel0ader/east](https://github.com/c0rel0ader/east) 
- [**251**星][4m] [C] [bcoles/kernel-exploits](https://github.com/bcoles/kernel-exploits) 
- [**245**星][9m] [Visual Basic] [houjingyi233/office-exploit-case-study](https://github.com/houjingyi233/office-exploit-case-study) 
- [**234**星][19d] [C#] [tyranid/exploitremotingservice](https://github.com/tyranid/exploitremotingservice) 
- [**219**星][8m] [Py] [coalfire-research/deathmetal](https://github.com/coalfire-research/deathmetal) 
- [**218**星][3m] [PowerShell] [byt3bl33d3r/offensivedlr](https://github.com/byt3bl33d3r/offensivedlr) 
- [**218**星][1m] [C++] [soarqin/finalhe](https://github.com/soarqin/finalhe) 
- [**215**星][3m] [C] [semmle/securityexploits](https://github.com/semmle/securityexploits) 
- [**210**星][1y] [Py] [kurobeats/fimap](https://github.com/kurobeats/fimap) 
- [**207**星][1y] [C] [crozone/spectrepoc](https://github.com/crozone/spectrepoc) 
- [**201**星][6m] [Py] [invictus1306/beebug](https://github.com/invictus1306/beebug) 




### <a id="5d7191f01544a12bdaf1315c3e986dff"></a>XSS&&XXE


#### <a id="493e36d0ceda2fb286210a27d617c44d"></a>收集


- [**2671**星][5m] [JS] [s0md3v/awesomexss](https://github.com/s0md3v/AwesomeXSS) 
- [**454**星][1y] [HTML] [metnew/uxss-db](https://github.com/metnew/uxss-db) 


#### <a id="648e49b631ea4ba7c128b53764328c39"></a>未分类-XSS


- [**7288**星][25d] [Py] [s0md3v/xsstrike](https://github.com/s0md3v/XSStrike) 
    - 重复区段: [工具/扫描器&&安全扫描&&App扫描&&漏洞扫描/未分类-Scanner](#de63a029bda6a7e429af272f291bb769) |
- [**1641**星][10m] [JS] [evilcos/xssor2](https://github.com/evilcos/xssor2) 
- [**1318**星][3m] [Go] [microcosm-cc/bluemonday](https://github.com/microcosm-cc/bluemonday) a fast golang HTML sanitizer (inspired by the OWASP Java HTML Sanitizer) to scrub user generated content of XSS
- [**705**星][2m] [JS] [mandatoryprogrammer/xsshunter](https://github.com/mandatoryprogrammer/xsshunter) 
- [**683**星][18d] [C#] [mganss/htmlsanitizer](https://github.com/mganss/htmlsanitizer) 
- [**674**星][21d] [PHP] [ssl/ezxss](https://github.com/ssl/ezxss) 
- [**638**星][10m] [HTML] [bl4de/security_whitepapers](https://github.com/bl4de/security_whitepapers) 
- [**504**星][4m] [Py] [opensec-cn/vtest](https://github.com/opensec-cn/vtest) 
- [**495**星][4m] [PHP] [nettitude/xss_payloads](https://github.com/nettitude/xss_payloads) 
- [**477**星][1y] [JS] [koto/xsschef](https://github.com/koto/xsschef) 
- [**460**星][12m] [C] [laruence/taint](https://github.com/laruence/taint) 
- [**334**星][12m] [Py] [varbaek/xsser](https://github.com/varbaek/xsser) 
- [**325**星][7m] [Py] [s0md3v/jshell](https://github.com/s0md3v/JShell) 
- [**289**星][1m] [JS] [wicg/trusted-types](https://github.com/w3c/webappsec-trusted-types) 
- [**287**星][13d] [Py] [stamparm/dsxs](https://github.com/stamparm/dsxs) 
- [**286**星][13d] [PHP] [voku/anti-xss](https://github.com/voku/anti-xss) 
- [**251**星][3m] [PHP] [dotboris/vuejs-serverside-template-xss](https://github.com/dotboris/vuejs-serverside-template-xss) 
- [**243**星][4m] [JS] [lewisardern/bxss](https://github.com/lewisardern/bxss) 
- [**241**星][2m] [JS] [antswordproject/ant](https://github.com/antswordproject/ant) 




### <a id="f799ff186643edfcf7ac1e94f08ba018"></a>知名漏洞&&CVE&&特定产品


#### <a id="309751ccaee413cbf35491452d80480f"></a>未分类


- [**1066**星][28d] [Go] [neex/phuip-fpizdam](https://github.com/neex/phuip-fpizdam) 
- [**886**星][1y] [Py] [nixawk/labs](https://github.com/nixawk/labs) 漏洞分析实验室。包含若干CVE 漏洞（CVE-2016-6277、CVE-2017-5689…）
- [**601**星][1y] [C] [scottybauer/android_kernel_cve_pocs](https://github.com/scottybauer/android_kernel_cve_pocs) 
- [**562**星][10m] [Py] [fs0c131y/esfileexploreropenportvuln](https://github.com/fs0c131y/esfileexploreropenportvuln) 
- [**456**星][3m] [Py] [blacknbunny/libssh-authentication-bypass](https://github.com/blacknbunny/CVE-2018-10933) 
- [**449**星][6m] [Py] [n1xbyte/cve-2019-0708](https://github.com/n1xbyte/cve-2019-0708) 
- [**394**星][9m] [Ruby] [dreadlocked/drupalgeddon2](https://github.com/dreadlocked/drupalgeddon2) 
- [**371**星][1y] [Py] [rhynorater/cve-2018-15473-exploit](https://github.com/rhynorater/cve-2018-15473-exploit) 
- [**370**星][9m] [Py] [wyatu/cve-2018-20250](https://github.com/wyatu/cve-2018-20250) 
- [**357**星][9m] [Go] [frichetten/cve-2019-5736-poc](https://github.com/frichetten/cve-2019-5736-poc) 
- [**339**星][1m] [PHP] [opsxcq/exploit-cve-2016-10033](https://github.com/opsxcq/exploit-cve-2016-10033) 
- [**318**星][8m] [Py] [a2u/cve-2018-7600](https://github.com/a2u/cve-2018-7600) 
- [**300**星][10m] [Py] [basucert/winboxpoc](https://github.com/basucert/winboxpoc) 
- [**299**星][1y] [Py] [bhdresh/cve-2017-8759](https://github.com/bhdresh/cve-2017-8759) 
- [**299**星][27d] [Py] [rhinosecuritylabs/cves](https://github.com/rhinosecuritylabs/cves) 
- [**282**星][4m] [Py] [lufeirider/cve-2019-2725](https://github.com/lufeirider/cve-2019-2725) 
- [**281**星][1y] [Py] [mazen160/struts-pwn_cve-2018-11776](https://github.com/mazen160/struts-pwn_cve-2018-11776) 
- [**280**星][4m] [marcinguy/cve-2019-2107](https://github.com/marcinguy/cve-2019-2107) 
- [**276**星][11m] [Py] [wyatu/cve-2018-8581](https://github.com/wyatu/cve-2018-8581) 
- [**269**星][5m] [Py] [ridter/exchange2domain](https://github.com/ridter/exchange2domain) 
- [**259**星][1y] [C++] [alpha1ab/cve-2018-8120](https://github.com/alpha1ab/cve-2018-8120) 
- [**253**星][1m] [C] [a2nkf/macos-kernel-exploit](https://github.com/a2nkf/macos-kernel-exploit) 
- [**252**星][29d] [Vue] [nluedtke/linux_kernel_cves](https://github.com/nluedtke/linux_kernel_cves) 
- [**243**星][3m] [Shell] [projectzeroindia/cve-2019-11510](https://github.com/projectzeroindia/cve-2019-11510) 
- [**238**星][8m] [JS] [exodusintel/cve-2019-5786](https://github.com/exodusintel/cve-2019-5786) 
- [**237**星][10m] [C] [geosn0w/osirisjailbreak12](https://github.com/geosn0w/osirisjailbreak12) 
- [**234**星][9m] [JS] [adamyordan/cve-2019-1003000-jenkins-rce-poc](https://github.com/adamyordan/cve-2019-1003000-jenkins-rce-poc) 
- [**211**星][12m] [Py] [evict/poc_cve-2018-1002105](https://github.com/evict/poc_cve-2018-1002105) 
- [**203**星][8m] [C++] [rogue-kdc/cve-2019-0841](https://github.com/rogue-kdc/cve-2019-0841) 
- [**200**星][1y] [C] [bazad/blanket](https://github.com/bazad/blanket) 
- [**200**星][2m] [Go] [kotakanbe/go-cve-dictionary](https://github.com/kotakanbe/go-cve-dictionary) 


#### <a id="33386e1e125e0653f7a3c8b8aa75c921"></a>CVE


- [**1058**星][3m] [C] [zerosum0x0/cve-2019-0708](https://github.com/zerosum0x0/cve-2019-0708) 


#### <a id="67f7ce74d12e16cdee4e52c459afcba2"></a>Spectre&&Meltdown


- [**3728**星][29d] [C] [iaik/meltdown](https://github.com/iaik/meltdown) 
- [**2999**星][2m] [Shell] [speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker) 检查 Linux 主机是否受处理器漏洞Spectre & Meltdown 的影响
- [**531**星][1y] [C] [ionescu007/specucheck](https://github.com/ionescu007/specucheck) 
- [**249**星][5m] [nsacyber/hardware-and-firmware-security-guidance](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance) 


#### <a id="10baba9b8e7a2041ad6c55939cf9691f"></a>BlueKeep


- [**973**星][3m] [Py] [ekultek/bluekeep](https://github.com/ekultek/bluekeep) 
- [**633**星][6m] [C] [robertdavidgraham/rdpscan](https://github.com/robertdavidgraham/rdpscan) 
- [**303**星][4m] [Py] [algo7/bluekeep_cve-2019-0708_poc_to_exploit](https://github.com/algo7/bluekeep_cve-2019-0708_poc_to_exploit) 
- [**267**星][6m] [Py] [k8gege/cve-2019-0708](https://github.com/k8gege/cve-2019-0708) 


#### <a id="a6ebcba5cc1b4d2e3a72509b47b84ade"></a>Heartbleed




#### <a id="d84e7914572f626b338beeb03ea613de"></a>DirtyCow




#### <a id="dacdbd68d9ca31cee9688d6972698f63"></a>Blueborne






### <a id="79ed781159b7865dc49ffb5fe2211d87"></a>CSRF


- [**1668**星][4m] [JS] [expressjs/csurf](https://github.com/expressjs/csurf) 
- [**220**星][11m] [PHP] [paragonie/anti-csrf](https://github.com/paragonie/anti-csrf) 


### <a id="edbf1e5f4d570ed44080b30bc782c350"></a>容器&&Docker


- [**5906**星][13d] [Go] [quay/clair](https://github.com/quay/clair) 
- [**5905**星][13d] [Go] [quay/clair](https://github.com/quay/clair) clair：容器（appc、docker）漏洞静态分析工具。
- [**661**星][1y] [Shell] [c0ny1/vulstudy](https://github.com/c0ny1/vulstudy) 
- [**636**星][13d] [Go] [ullaakut/gorsair](https://github.com/ullaakut/gorsair) 
- [**602**星][6m] [Py] [eliasgranderubio/dagda](https://github.com/eliasgranderubio/dagda) Docker安全套件
- [**475**星][5m] [Go] [arminc/clair-scanner](https://github.com/arminc/clair-scanner) 
- [**332**星][6m] [Dockerfile] [mykings/docker-vulnerability-environment](https://github.com/mykings/docker-vulnerability-environment) 
- [**299**星][1y] [Dockerfile] [ston3o/docker-hacklab](https://github.com/ston3o/docker-hacklab) 


### <a id="9f068ea97c2e8865fac21d6fc50f86b3"></a>漏洞管理


- [**2381**星][2m] [Py] [infobyte/faraday](https://github.com/infobyte/faraday) 渗透测试和漏洞管理平台
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/渗透多合一&&渗透框架](#2051fd9e171f2698d8e7486e3dd35d87) |
- [**1177**星][17d] [Py] [cve-search/cve-search](https://github.com/cve-search/cve-search) 导入CVE/CPE 到本地 MongoDB 数据库，以便后续在本地进行搜索和处理


### <a id="4c80728d087c2f08c6012afd2377d544"></a>漏洞数据库


- [**4770**星][13d] [C] [offensive-security/exploitdb](https://github.com/offensive-security/exploitdb) 
- [**1265**星][2m] [PHP] [friendsofphp/security-advisories](https://github.com/friendsofphp/security-advisories) 


### <a id="13fb2b7d1617dd6e0f503f52b95ba86b"></a>CORS


- [**2716**星][8m] [JS] [cyu/rack-cors](https://github.com/cyu/rack-cors) 


### <a id="0af37d7feada6cb8ccd0c81097d0f115"></a>漏洞分析






***


## <a id="7e840ca27f1ff222fd25bc61a79b07ba"></a>特定目标


### <a id="eb2d1ffb231cee014ed24d59ca987da2"></a>未分类-XxTarget




### <a id="c71ad1932bbf9c908af83917fe1fd5da"></a>AWS


- [**4138**星][3m] [Py] [dxa4481/trufflehog](https://github.com/dxa4481/trufflehog) 
- [**3130**星][17d] [Shell] [toniblyx/my-arsenal-of-aws-security-tools](https://github.com/toniblyx/my-arsenal-of-aws-security-tools) 
- [**2758**星][12d] [Go] [99designs/aws-vault](https://github.com/99designs/aws-vault) 
- [**2633**星][3m] [Java] [teevity/ice](https://github.com/teevity/ice) 
- [**2347**星][4m] [Go] [mlabouardy/komiser](https://github.com/mlabouardy/komiser) 
- [**1892**星][19d] [Py] [mozilla/mozdef](https://github.com/mozilla/mozdef) Mozilla Enterprise Defense Platform
- [**1805**星][20d] [Shell] [toniblyx/prowler](https://github.com/toniblyx/prowler) 
- [**1597**星][1y] [Py] [nccgroup/scout2](https://github.com/nccgroup/Scout2) 
- [**1374**星][11m] [Py] [eth0izzle/bucket-stream](https://github.com/eth0izzle/bucket-stream) 通过certstream 监控多种证书 transparency 日志, 进而查找有趣的 Amazon S3 Buckets
- [**1161**星][17d] [Py] [lyft/cartography](https://github.com/lyft/cartography) 
- [**1105**星][3m] [Py] [rhinosecuritylabs/pacu](https://github.com/rhinosecuritylabs/pacu) 
- [**887**星][2m] [Py] [sa7mon/s3scanner](https://github.com/sa7mon/s3scanner) 
- [**824**星][5m] [Py] [jordanpotti/awsbucketdump](https://github.com/jordanpotti/awsbucketdump) 快速枚举 AWS S3 Buckets，查找感兴趣的文件。类似于子域名爆破，但针对S3 Bucket，有额外功能，例如下载文件等
- [**756**星][28d] [Go] [rebuy-de/aws-nuke](https://github.com/rebuy-de/aws-nuke) 
- [**749**星][1m] [Java] [tmobile/pacbot](https://github.com/tmobile/pacbot) 
- [**592**星][17d] [Shell] [securityftw/cs-suite](https://github.com/securityftw/cs-suite) 
- [**525**星][25d] [Ruby] [stelligent/cfn_nag](https://github.com/stelligent/cfn_nag) 
- [**490**星][16d] [Py] [salesforce/policy_sentry](https://github.com/salesforce/policy_sentry) 
- [**480**星][6m] [Py] [netflix-skunkworks/diffy](https://github.com/netflix-skunkworks/diffy) 
- [**433**星][7m] [Py] [ustayready/fireprox](https://github.com/ustayready/fireprox) 
- [**391**星][3m] [Py] [duo-labs/cloudtracker](https://github.com/duo-labs/cloudtracker) 
- [**382**星][20d] [Py] [riotgames/cloud-inquisitor](https://github.com/riotgames/cloud-inquisitor) 
- [**365**星][6m] [Py] [carnal0wnage/weirdaal](https://github.com/carnal0wnage/weirdaal) 
- [**363**星][10m] [Py] [awslabs/aws-security-automation](https://github.com/awslabs/aws-security-automation) 
- [**311**星][1y] [Py] [securing/dumpsterdiver](https://github.com/securing/dumpsterdiver) 
- [**273**星][7m] [Py] [cesar-rodriguez/terrascan](https://github.com/cesar-rodriguez/terrascan) 
- [**264**星][23d] [Py] [nccgroup/pmapper](https://github.com/nccgroup/pmapper) 
- [**224**星][29d] [HCL] [nozaq/terraform-aws-secure-baseline](https://github.com/nozaq/terraform-aws-secure-baseline) 
- [**216**星][26d] [Dockerfile] [thinkst/canarytokens-docker](https://github.com/thinkst/canarytokens-docker) 
- [**202**星][2m] [Py] [voulnet/barq](https://github.com/voulnet/barq) The AWS Cloud Post Exploitation framework!


### <a id="88716f4591b1df2149c2b7778d15d04e"></a>Phoenix


- [**810**星][16d] [Elixir] [nccgroup/sobelow](https://github.com/nccgroup/sobelow) Phoenix 框架安全方面的静态分析工具（Phoenix  框架：支持对webUI,接口, web性能,mobile app 或 mobile browser 进行自动化测试和监控的平台）


### <a id="4fd96686a470ff4e9e974f1503d735a2"></a>Kubernetes


- [**1761**星][27d] [Py] [aquasecurity/kube-hunter](https://github.com/aquasecurity/kube-hunter) 
- [**379**星][2m] [Shell] [kabachook/k8s-security](https://github.com/kabachook/k8s-security) 


### <a id="786201db0bcc40fdf486cee406fdad31"></a>Azure




### <a id="40dbffa18ec695a618eef96d6fd09176"></a>Nginx


- [**6164**星][1m] [Py] [yandex/gixy](https://github.com/yandex/gixy) Nginx 配置静态分析工具，防止配置错误导致安全问题，自动化错误配置检测


### <a id="6b90a3993f9846922396ec85713dc760"></a>ELK


- [**1875**星][18d] [CSS] [cyb3rward0g/helk](https://github.com/cyb3rward0g/helk) 对ELK栈进行分析，具备多种高级功能，例如SQL声明性语言，图形，结构化流，机器学习等




***


## <a id="d55d9dfd081aa2a02e636b97ca1bad0b"></a>物联网(IoT)&&嵌入式设备&&路由器&&交换机&&智能设备&&打印机


### <a id="cda63179d132f43441f8844c5df10024"></a>未分类-IoT


- [**1119**星][6m] [nebgnahz/awesome-iot-hacks](https://github.com/nebgnahz/awesome-iot-hacks) 
- [**817**星][14d] [v33ru/iotsecurity101](https://github.com/v33ru/iotsecurity101) 
- [**791**星][30d] [Py] [ct-open-source/tuya-convert](https://github.com/ct-open-source/tuya-convert) 
- [**582**星][8m] [Py] [woj-ciech/danger-zone](https://github.com/woj-ciech/danger-zone) 
- [**465**星][2m] [Py] [iti/ics-security-tools](https://github.com/iti/ics-security-tools) 
- [**437**星][18d] [Py] [rabobank-cdc/dettect](https://github.com/rabobank-cdc/dettect) 
- [**330**星][1y] [Py] [vmware/liota](https://github.com/vmware/liota) 
- [**307**星][1m] [Java] [erudika/para](https://github.com/erudika/para) 


### <a id="72bffacc109d51ea286797a7d5079392"></a>打印机 




### <a id="c9fd442ecac4e22d142731165b06b3fe"></a>路由器&&交换机




### <a id="3d345feb9fee1c101aea3838da8cbaca"></a>嵌入式设备


- [**7428**星][3m] [Py] [threat9/routersploit](https://github.com/threat9/routersploit) 




***


## <a id="1a9934198e37d6d06b881705b863afc8"></a>通信&&代理&&反向代理&&隧道


### <a id="56acb7c49c828d4715dce57410d490d1"></a>未分类-Proxy


- [**19800**星][2m] [Shell] [streisandeffect/streisand](https://github.com/StreisandEffect/streisand) 
- [**16743**星][18d] [Py] [mitmproxy/mitmproxy](https://github.com/mitmproxy/mitmproxy) 
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**10723**星][13d] [getlantern/download](https://github.com/getlantern/download) 
- [**5481**星][3m] [C] [rofl0r/proxychains-ng](https://github.com/rofl0r/proxychains-ng) 
- [**4915**星][13d] [Go] [dnscrypt/dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy) 灵活的DNS代理，支持现代的加密DNS协议，例如：DNS protocols such as DNSCrypt v2, DNS-over-HTTPS and Anonymized DNSCrypt.
- [**4662**星][28d] [Go] [alexellis/inlets](https://github.com/inlets/inlets) 
- [**4468**星][22d] [C] [jedisct1/dsvpn](https://github.com/jedisct1/dsvpn) 
- [**4223**星][5m] [Go] [ginuerzh/gost](https://github.com/ginuerzh/gost) GO语言实现的安全隧道
- [**4039**星][4m] [Py] [spiderclub/haipproxy](https://github.com/spiderclub/haipproxy) 
- [**3592**星][2m] [hq450/fancyss_history_package](https://github.com/hq450/fancyss_history_package) 
- [**3348**星][4m] [Go] [jpillora/chisel](https://github.com/jpillora/chisel) 基于HTTP的快速 TCP 隧道
- [**2804**星][8m] [C++] [wangyu-/udpspeeder](https://github.com/wangyu-/udpspeeder) 
- [**2468**星][3m] [C] [yrutschle/sslh](https://github.com/yrutschle/sslh) 
- [**2450**星][17d] [Shell] [teddysun/across](https://github.com/teddysun/across) This is a shell script for configure and start WireGuard VPN server
- [**2352**星][6m] [Lua] [snabbco/snabb](https://github.com/snabbco/snabb) Simple and fast packet networking
- [**2133**星][1m] [Go] [mmatczuk/go-http-tunnel](https://github.com/mmatczuk/go-http-tunnel) 
- [**1874**星][4m] [C] [darkk/redsocks](https://github.com/darkk/redsocks) 
- [**1844**星][1y] [Py] [aploium/zmirror](https://github.com/aploium/zmirror) 
- [**1813**星][3m] [C] [tinyproxy/tinyproxy](https://github.com/tinyproxy/tinyproxy) a light-weight HTTP/HTTPS proxy daemon for POSIX operating systems
- [**1678**星][9m] [Py] [constverum/proxybroker](https://github.com/constverum/proxybroker) 
- [**1665**星][4m] [C] [networkprotocol/netcode.io](https://github.com/networkprotocol/netcode.io) 
- [**1611**星][6m] [Go] [sipt/shuttle](https://github.com/sipt/shuttle) 
- [**1495**星][1m] [C] [ntop/n2n](https://github.com/ntop/n2n) 
- [**1448**星][7m] [C++] [wangyu-/tinyfecvpn](https://github.com/wangyu-/tinyfecvpn) 
- [**1334**星][1m] [Go] [davrodpin/mole](https://github.com/davrodpin/mole) 
- [**1308**星][12m] [C] [madeye/proxydroid](https://github.com/madeye/proxydroid) 
- [**1222**星][4m] [JS] [bubenshchykov/ngrok](https://github.com/bubenshchykov/ngrok) 
- [**1199**星][21d] [Objective-C] [onionbrowser/onionbrowser](https://github.com/onionbrowser/onionbrowser) 
- [**1048**星][5m] [C] [tcurdt/iproxy](https://github.com/tcurdt/iproxy) 
- [**1042**星][28d] [Go] [pusher/oauth2_proxy](https://github.com/pusher/oauth2_proxy) 
- [**999**星][7m] [Go] [adtac/autovpn](https://github.com/adtac/autovpn) 
- [**946**星][9m] [JS] [lukechilds/reverse-shell](https://github.com/lukechilds/reverse-shell) 
- [**927**星][3m] [Py] [christophetd/cloudflair](https://github.com/christophetd/cloudflair) a tool to find origin servers of websites protected by CloudFlare who are publicly exposed and don't restrict network access to the CloudFlare IP ranges as they should
- [**836**星][2m] [Py] [anorov/pysocks](https://github.com/anorov/pysocks) 
- [**810**星][1m] [Go] [henson/proxypool](https://github.com/henson/proxypool) 
- [**790**星][3m] [Py] [secforce/tunna](https://github.com/secforce/tunna) 
- [**753**星][1m] [C#] [justcoding121/titanium-web-proxy](https://github.com/justcoding121/titanium-web-proxy) 
- [**738**星][30d] [Shell] [zfl9/ss-tproxy](https://github.com/zfl9/ss-tproxy) 
- [**737**星][1m] [C#] [damianh/proxykit](https://github.com/damianh/proxykit) 
- [**674**星][1m] [Go] [dliv3/venom](https://github.com/dliv3/venom) 
- [**674**星][24d] [JS] [mellow-io/mellow](https://github.com/mellow-io/mellow) 
- [**664**星][19d] [Kotlin] [mygod/vpnhotspot](https://github.com/mygod/vpnhotspot) 
- [**651**星][27d] [Py] [abhinavsingh/proxy.py](https://github.com/abhinavsingh/proxy.py) 
- [**616**星][4m] [JS] [derhuerst/tcp-over-websockets](https://github.com/derhuerst/tcp-over-websockets) 
- [**574**星][4m] [Py] [trustedsec/trevorc2](https://github.com/trustedsec/trevorc2) trevorc2：通过正常的可浏览的网站隐藏 C&C 指令的客户端/服务器模型，因为时间间隔不同，检测变得更加困难，并且获取主机数据时不会使用 POST 请求
- [**568**星][12d] [Go] [cloudflare/cloudflared](https://github.com/cloudflare/cloudflared) 
- [**558**星][8m] [JS] [blinksocks/blinksocks](https://github.com/blinksocks/blinksocks) 
- [**556**星][27d] [clarketm/proxy-list](https://github.com/clarketm/proxy-list) 
- [**545**星][1y] [Py] [fate0/getproxy](https://github.com/fate0/getproxy) 是一个抓取发放代理网站，获取 http/https 代理的程序
- [**513**星][10m] [Erlang] [heroku/vegur](https://github.com/heroku/vegur) HTTP Proxy Library
- [**473**星][1y] [Go] [yinqiwen/gsnova](https://github.com/yinqiwen/gsnova) 
- [**449**星][28d] [Py] [aidaho12/haproxy-wi](https://github.com/aidaho12/haproxy-wi) 
- [**397**星][9m] [Go] [evilsocket/shellz](https://github.com/evilsocket/shellz) 
- [**382**星][1y] [Ruby] [aphyr/tund](https://github.com/aphyr/tund) 
- [**361**星][1m] [Py] [lyft/metadataproxy](https://github.com/lyft/metadataproxy) 
- [**355**星][1y] [C] [emptymonkey/revsh](https://github.com/emptymonkey/revsh) 
- [**345**星][6m] [Go] [coreos/jwtproxy](https://github.com/coreos/jwtproxy) 
- [**336**星][8m] [Py] [iphelix/dnschef](https://github.com/iphelix/dnschef) dnschef：DNS 代理，用于渗透测试和恶意代码分析
- [**331**星][6m] [Py] [fbkcs/thunderdns](https://github.com/fbkcs/thunderdns) 使用DNS协议转发TCP流量. Python编写, 无需编译客户端, 支持socks5
- [**325**星][4m] [Go] [sysdream/hershell](https://github.com/sysdream/hershell) Go 语言编写的反向 Shell
- [**320**星][9m] [JS] [mhzed/wstunnel](https://github.com/mhzed/wstunnel) 
- [**301**星][4m] [Py] [rootviii/proxy_requests](https://github.com/rootviii/proxy_requests) 
- [**293**星][2m] [JS] [bettercap/caplets](https://github.com/bettercap/caplets) 使用.cap脚本, 自动化bettercap的交互式会话
- [**290**星][8m] [C] [basil00/reqrypt](https://github.com/basil00/reqrypt) reqrypt：HTTP 请求 tunneling 工具
- [**289**星][2m] [Py] [covertcodes/multitun](https://github.com/covertcodes/multitun) 
- [**278**星][11m] [C] [dgoulet/torsocks](https://github.com/dgoulet/torsocks) 
- [**276**星][5m] [Py] [mthbernardes/rsg](https://github.com/mthbernardes/rsg) 多种方式生成反向Shell
- [**273**星][12d] [a2u/free-proxy-list](https://github.com/a2u/free-proxy-list) 
- [**273**星][9m] [Py] [chenjiandongx/async-proxy-pool](https://github.com/chenjiandongx/async-proxy-pool) 
- [**272**星][4m] [Go] [suyashkumar/ssl-proxy](https://github.com/suyashkumar/ssl-proxy) 
- [**257**星][8m] [C] [rofl0r/microsocks](https://github.com/rofl0r/microsocks) 
- [**254**星][3m] [Py] [fwkz/riposte](https://github.com/fwkz/riposte) 
- [**245**星][4m] [Shell] [thesecondsun/revssl](https://github.com/thesecondsun/revssl) 
- [**242**星][17d] [Go] [adguardteam/dnsproxy](https://github.com/adguardteam/dnsproxy) 
- [**242**星][4m] [Go] [lesnuages/hershell](https://github.com/lesnuages/hershell) 
- [**241**星][9m] [C] [pegasuslab/ghosttunnel](https://github.com/PegasusLab/GhostTunnel) 
- [**236**星][11m] [Go] [fardog/secureoperator](https://github.com/fardog/secureoperator) 
- [**224**星][1m] [Ruby] [zt2/sqli-hunter](https://github.com/zt2/sqli-hunter) 
- [**216**星][1y] [PHP] [softius/php-cross-domain-proxy](https://github.com/softius/php-cross-domain-proxy) 
- [**213**星][8m] [Go] [joncooperworks/judas](https://github.com/joncooperworks/judas) a phishing proxy
- [**207**星][9m] [Go] [justmao945/mallory](https://github.com/justmao945/mallory) 
- [**202**星][1y] [C#] [damonmohammadbagher/nativepayload_dns](https://github.com/damonmohammadbagher/nativepayload_dns) 


### <a id="837c9f22a3e1bb2ce29a0fb2bcd90b8f"></a>翻墙&&GFW


#### <a id="fe72fb9498defbdbb98448511cd1eaca"></a>未分类


- [**2918**星][11m] [Shell] [91yun/serverspeeder](https://github.com/91yun/serverspeeder) 


#### <a id="6e28befd418dc5b22fb3fd234db322d3"></a>翻墙


- [**12874**星][8m] [JS] [bannedbook/fanqiang](https://github.com/bannedbook/fanqiang) 
- [**6211**星][20d] [Py] [h2y/shadowrocket-adblock-rules](https://github.com/h2y/shadowrocket-adblock-rules) 
- [**3046**星][4m] [Shell] [softwaredownload/openwrt-fanqiang](https://github.com/softwaredownload/openwrt-fanqiang) 


#### <a id="e9cc4e00d5851a7430a9b28d74f297db"></a>GFW


- [**14484**星][21d] [gfwlist/gfwlist](https://github.com/gfwlist/gfwlist) gfwlist
- [**3531**星][14d] [acl4ssr/acl4ssr](https://github.com/acl4ssr/acl4ssr) 
- [**2482**星][2m] [C++] [trojan-gfw/trojan](https://github.com/trojan-gfw/trojan) 
- [**202**星][16d] [Shell] [zfl9/gfwlist2privoxy](https://github.com/zfl9/gfwlist2privoxy) 




### <a id="21cbd08576a3ead42f60963cdbfb8599"></a>代理


- [**7149**星][14d] [Go] [snail007/goproxy](https://github.com/snail007/goproxy) 
- [**5971**星][14d] [JS] [avwo/whistle](https://github.com/avwo/whistle) 基于Node实现的跨平台抓包调试代理工具（HTTP, HTTP2, HTTPS, Websocket）
- [**1380**星][1m] [C] [z3apa3a/3proxy](https://github.com/z3apa3a/3proxy) 
- [**304**星][17d] [Shell] [brainfucksec/kalitorify](https://github.com/brainfucksec/kalitorify) 


### <a id="a136c15727e341b9427b6570910a3a1f"></a>反向代理&&穿透


- [**29549**星][23d] [Go] [fatedier/frp](https://github.com/fatedier/frp) 快速的反向代理, 将NAT或防火墙之后的本地服务器暴露到公网
- [**9114**星][2m] [JS] [localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) 
- [**8706**星][2m] [Go] [cnlh/nps](https://github.com/cnlh/nps) 
- [**4887**星][10m] [Go] [bitly/oauth2_proxy](https://github.com/bitly/oauth2_proxy) 反向代理，静态文件服务器，提供Providers(Google/Github)认证
- [**3521**星][1m] [Java] [ffay/lanproxy](https://github.com/ffay/lanproxy) 
- [**2586**星][1m] [C++] [fanout/pushpin](https://github.com/fanout/pushpin) 
- [**2476**星][5m] [Go] [drk1wi/modlishka](https://github.com/drk1wi/modlishka) 
- [**656**星][4m] [Py] [aploium/shootback](https://github.com/aploium/shootback) 


### <a id="e996f5ff54050629de0d9d5e68fcb630"></a>隧道


- [**3271**星][4m] [C++] [wangyu-/udp2raw-tunnel](https://github.com/wangyu-/udp2raw-tunnel) udp2raw-tunnel：udp 打洞。通过raw socket给UDP包加上TCP或ICMP header，进而绕过UDP屏蔽或QoS，或在UDP不稳定的环境下提升稳定性
- [**3131**星][3m] [C] [yarrick/iodine](https://github.com/yarrick/iodine) 通过DNS服务器传输(tunnel)IPV4数据
- [**1779**星][5m] [C++] [iagox86/dnscat2](https://github.com/iagox86/dnscat2) dnscat2：在 DNS 协议上创建加密的 C&C channel


### <a id="b2241c68725526c88e69f1d71405c6b2"></a>代理爬取&&代理池


- [**4882**星][1y] [Go] [yinghuocho/firefly-proxy](https://github.com/yinghuocho/firefly-proxy) 


### <a id="b03a7c05fd5b154ad593b6327578718b"></a>匿名网络


#### <a id="f0979cd783d1d455cb5e3207d574aa1e"></a>未分类




#### <a id="e99ba5f3de02f68412b13ca718a0afb6"></a>Tor&&&Onion&&洋葱


- [**1302**星][1m] [C++] [purplei2p/i2pd](https://github.com/purplei2p/i2pd) a full-featured C++ implementation of I2P client
- [**423**星][2m] [Py] [nullhypothesis/exitmap](https://github.com/nullhypothesis/exitmap) 
- [**406**星][13d] [Awk] [alecmuffett/eotk](https://github.com/alecmuffett/eotk) 
- [**387**星][1m] [JS] [ayms/node-tor](https://github.com/ayms/node-tor) 
- [**377**星][1m] [Py] [maqp/tfc](https://github.com/maqp/tfc) 
- [**353**星][2m] [Py] [micahflee/torbrowser-launcher](https://github.com/micahflee/torbrowser-launcher) 
- [**286**星][28d] [Perl] [alecmuffett/real-world-onion-sites](https://github.com/alecmuffett/real-world-onion-sites) 
- [**261**星][9m] [C++] [wbenny/mini-tor](https://github.com/wbenny/mini-tor) mini-tor：使用 MSCNG/CryptoAPI 实现的 Tor 协议
- [**250**星][30d] [C] [basil00/torwall](https://github.com/basil00/torwall) 
- [**219**星][5m] [Py] [ruped24/toriptables2](https://github.com/ruped24/toriptables2) 




### <a id="f932418b594acb6facfc35c1ec414188"></a>Socks&&ShadowSocksXx


- [**25047**星][14d] [Swift] [shadowsocks/shadowsocksx-ng](https://github.com/shadowsocks/shadowsocksx-ng) 
- [**12355**星][1m] [C] [shadowsocks/shadowsocks-libev](https://github.com/shadowsocks/shadowsocks-libev) 
- [**7061**星][7m] [Shell] [teddysun/shadowsocks_install](https://github.com/teddysun/shadowsocks_install) 
- [**4154**星][15d] [Swift] [yanue/v2rayu](https://github.com/yanue/v2rayu) 
- [**3797**星][29d] [JS] [shadowsocks/shadowsocks-manager](https://github.com/shadowsocks/shadowsocks-manager) 
- [**3174**星][15d] [Smarty] [anankke/sspanel-uim](https://github.com/anankke/sspanel-uim) 专为 Shadowsocks / ShadowsocksR / V2Ray 设计的多用户管理面板
- [**2946**星][1m] [Go] [gwuhaolin/lightsocks](https://github.com/gwuhaolin/lightsocks) 轻量级网络混淆代理，基于 SOCKS5 协议，可用来代替 Shadowsocks
- [**2751**星][24d] [Makefile] [shadowsocks/openwrt-shadowsocks](https://github.com/shadowsocks/openwrt-shadowsocks) 
- [**2300**星][10m] [C] [haad/proxychains](https://github.com/haad/proxychains) a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4, SOCKS5 or HTTP(S) proxy. Supported auth-types: "user/pass" for SOCKS4/5, "basic" for HTTP.
- [**2029**星][15d] [C#] [netchx/netch](https://github.com/netchx/netch) 
- [**1821**星][3m] [C] [shadowsocks/simple-obfs](https://github.com/shadowsocks/simple-obfs) 
- [**1683**星][1y] [Swift] [haxpor/potatso](https://github.com/haxpor/potatso) 
- [**1621**星][17d] [Py] [ehco1996/django-sspanel](https://github.com/ehco1996/django-sspanel) 
- [**1567**星][16d] [C#] [hmbsbige/shadowsocksr-windows](https://github.com/hmbsbige/shadowsocksr-windows) 
- [**1306**星][4m] [Rust] [shadowsocks/shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) 
- [**1177**星][6m] [ssrbackup/shadowsocks-rss](https://github.com/ssrarchive/shadowsocks-rss) 
- [**1068**星][1m] [jadagates/shadowsocksbio](https://github.com/jadagates/shadowsocksbio) 
- [**922**星][1y] [Shell] [ywb94/openwrt-ssr](https://github.com/ywb94/openwrt-ssr) 
- [**900**星][1y] [Go] [huacnlee/flora-kit](https://github.com/huacnlee/flora-kit) 基于 shadowsocks-go 做的完善实现，完全兼容 Surge 的配置文件
- [**899**星][2m] [zhaoweih/shadowsocks-tutorial](https://github.com/zhaoweih/shadowsocks-tutorial) 
- [**840**星][11m] [PHP] [walkor/shadowsocks-php](https://github.com/walkor/shadowsocks-php) 
- [**830**星][1m] [C] [shadowsocksr-live/shadowsocksr-native](https://github.com/shadowsocksr-live/shadowsocksr-native) 
- [**730**星][6m] [Go] [cbeuw/goquiet](https://github.com/cbeuw/goquiet) 
- [**517**星][9m] [JS] [mrluanma/shadowsocks-heroku](https://github.com/mrluanma/shadowsocks-heroku) 
- [**421**星][2m] [PowerShell] [p3nt4/invoke-socksproxy](https://github.com/p3nt4/invoke-socksproxy) 
- [**402**星][3m] [JS] [lolimay/shadowsocks-deepin](https://github.com/lolimay/shadowsocks-deepin) 
- [**374**星][1y] [Go] [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2) 
- [**337**星][16d] [Py] [leitbogioro/ssr.go](https://github.com/leitbogioro/ssr.go) 
- [**318**星][3m] [Py] [qwj/python-proxy](https://github.com/qwj/python-proxy) 
- [**301**星][13d] [Shell] [loyess/shell](https://github.com/loyess/shell) 
- [**250**星][4m] [Py] [fsgmhoward/shadowsocks-py-mu](https://github.com/fsgmhoward/shadowsocks-py-mu) 


### <a id="dbc310300d300ae45b04779281fe6ec8"></a>V2Ray


- [**23571**星][28d] [Go] [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core) 
- [**2804**星][2m] [Dockerfile] [thinkdevelop/free-ss-ssr](https://github.com/thinkdevelop/free-ss-ssr) 
- [**2484**星][2m] [Py] [jrohy/multi-v2ray](https://github.com/jrohy/multi-v2ray) 
- [**1656**星][1m] [Shell] [wulabing/v2ray_ws-tls_bash_onekey](https://github.com/wulabing/v2ray_ws-tls_bash_onekey) 
- [**1556**星][4m] [CSS] [functionclub/v2ray.fun](https://github.com/functionclub/v2ray.fun) 
- [**1432**星][12d] [selierlin/share-ssr-v2ray](https://github.com/selierlin/share-ssr-v2ray) 
- [**1070**星][1m] [Go] [xiaoming2028/freenet](https://github.com/xiaoming2028/freenet) 
- [**783**星][16d] [HTML] [sprov065/v2-ui](https://github.com/sprov065/v2-ui) 
- [**589**星][21d] [Shell] [toutyrater/v2ray-guide](https://github.com/toutyrater/v2ray-guide) 
- [**553**星][29d] [ntkernel/lantern](https://github.com/ntkernel/lantern) 
- [**360**星][2m] [Dockerfile] [onplus/v2hero](https://github.com/onplus/v2hero) 
- [**307**星][2m] [Shell] [zw963/asuswrt-merlin-transparent-proxy](https://github.com/zw963/asuswrt-merlin-transparent-proxy) 
- [**256**星][24d] [Py] [jiangxufeng/v2rayl](https://github.com/jiangxufeng/v2rayl) 


### <a id="891b953fda837ead9eff17ff2626b20a"></a>VPN


- [**419**星][19d] [hugetiny/awesome-vpn](https://github.com/hugetiny/awesome-vpn) 




***


## <a id="1233584261c0cd5224b6e90a98cc9a94"></a>渗透&&offensive&&渗透框架&&后渗透框架


### <a id="2e40f2f1df5d7f93a7de47bf49c24a0e"></a>未分类-Pentest


- [**3005**星][3m] [Py] [spiderlabs/responder](https://github.com/spiderlabs/responder) LLMNR/NBT-NS/MDNS投毒，内置HTTP/SMB/MSSQL/FTP/LDAP认证服务器, 支持NTLMv1/NTLMv2/LMv2
- [**2013**星][1m] [C++] [lordnoteworthy/al-khaser](https://github.com/lordnoteworthy/al-khaser) 
    - 重复区段: [工具/恶意代码&&Malware&&APT](#8cb1c42a29fa3e8825a0f8fca780c481) |
- [**1721**星][1m] [Go] [chaitin/xray](https://github.com/chaitin/xray) 
- [**1444**星][1m] [C] [ufrisk/pcileech](https://github.com/ufrisk/pcileech) 直接内存访问（DMA：Direct Memory Access）攻击工具。通过 PCIe 硬件设备使用 DMA，直接读写目标系统的内存。目标系统不需要安装驱动。
- [**1393**星][4m] [yadox666/the-hackers-hardware-toolkit](https://github.com/yadox666/the-hackers-hardware-toolkit) 
- [**1361**星][2m] [Py] [ekultek/whatwaf](https://github.com/ekultek/whatwaf) 
- [**1212**星][3m] [Py] [owtf/owtf](https://github.com/owtf/owtf) 进攻性 Web 测试框架。着重于 OWASP + PTES，尝试统合强大的工具，提高渗透测试的效率。大部分以Python 编写
- [**945**星][19d] [C] [bt3gl/pentesting-toolkit](https://github.com/bt3gl/Pentesting-Toolkit) 
    - 重复区段: [工具/CTF&&HTB/收集](#30c4df38bcd1abaaaac13ffda7d206c6) |
- [**943**星][4m] [Py] [hatriot/zarp](https://github.com/hatriot/zarp) 网络攻击工具，主要是本地网络攻击
- [**918**星][1m] [Py] [d4vinci/one-lin3r](https://github.com/d4vinci/one-lin3r) 轻量级框架，提供在渗透测试中需要的所有one-liners
- [**808**星][1m] [Py] [jeffzh3ng/fuxi](https://github.com/jeffzh3ng/fuxi) 
- [**784**星][6m] [Py] [jivoi/pentest](https://github.com/jivoi/pentest) 
- [**728**星][7m] [Py] [gkbrk/slowloris](https://github.com/gkbrk/slowloris) 
- [**687**星][16d] [voorivex/pentest-guide](https://github.com/voorivex/pentest-guide) 
- [**666**星][5m] [leezj9671/pentest_interview](https://github.com/leezj9671/pentest_interview) 
- [**610**星][9m] [Py] [epsylon/ufonet](https://github.com/epsylon/ufonet) 
- [**489**星][13d] [netbiosx/checklists](https://github.com/netbiosx/checklists) 
- [**487**星][16d] [Ruby] [hackplayers/evil-winrm](https://github.com/hackplayers/evil-winrm) 
- [**487**星][1y] [Shell] [leonteale/pentestpackage](https://github.com/leonteale/pentestpackage) 
- [**479**星][10m] [Ruby] [sidaf/homebrew-pentest](https://github.com/sidaf/homebrew-pentest) 
- [**464**星][7m] [Java] [alpha1e0/pentestdb](https://github.com/alpha1e0/pentestdb) 
- [**459**星][2m] [C++] [fsecurelabs/c3](https://github.com/FSecureLABS/C3) 
- [**457**星][10m] [PHP] [l3m0n/pentest_tools](https://github.com/l3m0n/pentest_tools) 
- [**444**星][15d] [C++] [danielkrupinski/osiris](https://github.com/danielkrupinski/osiris) 
- [**439**星][7m] [C++] [rek7/mxtract](https://github.com/rek7/mxtract) Offensive Memory Extractor & Analyzer
- [**432**星][3m] [mel0day/redteam-bcs](https://github.com/mel0day/redteam-bcs) 
- [**414**星][18d] [PHP] [gwen001/pentest-tools](https://github.com/gwen001/pentest-tools) 
- [**404**星][1m] [Py] [admintony/prepare-for-awd](https://github.com/admintony/prepare-for-awd) 
- [**401**星][9m] [Py] [christruncer/pentestscripts](https://github.com/christruncer/pentestscripts) 
- [**398**星][27d] [PowerShell] [s3cur3th1ssh1t/winpwn](https://github.com/S3cur3Th1sSh1t/WinPwn) 
- [**388**星][12m] [Py] [cr4shcod3/pureblood](https://github.com/cr4shcod3/pureblood) 
- [**386**星][9m] [Go] [amyangxyz/assassingo](https://github.com/amyangxyz/assassingo) 
- [**385**星][3m] [ansjdnakjdnajkd/ios](https://github.com/ansjdnakjdnajkd/ios) 
    - 重复区段: [工具/移动&&Mobile/iOS&&MacOS&&iPhone&&iPad&&iWatch](#dbde77352aac39ee710d3150a921bcad) |
- [**385**星][23d] [Py] [clr2of8/dpat](https://github.com/clr2of8/dpat) 
- [**378**星][6m] [unprovable/pentesthardware](https://github.com/unprovable/pentesthardware) 
- [**371**星][8m] [C] [ridter/pentest](https://github.com/ridter/pentest) 
- [**368**星][4m] [C#] [bitsadmin/nopowershell](https://github.com/bitsadmin/nopowershell) 使用C#"重写"的PowerShell, 支持执行与PowerShell类似的命令, 然而对所有的PowerShell日志机制都不可见
- [**350**星][2m] [Shell] [maldevel/pentestkit](https://github.com/maldevel/pentestkit) 
- [**346**星][10m] [Py] [darkspiritz/darkspiritz](https://github.com/darkspiritz/darkspiritz) 
- [**341**星][15d] [Py] [ym2011/pest](https://github.com/ym2011/PEST) 
- [**338**星][3m] [Py] [xuanhun/pythonhackingbook1](https://github.com/xuanhun/pythonhackingbook1) 
- [**337**星][1y] [Java] [rub-nds/ws-attacker](https://github.com/rub-nds/ws-attacker) 
- [**327**星][1y] [PowerShell] [rootclay/powershell-attack-guide](https://github.com/rootclay/powershell-attack-guide) 
- [**320**星][2m] [PowerShell] [kmkz/pentesting](https://github.com/kmkz/pentesting) 
- [**316**星][28d] [Py] [m8r0wn/nullinux](https://github.com/m8r0wn/nullinux) nullinux：SMB null 会话识别和枚举工具
- [**307**星][2m] [PowerShell] [d0nkeys/redteam](https://github.com/d0nkeys/redteam) 
- [**300**星][3m] [HTML] [koutto/jok3r](https://github.com/koutto/jok3r) 
- [**298**星][2m] [Ruby] [fozavci/viproy-voipkit](https://github.com/fozavci/viproy-voipkit) VoIP渗透测试工具和 Metasploit 框架
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Metasploit/未分类-metasploit](#01be61d5bb9f6f7199208ff0fba86b5d) |
- [**295**星][11m] [stardustsky/saidict](https://github.com/stardustsky/saidict) 
- [**292**星][27d] [Lua] [pentesteracademy/patoolkit](https://github.com/pentesteracademy/patoolkit) 
- [**286**星][1y] [C++] [paranoidninja/pandoras-box](https://github.com/paranoidninja/pandoras-box) 
- [**283**星][1m] [Py] [bishopfox/eyeballer](https://github.com/bishopfox/eyeballer) 
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |
- [**267**星][18d] [Go] [rmikehodges/hidensneak](https://github.com/rmikehodges/hidensneak) 
- [**252**星][13d] [anyeduke/enterprise-security-skill](https://github.com/anyeduke/enterprise-security-skill) 
- [**251**星][3m] [Py] [giantbranch/python-hacker-code](https://github.com/giantbranch/python-hacker-code) 
- [**240**星][2m] [Shell] [leviathan36/kaboom](https://github.com/leviathan36/kaboom) 
- [**238**星][25d] [PowerShell] [sdcampbell/internal-pentest-playbook](https://github.com/sdcampbell/internal-pentest-playbook) 
- [**225**星][8m] [Go] [stevenaldinger/decker](https://github.com/stevenaldinger/decker) 
- [**216**星][5m] [Py] [mgeeky/tomcatwardeployer](https://github.com/mgeeky/tomcatwardeployer) 
- [**211**星][19d] [JS] [giper45/dockersecurityplayground](https://github.com/giper45/dockersecurityplayground) 


### <a id="9081db81f6f4b78d5c263723a3f7bd6d"></a>收集


- [**903**星][8m] [C] [0x90/wifi-arsenal](https://github.com/0x90/wifi-arsenal) 
- [**803**星][2m] [Shell] [shr3ddersec/shr3dkit](https://github.com/shr3ddersec/shr3dkit) 
- [**537**星][6m] [Py] [0xdea/tactical-exploitation](https://github.com/0xdea/tactical-exploitation) 渗透测试辅助工具包. Python/PowerShell脚本


### <a id="39931e776c23e80229368dfc6fd54770"></a>无线&&WiFi&&AP&&802.11


#### <a id="d4efda1853b2cb0909727188116a2a8c"></a>未分类-WiFi


- [**8337**星][17d] [Py] [wifiphisher/wifiphisher](https://github.com/wifiphisher/wifiphisher) 流氓AP框架, 用于RedTeam和Wi-Fi安全测试
    - 重复区段: [工具/社工(SET)&&钓鱼&&鱼叉攻击/钓鱼&&Phish](#290e9ae48108d21d6d8b9ea9e74d077d) |
- [**6109**星][9m] [Py] [schollz/howmanypeoplearearound](https://github.com/schollz/howmanypeoplearearound) 检测 Wifi 信号统计你周围的人数
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |
- [**5597**星][1m] [C] [spacehuhn/esp8266_deauther](https://github.com/spacehuhn/esp8266_deauther) 使用ESP8266 制作Wifi干扰器
- [**4313**星][27d] [Py] [jopohl/urh](https://github.com/jopohl/urh) 
- [**2723**星][1y] [C] [vanhoefm/krackattacks-scripts](https://github.com/vanhoefm/krackattacks-scripts) 检测客户端和AP是否受KRACK漏洞影响
- [**2706**星][8m] [Py] [p0cl4bs/wifi-pumpkin](https://github.com/P0cL4bs/WiFi-Pumpkin) AP攻击框架, 创建虚假网络, 取消验证攻击、请求和凭证监控、透明代理、Windows更新攻击、钓鱼管理、ARP投毒、DNS嗅探、Pumpkin代理、动态图片捕获等
- [**2480**星][15d] [Py] [evilsocket/pwnagotchi](https://github.com/evilsocket/pwnagotchi) 
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |[工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**2433**星][2m] [C] [martin-ger/esp_wifi_repeater](https://github.com/martin-ger/esp_wifi_repeater) 
- [**2374**星][1y] [Py] [danmcinerney/lans.py](https://github.com/danmcinerney/lans.py) 
- [**2194**星][22d] [Shell] [v1s1t0r1sh3r3/airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) 
- [**1816**星][1y] [Py] [derv82/wifite2](https://github.com/derv82/wifite2) 无线网络审计工具wifite 的升级版/重制版
- [**1799**星][4m] [Shell] [arismelachroinos/lscript](https://github.com/arismelachroinos/lscript) 自动化无线渗透和Hacking 任务的脚本
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/自动化](#fc8737aef0f59c3952d11749fe582dac) |
- [**1527**星][1m] [Py] [k4m4/kickthemout](https://github.com/k4m4/kickthemout) 使用ARP欺骗，将设备从网络中踢出去
- [**1525**星][1y] [HTML] [qiwihui/hiwifi-ss](https://github.com/qiwihui/hiwifi-ss) 
- [**1244**星][1m] [C] [seemoo-lab/nexmon](https://github.com/seemoo-lab/nexmon) 
- [**1219**星][12d] [C] [aircrack-ng/aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) 
- [**1022**星][1m] [C] [t6x/reaver-wps-fork-t6x](https://github.com/t6x/reaver-wps-fork-t6x) 攻击 Wi-Fi Protected Setup (WPS)， 恢复 WPA/WPA2 密码
- [**998**星][12m] [Py] [entropy1337/infernal-twin](https://github.com/entropy1337/infernal-twin) 自动化无线Hack 工具
- [**987**星][1y] [Py] [tylous/sniffair](https://github.com/tylous/sniffair) 无线渗透框架. 解析被动收集的无线数据, 执行复杂的无线攻击
- [**983**星][1y] [HTML] [sensepost/mana](https://github.com/sensepost/mana) 
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**977**星][14d] [C] [s0lst1c3/eaphammer](https://github.com/s0lst1c3/eaphammer) 针对WPA2-Enterprise 网络的定向双重攻击（evil twin attacks）
- [**903**星][1m] [TeX] [ethereum/yellowpaper](https://github.com/ethereum/yellowpaper) 
- [**818**星][2m] [C] [spacehuhn/wifi_ducky](https://github.com/spacehuhn/wifi_ducky) 
- [**796**星][1y] [Objective-C] [igrsoft/kismac2](https://github.com/igrsoft/kismac2) 
- [**766**星][22d] [Py] [konradit/gopro-py-api](https://github.com/konradit/gopro-py-api) 
- [**755**星][7m] [Py] [misterbianco/boopsuite](https://github.com/MisterBianco/BoopSuite) 无线审计与安全测试
- [**676**星][10m] [Objective-C] [unixpickle/jamwifi](https://github.com/unixpickle/jamwifi) 
- [**649**星][7m] [C] [wifidog/wifidog-gateway](https://github.com/wifidog/wifidog-gateway) 
- [**608**星][3m] [C] [matheus-garbelini/esp32_esp8266_attacks](https://github.com/matheus-garbelini/esp32_esp8266_attacks) 
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞利用/Exp&&PoC](#5c1af335b32e43dba993fceb66c470bc) |
- [**502**星][14d] [C++] [cyberman54/esp32-paxcounter](https://github.com/cyberman54/esp32-paxcounter) 
- [**463**星][2m] [Shell] [staz0t/hashcatch](https://github.com/staz0t/hashcatch) 
- [**455**星][3m] [Java] [lennartkoopmann/nzyme](https://github.com/lennartkoopmann/nzyme) 直接收集空中的802.11 管理帧，并将其发送到 Graylog，用于WiFi IDS, 监控, 及事件响应。（Graylog：开源的日志管理系统）
- [**450**星][1m] [Py] [savio-code/fern-wifi-cracker](https://github.com/savio-code/fern-wifi-cracker) 无线安全审计和攻击工具, 能破解/恢复 WEP/WPA/WPSkey等
- [**396**星][18d] [C] [freifunk-gluon/gluon](https://github.com/freifunk-gluon/gluon) 
- [**387**星][1y] [Py] [jpaulmora/pyrit](https://github.com/jpaulmora/pyrit) 
- [**373**星][3m] [C++] [bastibl/gr-ieee802-11](https://github.com/bastibl/gr-ieee802-11) 
- [**320**星][2m] [Shell] [vanhoefm/modwifi](https://github.com/vanhoefm/modwifi) 
- [**316**星][2m] [Java] [wiglenet/wigle-wifi-wardriving](https://github.com/wiglenet/wigle-wifi-wardriving) 
- [**310**星][3m] [TeX] [chronaeon/beigepaper](https://github.com/chronaeon/beigepaper) 
- [**266**星][6m] [C] [br101/horst](https://github.com/br101/horst) 
- [**265**星][2m] [C] [sensepost/hostapd-mana](https://github.com/sensepost/hostapd-mana) 
- [**253**星][1y] [Py] [wipi-hunter/pidense](https://github.com/wipi-hunter/pidense) Monitor illegal wireless network activities.
- [**237**星][7m] [Py] [lionsec/wifresti](https://github.com/lionsec/wifresti) 
- [**234**星][2m] [C] [mame82/logitacker](https://github.com/mame82/logitacker) 
- [**218**星][18d] [Py] [ghostop14/sparrow-wifi](https://github.com/ghostop14/sparrow-wifi) 
    - 重复区段: [工具/蓝牙&&Bluetooth](#ceb90405292daed9bb32ac20836c219a) |[工具/浏览嗅探&&流量拦截&&流量分析&&中间人/未分类-Network](#99398a5a8aaf99228829dadff48fb6a7) |


#### <a id="8d233e2d068cce2b36fd0cf44d10f5d8"></a>WPS&&WPA&&WPA2


- [**302**星][4m] [Py] [hash3lizer/wifibroot](https://github.com/hash3lizer/wifibroot) 


#### <a id="8863b7ba27658d687a85585e43b23245"></a>802.11






### <a id="80301821d0f5d8ec2dd3754ebb1b4b10"></a>Payload&&远控&&RAT


#### <a id="6602e118e0245c83b13ff0db872c3723"></a>未分类-payload


- [**1231**星][19d] [PowerShell] [hak5/bashbunny-payloads](https://github.com/hak5/bashbunny-payloads) 
- [**962**星][27d] [C] [zardus/preeny](https://github.com/zardus/preeny) 
- [**560**星][10m] [Py] [genetic-malware/ebowla](https://github.com/genetic-malware/ebowla) 
- [**529**星][2m] [C++] [screetsec/brutal](https://github.com/screetsec/brutal) 
- [**438**星][12d] [Py] [ctxis/cape](https://github.com/ctxis/cape) 
- [**339**星][11m] [JS] [gabemarshall/brosec](https://github.com/gabemarshall/brosec) 
- [**259**星][3m] [Py] [felixweyne/imaginaryc2](https://github.com/felixweyne/imaginaryc2) 
- [**234**星][3m] [cujanovic/markdown-xss-payloads](https://github.com/cujanovic/markdown-xss-payloads) 
- [**229**星][17d] [cujanovic/open-redirect-payloads](https://github.com/cujanovic/open-redirect-payloads) 
- [**226**星][5m] [cr0hn/nosqlinjection_wordlists](https://github.com/cr0hn/nosqlinjection_wordlists) 
- [**216**星][2m] [Py] [whitel1st/docem](https://github.com/whitel1st/docem) 
- [**210**星][1m] [Py] [brent-stone/can_reverse_engineering](https://github.com/brent-stone/can_reverse_engineering) 
- [**210**星][24d] [C] [shchmue/lockpick_rcm](https://github.com/shchmue/lockpick_rcm) 
- [**210**星][20d] [PHP] [zigoo0/jsonbee](https://github.com/zigoo0/jsonbee) 


#### <a id="b5d99a78ddb383c208aae474fc2cb002"></a>Payload收集


- [**21409**星][14d] [PHP] [danielmiessler/seclists](https://github.com/danielmiessler/seclists) 多种类型资源收集：用户名、密码、URL、敏感数据类型、Fuzzing  Payload、WebShell等
    - 重复区段: [工具/webshell/收集](#e08366dcf7aa021c6973d9e2a8944dff) |[工具/wordlist/收集](#3202d8212db5699ea5e6021833bf3fa2) |
- [**10579**星][14d] [Py] [swisskyrepo/payloadsallthethings](https://github.com/swisskyrepo/payloadsallthethings) 
- [**1994**星][8m] [Shell] [foospidy/payloads](https://github.com/foospidy/payloads) payloads：web 攻击 Payload 集合
- [**1989**星][26d] [edoverflow/bugbounty-cheatsheet](https://github.com/edoverflow/bugbounty-cheatsheet) 
- [**1856**星][10m] [PHP] [bartblaze/php-backdoors](https://github.com/bartblaze/php-backdoors) 
- [**717**星][2m] [HTML] [ismailtasdelen/xss-payload-list](https://github.com/payloadbox/xss-payload-list) XSS 漏洞Payload列表
- [**367**星][2m] [renwax23/xss-payloads](https://github.com/renwax23/xss-payloads) 
- [**272**星][3m] [Py] [thekingofduck/easyxsspayload](https://github.com/thekingofduck/easyxsspayload) 
- [**238**星][3m] [payloadbox/command-injection-payload-list](https://github.com/payloadbox/command-injection-payload-list) 


#### <a id="b318465d0d415e35fc0883e9894261d1"></a>远控&&RAT


- [**5045**星][3m] [Py] [n1nj4sec/pupy](https://github.com/n1nj4sec/pupy) 
- [**1696**星][6m] [Smali] [ahmyth/ahmyth-android-rat](https://github.com/ahmyth/ahmyth-android-rat) 
- [**1306**星][1y] [Py] [marten4n6/evilosx](https://github.com/marten4n6/evilosx) 
- [**763**星][22d] [Py] [kevthehermit/ratdecoders](https://github.com/kevthehermit/ratdecoders) 
- [**597**星][1y] [PowerShell] [fortynorthsecurity/wmimplant](https://github.com/FortyNorthSecurity/WMImplant) 
- [**477**星][5m] [Visual Basic] [nyan-x-cat/lime-rat](https://github.com/nyan-x-cat/lime-rat) 
- [**352**星][2m] [C++] [werkamsus/lilith](https://github.com/werkamsus/lilith) 
- [**307**星][5m] [Py] [mvrozanti/rat-via-telegram](https://github.com/mvrozanti/rat-via-telegram) 
- [**271**星][1m] [C#] [nyan-x-cat/asyncrat-c-sharp](https://github.com/nyan-x-cat/asyncrat-c-sharp) 
- [**269**星][3m] [C++] [yuanyuanxiang/simpleremoter](https://github.com/yuanyuanxiang/simpleremoter) 


#### <a id="ad92f6b801a18934f1971e2512f5ae4f"></a>Payload生成


- [**3268**星][2m] [C] [screetsec/thefatrat](https://github.com/screetsec/thefatrat) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/后渗透/未分类-post-exp](#12abc279c69d1fcf10692b9cb89bcdf7) |
- [**2591**星][3m] [Java] [frohoff/ysoserial](https://github.com/frohoff/ysoserial) 生成会利用不安全的Java对象反序列化的Payload
- [**1741**星][21d] [Shell] [leebaird/discover](https://github.com/leebaird/discover) 自定义的bash脚本, 用于自动化多个渗透测试任务, 包括: 侦查、扫描、解析、在Metasploit中创建恶意Payload和Listener
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/自动化](#fc8737aef0f59c3952d11749fe582dac) |[工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Metasploit/未分类-metasploit](#01be61d5bb9f6f7199208ff0fba86b5d) |
- [**1061**星][5m] [Py] [nccgroup/winpayloads](https://github.com/nccgroup/winpayloads) 
- [**1003**星][1y] [Py] [d4vinci/dr0p1t-framework](https://github.com/d4vinci/dr0p1t-framework) 创建免杀的Dropper
- [**857**星][10m] [Visual Basic] [mdsecactivebreach/sharpshooter](https://github.com/mdsecactivebreach/sharpshooter) 
- [**816**星][6m] [Go] [tiagorlampert/chaos](https://github.com/tiagorlampert/chaos) a PoC that allow generate payloads and control remote operating system
- [**810**星][2m] [PHP] [ambionics/phpggc](https://github.com/ambionics/phpggc) 
- [**794**星][1m] [C#] [pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net) ysoserial.net：生成Payload，恶意利用不安全的 .NET 对象反序列化
- [**733**星][12m] [Py] [oddcod3/phantom-evasion](https://github.com/oddcod3/phantom-evasion) 
- [**684**星][3m] [Py] [sevagas/macro_pack](https://github.com/sevagas/macro_pack) 自动生成并混淆MS 文档, 用于渗透测试、演示、社会工程评估等
- [**618**星][8m] [Shell] [g0tmi1k/mpc](https://github.com/g0tmi1k/msfpc) 
- [**560**星][14d] [C] [thewover/donut](https://github.com/thewover/donut) 
- [**397**星][28d] [Perl] [chinarulezzz/pixload](https://github.com/chinarulezzz/pixload) 
- [**287**星][7m] [Py] [0xacb/viewgen](https://github.com/0xacb/viewgen) 
- [**268**星][1y] [Shell] [abedalqaderswedan1/aswcrypter](https://github.com/abedalqaderswedan1/aswcrypter) 
- [**262**星][1y] [Java] [ewilded/shelling](https://github.com/ewilded/shelling) 
- [**222**星][1y] [Java] [ewilded/psychopath](https://github.com/ewilded/psychopath) 


#### <a id="c45a90ab810d536a889e4e2dd45132f8"></a>Botnet&&僵尸网络


- [**3690**星][3m] [Py] [malwaredllc/byob](https://github.com/malwaredllc/byob) 
- [**2135**星][1y] [C++] [maestron/botnets](https://github.com/maestron/botnets) 
- [**390**星][19d] [C++] [souhardya/uboat](https://github.com/souhardya/uboat) 
- [**319**星][5m] [Go] [saturnsvoid/gobot2](https://github.com/saturnsvoid/gobot2) 


#### <a id="b6efee85bca01cde45faa45a92ece37f"></a>后门&&添加后门


- [**378**星][7m] [C] [zerosum0x0/smbdoor](https://github.com/zerosum0x0/smbdoor) 
- [**364**星][2m] [Shell] [screetsec/vegile](https://github.com/screetsec/vegile) 
- [**362**星][7m] [Py] [s0md3v/cloak](https://github.com/s0md3v/Cloak) 
- [**341**星][11m] [Shell] [r00t-3xp10it/backdoorppt](https://github.com/r00t-3xp10it/backdoorppt) backdoorppt：将Exe格式Payload伪装成Doc（.ppt）
- [**317**星][1y] [Ruby] [carletonstuberg/browser-backdoor](https://github.com/CarletonStuberg/browser-backdoor) 
- [**287**星][3m] [C#] [mvelazc0/defcon27_csharp_workshop](https://github.com/mvelazc0/defcon27_csharp_workshop) 
- [**201**星][8m] [C] [paradoxis/php-backdoor](https://github.com/Paradoxis/PHP-Backdoor) 


#### <a id="85bb0c28850ffa2b4fd44f70816db306"></a>混淆器&&Obfuscate


- [**1351**星][9m] [PowerShell] [danielbohannon/invoke-obfuscation](https://github.com/danielbohannon/invoke-obfuscation) 


#### <a id="78d0ac450a56c542e109c07a3b0225ae"></a>Payload管理


- [**930**星][1y] [JS] [netflix/sleepy-puppy](https://github.com/Netflix-Skunkworks/sleepy-puppy) 


#### <a id="d08b7bd562a4bf18275c63ffe7d8fc91"></a>勒索软件


- [**379**星][1y] [Go] [mauri870/ransomware](https://github.com/mauri870/ransomware) 
- [**313**星][13d] [Batchfile] [mitchellkrogza/ultimate.hosts.blacklist](https://github.com/mitchellkrogza/ultimate.hosts.blacklist) 


#### <a id="82f546c7277db7919986ecf47f3c9495"></a>键盘记录器


- [**359**星][11m] [Py] [ajinabraham/xenotix-python-keylogger](https://github.com/ajinabraham/xenotix-python-keylogger) 


#### <a id="8f99087478f596139922cd1ad9ec961b"></a>Meterpreter


- [**233**星][5m] [Py] [mez0cc/ms17-010-python](https://github.com/mez0cc/ms17-010-python) 


#### <a id="63e0393e375e008af46651a3515072d8"></a>Payload投递


- [**255**星][3m] [Py] [no0be/dnslivery](https://github.com/no0be/dnslivery) 




### <a id="2051fd9e171f2698d8e7486e3dd35d87"></a>渗透多合一&&渗透框架


- [**4965**星][4m] [PowerShell] [empireproject/empire](https://github.com/EmpireProject/Empire) 后渗透框架. Windows客户端用PowerShell, Linux/OSX用Python. 之前PowerShell Empire和Python EmPyre的组合
- [**4576**星][22d] [Py] [manisso/fsociety](https://github.com/manisso/fsociety) 
- [**3313**星][5m] [PowerShell] [samratashok/nishang](https://github.com/samratashok/nishang) 渗透框架，脚本和Payload收集，主要是PowerShell，涵盖渗透的各个阶段
- [**3053**星][1m] [Shell] [1n3/sn1per](https://github.com/1n3/sn1per) 自动化渗透测试框架
- [**3041**星][1m] [Py] [byt3bl33d3r/crackmapexec](https://github.com/byt3bl33d3r/crackmapexec) 后渗透工具，自动化评估大型Active Directory网络的安全性
- [**2961**星][17d] [Py] [guardicore/monkey](https://github.com/guardicore/monkey) 自动化渗透测试工具, 测试数据中心的弹性, 以防范周边(perimeter)泄漏和内部服务器感染
- [**2767**星][7m] [C#] [quasar/quasarrat](https://github.com/quasar/quasarrat) 
- [**2381**星][2m] [Py] [infobyte/faraday](https://github.com/infobyte/faraday) 渗透测试和漏洞管理平台
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞管理](#9f068ea97c2e8865fac21d6fc50f86b3) |
- [**1482**星][16d] [Py] [zerosum0x0/koadic](https://github.com/zerosum0x0/koadic) koadic：类似于Meterpreter、Powershell Empire 的post-exploitation rootkit，区别在于其大多数操作都是由 Windows 脚本主机 JScript/VBScript 执行
- [**1081**星][10m] [Py] [secforce/sparta](https://github.com/secforce/sparta) 网络基础架构渗透测试
- [**934**星][3m] [Py] [0xinfection/tidos-framework](https://github.com/0xInfection/TIDoS-Framework) Web App渗透测试框架, 攻击性, 手动
- [**918**星][1y] [Py] [m4n3dw0lf/pythem](https://github.com/m4n3dw0lf/pythem) 多功能渗透测试框架
- [**513**星][21d] [Py] [gyoisamurai/gyoithon](https://github.com/gyoisamurai/gyoithon) 使用机器学习的成长型渗透测试工具
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |


### <a id="a9494547a9359c60f09aea89f96a2c83"></a>后渗透


#### <a id="12abc279c69d1fcf10692b9cb89bcdf7"></a>未分类-post-exp


- [**6832**星][17d] [C] [hashcat/hashcat](https://github.com/hashcat/hashcat) 世界上最快最先进的密码恢复工具
    - 重复区段: [工具/密码&&凭证/密码](#86dc226ae8a71db10e4136f4b82ccd06) |
- [**3268**星][2m] [C] [screetsec/thefatrat](https://github.com/screetsec/thefatrat) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload生成](#ad92f6b801a18934f1971e2512f5ae4f) |
- [**2346**星][1m] [Shell] [rebootuser/linenum](https://github.com/rebootuser/linenum) 
- [**2136**星][14d] [Py] [commixproject/commix](https://github.com/commixproject/commix) 
- [**1226**星][9m] [C] [a0rtega/pafish](https://github.com/a0rtega/pafish) 
- [**1191**星][1y] [C#] [cn33liz/p0wnedshell](https://github.com/cn33liz/p0wnedshell) 
- [**1045**星][8m] [Py] [0x00-0x00/shellpop](https://github.com/0x00-0x00/shellpop) 在渗透中生产简易的/复杂的反向/绑定Shell
- [**1029**星][28d] [Boo] [byt3bl33d3r/silenttrinity](https://github.com/byt3bl33d3r/silenttrinity) 
- [**1015**星][3m] [Py] [byt3bl33d3r/deathstar](https://github.com/byt3bl33d3r/deathstar) 在Active Directory环境中使用Empire自动获取域管理员权限
- [**754**星][4m] [Py] [lgandx/pcredz](https://github.com/lgandx/pcredz) 
- [**737**星][4m] [PowerShell] [hausec/adape-script](https://github.com/hausec/adape-script) 
- [**668**星][1m] [C#] [cobbr/sharpsploit](https://github.com/cobbr/sharpsploit) 
- [**405**星][4m] [Shell] [thesecondsun/bashark](https://github.com/thesecondsun/bashark) 
- [**341**星][4m] [Py] [adrianvollmer/powerhub](https://github.com/adrianvollmer/powerhub) 
- [**282**星][1y] [JS] [chrisallenlane/novahot](https://github.com/chrisallenlane/novahot) Webshell框架，实现了基于Json的API，可与任何语言编写的后门（默认支持PHP/Ruby/Python）进行通信。
    - 重复区段: [工具/webshell/未分类-webshell](#faa91844951d2c29b7b571c6e8a3eb54) |
- [**212**星][2m] [Go] [brompwnie/botb](https://github.com/brompwnie/botb) 


#### <a id="4c2095e7e192ac56f6ae17c8fc045c51"></a>提权&&PrivilegeEscalation


- [**3509**星][4m] [C] [secwiki/windows-kernel-exploits](https://github.com/secwiki/windows-kernel-exploits) 
- [**1245**星][2m] [Py] [alessandroz/beroot](https://github.com/alessandroz/beroot) 
- [**583**星][11m] [C++] [ohpe/juicy-potato](https://github.com/ohpe/juicy-potato) 
- [**529**星][4m] [rhinosecuritylabs/aws-iam-privilege-escalation](https://github.com/rhinosecuritylabs/aws-iam-privilege-escalation) 
- [**492**星][7m] [Py] [initstring/dirty_sock](https://github.com/initstring/dirty_sock) 
- [**467**星][8m] [C] [nongiach/sudo_inject](https://github.com/nongiach/sudo_inject) 
- [**443**星][1m] [C#] [rasta-mouse/watson](https://github.com/rasta-mouse/watson) 
- [**383**星][3m] [PowerShell] [cyberark/aclight](https://github.com/cyberark/ACLight) 
- [**353**星][2m] [PowerShell] [gdedrouas/exchange-ad-privesc](https://github.com/gdedrouas/exchange-ad-privesc) 
- [**337**星][20d] [Shell] [nullarray/roothelper](https://github.com/nullarray/roothelper) 辅助在被攻克系统上的提权过程：自动枚举、下载、解压并执行提权脚本
- [**302**星][4m] [Batchfile] [frizb/windows-privilege-escalation](https://github.com/frizb/windows-privilege-escalation) 
- [**258**星][3m] [PHP] [lawrenceamer/0xsp-mongoose](https://github.com/lawrenceamer/0xsp-mongoose) 


#### <a id="caab36bba7fa8bb931a9133e37d397f6"></a>Windows


##### <a id="7ed8ee71c4a733d5e5e5d239f0e8b9e0"></a>未分类


- [**328**星][2m] [C] [mattiwatti/efiguard](https://github.com/mattiwatti/efiguard) 
- [**209**星][1y] [C++] [tandasat/pgresarch](https://github.com/tandasat/pgresarch) 


##### <a id="58f3044f11a31d0371daa91486d3694e"></a>UAC


- [**2283**星][15d] [C] [hfiref0x/uacme](https://github.com/hfiref0x/uacme) 


##### <a id="b84c84a853416b37582c3b7f13eabb51"></a>AppLocker




##### <a id="e3c4c83dfed529ceee65040e565003c4"></a>ActiveDirectory


- [**1943**星][2m] [infosecn1nja/ad-attack-defense](https://github.com/infosecn1nja/ad-attack-defense) 


##### <a id="25697cca32bd8c9492b8e2c8a3a93bfe"></a>域渗透






#### <a id="2dd40db455d3c6f1f53f8a9c25bbe63e"></a>驻留&&Persistence


- [**271**星][2m] [C#] [fireeye/sharpersist](https://github.com/fireeye/sharpersist) Windows persistence toolkit 
- [**260**星][1y] [C++] [ewhitehats/invisiblepersistence](https://github.com/ewhitehats/invisiblepersistence) 




### <a id="fc8737aef0f59c3952d11749fe582dac"></a>自动化


- [**1799**星][4m] [Shell] [arismelachroinos/lscript](https://github.com/arismelachroinos/lscript) 自动化无线渗透和Hacking 任务的脚本
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**1741**星][21d] [Shell] [leebaird/discover](https://github.com/leebaird/discover) 自定义的bash脚本, 用于自动化多个渗透测试任务, 包括: 侦查、扫描、解析、在Metasploit中创建恶意Payload和Listener
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload生成](#ad92f6b801a18934f1971e2512f5ae4f) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Metasploit/未分类-metasploit](#01be61d5bb9f6f7199208ff0fba86b5d) |
- [**1656**星][2m] [Py] [rootm0s/winpwnage](https://github.com/rootm0s/winpwnage) 


### <a id="3ae4408f4ab03f99bab9ef9ee69642a8"></a>数据渗透


- [**453**星][3m] [Py] [viralmaniar/powershell-rat](https://github.com/viralmaniar/powershell-rat) 


### <a id="adfa06d452147ebacd35981ce56f916b"></a>横向渗透




### <a id="39e9a0fe929fffe5721f7d7bb2dae547"></a>Burp


#### <a id="6366edc293f25b57bf688570b11d6584"></a>收集


- [**1920**星][1y] [BitBake] [1n3/intruderpayloads](https://github.com/1n3/intruderpayloads) 
- [**1058**星][27d] [snoopysecurity/awesome-burp-extensions](https://github.com/snoopysecurity/awesome-burp-extensions) Burp扩展收集


#### <a id="5b761419863bc686be12c76451f49532"></a>未分类-Burp


- [**1091**星][1y] [Py] [bugcrowd/hunt](https://github.com/bugcrowd/HUNT) Burp和ZAP的扩展收集
- [**742**星][13d] [Batchfile] [mr-xn/burpsuite-collections](https://github.com/mr-xn/burpsuite-collections) 
- [**705**星][1y] [Java] [d3vilbug/hackbar](https://github.com/d3vilbug/hackbar) 
- [**646**星][8m] [Java] [vulnerscom/burp-vulners-scanner](https://github.com/vulnerscom/burp-vulners-scanner) 
- [**563**星][1y] [Java] [federicodotta/brida](https://github.com/federicodotta/brida) 
- [**549**星][8m] [Java] [c0ny1/chunked-coding-converter](https://github.com/c0ny1/chunked-coding-converter) 
- [**466**星][19d] [Java] [wagiro/burpbounty](https://github.com/wagiro/burpbounty) 
- [**436**星][5m] [Py] [albinowax/activescanplusplus](https://github.com/albinowax/activescanplusplus) 
- [**434**星][1m] [Py] [romanzaikin/burpextension-whatsapp-decryption-checkpoint](https://github.com/romanzaikin/burpextension-whatsapp-decryption-checkpoint) 
- [**402**星][4m] [Java] [bit4woo/recaptcha](https://github.com/bit4woo/recaptcha) 
- [**397**星][7m] [Java] [nccgroup/burpsuitehttpsmuggler](https://github.com/nccgroup/burpsuitehttpsmuggler) 
- [**373**星][1y] [Py] [rhinosecuritylabs/sleuthql](https://github.com/rhinosecuritylabs/sleuthql) 
- [**371**星][2m] [Java] [nccgroup/autorepeater](https://github.com/nccgroup/autorepeater) 
- [**352**星][4m] [Java] [bit4woo/domain_hunter](https://github.com/bit4woo/domain_hunter) 
- [**327**星][2m] [Kotlin] [portswigger/turbo-intruder](https://github.com/portswigger/turbo-intruder) 
- [**309**星][1y] [Java] [ebryx/aes-killer](https://github.com/ebryx/aes-killer) 
- [**300**星][3m] [Java] [bit4woo/knife](https://github.com/bit4woo/knife) 
- [**300**星][7m] [Java] [ilmila/j2eescan](https://github.com/ilmila/j2eescan) 
- [**299**星][2m] [Java] [portswigger/http-request-smuggler](https://github.com/PortSwigger/http-request-smuggler) an extension for Burp Suite designed to help you launch HTTP Request Smuggling attack
- [**297**星][11m] [Shell] [yw9381/burp_suite_doc_zh_cn](https://github.com/yw9381/burp_suite_doc_zh_cn) 
- [**296**星][1y] [Java] [vmware/burp-rest-api](https://github.com/vmware/burp-rest-api) 
- [**272**星][1y] [Java] [elkokc/reflector](https://github.com/elkokc/reflector) reflector：Burp 插件，浏览网页时实时查找反射 XSS
- [**264**星][18d] [Py] [quitten/autorize](https://github.com/quitten/autorize) 
- [**250**星][2m] [Py] [rhinosecuritylabs/iprotate_burp_extension](https://github.com/rhinosecuritylabs/iprotate_burp_extension) 
- [**241**星][4m] [Py] [initroot/burpjslinkfinder](https://github.com/initroot/burpjslinkfinder) 
- [**235**星][1m] [Java] [samlraider/samlraider](https://github.com/samlraider/samlraider) 
- [**231**星][1y] [Java] [nccgroup/burpsuiteloggerplusplus](https://github.com/nccgroup/burpsuiteloggerplusplus) 
- [**230**星][1y] [Py] [audibleblink/doxycannon](https://github.com/audibleblink/doxycannon) DoxyCannon: 为一堆OpenVPN文件分别创建Docker容器, 每个容器开启SOCKS5代理服务器并绑定至Docker主机端口, 再结合使用Burp或ProxyChains, 构建私有的Botnet
- [**230**星][1y] [Java] [difcareer/sqlmap4burp](https://github.com/difcareer/sqlmap4burp) 
- [**222**星][6m] [Java] [c0ny1/jsencrypter](https://github.com/c0ny1/jsencrypter) 
- [**214**星][2m] [Java] [c0ny1/passive-scan-client](https://github.com/c0ny1/passive-scan-client) 
- [**205**星][2m] [Java] [h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator) 
- [**202**星][5m] [Perl] [modzero/mod0burpuploadscanner](https://github.com/modzero/mod0burpuploadscanner) 




### <a id="8e7a6a74ff322cbf2bad59092598de77"></a>Metasploit


#### <a id="01be61d5bb9f6f7199208ff0fba86b5d"></a>未分类-metasploit


- [**18724**星][14d] [Ruby] [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework) 
- [**1741**星][21d] [Shell] [leebaird/discover](https://github.com/leebaird/discover) 自定义的bash脚本, 用于自动化多个渗透测试任务, 包括: 侦查、扫描、解析、在Metasploit中创建恶意Payload和Listener
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/自动化](#fc8737aef0f59c3952d11749fe582dac) |[工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload生成](#ad92f6b801a18934f1971e2512f5ae4f) |
- [**1284**星][1y] [Shell] [dana-at-cp/backdoor-apk](https://github.com/dana-at-cp/backdoor-apk) 
- [**709**星][2m] [C] [rapid7/metasploit-payloads](https://github.com/rapid7/metasploit-payloads) 
- [**683**星][2m] [Java] [isafeblue/trackray](https://github.com/isafeblue/trackray) 
- [**445**星][4m] [Py] [cchio/deep-pwning](https://github.com/cchio/deep-pwning) 
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |
- [**389**星][5m] [Ruby] [praetorian-code/purple-team-attack-automation](https://github.com/praetorian-code/purple-team-attack-automation) 
- [**309**星][10m] [Ruby] [darkoperator/metasploit-plugins](https://github.com/darkoperator/metasploit-plugins) 
- [**298**星][2m] [Ruby] [fozavci/viproy-voipkit](https://github.com/fozavci/viproy-voipkit) VoIP渗透测试工具和 Metasploit 框架
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |
- [**296**星][1m] [Py] [3ndg4me/autoblue-ms17-010](https://github.com/3ndg4me/autoblue-ms17-010) 
- [**265**星][3m] [Vue] [zerx0r/kage](https://github.com/Zerx0r/Kage) 




### <a id="b1161d6c4cb520d0cd574347cd18342e"></a>免杀&&躲避AV检测


- [**1009**星][4m] [C] [govolution/avet](https://github.com/govolution/avet) avet：免杀工具
- [**698**星][9m] [Py] [mr-un1k0d3r/dkmc](https://github.com/mr-un1k0d3r/dkmc) 
- [**620**星][6m] [Py] [paranoidninja/carboncopy](https://github.com/paranoidninja/carboncopy) 
- [**461**星][1y] [Go] [arvanaghi/checkplease](https://github.com/arvanaghi/checkplease) 
- [**299**星][1y] [Py] [two06/inception](https://github.com/two06/inception) 
- [**280**星][1m] [C#] [ch0pin/aviator](https://github.com/ch0pin/aviator) 
- [**252**星][1m] [C#] [hackplayers/salsa-tools](https://github.com/hackplayers/salsa-tools) 


### <a id="98a851c8e6744850efcb27b8e93dff73"></a>C&C


- [**2387**星][3m] [Go] [ne0nd0g/merlin](https://github.com/ne0nd0g/merlin) 
- [**1104**星][1y] [Py] [byt3bl33d3r/gcat](https://github.com/byt3bl33d3r/gcat) 
- [**917**星][19d] [C#] [cobbr/covenant](https://github.com/cobbr/covenant) 
- [**632**星][10m] [Py] [mehulj94/braindamage](https://github.com/mehulj94/braindamage) 
- [**314**星][1y] [C#] [spiderlabs/dohc2](https://github.com/spiderlabs/dohc2) 
- [**240**星][14d] [PowerShell] [nettitude/poshc2](https://github.com/nettitude/poshc2) 
- [**240**星][14d] [PowerShell] [nettitude/poshc2](https://github.com/nettitude/PoshC2) 


### <a id="a0897294e74a0863ea8b83d11994fad6"></a>DDOS


- [**2443**星][17d] [C++] [pavel-odintsov/fastnetmon](https://github.com/pavel-odintsov/fastnetmon) 快速 DDoS 检测/分析工具，支持 sflow/netflow/mirror
- [**1174**星][29d] [Shell] [mitchellkrogza/nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) 
- [**831**星][2m] [Py] [649/memcrashed-ddos-exploit](https://github.com/649/memcrashed-ddos-exploit) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/Shodan](#18c7c1df2e6ae5e9135dfa2e4eb1d4db) |
- [**457**星][6m] [Shell] [jgmdev/ddos-deflate](https://github.com/jgmdev/ddos-deflate) 
- [**451**星][2m] [JS] [codemanki/cloudscraper](https://github.com/codemanki/cloudscraper) 
- [**374**星][12m] [C] [markus-go/bonesi](https://github.com/markus-go/bonesi) 
- [**293**星][3m] [Shell] [anti-ddos/anti-ddos](https://github.com/anti-ddos/Anti-DDOS) 
- [**243**星][12m] [Py] [wenfengshi/ddos-dos-tools](https://github.com/wenfengshi/ddos-dos-tools) 


### <a id="8e1069b2bce90b87eea762ee3d0935d8"></a>OWASP


- [**10690**星][13d] [Py] [owasp/cheatsheetseries](https://github.com/owasp/cheatsheetseries) 
- [**2245**星][13d] [Go] [owasp/amass](https://github.com/owasp/amass) 
- [**1902**星][28d] [Perl] [spiderlabs/owasp-modsecurity-crs](https://github.com/spiderlabs/owasp-modsecurity-crs) 
- [**1680**星][1y] [owasp/devguide](https://github.com/owasp/devguide) 
- [**1390**星][2m] [HTML] [owasp/top10](https://github.com/owasp/top10) 
- [**1000**星][3m] [HTML] [owasp/nodegoat](https://github.com/owasp/nodegoat) 学习OWASP安全威胁Top10如何应用到Web App的，以及如何处理
- [**731**星][2m] [Java] [owasp/securityshepherd](https://github.com/owasp/securityshepherd) 
- [**665**星][13d] [HTML] [owasp/asvs](https://github.com/owasp/asvs) 
- [**597**星][10m] [Py] [zdresearch/owasp-nettacker](https://github.com/zdresearch/OWASP-Nettacker) 
- [**480**星][17d] [owasp/wstg](https://github.com/OWASP/wstg) 
- [**480**星][17d] [owasp/wstg](https://github.com/owasp/wstg) 
- [**461**星][7m] [Java] [owasp/owasp-webscarab](https://github.com/owasp/owasp-webscarab) 
- [**402**星][5m] [Py] [stanislav-web/opendoor](https://github.com/stanislav-web/opendoor) 
- [**360**星][1m] [Java] [zaproxy/zap-extensions](https://github.com/zaproxy/zap-extensions) 
- [**341**星][1m] [Java] [esapi/esapi-java-legacy](https://github.com/esapi/esapi-java-legacy) 
- [**292**星][5m] [0xradi/owasp-web-checklist](https://github.com/0xradi/owasp-web-checklist) 
- [**271**星][5m] [JS] [mike-goodwin/owasp-threat-dragon](https://github.com/mike-goodwin/owasp-threat-dragon) 
- [**269**星][4m] [tanprathan/owasp-testing-checklist](https://github.com/tanprathan/owasp-testing-checklist) 
- [**248**星][11m] [Java] [owasp/owasp-java-encoder](https://github.com/owasp/owasp-java-encoder) 
- [**225**星][1m] [owasp/api-security](https://github.com/owasp/api-security) 


### <a id="7667f6a0381b6cded2014a0d279b5722"></a>Kali


- [**2522**星][7m] [offensive-security/kali-nethunter](https://github.com/offensive-security/kali-nethunter) 
- [**2332**星][7m] [Py] [lionsec/katoolin](https://github.com/lionsec/katoolin) 
- [**1690**星][2m] [PHP] [xtr4nge/fruitywifi](https://github.com/xtr4nge/fruitywifi) 
- [**849**星][10m] [Shell] [esc0rtd3w/wifi-hacker](https://github.com/esc0rtd3w/wifi-hacker) 
- [**714**星][3m] [Py] [rajkumrdusad/tool-x](https://github.com/rajkumrdusad/tool-x) 
- [**667**星][7m] [offensive-security/kali-arm-build-scripts](https://github.com/offensive-security/kali-arm-build-scripts) 
- [**542**星][1m] [Shell] [offensive-security/kali-linux-docker](https://github.com/offensive-security/kali-linux-docker) 
- [**385**星][3m] [jack-liang/kalitools](https://github.com/jack-liang/kalitools) 
- [**328**星][7m] [offensive-security/kali-linux-recipes](https://github.com/offensive-security/kali-linux-recipes) 


### <a id="0b8e79b79094082d0906153445d6ef9a"></a>CobaltStrike


- [**389**星][1y] [Shell] [killswitch-gui/cobaltstrike-toolkit](https://github.com/killswitch-gui/cobaltstrike-toolkit) 
- [**203**星][1y] [C#] [spiderlabs/sharpcompile](https://github.com/spiderlabs/sharpcompile) 




***


## <a id="8f92ead9997a4b68d06a9acf9b01ef63"></a>扫描器&&安全扫描&&App扫描&&漏洞扫描


### <a id="de63a029bda6a7e429af272f291bb769"></a>未分类-Scanner


- [**11006**星][2m] [C] [robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) masscan：世界上最快的互联网端口扫描器，号称可6分钟内扫描整个互联网
- [**7288**星][25d] [Py] [s0md3v/xsstrike](https://github.com/s0md3v/XSStrike) 
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/XSS&&XXE/未分类-XSS](#648e49b631ea4ba7c128b53764328c39) |
- [**5245**星][1m] [Go] [zricethezav/gitleaks](https://github.com/zricethezav/gitleaks) 
- [**4474**星][16d] [Ruby] [wpscanteam/wpscan](https://github.com/wpscanteam/wpscan) 
- [**4101**星][24d] [we5ter/scanners-box](https://github.com/we5ter/scanners-box)  安全行业从业者自研开源扫描器合辑
- [**3375**星][1m] [Perl] [sullo/nikto](https://github.com/sullo/nikto) 
- [**3119**星][2m] [Go] [mozilla/sops](https://github.com/mozilla/sops) 
- [**3049**星][20d] [Py] [maurosoria/dirsearch](https://github.com/maurosoria/dirsearch) 
- [**3022**星][2m] [C] [zmap/zmap](https://github.com/zmap/zmap) 
- [**2904**星][21d] [Py] [andresriancho/w3af](https://github.com/andresriancho/w3af) Web App安全扫描器, 辅助开发者和渗透测试人员识别和利用Web App中的漏洞
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞扫描&&挖掘&&发现/漏洞扫描/未分类](#0ed7e90d216a8a5be1dafebaf9eaeb5d) |
- [**2261**星][3m] [JS] [retirejs/retire.js](https://github.com/retirejs/retire.js) 
- [**2027**星][2m] [Ruby] [urbanadventurer/whatweb](https://github.com/urbanadventurer/whatweb) 
- [**2023**星][2m] [Py] [nabla-c0d3/sslyze](https://github.com/nabla-c0d3/sslyze) SSL/TLS服务器扫描
- [**1630**星][1m] [NSIS] [angryip/ipscan](https://github.com/angryip/ipscan) 
- [**1530**星][7m] [Py] [m4ll0k/wascan](https://github.com/m4ll0k/WAScan) 
- [**1494**星][4m] [Py] [hannob/snallygaster](https://github.com/hannob/snallygaster) Python脚本, 扫描HTTP服务器"秘密文件"
- [**1060**星][2m] [PHP] [tuhinshubhra/red_hawk](https://github.com/tuhinshubhra/red_hawk) 信息收集、漏洞扫描、爬虫多合一
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |
- [**1054**星][3m] [Py] [gerbenjavado/linkfinder](https://github.com/gerbenjavado/linkfinder) 
- [**1037**星][7m] [Py] [lucifer1993/struts-scan](https://github.com/lucifer1993/struts-scan) struts2漏洞全版本检测和利用工具
- [**985**星][3m] [Py] [h4ckforjob/dirmap](https://github.com/h4ckforjob/dirmap) 一个高级web目录、文件扫描工具，功能将会强于DirBuster、Dirsearch、cansina、御剑。
- [**905**星][2m] [Py] [tuhinshubhra/cmseek](https://github.com/tuhinshubhra/cmseek) 
- [**880**星][5m] [PHP] [tidesec/wdscanner](https://github.com/tidesec/wdscanner) 分布式web漏洞扫描、客户管理、漏洞定期扫描、子域名枚举、端口扫描、网站爬虫、暗链检测、坏链检测、网站指纹搜集、专项漏洞检测、代理搜集及部署等功能。
- [**862**星][1m] [Py] [ajinabraham/nodejsscan](https://github.com/ajinabraham/nodejsscan) 
- [**759**星][17d] [Py] [vesche/scanless](https://github.com/vesche/scanless) scanless：端口扫描器
- [**741**星][19d] [Py] [nekmo/dirhunt](https://github.com/nekmo/dirhunt) Web爬虫, 针对搜索和分析路径做了优化
    - 重复区段: [工具/爬虫](#785ad72c95e857273dce41842f5e8873) |
- [**722**星][6m] [Py] [ztgrace/changeme](https://github.com/ztgrace/changeme) 默认证书扫描器
- [**694**星][4m] [CSS] [ajinabraham/cmsscan](https://github.com/ajinabraham/cmsscan) Scan Wordpress, Drupal, Joomla, vBulletin websites for Security issues
- [**690**星][2m] [CSS] [boy-hack/w12scan](https://github.com/w-digital-scanner/w12scan) a network asset discovery engine that can automatically aggregate related assets for analysis and use
- [**681**星][28d] [C] [scanmem/scanmem](https://github.com/scanmem/scanmem) 
- [**671**星][1m] [Ruby] [mozilla/ssh_scan](https://github.com/mozilla/ssh_scan) 
- [**657**星][7m] [Py] [m4ll0k/wpseku](https://github.com/m4ll0k/wpseku) 
- [**656**星][2m] [Py] [kevthehermit/pastehunter](https://github.com/kevthehermit/pastehunter) 
- [**649**星][5m] [Py] [droope/droopescan](https://github.com/droope/droopescan) 
- [**636**星][1y] [Py] [lmco/laikaboss](https://github.com/lmco/laikaboss) 
- [**613**星][5m] [Py] [rabbitmask/weblogicscan](https://github.com/rabbitmask/weblogicscan) 
- [**612**星][12m] [Ruby] [thesp0nge/dawnscanner](https://github.com/thesp0nge/dawnscanner) 
- [**604**星][4m] [Py] [faizann24/xsspy](https://github.com/faizann24/xsspy) Web Application XSS Scanner
- [**569**星][2m] [HTML] [gwillem/magento-malware-scanner](https://github.com/gwillem/magento-malware-scanner) 用于检测 Magento 恶意软件的规则/样本集合
- [**564**星][2m] [Perl] [alisamtechnology/atscan](https://github.com/alisamtechnology/atscan) 
- [**555**星][5m] [Py] [codingo/vhostscan](https://github.com/codingo/vhostscan) 
- [**542**星][7m] [Go] [marco-lancini/goscan](https://github.com/marco-lancini/goscan) 
- [**536**星][4m] [Py] [dhs-ncats/pshtt](https://github.com/cisagov/pshtt) 
- [**526**星][6m] [Py] [grayddq/gscan](https://github.com/grayddq/gscan) 
- [**481**星][1m] [Py] [fcavallarin/htcap](https://github.com/fcavallarin/htcap) 
- [**475**星][1y] [C] [nanshihui/scan-t](https://github.com/nanshihui/scan-t) 
- [**399**星][2m] [Py] [boy-hack/w13scan](https://github.com/w-digital-scanner/w13scan) 
- [**397**星][10m] [JS] [eviltik/evilscan](https://github.com/eviltik/evilscan) evilscan：大规模 IP/端口扫描器，Node.js 编写
- [**390**星][10m] [Py] [mitre/multiscanner](https://github.com/mitre/multiscanner) 
- [**386**星][1y] [Py] [grayddq/publicmonitors](https://github.com/grayddq/publicmonitors) 
- [**385**星][1m] [C] [hasherezade/hollows_hunter](https://github.com/hasherezade/hollows_hunter) 
- [**379**星][13d] [Py] [stamparm/dsss](https://github.com/stamparm/dsss) 
- [**340**星][4m] [Py] [swisskyrepo/wordpresscan](https://github.com/swisskyrepo/wordpresscan) 
- [**339**星][12m] [Py] [skavngr/rapidscan](https://github.com/skavngr/rapidscan) 
- [**338**星][1m] [Py] [fgeek/pyfiscan](https://github.com/fgeek/pyfiscan) pyfiscan：Web App 漏洞及版本扫描
- [**335**星][3m] [Java] [portswigger/backslash-powered-scanner](https://github.com/portswigger/backslash-powered-scanner) 
- [**330**星][1y] [Py] [flipkart-incubator/rta](https://github.com/flipkart-incubator/rta) 
- [**316**星][2m] [HTML] [coinbase/salus](https://github.com/coinbase/salus) 
- [**315**星][15d] [C] [royhills/arp-scan](https://github.com/royhills/arp-scan) 
- [**301**星][10m] [PHP] [steverobbins/magescan](https://github.com/steverobbins/magescan) 
- [**299**星][1m] [PowerShell] [canix1/adaclscanner](https://github.com/canix1/adaclscanner) 
- [**294**星][1y] [Shell] [cryptolok/ghostinthenet](https://github.com/cryptolok/ghostinthenet) 
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**294**星][2m] [Ruby] [m0nad/hellraiser](https://github.com/m0nad/hellraiser) 
- [**294**星][1m] [Shell] [mitchellkrogza/apache-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/apache-ultimate-bad-bot-blocker) 
- [**286**星][4m] [enkomio/taipan](https://github.com/enkomio/Taipan) 
- [**284**星][1y] [Py] [code-scan/dzscan](https://github.com/code-scan/dzscan) 
- [**280**星][8m] [Py] [boy-hack/w8fuckcdn](https://github.com/boy-hack/w8fuckcdn) 通过扫描全网绕过CDN获取网站IP地址
- [**278**星][3m] [Py] [shenril/sitadel](https://github.com/shenril/sitadel) 
- [**276**星][2m] [Py] [target/strelka](https://github.com/target/strelka) 
- [**268**星][1y] [PHP] [psecio/parse](https://github.com/psecio/parse) 
- [**262**星][5m] [Py] [abhisharma404/vault_scanner](https://github.com/abhisharma404/vault) 
- [**254**星][3m] [Py] [m4ll0k/konan](https://github.com/m4ll0k/Konan) 
- [**253**星][9m] [jeffzh3ng/insectsawake](https://github.com/jeffzh3ng/insectsawake) 
- [**246**星][1m] [Py] [gildasio/h2t](https://github.com/gildasio/h2t) 
- [**245**星][2m] [Go] [zmap/zgrab2](https://github.com/zmap/zgrab2) 
- [**235**星][3m] [PHP] [psecio/versionscan](https://github.com/psecio/versionscan) 
- [**233**星][7m] [Go] [gocaio/goca](https://github.com/gocaio/goca) 
- [**217**星][5m] [JS] [pavanw3b/sh00t](https://github.com/pavanw3b/sh00t) 
- [**209**星][3m] [Py] [iojw/socialscan](https://github.com/iojw/socialscan) 
- [**207**星][9m] [Py] [nullarray/dorknet](https://github.com/nullarray/dorknet) 
- [**202**星][1y] [Py] [dionach/cmsmap](https://github.com/dionach/cmsmap) 
- [**201**星][12m] [PowerShell] [sud0woodo/dcomrade](https://github.com/sud0woodo/dcomrade) 


### <a id="58d8b993ffc34f7ded7f4a0077129eb2"></a>隐私&&Secret&&Privacy扫描


- [**6673**星][10m] [Shell] [awslabs/git-secrets](https://github.com/awslabs/git-secrets) 
- [**4346**星][7m] [Py] [boxug/trape](https://github.com/jofpin/trape) 学习在互联网上跟踪别人，获取其详细信息，并避免被别人跟踪
- [**3064**星][28d] [Py] [tribler/tribler](https://github.com/tribler/tribler) 
- [**1102**星][4m] [Vue] [0xbug/hawkeye](https://github.com/0xbug/hawkeye) 
- [**935**星][20d] [Py] [mozilla/openwpm](https://github.com/mozilla/OpenWPM) 
- [**884**星][2m] [C#] [elevenpaths/foca](https://github.com/elevenpaths/foca) 
- [**822**星][18d] [Py] [al0ne/vxscan](https://github.com/al0ne/vxscan) 
- [**390**星][6m] [Py] [repoog/gitprey](https://github.com/repoog/gitprey) 
- [**356**星][2m] [Py] [hell0w0rld0/github-hunter](https://github.com/hell0w0rld0/github-hunter) 
- [**312**星][15d] [HTML] [tanjiti/sec_profile](https://github.com/tanjiti/sec_profile) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/社交网络/Github](#8d1ae776898748b8249132e822f6c919) |


### <a id="1927ed0a77ff4f176b0b7f7abc551e4a"></a>隐私存储


#### <a id="1af1c4f9dba1db2a4137be9c441778b8"></a>未分类


- [**5029**星][2m] [Shell] [stackexchange/blackbox](https://github.com/stackexchange/blackbox) 文件使用PGP加密后隐藏在Git/Mercurial/Subversion


#### <a id="362dfd9c1f530dd20f922fd4e0faf0e3"></a>隐写


- [**569**星][1m] [Go] [dimitarpetrov/stegify](https://github.com/dimitarpetrov/stegify) 
- [**344**星][6m] [Go] [lukechampine/jsteg](https://github.com/lukechampine/jsteg) 
- [**342**星][5m] [Java] [syvaidya/openstego](https://github.com/syvaidya/openstego) 
- [**274**星][1y] [C] [abeluck/stegdetect](https://github.com/abeluck/stegdetect) 
- [**256**星][26d] [Py] [cedricbonhomme/stegano](https://github.com/cedricbonhomme/stegano) 






***


## <a id="a76463feb91d09b3d024fae798b92be6"></a>侦察&&信息收集&&子域名发现与枚举&&OSINT


### <a id="05ab1b75266fddafc7195f5b395e4d99"></a>未分类-OSINT


- [**7042**星][28d] [Java] [lionsoul2014/ip2region](https://github.com/lionsoul2014/ip2region) 
- [**6894**星][27d] [greatfire/wiki](https://github.com/greatfire/wiki) 自由浏览
- [**6109**星][9m] [Py] [schollz/howmanypeoplearearound](https://github.com/schollz/howmanypeoplearearound) 检测 Wifi 信号统计你周围的人数
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**2154**星][28d] [C] [texane/stlink](https://github.com/texane/stlink) 
- [**2061**星][16d] [Py] [fortynorthsecurity/eyewitness](https://github.com/FortyNorthSecurity/EyeWitness) 给网站做快照，提供服务器Header信息，识别默认凭证等
- [**1741**星][21d] [Shell] [leebaird/discover](https://github.com/leebaird/discover) 自定义的bash脚本, 用于自动化多个渗透测试任务, 包括: 侦查、扫描、解析、在Metasploit中创建恶意Payload和Listener
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/自动化](#fc8737aef0f59c3952d11749fe582dac) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload生成](#ad92f6b801a18934f1971e2512f5ae4f) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Metasploit/未分类-metasploit](#01be61d5bb9f6f7199208ff0fba86b5d) |
- [**1627**星][28d] [Py] [cea-sec/ivre](https://github.com/cea-sec/ivre) 
- [**1593**星][28d] [Go] [awnumar/memguard](https://github.com/awnumar/memguard) 处理内存中敏感的值，纯Go语言编写。
- [**1591**星][4m] [Py] [mozilla/cipherscan](https://github.com/mozilla/cipherscan) 查找指定目标支持的SSL ciphersuites
- [**1392**星][6m] [Py] [enablesecurity/wafw00f](https://github.com/enablesecurity/wafw00f) 识别保护网站的WAF产品
- [**1309**星][3m] [JS] [lockfale/osint-framework](https://github.com/lockfale/osint-framework) 
- [**1301**星][26d] [CSS] [undeadsec/socialfish](https://github.com/undeadsec/socialfish) 网络钓鱼培训与信息收集
    - 重复区段: [工具/社工(SET)&&钓鱼&&鱼叉攻击/未分类-SET](#ce734598055ad3885d45d0b35d2bf0d7) |
- [**1261**星][1m] [Py] [s0md3v/arjun](https://github.com/s0md3v/Arjun) 
- [**1256**星][2m] [Py] [codingo/reconnoitre](https://github.com/codingo/reconnoitre) 
- [**1253**星][1y] [PowerShell] [dafthack/mailsniper](https://github.com/dafthack/mailsniper) 在Microsoft Exchange环境中搜索邮件中包含的指定内容：密码、insider intel、网络架构信息等
- [**1180**星][15d] [Py] [codingo/nosqlmap](https://github.com/codingo/NoSQLMap) 
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞利用/漏洞利用](#c83f77f27ccf5f26c8b596979d7151c3) |[工具/数据库&&SQL攻击&&SQL注入/NoSQL/未分类-NoSQL](#af0aaaf233cdff3a88d04556dc5871e0) |
- [**1135**星][10m] [C] [blechschmidt/massdns](https://github.com/blechschmidt/massdns) 
- [**1060**星][2m] [PHP] [tuhinshubhra/red_hawk](https://github.com/tuhinshubhra/red_hawk) 信息收集、漏洞扫描、爬虫多合一
    - 重复区段: [工具/扫描器&&安全扫描&&App扫描&&漏洞扫描/未分类-Scanner](#de63a029bda6a7e429af272f291bb769) |
- [**1041**星][1m] [Rust] [fgribreau/mailchecker](https://github.com/fgribreau/mailchecker) 邮件检测库，跨语言。覆盖33078虚假邮件提供者
- [**944**星][4m] [C] [rbsec/sslscan](https://github.com/rbsec/sslscan) 测试启用SSL/TLS的服务，发现其支持的cipher suites
- [**930**星][2m] [Py] [sundowndev/phoneinfoga](https://github.com/sundowndev/phoneinfoga) 
- [**924**星][17d] [OCaml] [airbus-seclab/bincat](https://github.com/airbus-seclab/bincat) 二进制代码静态分析工具。值分析（寄存器、内存）、污点分析、类型重建和传播（propagation）、前向/后向分析
- [**871**星][4m] [derpopo/uabe](https://github.com/derpopo/uabe) 
- [**851**星][7m] [Py] [s0md3v/recondog](https://github.com/s0md3v/ReconDog) 
- [**760**星][12m] [HTML] [sense-of-security/adrecon](https://github.com/sense-of-security/adrecon) 收集Active Directory信息并生成报告
- [**742**星][3m] [Py] [threatexpress/domainhunter](https://github.com/threatexpress/domainhunter) 
    - 重复区段: [工具/社工(SET)&&钓鱼&&鱼叉攻击/未分类-SET](#ce734598055ad3885d45d0b35d2bf0d7) |
- [**698**星][17d] [Ruby] [intrigueio/intrigue-core](https://github.com/intrigueio/intrigue-core) 外部攻击面发现框架，自动化OSINT
- [**694**星][27d] [Py] [khast3x/h8mail](https://github.com/khast3x/h8mail) 
- [**680**星][4m] [Shell] [nahamsec/lazyrecon](https://github.com/nahamsec/lazyrecon) 侦查(reconnaissance)过程自动化脚本, 可自动使用Sublist3r/certspotter获取子域名, 调用nmap/dirsearch等
- [**617**星][5m] [Py] [deibit/cansina](https://github.com/deibit/cansina) cansina：web 内容发现工具。发出各种请求并过滤回复，识别是否存在请求的资源。
- [**579**星][7m] [Py] [ekultek/zeus-scanner](https://github.com/ekultek/zeus-scanner) 
- [**537**星][8m] [Py] [m4ll0k/infoga](https://github.com/m4ll0k/infoga) infoga：邮件信息收集工具
- [**483**星][2m] [no-github/digital-privacy](https://github.com/no-github/digital-privacy) 
- [**463**星][3m] [Py] [xillwillx/skiptracer](https://github.com/xillwillx/skiptracer) 
- [**462**星][14d] [Rust] [kpcyrd/sn0int](https://github.com/kpcyrd/sn0int) 
- [**417**星][2m] [Py] [superhedgy/attacksurfacemapper](https://github.com/superhedgy/attacksurfacemapper) 
- [**404**星][4m] [Shell] [d4rk007/redghost](https://github.com/d4rk007/redghost) 
- [**388**星][3m] [Go] [graniet/operative-framework](https://github.com/graniet/operative-framework) 
- [**387**星][12m] [Py] [chrismaddalena/odin](https://github.com/chrismaddalena/odin) 
- [**378**星][2m] [ph055a/osint-collection](https://github.com/ph055a/osint-collection) 
- [**362**星][1m] [Py] [dedsecinside/torbot](https://github.com/dedsecinside/torbot) 
- [**350**星][11m] [Py] [aancw/belati](https://github.com/aancw/belati) 
- [**350**星][18d] [Py] [depthsecurity/armory](https://github.com/depthsecurity/armory) 
- [**335**星][1m] [Py] [darryllane/bluto](https://github.com/darryllane/bluto) 
- [**329**星][11m] [Py] [mdsecactivebreach/linkedint](https://github.com/mdsecactivebreach/linkedint) A LinkedIn scraper for reconnaissance during adversary simulation
- [**320**星][5m] [Go] [nhoya/gosint](https://github.com/nhoya/gosint) 
- [**304**星][4m] [Py] [initstring/linkedin2username](https://github.com/initstring/linkedin2username) Generate username lists for companies on LinkedIn
- [**302**星][1y] [Py] [sharadkumar97/osint-spy](https://github.com/sharadkumar97/osint-spy) 
- [**299**星][1y] [Py] [twelvesec/gasmask](https://github.com/twelvesec/gasmask) 
- [**296**星][11m] [Py] [r3vn/badkarma](https://github.com/r3vn/badkarma) 
- [**289**星][6m] [Shell] [eschultze/urlextractor](https://github.com/eschultze/urlextractor) 
- [**284**星][2m] [JS] [pownjs/pown-recon](https://github.com/pownjs/pown-recon) 
- [**279**星][1y] [Shell] [ha71/namechk](https://github.com/ha71/namechk) 
- [**268**星][1y] [Go] [tomsteele/blacksheepwall](https://github.com/tomsteele/blacksheepwall) 
- [**264**星][2m] [Py] [ekultek/whatbreach](https://github.com/ekultek/whatbreach) 
- [**242**星][2m] [Shell] [solomonsklash/chomp-scan](https://github.com/solomonsklash/chomp-scan) 
- [**236**星][13d] [Py] [zephrfish/googd0rker](https://github.com/zephrfish/googd0rker) 
- [**229**星][7m] [JS] [cliqz-oss/local-sheriff](https://github.com/cliqz-oss/local-sheriff) 
- [**229**星][1m] [Propeller Spin] [grandideastudio/jtagulator](https://github.com/grandideastudio/jtagulator) Assisted discovery of on-chip debug interfaces
- [**227**星][1m] [Py] [sc1341/instagramosint](https://github.com/sc1341/instagramosint) 
- [**225**星][1m] [Py] [anon-exploiter/sitebroker](https://github.com/anon-exploiter/sitebroker) 
- [**220**星][3m] [Py] [thewhiteh4t/finalrecon](https://github.com/thewhiteh4t/finalrecon) 
- [**220**星][13d] [PowerShell] [tonyphipps/meerkat](https://github.com/tonyphipps/meerkat) 
- [**219**星][3m] [Py] [eth0izzle/the-endorser](https://github.com/eth0izzle/the-endorser) 
- [**218**星][1y] [Shell] [edoverflow/megplus](https://github.com/edoverflow/megplus) 
- [**210**星][4m] [Py] [spiderlabs/hosthunter](https://github.com/spiderlabs/hosthunter) 


### <a id="e945721056c78a53003e01c3d2f3b8fe"></a>子域名枚举&&爆破


- [**4008**星][1m] [Py] [aboul3la/sublist3r](https://github.com/aboul3la/sublist3r) 
- [**3147**星][15d] [Py] [laramies/theharvester](https://github.com/laramies/theharvester) 
- [**2981**星][6m] [Go] [michenriksen/aquatone](https://github.com/michenriksen/aquatone) 子域名枚举工具。除了经典的爆破枚举之外，还利用多种开源工具和在线服务大幅度增加发现子域名的数量。
- [**1750**星][6m] [Py] [lijiejie/subdomainsbrute](https://github.com/lijiejie/subdomainsbrute) 子域名爆破
- [**1686**星][1m] [Go] [subfinder/subfinder](https://github.com/subfinder/subfinder) 使用Passive Sources, Search Engines, Pastebins, Internet Archives等查找子域名
- [**1668**星][7m] [Py] [guelfoweb/knock](https://github.com/guelfoweb/knock) 使用 Wordlist 枚举子域名
    - 重复区段: [工具/wordlist/未分类-wordlist](#af1d71122d601229dc4aa9d08f4e3e15) |
- [**1555**星][14d] [Go] [caffix/amass](https://github.com/caffix/amass) 子域名枚举, 搜索互联网数据源, 使用机器学习猜测子域名. Go语言
- [**1087**星][1m] [Py] [john-kurkowski/tldextract](https://github.com/john-kurkowski/tldextract) 
- [**752**星][12d] [Rust] [edu4rdshl/findomain](https://github.com/edu4rdshl/findomain) 
- [**687**星][4m] [Go] [haccer/subjack](https://github.com/haccer/subjack) 异步多线程扫描子域列表，识别能够被劫持的子域。Go 编写
- [**639**星][1y] [Py] [simplysecurity/simplyemail](https://github.com/SimplySecurity/SimplyEmail) 
- [**573**星][2m] [Py] [jonluca/anubis](https://github.com/jonluca/anubis) 
- [**537**星][8m] [Py] [feeicn/esd](https://github.com/feeicn/esd) 
- [**468**星][1m] [Py] [typeerror/domained](https://github.com/TypeError/domained) 
- [**435**星][1y] [Go] [ice3man543/subover](https://github.com/ice3man543/subover) 
- [**434**星][5m] [Py] [threezh1/jsfinder](https://github.com/threezh1/jsfinder) 
- [**425**星][1m] [Py] [nsonaniya2010/subdomainizer](https://github.com/nsonaniya2010/subdomainizer) 
- [**422**星][10m] [Py] [appsecco/bugcrowd-levelup-subdomain-enumeration](https://github.com/appsecco/bugcrowd-levelup-subdomain-enumeration) 
- [**407**星][2m] [Py] [yanxiu0614/subdomain3](https://github.com/yanxiu0614/subdomain3) subdomain3：简单快速的子域名爆破工具。
- [**327**星][4m] [Py] [chris408/ct-exposer](https://github.com/chris408/ct-exposer) 
- [**302**星][1y] [Py] [christophetd/censys-subdomain-finder](https://github.com/christophetd/censys-subdomain-finder) 利用搜索引擎 Censys 提供的 certificate transparency 日志, 实现子域名枚举. (Censys: 搜索联网设备信息的搜索引擎)
- [**275**星][7m] [Py] [franccesco/getaltname](https://github.com/franccesco/getaltname) 直接从SSL证书中提取子域名或虚拟域名
- [**254**星][10m] [Py] [appsecco/the-art-of-subdomain-enumeration](https://github.com/appsecco/the-art-of-subdomain-enumeration) 
- [**251**星][5m] [Go] [anshumanbh/tko-subs](https://github.com/anshumanbh/tko-subs) 
- [**204**星][1m] [Shell] [screetsec/sudomy](https://github.com/screetsec/sudomy) 


### <a id="375a8baa06f24de1b67398c1ac74ed24"></a>信息收集&&侦查&&Recon&&InfoGather


- [**3496**星][15d] [Shell] [drwetter/testssl.sh](https://github.com/drwetter/testssl.sh) 检查服务器任意端口对 TLS/SSL 的支持、协议以及一些加密缺陷，命令行工具
- [**2378**星][15d] [Py] [smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) 自动收集指定目标的信息：IP、域名、主机名、网络子网、ASN、邮件地址、用户名
- [**2168**星][1y] [Py] [datasploit/datasploit](https://github.com/DataSploit/datasploit) 对指定目标执行多种侦查技术：企业、人、电话号码、比特币地址等
- [**1963**星][8m] [JS] [weichiachang/stacks-cli](https://github.com/weichiachang/stacks-cli) Check website stack from the terminal
- [**1873**星][1m] [Py] [j3ssie/osmedeus](https://github.com/j3ssie/osmedeus) 
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞扫描&&挖掘&&发现/漏洞扫描/未分类](#0ed7e90d216a8a5be1dafebaf9eaeb5d) |
- [**1629**星][1y] [Py] [evyatarmeged/raccoon](https://github.com/evyatarmeged/raccoon) 高性能的侦查和漏洞扫描工具
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞扫描&&挖掘&&发现/漏洞扫描/未分类](#0ed7e90d216a8a5be1dafebaf9eaeb5d) |
- [**1420**星][6m] [Py] [oros42/imsi-catcher](https://github.com/oros42/imsi-catcher) 
- [**1271**星][1y] [Go] [evilsocket/xray](https://github.com/evilsocket/xray) 自动化执行一些信息收集、网络映射的初始化工作
- [**619**星][29d] [Py] [tib3rius/autorecon](https://github.com/tib3rius/autorecon) 
- [**510**星][9m] [Py] [fortynorthsecurity/just-metadata](https://github.com/FortyNorthSecurity/Just-Metadata) 
- [**453**星][19d] [Py] [yassineaboukir/sublert](https://github.com/yassineaboukir/sublert) 
- [**388**星][10m] [Swift] [ibm/mac-ibm-enrollment-app](https://github.com/ibm/mac-ibm-enrollment-app) 
- [**349**星][4m] [C++] [wbenny/pdbex](https://github.com/wbenny/pdbex) 
- [**343**星][27d] [Py] [lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng) 
- [**283**星][2m] [Py] [govanguard/legion](https://github.com/govanguard/legion) 
- [**269**星][10m] [Py] [LaNMaSteR53/recon-ng](https://bitbucket.org/lanmaster53/recon-ng) 


### <a id="016bb6bd00f1e0f8451f779fe09766db"></a>指纹&&Fingerprinting


- [**8843**星][13d] [JS] [valve/fingerprintjs2](https://github.com/valve/fingerprintjs2) 
- [**3029**星][1m] [JS] [valve/fingerprintjs](https://github.com/valve/fingerprintjs) 
- [**1595**星][14d] [JS] [ghacksuserjs/ghacks-user.js](https://github.com/ghacksuserjs/ghacks-user.js) 
- [**1595**星][9m] [C] [nmikhailov/validity90](https://github.com/nmikhailov/validity90) 
- [**918**星][7m] [JS] [song-li/cross_browser](https://github.com/song-li/cross_browser) 
- [**783**星][1m] [Py] [salesforce/ja3](https://github.com/salesforce/ja3) SSL/TLS 客户端指纹，用于恶意代码检测
- [**372**星][21d] [Py] [0x4d31/fatt](https://github.com/0x4d31/fatt) 
- [**309**星][2m] [Py] [dpwe/audfprint](https://github.com/dpwe/audfprint) 
- [**305**星][3m] [Py] [salesforce/hassh](https://github.com/salesforce/hassh) 
- [**268**星][1y] [CSS] [w-digital-scanner/w11scan](https://github.com/w-digital-scanner/w11scan) 
- [**240**星][2m] [C] [leebrotherston/tls-fingerprinting](https://github.com/leebrotherston/tls-fingerprinting) 
- [**224**星][2m] [GLSL] [westpointltd/tls_prober](https://github.com/westpointltd/tls_prober) 
- [**212**星][1y] [Py] [sensepost/spartan](https://github.com/sensepost/spartan) 
- [**200**星][1y] [Erlang] [kudelskisecurity/scannerl](https://github.com/kudelskisecurity/scannerl) scannerl：模块化、分布式指纹识别引擎，在单个主机运行即可扫描数千目标，也可轻松的部署到多台主机


### <a id="6ea9006a5325dd21d246359329a3ede2"></a>收集


- [**3674**星][15d] [jivoi/awesome-osint](https://github.com/jivoi/awesome-osint) OSINT资源收集


### <a id="dc74ad2dd53aa8c8bf3a3097ad1f12b7"></a>社交网络


#### <a id="de93515e77c0ca100bbf92c83f82dc2a"></a>Twitter


- [**2797**星][21d] [Py] [twintproject/twint](https://github.com/twintproject/twint) 


#### <a id="8d1ae776898748b8249132e822f6c919"></a>Github


- [**1627**星][22d] [Go] [eth0izzle/shhgit](https://github.com/eth0izzle/shhgit) 监听Github Event API，实时查找Github代码和Gist中的secret和敏感文件
- [**1549**星][1y] [Py] [unkl4b/gitminer](https://github.com/unkl4b/gitminer) Github内容挖掘
- [**1321**星][7m] [Py] [feeicn/gsil](https://github.com/feeicn/gsil) GitHub敏感信息泄露监控，几乎实时监控，发送警告
- [**840**星][7m] [Go] [misecurity/x-patrol](https://github.com/misecurity/x-patrol) 
- [**834**星][1m] [JS] [vksrc/github-monitor](https://github.com/vksrc/github-monitor) 
- [**767**星][1m] [Py] [bishopfox/gitgot](https://github.com/bishopfox/gitgot) 
- [**750**星][3m] [Py] [techgaun/github-dorks](https://github.com/techgaun/github-dorks) 快速搜索Github repo中的敏感信息
- [**602**星][2m] [Py] [hisxo/gitgraber](https://github.com/hisxo/gitgraber) monitor GitHub to search and find sensitive data in real time for different online services such as: Google, Amazon, Paypal, Github, Mailgun, Facebook, Twitter, Heroku, Stripe...
- [**312**星][15d] [HTML] [tanjiti/sec_profile](https://github.com/tanjiti/sec_profile) 
    - 重复区段: [工具/扫描器&&安全扫描&&App扫描&&漏洞扫描/隐私&&Secret&&Privacy扫描](#58d8b993ffc34f7ded7f4a0077129eb2) |
- [**290**星][7m] [Py] [s0md3v/zen](https://github.com/s0md3v/zen) 查找Github用户的邮箱地址


#### <a id="6d36e9623aadaf40085ef5af89c8d698"></a>其他


- [**7541**星][30d] [Py] [theyahya/sherlock](https://github.com/sherlock-project/sherlock) Find Usernames Across Social Networks
- [**2504**星][2m] [Py] [greenwolf/social_mapper](https://github.com/Greenwolf/social_mapper) 对多个社交网站的用户Profile图片进行大规模的人脸识别
- [**653**星][1y] [Go] [0x09al/raven](https://github.com/0x09al/raven) 




### <a id="a695111d8e30d645354c414cb27b7843"></a>DNS


- [**2421**星][4m] [Go] [oj/gobuster](https://github.com/oj/gobuster) 
- [**2278**星][30d] [Py] [ab77/netflix-proxy](https://github.com/ab77/netflix-proxy) 
- [**2081**星][19d] [Py] [elceef/dnstwist](https://github.com/elceef/dnstwist) 域名置换引擎，用于检测打字错误，网络钓鱼和企业间谍活动
- [**1885**星][27d] [C++] [powerdns/pdns](https://github.com/powerdns/pdns) 
- [**1669**星][3m] [Py] [lgandx/responder](https://github.com/lgandx/responder) 
- [**1117**星][7m] [Py] [darkoperator/dnsrecon](https://github.com/darkoperator/dnsrecon) DNS 枚举脚本
- [**1044**星][2m] [Py] [infosec-au/altdns](https://github.com/infosec-au/altdns) 
- [**1039**星][1m] [Go] [nadoo/glider](https://github.com/nadoo/glider) 正向代理，支持若干协议
- [**969**星][6m] [Py] [m57/dnsteal](https://github.com/m57/dnsteal) 
- [**891**星][18d] [Py] [mschwager/fierce](https://github.com/mschwager/fierce) 
- [**877**星][5m] [Py] [m0rtem/cloudfail](https://github.com/m0rtem/cloudfail) 通过错误配置的DNS和老数据库，发现CloudFlare网络后面的隐藏IP
- [**681**星][1y] [Py] [bugscanteam/dnslog](https://github.com/bugscanteam/dnslog) 监控 DNS 解析记录和 HTTP 访问记录
- [**594**星][7m] [Shell] [cokebar/gfwlist2dnsmasq](https://github.com/cokebar/gfwlist2dnsmasq) 
- [**558**星][6m] [C] [getdnsapi/stubby](https://github.com/getdnsapi/stubby) 
- [**457**星][8m] [C] [cofyc/dnscrypt-wrapper](https://github.com/cofyc/dnscrypt-wrapper) 
- [**359**星][3m] [JS] [nccgroup/singularity](https://github.com/nccgroup/singularity) 
- [**259**星][11m] [Py] [trycatchhcf/packetwhisper](https://github.com/trycatchhcf/packetwhisper) Stealthily exfiltrate data and defeat attribution using DNS queries and text-based steganography. Avoid the problems associated with typical DNS exfiltration methods. Transfer data between systems without the communicating devices directly connecting to each other or to a common endpoint. No need to control a DNS Name Server.
- [**258**星][2m] [Go] [zmap/zdns](https://github.com/zmap/zdns) 快速DNS查找, 命令行工具
- [**249**星][3m] [C#] [kevin-robertson/inveighzero](https://github.com/kevin-robertson/inveighzero) 
- [**243**星][9m] [Go] [erbbysam/dnsgrep](https://github.com/erbbysam/dnsgrep) 
- [**237**星][25d] [Py] [mandatoryprogrammer/trusttrees](https://github.com/mandatoryprogrammer/trusttrees) a script to recursively follow all the possible delegation paths for a target domain and graph the relationships between various nameservers along the way.
- [**230**星][1m] [Go] [sensepost/godoh](https://github.com/sensepost/godoh)  A DNS-over-HTTPS Command & Control Proof of Concept 
- [**213**星][1y] [PowerShell] [lukebaggett/dnscat2-powershell](https://github.com/lukebaggett/dnscat2-powershell) 


### <a id="18c7c1df2e6ae5e9135dfa2e4eb1d4db"></a>Shodan


- [**1082**星][2m] [Py] [achillean/shodan-python](https://github.com/achillean/shodan-python) 
- [**954**星][4m] [Py] [woj-ciech/kamerka](https://github.com/woj-ciech/kamerka) 利用Shodan构建交互式摄像头地图
- [**831**星][2m] [Py] [649/memcrashed-ddos-exploit](https://github.com/649/memcrashed-ddos-exploit) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/DDOS](#a0897294e74a0863ea8b83d11994fad6) |
- [**669**星][2m] [jakejarvis/awesome-shodan-queries](https://github.com/jakejarvis/awesome-shodan-queries) 
- [**353**星][1m] [Py] [pielco11/fav-up](https://github.com/pielco11/fav-up) 
- [**337**星][2m] [Py] [random-robbie/my-shodan-scripts](https://github.com/random-robbie/my-shodan-scripts) 
- [**233**星][10m] [Py] [nethunteros/punter](https://github.com/nethunteros/punter) punter：使用 DNSDumpster, WHOIS, Reverse WHOIS 挖掘域名


### <a id="94c01f488096fafc194b9a07f065594c"></a>nmap


- [**3492**星][16d] [C] [nmap/nmap](https://github.com/nmap/nmap) Nmap
- [**2099**星][6m] [Py] [calebmadrigal/trackerjacker](https://github.com/calebmadrigal/trackerjacker) 映射你没连接到的Wifi网络, 类似于NMap, 另外可以追踪设备
- [**1666**星][3m] [Lua] [vulnerscom/nmap-vulners](https://github.com/vulnerscom/nmap-vulners) 
- [**1497**星][2m] [C] [nmap/npcap](https://github.com/nmap/npcap) 
- [**1237**星][2m] [Lua] [scipag/vulscan](https://github.com/scipag/vulscan) vulscan：Nmap 模块，将 Nmap 转化为高级漏洞扫描器
- [**936**星][4m] [Shell] [trimstray/sandmap](https://github.com/trimstray/sandmap) 使用NMap引擎, 辅助网络和系统侦查(reconnaissance)
- [**887**星][11m] [Py] [rev3rsesecurity/webmap](https://github.com/rev3rsesecurity/webmap) 
- [**822**星][2m] [Py] [x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) brutespray：获取 nmapGNMAP 输出，自动调用 Medusa 使用默认证书爆破服务（brute-forces services）
- [**728**星][4m] [Lua] [cldrn/nmap-nse-scripts](https://github.com/cldrn/nmap-nse-scripts) 
- [**658**星][4m] [Py] [iceyhexman/onlinetools](https://github.com/iceyhexman/onlinetools) 
- [**481**星][1y] [XSLT] [honze-net/nmap-bootstrap-xsl](https://github.com/honze-net/nmap-bootstrap-xsl) 
- [**391**星][7m] [Py] [savon-noir/python-libnmap](https://github.com/savon-noir/python-libnmap) 
- [**325**星][9m] [Py] [samhaxr/hackbox](https://github.com/samhaxr/hackbox) 集合了某些Hacking工具和技巧的攻击工具
- [**307**星][1y] [Java] [s4n7h0/halcyon](https://github.com/s4n7h0/halcyon) 
- [**282**星][1y] [Ruby] [danmcinerney/pentest-machine](https://github.com/danmcinerney/pentest-machine) 
- [**257**星][1y] [Java] [danicuestasuarez/nmapgui](https://github.com/danicuestasuarez/nmapgui) 
- [**247**星][1y] [Shell] [m4ll0k/autonse](https://github.com/m4ll0k/autonse) 
- [**230**星][7m] [Lua] [rvn0xsy/nse_vuln](https://github.com/rvn0xsy/nse_vuln) 
- [**228**星][5m] [Py] [maaaaz/nmaptocsv](https://github.com/maaaaz/nmaptocsv) 




***


## <a id="969212c047f97652ceb9c789e4d8dae5"></a>数据库&&SQL攻击&&SQL注入


### <a id="e8d5cfc417b84fa90eff2e02c3231ed1"></a>未分类-Database


- [**950**星][18d] [PowerShell] [netspi/powerupsql](https://github.com/netspi/powerupsql) 攻击SQL服务器的PowerShell工具箱
- [**661**星][3m] [Py] [v3n0m-scanner/v3n0m-scanner](https://github.com/v3n0m-scanner/v3n0m-scanner) 
- [**638**星][2m] [Py] [quentinhardy/odat](https://github.com/quentinhardy/odat) Oracle Database Attacking Tool
- [**526**星][4m] [Py] [quentinhardy/msdat](https://github.com/quentinhardy/msdat) Microsoft SQL Database Attacking Tool


### <a id="3157bf5ee97c32454d99fd4a9fa3f04a"></a>SQL


#### <a id="1cfe1b2a2c88cd92a414f81605c8d8e7"></a>未分类-SQL


- [**2883**星][1m] [Go] [cookiey/yearning](https://github.com/cookiey/yearning) 
- [**712**星][1y] [Py] [the-robot/sqliv](https://github.com/the-robot/sqliv) 
- [**553**星][1m] [HTML] [netspi/sqlinjectionwiki](https://github.com/netspi/sqlinjectionwiki) 
- [**444**星][9m] [Go] [netxfly/x-crack](https://github.com/netxfly/x-crack) Weak password scanner, Support: FTP/SSH/SNMP/MSSQL/MYSQL/PostGreSQL/REDIS/ElasticSearch/MONGODB
- [**439**星][3m] [Go] [stripe/safesql](https://github.com/stripe/safesql) 
- [**395**星][3m] [C#] [shack2/supersqlinjectionv1](https://github.com/shack2/supersqlinjectionv1) 
- [**295**星][8m] [JS] [ning1022/sqlinjectionwiki](https://github.com/ning1022/SQLInjectionWiki) 
- [**255**星][7m] [Py] [s0md3v/sqlmate](https://github.com/s0md3v/sqlmate) 


#### <a id="0519846509746aa50a04abd3ccf2f1d5"></a>SQL注入


- [**15554**星][16d] [Py] [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) 
- [**592**星][6m] [aleenzz/mysql_sql_bypass_wiki](https://github.com/aleenzz/mysql_sql_bypass_wiki) 


#### <a id="5a7451cdff13bc6709da7c943dda967f"></a>SQL漏洞






### <a id="ca6f4bd198f3712db7f24383e8544dfd"></a>NoSQL


#### <a id="af0aaaf233cdff3a88d04556dc5871e0"></a>未分类-NoSQL


- [**1180**星][15d] [Py] [codingo/nosqlmap](https://github.com/codingo/NoSQLMap) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |[工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞利用/漏洞利用](#c83f77f27ccf5f26c8b596979d7151c3) |
- [**275**星][1y] [Java] [florent37/android-nosql](https://github.com/florent37/android-nosql) 


#### <a id="54d36c89712652a7064db6179faa7e8c"></a>MongoDB


- [**1069**星][2m] [Py] [stampery/mongoaudit](https://github.com/stampery/mongoaudit) 






***


## <a id="df8a5514775570707cce56bb36ca32c8"></a>审计&&安全审计&&代码审计


### <a id="6a5e7dd060e57d9fdb3fed8635d61bc7"></a>未分类-Audit


- [**6407**星][1m] [Shell] [cisofy/lynis](https://github.com/cisofy/lynis) Security auditing tool for Linux, macOS, and UNIX-based systems. Assists with compliance testing (HIPAA/ISO27001/PCI DSS) and system hardening. Agentless, and installation optional.
- [**1465**星][27d] [Shell] [mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester) 
- [**967**星][2m] [Py] [nccgroup/scoutsuite](https://github.com/nccgroup/scoutsuite) 
- [**604**星][6m] [JS] [vincentcox/stacoan](https://github.com/vincentcox/stacoan) 
    - 重复区段: [工具/移动&&Mobile/未分类-Mobile](#4a64f5e8fdbd531a8c95d94b28c6c2c1) |
- [**271**星][17d] [Py] [lorexxar/cobra-w](https://github.com/lorexxar/cobra-w) 


### <a id="34569a6fdce10845eae5fbb029cd8dfa"></a>代码审计


- [**2041**星][3m] [Py] [whaleshark-team/cobra](https://github.com/WhaleShark-Team/cobra) 
- [**807**星][1y] [Py] [utkusen/leviathan](https://github.com/utkusen/leviathan) 
- [**646**星][1y] [chybeta/code-audit-challenges](https://github.com/chybeta/code-audit-challenges) 
- [**626**星][8m] [Py] [klen/pylama](https://github.com/klen/pylama) 
- [**399**星][4m] [C] [anssi-fr/ad-control-paths](https://github.com/anssi-fr/ad-control-paths) 
- [**355**星][11m] [Py] [enablesecurity/sipvicious](https://github.com/enablesecurity/sipvicious) 
- [**293**星][2m] [C#] [ossindex/devaudit](https://github.com/ossindex/devaudit) 
- [**263**星][14d] [Py] [exodus-privacy/exodus](https://github.com/exodus-privacy/exodus) 
- [**254**星][1m] [Py] [hubblestack/hubble](https://github.com/hubblestack/hubble) 
- [**240**星][4m] [PowerShell] [nccgroup/azucar](https://github.com/nccgroup/azucar) Azure环境安全审计工具
- [**215**星][1y] [C] [meliot/filewatcher](https://github.com/meliot/filewatcher) 




***


## <a id="546f4fe70faa2236c0fbc2d486a83391"></a>社工(SET)&&钓鱼&&鱼叉攻击


### <a id="ce734598055ad3885d45d0b35d2bf0d7"></a>未分类-SET


- [**1301**星][26d] [CSS] [undeadsec/socialfish](https://github.com/undeadsec/socialfish) 网络钓鱼培训与信息收集
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |
- [**742**星][3m] [Py] [threatexpress/domainhunter](https://github.com/threatexpress/domainhunter) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |
- [**556**星][2m] [Py] [thewhiteh4t/seeker](https://github.com/thewhiteh4t/seeker) 
- [**305**星][1m] [Py] [raikia/uhoh365](https://github.com/raikia/uhoh365) 


### <a id="f30507893511f89b19934e082a54023e"></a>社工


- [**4854**星][2m] [Py] [trustedsec/social-engineer-toolkit](https://github.com/trustedsec/social-engineer-toolkit) 


### <a id="290e9ae48108d21d6d8b9ea9e74d077d"></a>钓鱼&&Phish


- [**8337**星][17d] [Py] [wifiphisher/wifiphisher](https://github.com/wifiphisher/wifiphisher) 流氓AP框架, 用于RedTeam和Wi-Fi安全测试
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**4161**星][12d] [Go] [gophish/gophish](https://github.com/gophish/gophish) 网络钓鱼工具包
- [**2721**星][1m] [Go] [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2) 独立的MITM攻击工具，用于登录凭证钓鱼，可绕过双因素认证
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**1402**星][8m] [JS] [anttiviljami/browser-autofill-phishing](https://github.com/anttiviljami/browser-autofill-phishing) 
- [**1331**星][10m] [HTML] [thelinuxchoice/blackeye](https://github.com/thelinuxchoice/blackeye) 
- [**994**星][17d] [Py] [securestate/king-phisher](https://github.com/securestate/king-phisher) 
- [**976**星][1m] [Py] [x0rz/phishing_catcher](https://github.com/x0rz/phishing_catcher) phishing_catcher：使用Certstream 捕获钓鱼域名
- [**861**星][19d] [HTML] [darksecdevelopers/hiddeneye](https://github.com/darksecdevelopers/hiddeneye) 
- [**858**星][7m] [HTML] [thelinuxchoice/shellphish](https://github.com/thelinuxchoice/shellphish) 针对18个社交媒体的钓鱼工具：Instagram, Facebook, Snapchat, Github, Twitter, Yahoo, Protonmail, Spotify, Netflix, Linkedin, Wordpress, Origin, Steam, Microsoft, InstaFollowers, Gitlab, Pinterest
- [**831**星][4m] [PHP] [raikia/fiercephish](https://github.com/Raikia/FiercePhish) 
- [**828**星][1y] [HTML] [ustayready/credsniper](https://github.com/ustayready/credsniper) 
- [**524**星][26d] [Py] [shellphish/driller](https://github.com/shellphish/driller) augmenting AFL with symbolic execution!
- [**348**星][4m] [Py] [tatanus/spf](https://github.com/tatanus/spf) 
- [**297**星][10m] [Py] [mr-un1k0d3r/catmyphish](https://github.com/Mr-Un1k0d3r/CatMyPhish) 
- [**265**星][3m] [Go] [muraenateam/muraena](https://github.com/muraenateam/muraena) 
- [**240**星][2m] [Py] [atexio/mercure](https://github.com/atexio/mercure) 对员工进行网络钓鱼的培训
- [**228**星][1y] [Jupyter Notebook] [wesleyraptor/streamingphish](https://github.com/wesleyraptor/streamingphish) 使用受监督的机器学习, 从证书透明度(Certificate Transparency)日志中检测钓鱼域名
- [**220**星][3m] [Py] [duo-labs/isthislegit](https://github.com/duo-labs/isthislegit) isthislegit：收集、分析和回复网络钓鱼邮件的框架


### <a id="ab3e6e6526d058e35c7091d8801ebf3a"></a>鱼叉攻击






***


## <a id="04102345243a4bcaec83f703afff6cb3"></a>硬件设备&&USB&树莓派


### <a id="ff462a6d508ef20aa41052b1cc8ad044"></a>未分类-Hardware


- [**2190**星][18d] [Shell] [eliaskotlyar/xiaomi-dafang-hacks](https://github.com/eliaskotlyar/xiaomi-dafang-hacks) 
- [**2009**星][1y] [C] [xoreaxeaxeax/rosenbridge](https://github.com/xoreaxeaxeax/rosenbridge) 
- [**1932**星][13d] [Go] [ullaakut/cameradar](https://github.com/Ullaakut/cameradar) 
- [**1327**星][1y] [Py] [carmaa/inception](https://github.com/carmaa/inception) 利用基于PCI的DMA实现物理内存的操纵与Hacking，可以攻击FireWire，Thunderbolt，ExpressCard，PC Card和任何其他PCI / PCIe硬件接口
- [**1117**星][10m] [JS] [mame82/p4wnp1_aloa](https://github.com/mame82/p4wnp1_aloa) 将 Rapsberry Pi Zero W 转变成灵活的渗透平台
    - 重复区段: [工具/环境配置&&分析系统/未分类-Env](#f5a7a43f964b2c50825f3e2fee5078c8) |
- [**962**星][2m] [C] [olimex/olinuxino](https://github.com/olimex/olinuxino) 
- [**516**星][3m] [Java] [1998lixin/hardwarecode](https://github.com/1998lixin/hardwarecode) 


### <a id="48c53d1304b1335d9addf45b959b7d8a"></a>USB


- [**3811**星][17d] [drduh/yubikey-guide](https://github.com/drduh/yubikey-guide) 
- [**2643**星][12m] [Py] [mame82/p4wnp1](https://github.com/mame82/p4wnp1) 基于Raspberry Pi Zero 或 Raspberry Pi Zero W 的USB攻击平台, 高度的可定制性
    - 重复区段: [工具/硬件设备&&USB&树莓派/树莓派&&RaspberryPi](#77c39a0ad266ad42ab8157ba4b3d874a) |
- [**2149**星][9m] [C] [conorpp/u2f-zero](https://github.com/conorpp/u2f-zero) 
- [**1018**星][28d] [C] [solokeys/solo](https://github.com/solokeys/solo) open security key supporting FIDO2 & U2F over USB + NFC
- [**982**星][11m] [C#] [kenvix/usbcopyer](https://github.com/kenvix/usbcopyer) 插上U盘自动按需复制文件 
- [**865**星][2m] [C++] [whid-injector/whid](https://github.com/whid-injector/whid) 
- [**832**星][6m] [Objective-C] [sevenbits/mac-linux-usb-loader](https://github.com/sevenbits/mac-linux-usb-loader) 
- [**825**星][1m] [C++] [openzwave/open-zwave](https://github.com/openzwave/open-zwave) 
- [**744**星][19d] [Py] [snovvcrash/usbrip](https://github.com/snovvcrash/usbrip) 
    - 重复区段: [工具/事件响应&&取证&&内存取证&&数字取证/取证&&Forensics&&数字取证&&内存取证](#1fc5d3621bb13d878f337c8031396484) |
- [**695**星][2m] [C] [nuand/bladerf](https://github.com/nuand/bladerf) 
- [**596**星][5m] [C] [pelya/android-keyboard-gadget](https://github.com/pelya/android-keyboard-gadget) 
- [**410**星][8m] [Shell] [jsamr/bootiso](https://github.com/jsamr/bootiso) 
- [**307**星][3m] [Py] [circl/circlean](https://github.com/circl/circlean) 
- [**305**星][3m] [C++] [cedarctic/digispark-scripts](https://github.com/cedarctic/digispark-scripts) 
- [**221**星][5m] [ANTLR] [myriadrf/limesdr-usb](https://github.com/myriadrf/limesdr-usb) 


### <a id="77c39a0ad266ad42ab8157ba4b3d874a"></a>树莓派&&RaspberryPi


- [**2643**星][12m] [Py] [mame82/p4wnp1](https://github.com/mame82/p4wnp1) 基于Raspberry Pi Zero 或 Raspberry Pi Zero W 的USB攻击平台, 高度的可定制性
    - 重复区段: [工具/硬件设备&&USB&树莓派/USB](#48c53d1304b1335d9addf45b959b7d8a) |
- [**1658**星][7m] [Makefile] [raspberrypi/noobs](https://github.com/raspberrypi/noobs) 
- [**1510**星][1m] [C] [raspberrypi/userland](https://github.com/raspberrypi/userland) 
- [**296**星][6m] [C++] [cyphunk/jtagenum](https://github.com/cyphunk/jtagenum) 
- [**258**星][5m] [Py] [mbro95/portablecellnetwork](https://github.com/mbro95/portablecellnetwork) 
- [**246**星][4m] [Py] [tipam/pi3d](https://github.com/tipam/pi3d) 


### <a id="da75af123f2f0f85a4c8ecc08a8aa848"></a>车&&汽车&&Vehicle


- [**1305**星][1m] [jaredthecoder/awesome-vehicle-security](https://github.com/jaredthecoder/awesome-vehicle-security) 
- [**768**星][1y] [C++] [polysync/oscc](https://github.com/polysync/oscc) 
- [**513**星][7m] [Py] [schutzwerk/canalyzat0r](https://github.com/schutzwerk/canalyzat0r) 
- [**261**星][1y] [Shell] [jgamblin/carhackingtools](https://github.com/jgamblin/carhackingtools) 
- [**216**星][2m] [Py] [caringcaribou/caringcaribou](https://github.com/caringcaribou/caringcaribou) 




***


## <a id="dc89c90b80529c1f62f413288bca89c4"></a>环境配置&&分析系统


### <a id="f5a7a43f964b2c50825f3e2fee5078c8"></a>未分类-Env


- [**1571**星][13d] [HTML] [clong/detectionlab](https://github.com/clong/detectionlab) 
- [**1371**星][16d] [Go] [crazy-max/windowsspyblocker](https://github.com/crazy-max/windowsspyblocker) 
- [**1294**星][2m] [C] [cisco-talos/pyrebox](https://github.com/cisco-talos/pyrebox) 逆向沙箱，基于QEMU，Python Scriptable
- [**1117**星][10m] [JS] [mame82/p4wnp1_aloa](https://github.com/mame82/p4wnp1_aloa) 将 Rapsberry Pi Zero W 转变成灵活的渗透平台
    - 重复区段: [工具/硬件设备&&USB&树莓派/未分类-Hardware](#ff462a6d508ef20aa41052b1cc8ad044) |
- [**799**星][3m] [redhuntlabs/redhunt-os](https://github.com/redhuntlabs/redhunt-os) 
- [**781**星][2m] [sh4hin/androl4b](https://github.com/sh4hin/androl4b) 用于评估Android应用程序，逆向工程和恶意软件分析的虚拟机
    - 重复区段: [工具/移动&&Mobile/Android](#fe88ee8c0df10870b44c2dedcd86d3d3) |
- [**560**星][5m] [Ruby] [sliim/pentest-env](https://github.com/sliim/pentest-env) 
- [**210**星][11m] [Shell] [proxycannon/proxycannon-ng](https://github.com/proxycannon/proxycannon-ng) 使用多个云环境构建私人僵尸网络, 用于渗透测试和RedTeaming


### <a id="cf07b04dd2db1deedcf9ea18c05c83e0"></a>Linux-Distro


- [**2830**星][1m] [Py] [trustedsec/ptf](https://github.com/trustedsec/ptf) 创建基于Debian/Ubuntu/ArchLinux的渗透测试环境
- [**2310**星][1m] [security-onion-solutions/security-onion](https://github.com/security-onion-solutions/security-onion) 
- [**1459**星][13d] [Shell] [blackarch/blackarch](https://github.com/blackarch/blackarch) 
- [**342**星][13d] [Shell] [archstrike/archstrike](https://github.com/archstrike/archstrike) 


### <a id="4709b10a8bb691204c0564a3067a0004"></a>环境自动配置&&自动安装


- [**3058**星][2m] [PowerShell] [fireeye/commando-vm](https://github.com/fireeye/commando-vm) 
- [**1686**星][18d] [PowerShell] [fireeye/flare-vm](https://github.com/fireeye/flare-vm) 火眼发布用于 Windows 恶意代码分析的虚拟机：FLARE VM




***


## <a id="761a373e2ec1c58c9cd205cd7a03e8a8"></a>靶机&&漏洞环境&&漏洞App


### <a id="3e751670de79d2649ba62b177bd3e4ef"></a>未分类-VulnerableMachine


- [**4986**星][1m] [Shell] [vulhub/vulhub](https://github.com/vulhub/vulhub) 
- [**3680**星][2m] [PHP] [ethicalhack3r/dvwa](https://github.com/ethicalhack3r/DVWA) 
- [**2536**星][25d] [Shell] [medicean/vulapps](https://github.com/medicean/vulapps) 
- [**2382**星][27d] [TSQL] [rapid7/metasploitable3](https://github.com/rapid7/metasploitable3) 
- [**1522**星][1m] [PHP] [c0ny1/upload-labs](https://github.com/c0ny1/upload-labs) 一个帮你总结所有类型的上传漏洞的靶场
- [**981**星][1m] [C] [hacksysteam/hacksysextremevulnerabledriver](https://github.com/hacksysteam/hacksysextremevulnerabledriver) 
- [**831**星][27d] [JS] [lirantal/is-website-vulnerable](https://github.com/lirantal/is-website-vulnerable) 
- [**741**星][1m] [Ruby] [rubysec/ruby-advisory-db](https://github.com/rubysec/ruby-advisory-db) 
- [**633**星][2m] [HCL] [rhinosecuritylabs/cloudgoat](https://github.com/rhinosecuritylabs/cloudgoat) 
- [**577**星][2m] [HTML] [owasp/railsgoat](https://github.com/owasp/railsgoat) 
- [**563**星][1m] [C++] [bkerler/exploit_me](https://github.com/bkerler/exploit_me) 带洞的 ARMApp, 可用于漏洞开发练习
- [**517**星][5m] [PHP] [acmesec/dorabox](https://github.com/Acmesec/DoraBox) 
- [**311**星][28d] [Py] [owasp/owasp-vwad](https://github.com/owasp/owasp-vwad) 
- [**252**星][2m] [PHP] [incredibleindishell/ssrf_vulnerable_lab](https://github.com/incredibleindishell/ssrf_vulnerable_lab) 
- [**237**星][2m] [JS] [owasp/dvsa](https://github.com/owasp/dvsa) 
- [**218**星][11m] [C] [stephenbradshaw/vulnserver](https://github.com/stephenbradshaw/vulnserver) 


### <a id="a6a2bb02c730fc1e1f88129d4c2b3d2e"></a>WebApp


- [**2902**星][13d] [JS] [webgoat/webgoat](https://github.com/webgoat/webgoat) 带漏洞WebApp
- [**2556**星][15d] [JS] [bkimminich/juice-shop](https://github.com/bkimminich/juice-shop) 
- [**459**星][14d] [Py] [stamparm/dsvw](https://github.com/stamparm/dsvw) 
- [**427**星][3m] [Py] [payatu/tiredful-api](https://github.com/payatu/tiredful-api) 
- [**289**星][1y] [CSS] [appsecco/dvna](https://github.com/appsecco/dvna) 
- [**218**星][5m] [JS] [cr0hn/vulnerable-node](https://github.com/cr0hn/vulnerable-node) 


### <a id="60b4d03a0cff6efc4b9b998a4a1a79d6"></a>靶机生成


- [**1699**星][13d] [Ruby] [cliffe/secgen](https://github.com/cliffe/secgen) 
- [**1408**星][5m] [PHP] [s4n7h0/xvwa](https://github.com/s4n7h0/xvwa) 
- [**305**星][7m] [Ruby] [secgen/secgen](https://github.com/secgen/secgen) 


### <a id="383ad9174d3f7399660d36cd6e0b2c00"></a>收集


- [**358**星][4m] [xtiankisutsa/awesome-mobile-ctf](https://github.com/xtiankisutsa/awesome-mobile-ctf) 
    - 重复区段: [工具/CTF&&HTB/收集](#30c4df38bcd1abaaaac13ffda7d206c6) |


### <a id="aa60e957e4da03301643a7abe4c1938a"></a>MobileApp


- [**645**星][4m] [Java] [dineshshetty/android-insecurebankv2](https://github.com/dineshshetty/android-insecurebankv2) 
- [**203**星][2m] [Java] [owasp/mstg-hacking-playground](https://github.com/OWASP/MSTG-Hacking-Playground) 不安全的iOS/Android App集合




***


## <a id="79499aeece9a2a9f64af6f61ee18cbea"></a>浏览嗅探&&流量拦截&&流量分析&&中间人


### <a id="99398a5a8aaf99228829dadff48fb6a7"></a>未分类-Network


- [**11823**星][24d] [Go] [buger/goreplay](https://github.com/buger/goreplay) 实时捕获HTTP流量并输入测试环境，以便持续使用真实数据测试你的系统
- [**6391**星][1m] [Py] [networkx/networkx](https://github.com/networkx/networkx) 用于创建、操纵和研究复杂网络的结构，Python包
- [**5204**星][6m] [Py] [usarmyresearchlab/dshell](https://github.com/usarmyresearchlab/dshell) 网络审计分析
- [**4526**星][15d] [Py] [secdev/scapy](https://github.com/secdev/scapy) 交互式数据包操作, Python, 命令行+库
- [**4144**星][11m] [JS] [kdzwinel/betwixt](https://github.com/kdzwinel/betwixt) Betwixt will help you analyze web traffic outside the browser using familiar Chrome DevTools interface.
- [**3729**星][20d] [Py] [secureauthcorp/impacket](https://github.com/SecureAuthCorp/impacket) Python类收集, 用于与网络协议交互
- [**3482**星][15d] [JS] [aol/moloch](https://github.com/aol/moloch) 数据包捕获、索引工具，支持数据库
- [**3480**星][7m] [Go] [fanpei91/torsniff](https://github.com/fanpei91/torsniff) 
- [**3191**星][14d] [Py] [stamparm/maltrail](https://github.com/stamparm/maltrail) 恶意网络流量检测系统
- [**3096**星][25d] [C] [valdikss/goodbyedpi](https://github.com/valdikss/goodbyedpi) 
- [**2503**星][7m] [C++] [chengr28/pcap_dnsproxy](https://github.com/chengr28/pcap_dnsproxy) 
- [**1877**星][28d] [C] [ntop/ndpi](https://github.com/ntop/ndpi) 
- [**1799**星][1m] [C] [merbanan/rtl_433](https://github.com/merbanan/rtl_433) 
- [**1419**星][2m] [Go] [google/stenographer](https://github.com/google/stenographer) 
- [**1328**星][2m] [C++] [mfontanini/libtins](https://github.com/mfontanini/libtins) 
- [**1271**星][2m] [C] [traviscross/mtr](https://github.com/traviscross/mtr) 
- [**1258**星][1m] [Go] [dreadl0ck/netcap](https://github.com/dreadl0ck/netcap) 
- [**1207**星][1y] [Py] [danmcinerney/net-creds](https://github.com/danmcinerney/net-creds) 
- [**1056**星][6m] [PowerShell] [nytrorst/netripper](https://github.com/nytrorst/netripper) 后渗透工具,针对Windows, 使用API Hooking拦截网络流量和加密相关函数, 可捕获明文和加密前后的内容
- [**1046**星][10m] [C++] [simsong/tcpflow](https://github.com/simsong/tcpflow) 
- [**952**星][2m] [Py] [kiminewt/pyshark](https://github.com/kiminewt/pyshark) 
- [**945**星][7m] [Py] [fireeye/flare-fakenet-ng](https://github.com/fireeye/flare-fakenet-ng) 下一代动态网络分析工具
- [**853**星][3m] [C] [cisco/joy](https://github.com/cisco/joy) 捕获和分析网络流数据和intraflow数据，用于网络研究、取证和安全监视
- [**820**星][6m] [Go] [40t/go-sniffer](https://github.com/40t/go-sniffer) 
- [**817**星][29d] [C] [zerbea/hcxtools](https://github.com/zerbea/hcxtools) 
- [**800**星][2m] [C] [emmericp/ixy](https://github.com/emmericp/ixy) 
- [**790**星][7m] [Py] [phaethon/kamene](https://github.com/phaethon/kamene) 
- [**779**星][2m] [C] [netsniff-ng/netsniff-ng](https://github.com/netsniff-ng/netsniff-ng) 
- [**713**星][2m] [Py] [cloudflare/bpftools](https://github.com/cloudflare/bpftools) 
- [**652**星][1m] [Py] [kbandla/dpkt](https://github.com/kbandla/dpkt) 
- [**645**星][1m] [C] [zerbea/hcxdumptool](https://github.com/zerbea/hcxdumptool) 
- [**636**星][1y] [Go] [ga0/netgraph](https://github.com/ga0/netgraph) 
- [**509**星][9m] [Perl] [mrash/fwknop](https://github.com/mrash/fwknop) 
- [**505**星][7m] [C++] [kohler/click](https://github.com/kohler/click) 
- [**499**星][1m] [C] [sam-github/libnet](https://github.com/libnet/libnet) 
- [**458**星][1m] [Py] [netzob/netzob](https://github.com/netzob/netzob)  Protocol Reverse Engineering, Modeling and Fuzzing
- [**451**星][4m] [C] [jarun/keysniffer](https://github.com/jarun/keysniffer) 
- [**440**星][20d] [C#] [malwareinfosec/ekfiddle](https://github.com/malwareinfosec/ekfiddle) 
- [**435**星][2m] [C++] [pstavirs/ostinato](https://github.com/pstavirs/ostinato) Packet/Traffic Generator and Analyzer
- [**431**星][2m] [Ruby] [aderyabin/sniffer](https://github.com/aderyabin/sniffer) 
- [**412**星][10m] [C] [jpr5/ngrep](https://github.com/jpr5/ngrep) 
- [**411**星][2m] [C] [desowin/usbpcap](https://github.com/desowin/usbpcap) 
- [**407**星][8m] [Py] [mitrecnd/chopshop](https://github.com/mitrecnd/chopshop) 
- [**387**星][1m] [Rust] [kpcyrd/sniffglue](https://github.com/kpcyrd/sniffglue) 
- [**382**星][2m] [Go] [alphasoc/flightsim](https://github.com/alphasoc/flightsim) 
- [**379**星][4m] [PHP] [floedesigntechnologies/phpcs-security-audit](https://github.com/floedesigntechnologies/phpcs-security-audit) 
- [**375**星][28d] [Py] [idaholab/malcolm](https://github.com/idaholab/malcolm) 
- [**330**星][12m] [Ruby] [packetfu/packetfu](https://github.com/packetfu/packetfu) 数据包篡改工具。Ruby语言编写。
- [**326**星][14d] [TypeScript] [shroudedcode/apk-mitm](https://github.com/shroudedcode/apk-mitm) 
    - 重复区段: [工具/移动&&Mobile/Android](#fe88ee8c0df10870b44c2dedcd86d3d3) |[工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**303**星][1y] [Py] [tintinweb/scapy-ssl_tls](https://github.com/tintinweb/scapy-ssl_tls) 
- [**292**星][4m] [C] [pulkin/esp8266-injection-example](https://github.com/pulkin/esp8266-injection-example) 
- [**278**星][23d] [C] [troglobit/nemesis](https://github.com/troglobit/nemesis) 网络数据包构造和注入的命令行工具
- [**273**星][9m] [C] [jiaoxianjun/btle](https://github.com/jiaoxianjun/btle) 
- [**254**星][2m] [Go] [sachaos/tcpterm](https://github.com/sachaos/tcpterm) 
- [**243**星][7m] [Py] [needmorecowbell/sniff-paste](https://github.com/needmorecowbell/sniff-paste) 
- [**241**星][2m] [C] [nccgroup/sniffle](https://github.com/nccgroup/sniffle) 
- [**218**星][18d] [Py] [ghostop14/sparrow-wifi](https://github.com/ghostop14/sparrow-wifi) 
    - 重复区段: [工具/蓝牙&&Bluetooth](#ceb90405292daed9bb32ac20836c219a) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**213**星][2m] [C] [dns-oarc/dnscap](https://github.com/dns-oarc/dnscap) 


### <a id="11c73d3e2f71f3914a3bca35ba90de36"></a>中间人&&MITM


- [**16743**星][18d] [Py] [mitmproxy/mitmproxy](https://github.com/mitmproxy/mitmproxy) 
    - 重复区段: [工具/通信&&代理&&反向代理&&隧道/未分类-Proxy](#56acb7c49c828d4715dce57410d490d1) |
- [**6294**星][12d] [Go] [bettercap/bettercap](https://github.com/bettercap/bettercap) 新版的bettercap, Go 编写. bettercap 是强大的、模块化、可移植且易于扩展的 MITM 框架, 旧版用 Ruby 编写
- [**2886**星][1y] [Py] [byt3bl33d3r/mitmf](https://github.com/byt3bl33d3r/mitmf) 
- [**2721**星][1m] [Go] [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2) 独立的MITM攻击工具，用于登录凭证钓鱼，可绕过双因素认证
    - 重复区段: [工具/社工(SET)&&钓鱼&&鱼叉攻击/钓鱼&&Phish](#290e9ae48108d21d6d8b9ea9e74d077d) |
- [**2480**星][15d] [Py] [evilsocket/pwnagotchi](https://github.com/evilsocket/pwnagotchi) 
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**1258**星][2m] [Go] [unrolled/secure](https://github.com/unrolled/secure) 
- [**1199**星][3m] [C] [droe/sslsplit](https://github.com/droe/sslsplit) 透明SSL/TLS拦截
- [**1184**星][2m] [Py] [jtesta/ssh-mitm](https://github.com/jtesta/ssh-mitm) ssh-mitm：SSH 中间人攻击工具
- [**1085**星][7m] [Ruby] [lionsec/xerosploit](https://github.com/lionsec/xerosploit) 
- [**1017**星][3m] [PowerShell] [kevin-robertson/inveigh](https://github.com/kevin-robertson/inveigh) 
- [**999**星][7m] [Go] [justinas/nosurf](https://github.com/justinas/nosurf) 
- [**983**星][1y] [HTML] [sensepost/mana](https://github.com/sensepost/mana) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**977**星][30d] [Py] [syss-research/seth](https://github.com/syss-research/seth) 
- [**568**星][11m] [HTML] [r00t-3xp10it/morpheus](https://github.com/r00t-3xp10it/morpheus) 
- [**551**星][8m] [Py] [fox-it/mitm6](https://github.com/fox-it/mitm6) mitm6: 攻击代码
- [**509**星][5m] [JS] [moll/node-mitm](https://github.com/moll/node-mitm) 
- [**432**星][1y] [JS] [digitalsecurity/btlejuice](https://github.com/digitalsecurity/btlejuice) 
- [**393**星][3m] [Go] [cloudflare/mitmengine](https://github.com/cloudflare/mitmengine) 
- [**382**星][3m] [JS] [joeferner/node-http-mitm-proxy](https://github.com/joeferner/node-http-mitm-proxy) 
- [**379**星][1y] [JS] [securing/gattacker](https://github.com/securing/gattacker) 
- [**365**星][10m] [Py] [crypt0s/fakedns](https://github.com/crypt0s/fakedns) 
- [**347**星][17d] [Py] [gosecure/pyrdp](https://github.com/gosecure/pyrdp) 
- [**347**星][1y] [Py] [quickbreach/smbetray](https://github.com/quickbreach/smbetray) 
- [**326**星][14d] [TypeScript] [shroudedcode/apk-mitm](https://github.com/shroudedcode/apk-mitm) 
    - 重复区段: [工具/移动&&Mobile/Android](#fe88ee8c0df10870b44c2dedcd86d3d3) |[工具/浏览嗅探&&流量拦截&&流量分析&&中间人/未分类-Network](#99398a5a8aaf99228829dadff48fb6a7) |
- [**294**星][1y] [Shell] [cryptolok/ghostinthenet](https://github.com/cryptolok/ghostinthenet) 
    - 重复区段: [工具/扫描器&&安全扫描&&App扫描&&漏洞扫描/未分类-Scanner](#de63a029bda6a7e429af272f291bb769) |
- [**225**星][8m] [Py] [ivanvza/arpy](https://github.com/ivanvza/arpy) 
- [**205**星][3m] [sab0tag3d/mitm-cheatsheet](https://github.com/sab0tag3d/mitm-cheatsheet) 


### <a id="c09843b4d4190dea0bf9773f8114300a"></a>流量嗅探&&监控


- [**3480**星][7m] [Go] [fanpei91/torsniff](https://github.com/fanpei91/torsniff) 从BitTorrent网络嗅探种子
- [**2950**星][14d] [Lua] [ntop/ntopng](https://github.com/ntop/ntopng) 基于Web的流量监控工具
- [**1328**星][1y] [C] [gamelinux/passivedns](https://github.com/gamelinux/passivedns) 
- [**286**星][1m] [Shell] [tehw0lf/airbash](https://github.com/tehw0lf/airbash) airbash: 全自动的WPAPSK握手包捕获脚本, 用于渗透测试


### <a id="dde87061175108fc66b00ef665b1e7d0"></a>pcap数据包


- [**820**星][13d] [C++] [seladb/pcapplusplus](https://github.com/seladb/pcapplusplus) 
- [**780**星][3m] [Py] [srinivas11789/pcapxray](https://github.com/srinivas11789/pcapxray) A Network Forensics Tool
- [**459**星][30d] [C#] [chmorgan/sharppcap](https://github.com/chmorgan/sharppcap) 
- [**210**星][12m] [Py] [mateuszk87/pcapviz](https://github.com/mateuszk87/pcapviz) 
- [**209**星][7m] [JS] [dirtbags/pcapdb](https://github.com/dirtbags/pcapdb) 分布式、搜索优化的网络数据包捕获系统
- [**206**星][4m] [Py] [pynetwork/pypcap](https://github.com/pynetwork/pypcap) python libpcap module, forked from code.google.com/p/pypcap, now actively maintained


### <a id="1692d675f0fc7d190e0a33315f4abae8"></a>劫持&&TCP/HTTP/流量劫持




### <a id="3c28b67524f117ed555daed9cc99e35e"></a>协议分析&&流量分析


- [**1401**星][1m] [Go] [skydive-project/skydive](https://github.com/skydive-project/skydive) 




***


## <a id="c49aef477cf3397f97f8b72185c3d100"></a>密码&&凭证


### <a id="20bf2e2fefd6de7aadbf0774f4921824"></a>未分类-Password


- [**4772**星][1m] [Py] [alessandroz/lazagne](https://github.com/alessandroz/lazagne) 
- [**1441**星][1y] [Py] [d4vinci/cr3dov3r](https://github.com/d4vinci/cr3dov3r) 
- [**1025**星][1y] [PowerShell] [danmcinerney/icebreaker](https://github.com/danmcinerney/icebreaker) 
- [**891**星][16d] [C] [cossacklabs/themis](https://github.com/cossacklabs/themis) themis：用于存储或通信的加密库，可用于Swift, ObjC, Android, С++, JS, Python, Ruby, PHP, Go。
- [**514**星][2m] [Py] [unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) 
- [**492**星][2m] [Py] [byt3bl33d3r/sprayingtoolkit](https://github.com/byt3bl33d3r/sprayingtoolkit) 
- [**483**星][1y] [JS] [emilbayes/secure-password](https://github.com/emilbayes/secure-password) 
- [**442**星][1y] [Go] [ncsa/ssh-auditor](https://github.com/ncsa/ssh-auditor) 扫描网络中的弱SSH密码
- [**385**星][11m] [Shell] [mthbernardes/sshlooter](https://github.com/mthbernardes/sshlooter) 
- [**347**星][3m] [Py] [davidtavarez/pwndb](https://github.com/davidtavarez/pwndb) 
- [**295**星][5m] [C#] [raikia/credninja](https://github.com/raikia/credninja) 
- [**284**星][6m] [Shell] [greenwolf/spray](https://github.com/Greenwolf/Spray) 
- [**272**星][2m] [JS] [kspearrin/ff-password-exporter](https://github.com/kspearrin/ff-password-exporter) 
- [**267**星][1m] [Py] [xfreed0m/rdpassspray](https://github.com/xfreed0m/rdpassspray) 
- [**255**星][5m] [C] [rub-syssec/omen](https://github.com/rub-syssec/omen) Ordered Markov ENumerator - Password Guesser
- [**210**星][3m] [Ruby] [bdmac/strong_password](https://github.com/bdmac/strong_password) 


### <a id="86dc226ae8a71db10e4136f4b82ccd06"></a>密码


- [**6832**星][17d] [C] [hashcat/hashcat](https://github.com/hashcat/hashcat) 世界上最快最先进的密码恢复工具
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/后渗透/未分类-post-exp](#12abc279c69d1fcf10692b9cb89bcdf7) |
- [**5149**星][12m] [JS] [samyk/poisontap](https://github.com/samyk/poisontap) 
- [**3083**星][13d] [C] [magnumripper/johntheripper](https://github.com/magnumripper/johntheripper) 
- [**2536**星][1m] [C] [huntergregal/mimipenguin](https://github.com/huntergregal/mimipenguin) dump 当前Linux用户的登录密码
- [**1124**星][7m] [Py] [mebus/cupp](https://github.com/mebus/cupp) 
- [**859**星][4m] [Go] [fireeye/gocrack](https://github.com/fireeye/gocrack) 火眼开源的密码破解工具，可以跨多个 GPU 服务器执行任务
- [**843**星][2m] [Go] [ukhomeoffice/repo-security-scanner](https://github.com/ukhomeoffice/repo-security-scanner) 
- [**628**星][1y] [Java] [faizann24/wifi-bruteforcer-fsecurify](https://github.com/faizann24/wifi-bruteforcer-fsecurify) Android app，无需 Root 即可爆破 Wifi 密码
- [**585**星][1y] [Py] [brannondorsey/passgan](https://github.com/brannondorsey/passgan) 
- [**578**星][6m] [C] [hashcat/hashcat-utils](https://github.com/hashcat/hashcat-utils) 
- [**574**星][3m] [Py] [thewhiteh4t/pwnedornot](https://github.com/thewhiteh4t/pwnedornot) 
- [**482**星][1y] [PowerShell] [dafthack/domainpasswordspray](https://github.com/dafthack/domainpasswordspray) 
- [**404**星][1y] [C++] [vah13/extracttvpasswords](https://github.com/vah13/extracttvpasswords) 
- [**344**星][7m] [Py] [iphelix/pack](https://github.com/iphelix/pack) 
- [**318**星][2m] [JS] [auth0/repo-supervisor](https://github.com/auth0/repo-supervisor) Serverless工具，在pull请求中扫描源码，搜索密码及其他秘密
- [**318**星][1m] [CSS] [guyoung/captfencoder](https://github.com/guyoung/captfencoder) 




***


## <a id="d5e869a870d6e2c14911de2bc527a6ef"></a>古老的&&有新的替代版本的


- [**1593**星][3m] [Py] [knownsec/pocsuite](https://github.com/knownsec/pocsuite) 
- [**1510**星][1y] [dripcap/dripcap](https://github.com/dripcap/dripcap) 
- [**845**星][1y] [Py] [kgretzky/evilginx](https://github.com/kgretzky/evilginx) 


***


## <a id="983f763457e9599b885b13ea49682130"></a>Windows


- [**8590**星][3m] [C] [gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz) 
- [**2084**星][1m] [Py] [trustedsec/unicorn](https://github.com/trustedsec/unicorn) 通过PowerShell降级攻击, 直接将Shellcode注入到内存


***


## <a id="bad06ceb38098c26b1b8b46104f98d25"></a>webshell


### <a id="e08366dcf7aa021c6973d9e2a8944dff"></a>收集


- [**21409**星][14d] [PHP] [danielmiessler/seclists](https://github.com/danielmiessler/seclists) 多种类型资源收集：用户名、密码、URL、敏感数据类型、Fuzzing  Payload、WebShell等
    - 重复区段: [工具/wordlist/收集](#3202d8212db5699ea5e6021833bf3fa2) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload收集](#b5d99a78ddb383c208aae474fc2cb002) |
- [**5033**星][1m] [PHP] [tennc/webshell](https://github.com/tennc/webshell) webshell收集


### <a id="faa91844951d2c29b7b571c6e8a3eb54"></a>未分类-webshell


- [**1739**星][2m] [Py] [epinna/weevely3](https://github.com/epinna/weevely3) 
- [**956**星][1m] [Py] [yzddmr6/webshell-venom](https://github.com/yzddmr6/webshell-venom) 
- [**474**星][7m] [ASP] [landgrey/webshell-detect-bypass](https://github.com/landgrey/webshell-detect-bypass) 
- [**421**星][1y] [Py] [shmilylty/cheetah](https://github.com/shmilylty/cheetah) 
- [**411**星][1y] [PHP] [ysrc/webshell-sample](https://github.com/ysrc/webshell-sample) 
- [**366**星][5m] [PHP] [blackarch/webshells](https://github.com/blackarch/webshells) 
- [**351**星][7m] [PHP] [s0md3v/nano](https://github.com/s0md3v/nano) PHP Webshell家族
- [**305**星][8m] [Py] [wangyihang/webshell-sniper](https://github.com/wangyihang/webshell-sniper) webshell管理器，命令行工具
- [**282**星][1y] [JS] [chrisallenlane/novahot](https://github.com/chrisallenlane/novahot) Webshell框架，实现了基于Json的API，可与任何语言编写的后门（默认支持PHP/Ruby/Python）进行通信。
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/后渗透/未分类-post-exp](#12abc279c69d1fcf10692b9cb89bcdf7) |
- [**243**星][8m] [Py] [antoniococo/sharpyshell](https://github.com/antoniococo/sharpyshell) ASP.NET webshell，小型，混淆，针对C# Web App
- [**207**星][6m] [PHP] [samdark/yii2-webshell](https://github.com/samdark/yii2-webshell) 




***


## <a id="43b0310ac54c147a62c545a2b0f4bce2"></a>辅助周边


### <a id="569887799ee0148230cc5d7bf98e96d0"></a>未分类


- [**25893**星][12d] [Py] [certbot/certbot](https://github.com/certbot/certbot) 
- [**7594**星][17d] [JS] [gchq/cyberchef](https://github.com/gchq/cyberchef) 
- [**4838**星][2m] [Rust] [sharkdp/hexyl](https://github.com/sharkdp/hexyl) 命令行中查看hex
- [**4230**星][14d] [JS] [cure53/dompurify](https://github.com/cure53/dompurify) 
- [**3166**星][6m] [HTML] [leizongmin/js-xss](https://github.com/leizongmin/js-xss) 
- [**3078**星][2m] [Shell] [trimstray/htrace.sh](https://github.com/trimstray/htrace.sh) 
- [**949**星][8m] [Go] [maliceio/malice](https://github.com/maliceio/malice) 开源版的VirusTotal
- [**500**星][17d] [Py] [certtools/intelmq](https://github.com/certtools/intelmq) 
- [**464**星][4m] [JS] [ehrishirajsharma/swiftnessx](https://github.com/ehrishirajsharma/swiftnessx) 


### <a id="86d5daccb4ed597e85a0ec9c87f3c66f"></a>TLS&&SSL&&HTTPS


- [**4292**星][5m] [Py] [diafygi/acme-tiny](https://github.com/diafygi/acme-tiny) 
- [**1663**星][2m] [HTML] [chromium/badssl.com](https://github.com/chromium/badssl.com) 
- [**1177**星][2m] [Go] [jsha/minica](https://github.com/jsha/minica) 
- [**1126**星][19d] [Go] [smallstep/certificates](https://github.com/smallstep/certificates) 私有的证书颁发机构（X.509和SSH）和ACME服务器，用于安全的自动证书管理，因此您可以在SSH和SSO处使用TLS
- [**507**星][14d] [Java] [rub-nds/tls-attacker](https://github.com/rub-nds/tls-attacker) 




***


## <a id="e1fc1d87056438f82268742dc2ba08f5"></a>事件响应&&取证&&内存取证&&数字取证


### <a id="65f1e9dc3e08dff9fcda9d2ee245764e"></a>未分类-Forensics




### <a id="d0f59814394c5823210aa04a8fcd1220"></a>事件响应&&IncidentResponse


- [**3054**星][14d] [meirwah/awesome-incident-response](https://github.com/meirwah/awesome-incident-response) 
- [**1801**星][4m] [bypass007/emergency-response-notes](https://github.com/bypass007/emergency-response-notes) 
- [**1310**星][3m] [HTML] [thehive-project/thehive](https://github.com/thehive-project/thehive) 
- [**1132**星][10m] [Py] [certsocietegenerale/fir](https://github.com/certsocietegenerale/fir) 
- [**988**星][9m] [Go] [gencebay/httplive](https://github.com/gencebay/httplive) 
- [**965**星][1m] [JS] [monzo/response](https://github.com/monzo/response) 
- [**764**星][16d] [microsoft/msrc-security-research](https://github.com/microsoft/msrc-security-research) 
- [**744**星][10m] [PowerShell] [davehull/kansa](https://github.com/davehull/kansa) 
- [**710**星][2m] [HTML] [pagerduty/incident-response-docs](https://github.com/pagerduty/incident-response-docs) 
- [**634**星][9m] [Roff] [palantir/windows-event-forwarding](https://github.com/palantir/windows-event-forwarding) 使用 Windows 事件转发实现网络事件监测和防御
- [**627**星][21d] [Kotlin] [chuckerteam/chucker](https://github.com/chuckerteam/chucker) simplifies the inspection of HTTP(S) requests/responses, and Throwables fired by your Android App
- [**579**星][9m] [Go] [nytimes/gziphandler](https://github.com/nytimes/gziphandler) 
- [**535**星][5m] [Py] [owasp/qrljacking](https://github.com/owasp/qrljacking) 一个简单的能够进行会话劫持的社会工程攻击向量，影响所有使用“使用 QR 码登录”作为安全登录方式的应用程序。（ Quick Response CodeLogin Jacking）
- [**459**星][6m] [palantir/osquery-configuration](https://github.com/palantir/osquery-configuration) 使用 osquery 做事件检测和响应
- [**452**星][28d] [Py] [controlscanmdr/cyphon](https://github.com/controlscanmdr/cyphon) 事件管理和响应平台
- [**286**星][1m] [Py] [alexandreborges/malwoverview](https://github.com/alexandreborges/malwoverview) 
- [**251**星][1m] [C#] [orlikoski/cylr](https://github.com/orlikoski/CyLR) 
- [**204**星][2m] [PowerShell] [wiredpulse/posh-r2](https://github.com/wiredpulse/posh-r2) 


### <a id="1fc5d3621bb13d878f337c8031396484"></a>取证&&Forensics&&数字取证&&内存取证


- [**3315**星][2m] [Py] [google/grr](https://github.com/google/grr) 
- [**1486**星][9m] [Py] [google/rekall](https://github.com/google/rekall) 
- [**1465**星][18d] [C] [sleuthkit/sleuthkit](https://github.com/sleuthkit/sleuthkit) 
- [**1200**星][27d] [Py] [google/timesketch](https://github.com/google/timesketch) 
- [**1152**星][2m] [Go] [mozilla/mig](https://github.com/mozilla/mig) mig：分布式实时数字取证和研究平台
- [**953**星][1m] [Rich Text Format] [decalage2/oletools](https://github.com/decalage2/oletools) 
- [**940**星][17d] [C++] [hasherezade/pe-sieve](https://github.com/hasherezade/pe-sieve) 
- [**909**星][2m] [Py] [ondyari/faceforensics](https://github.com/ondyari/faceforensics) 
- [**826**星][12d] [Java] [sleuthkit/autopsy](https://github.com/sleuthkit/autopsy) 
- [**817**星][21d] [cugu/awesome-forensics](https://github.com/cugu/awesome-forensics) 
- [**802**星][14d] [Py] [yampelo/beagle](https://github.com/yampelo/beagle) 
- [**744**星][19d] [Py] [snovvcrash/usbrip](https://github.com/snovvcrash/usbrip) 
    - 重复区段: [工具/硬件设备&&USB&树莓派/USB](#48c53d1304b1335d9addf45b959b7d8a) |
- [**419**星][2m] [Py] [obsidianforensics/hindsight](https://github.com/obsidianforensics/hindsight) 
- [**400**星][14d] [Py] [forensicartifacts/artifacts](https://github.com/forensicartifacts/artifacts) 
- [**391**星][10m] [Go] [mozilla/masche](https://github.com/mozilla/masche) 
- [**321**星][10m] [Py] [alessandroz/lazagneforensic](https://github.com/alessandroz/lazagneforensic) 
- [**317**星][3m] [HTML] [intezer/linux-explorer](https://github.com/intezer/linux-explorer) linux-explorer: 针对Linux 系统的现场取证工具箱. Web 界面, 简单易用
- [**311**星][8m] [Py] [n0fate/chainbreaker](https://github.com/n0fate/chainbreaker) 
- [**301**星][2m] [Py] [google/turbinia](https://github.com/google/turbinia) 
- [**296**星][24d] [Shell] [vitaly-kamluk/bitscout](https://github.com/vitaly-kamluk/bitscout) bitscout：远程数据取证工具
- [**268**星][12d] [Perl] [owasp/o-saft](https://github.com/owasp/o-saft) 
- [**255**星][6m] [Batchfile] [diogo-fernan/ir-rescue](https://github.com/diogo-fernan/ir-rescue) 
- [**250**星][21d] [Py] [google/docker-explorer](https://github.com/google/docker-explorer) 
- [**248**星][12m] [C++] [comaeio/swishdbgext](https://github.com/comaeio/SwishDbgExt) 
- [**243**星][11m] [Py] [crowdstrike/forensics](https://github.com/crowdstrike/forensics) 
- [**241**星][1m] [Py] [orlikoski/cdqr](https://github.com/orlikoski/CDQR) 
- [**227**星][30d] [C] [elfmaster/libelfmaster](https://github.com/elfmaster/libelfmaster) 
- [**217**星][2m] [Py] [crowdstrike/automactc](https://github.com/crowdstrike/automactc) 


### <a id="4d2a33083a894d6e6ef01b360929f30a"></a>Volatility


- [**3199**星][2m] [Py] [volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility) 
- [**308**星][7m] [Py] [jasonstrimpel/volatility-trading](https://github.com/jasonstrimpel/volatility-trading) 
- [**224**星][2m] [Py] [volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles) 
- [**219**星][1m] [Py] [volatilityfoundation/community](https://github.com/volatilityfoundation/community) 




***


## <a id="a2df15c7819a024c2f5c4a7489285597"></a>密罐&&Honeypot


### <a id="2af349669891f54649a577b357aa81a6"></a>未分类-Honeypot


- [**1784**星][1m] [Py] [threatstream/mhn](https://github.com/pwnlandia/mhn) 蜜罐网络
- [**1259**星][21d] [C] [dtag-dev-sec/tpotce](https://github.com/dtag-dev-sec/tpotce) tpotce：创建多蜜罐平台T-Pot ISO 镜像
- [**1201**星][24d] [Go] [hacklcx/hfish](https://github.com/hacklcx/hfish) 扩展企业安全测试主动诱导型开源蜜罐框架系统，记录黑客攻击手段
- [**400**星][3m] [Py] [nsmfoo/antivmdetection](https://github.com/nsmfoo/antivmdetection) 
- [**356**星][2m] [Py] [p1r06u3/opencanary_web](https://github.com/p1r06u3/opencanary_web) 
- [**325**星][1y] [JS] [shmakov/honeypot](https://github.com/shmakov/honeypot) 
- [**303**星][1m] [Py] [hatching/vmcloak](https://github.com/hatching/vmcloak) 
- [**271**星][1y] [Py] [gbafana25/esp8266_honeypot](https://github.com/gbafana25/esp8266_honeypot) 
- [**229**星][1y] [Shell] [aplura/tango](https://github.com/aplura/tango) 
- [**227**星][9m] [Py] [honeynet/beeswarm](https://github.com/honeynet/beeswarm) 
- [**219**星][1m] [Py] [jamesturk/django-honeypot](https://github.com/jamesturk/django-honeypot) 


### <a id="d20acdc34ca7c084eb52ca1c14f71957"></a>密罐


- [**735**星][1m] [Py] [buffer/thug](https://github.com/buffer/thug) 
- [**687**星][4m] [Py] [mushorg/conpot](https://github.com/mushorg/conpot) 
- [**668**星][6m] [Go] [honeytrap/honeytrap](https://github.com/honeytrap/honeytrap) 高级蜜罐框架, 可以运行/监控/管理蜜罐. Go语言编写
- [**574**星][2m] [Py] [thinkst/opencanary](https://github.com/thinkst/opencanary) 
- [**396**星][2m] [Py] [mushorg/glastopf](https://github.com/mushorg/glastopf) 
- [**379**星][3m] [Py] [foospidy/honeypy](https://github.com/foospidy/honeypy) 
- [**371**星][1m] [Py] [dinotools/dionaea](https://github.com/dinotools/dionaea) 
- [**224**星][1m] [Py] [johnnykv/heralding](https://github.com/johnnykv/heralding) 
- [**215**星][1m] [Py] [mushorg/snare](https://github.com/mushorg/snare) 


### <a id="efde8c850d8d09e7c94aa65a1ab92acf"></a>收集


- [**3708**星][1m] [Py] [paralax/awesome-honeypots](https://github.com/paralax/awesome-honeypots) 


### <a id="c8f749888134d57b5fb32382c78ef2d1"></a>SSH&&Telnet


- [**2906**星][18d] [Py] [cowrie/cowrie](https://github.com/cowrie/cowrie) cowrie：中型/交互型 SSH/Telnet 蜜罐，
- [**272**星][27d] [C] [droberson/ssh-honeypot](https://github.com/droberson/ssh-honeypot) 


### <a id="356be393f6fb9215c14799e5cd723fca"></a>TCP&&UDP




### <a id="577fc2158ab223b65442fb0fd4eb8c3e"></a>HTTP&&Web


- [**433**星][1y] [Py] [0x4d31/honeylambda](https://github.com/0x4d31/honeylambda) 


### <a id="35c6098cbdc5202bf7f60979a76a5691"></a>ActiveDirectory




### <a id="7ac08f6ae5c88efe2cd5b47a4d391e7e"></a>SMTP




### <a id="8c58c819e0ba0442ae90d8555876d465"></a>打印机




### <a id="1a6b81fd9550736d681d6d0e99ae69e3"></a>Elasticsearch




### <a id="57356b67511a9dc7497b64b007047ee7"></a>ADB




### <a id="c5b6762b3dc783a11d72dea648755435"></a>蓝牙&&Bluetooth 


- [**1261**星][1m] [Py] [virtualabs/btlejack](https://github.com/virtualabs/btlejack) 
- [**1120**星][9m] [evilsocket/bleah](https://github.com/evilsocket/bleah) 低功耗蓝牙扫描器
- [**865**星][3m] [Java] [googlearchive/android-bluetoothlegatt](https://github.com/googlearchive/android-BluetoothLeGatt) 
- [**292**星][11m] [JS] [jeija/bluefluff](https://github.com/jeija/bluefluff) 


### <a id="2a77601ce72f944679b8c5650d50148d"></a>其他类型


#### <a id="1d0819697e6bc533f564383d0b98b386"></a>Wordpress








***


## <a id="f56806b5b229bdf6c118f5fb1092e141"></a>威胁情报


### <a id="8fd1f0cfde78168c88fc448af9c6f20f"></a>未分类-ThreatIntelligence


- [**2390**星][13d] [PHP] [misp/misp](https://github.com/misp/misp) 
- [**1836**星][3m] [YARA] [yara-rules/rules](https://github.com/yara-rules/rules) 
- [**1246**星][15d] [Shell] [firehol/blocklist-ipsets](https://github.com/firehol/blocklist-ipsets) 
- [**826**星][19d] [YARA] [neo23x0/signature-base](https://github.com/neo23x0/signature-base) 
- [**824**星][27d] [JS] [opencti-platform/opencti](https://github.com/opencti-platform/opencti) 
- [**786**星][17d] [Py] [yeti-platform/yeti](https://github.com/yeti-platform/yeti) yeti：情报威胁管理平台
- [**715**星][24d] [C++] [facebook/threatexchange](https://github.com/facebook/threatexchange) 
- [**704**星][2m] [Go] [activecm/rita](https://github.com/activecm/rita) 
- [**505**星][6m] [Py] [te-k/harpoon](https://github.com/te-k/harpoon) 
- [**444**星][4m] [PHP] [kasperskylab/klara](https://github.com/kasperskylab/klara) 
- [**411**星][1m] [mitre/cti](https://github.com/mitre/cti) 
- [**407**星][3m] [Scala] [thehive-project/cortex](https://github.com/TheHive-Project/Cortex) 
- [**374**星][7m] [Py] [hurricanelabs/machinae](https://github.com/hurricanelabs/machinae) 
- [**290**星][6m] [YARA] [supportintelligence/icewater](https://github.com/supportintelligence/icewater) 
- [**253**星][2m] [Py] [diogo-fernan/malsub](https://github.com/diogo-fernan/malsub) 
- [**234**星][2m] [Py] [cylance/cybot](https://github.com/cylance/CyBot) 
- [**231**星][1m] [Py] [anouarbensaad/vulnx](https://github.com/anouarbensaad/vulnx) An Intelligent Bot Auto Shell Injector that detect vulnerabilities in multiple types of CMS
- [**217**星][2m] [Py] [inquest/threatingestor](https://github.com/inquest/threatingestor) 
- [**208**星][18d] [Py] [inquest/omnibus](https://github.com/inquest/omnibus) 
- [**201**星][3m] [Py] [yelp/threat_intel](https://github.com/yelp/threat_intel) 


### <a id="91dc39dc492ee8ef573e1199117bc191"></a>收集


- [**3117**星][5m] [hslatman/awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence) 
- [**1459**星][14d] [YARA] [cybermonitor/apt_cybercriminal_campagin_collections](https://github.com/cybermonitor/apt_cybercriminal_campagin_collections) 


### <a id="3e10f389acfbd56b79f52ab4765e11bf"></a>IOC


#### <a id="c94be209c558a65c5e281a36667fc27a"></a>未分类


- [**1408**星][1m] [Py] [neo23x0/loki](https://github.com/neo23x0/loki) 
- [**208**星][4m] [Shell] [neo23x0/fenrir](https://github.com/neo23x0/fenrir) 


#### <a id="20a019435f1c5cc75e574294c01f3fee"></a>IOC集合


- [**405**星][8m] [Shell] [sroberts/awesome-iocs](https://github.com/sroberts/awesome-iocs) 


#### <a id="1b1aa1dfcff3054bc20674230ee52cfe"></a>IOC提取


- [**212**星][23d] [Py] [inquest/python-iocextract](https://github.com/inquest/python-iocextract) IoC提取器


#### <a id="9bcb156b2e3b7800c42d5461c0062c02"></a>IOC获取


- [**652**星][13d] [Py] [blackorbird/apt_report](https://github.com/blackorbird/apt_report) 
- [**626**星][28d] [YARA] [eset/malware-ioc](https://github.com/eset/malware-ioc) 
- [**418**星][1y] [JS] [ciscocsirt/gosint](https://github.com/ciscocsirt/gosint) 收集、处理、索引高质量IOC的框架
- [**303**星][1y] [Py] [fsecurelabs/win_driver_plugin](https://github.com/FSecureLABS/win_driver_plugin) 
- [**257**星][2m] [PHP] [pan-unit42/iocs](https://github.com/pan-unit42/iocs) 






***


## <a id="946d766c6a0fb23b480ff59d4029ec71"></a>防护&&Defense


### <a id="7a277f8b0e75533e0b50d93c902fb351"></a>未分类-Defense


- [**630**星][5m] [Py] [binarydefense/artillery](https://github.com/binarydefense/artillery) 


### <a id="784ea32a3f4edde1cd424b58b17e7269"></a>WAF


- [**3248**星][2m] [C] [nbs-system/naxsi](https://github.com/nbs-system/naxsi) 
- [**3125**星][17d] [C++] [spiderlabs/modsecurity](https://github.com/spiderlabs/modsecurity) 
- [**617**星][2m] [Py] [3xp10it/xwaf](https://github.com/3xp10it/xwaf) waf 自动爆破(绕过)工具
- [**600**星][3m] [Lua] [jx-sec/jxwaf](https://github.com/jx-sec/jxwaf) 
- [**599**星][1y] [Lua] [unixhot/waf](https://github.com/unixhot/waf) 
- [**543**星][7m] [Py] [s0md3v/blazy](https://github.com/s0md3v/Blazy) 
- [**500**星][1m] [Go] [janusec/janusec](https://github.com/janusec/janusec) 
- [**462**星][7m] [Java] [chengdedeng/waf](https://github.com/chengdedeng/waf) 
- [**436**星][2m] [PHP] [akaunting/firewall](https://github.com/akaunting/firewall) 
- [**424**星][8m] [Py] [aws-samples/aws-waf-sample](https://github.com/aws-samples/aws-waf-sample) 
- [**406**星][1m] [C#] [jbe2277/waf](https://github.com/jbe2277/waf) 
- [**401**星][7m] [Py] [awslabs/aws-waf-security-automations](https://github.com/awslabs/aws-waf-security-automations) 
- [**401**星][10m] [C] [titansec/openwaf](https://github.com/titansec/openwaf) 
- [**243**星][1y] [Py] [warflop/cloudbunny](https://github.com/warflop/cloudbunny) 
- [**207**星][6m] [C] [coolervoid/raptor_waf](https://github.com/coolervoid/raptor_waf) 


### <a id="ce6532938f729d4c9d66a5c75d1676d3"></a>防火墙&&FireWall


- [**4162**星][2m] [Py] [evilsocket/opensnitch](https://github.com/evilsocket/opensnitch) opensnitch：Little Snitch 应用程序防火墙的 GNU/Linux 版本。（Little Snitch：Mac操作系统的应用程序防火墙，能防止应用程序在你不知道的情况下自动访问网络）
- [**3186**星][1m] [Objective-C] [objective-see/lulu](https://github.com/objective-see/lulu) 
- [**1515**星][12d] [Java] [ukanth/afwall](https://github.com/ukanth/afwall) 
- [**1031**星][9m] [Shell] [firehol/firehol](https://github.com/firehol/firehol) 
- [**817**星][4m] [trimstray/iptables-essentials](https://github.com/trimstray/iptables-essentials) 
- [**545**星][6m] [Go] [sysdream/chashell](https://github.com/sysdream/chashell) 
- [**449**星][5m] [Shell] [vincentcox/bypass-firewalls-by-dns-history](https://github.com/vincentcox/bypass-firewalls-by-dns-history) 
- [**232**星][4m] [Shell] [essandess/macos-fortress](https://github.com/essandess/macos-fortress) 
- [**220**星][1y] [Go] [maksadbek/tcpovericmp](https://github.com/maksadbek/tcpovericmp) 


### <a id="ff3e0b52a1477704b5f6a94ccf784b9a"></a>IDS&&IPS


- [**2874**星][27d] [Zeek] [zeek/zeek](https://github.com/zeek/zeek) 
- [**2798**星][1m] [C] [ossec/ossec-hids](https://github.com/ossec/ossec-hids) ossec-hids：入侵检测系统
- [**1589**星][1m] [Go] [ysrc/yulong-hids](https://github.com/ysrc/yulong-hids) 
- [**1252**星][1m] [C] [oisf/suricata](https://github.com/OISF/suricata) a network IDS, IPS and NSM engine
- [**524**星][19d] [Py] [0kee-team/watchad](https://github.com/0kee-team/watchad) 
- [**507**星][4m] [C] [decaf-project/decaf](https://github.com/decaf-project/DECAF) 
- [**489**星][7m] [Shell] [stamusnetworks/selks](https://github.com/stamusnetworks/selks) 
- [**369**星][6m] [jnusimba/androidsecnotes](https://github.com/jnusimba/androidsecnotes) 
- [**278**星][13d] [C] [ebwi11/agentsmith-hids](https://github.com/EBWi11/AgentSmith-HIDS) 
- [**243**星][1y] [Perl] [mrash/psad](https://github.com/mrash/psad) psad：iptables 的入侵检测和日志分析（psad：Port Scan Attack Detector）
- [**220**星][1m] [Py] [secureworks/dalton](https://github.com/secureworks/dalton) dalton: 使用预定义/指定的规则, 针对IDS传感器(例如Snort/Suricata)进行网络数据包捕获




***


## <a id="785ad72c95e857273dce41842f5e8873"></a>爬虫


- [**741**星][19d] [Py] [nekmo/dirhunt](https://github.com/nekmo/dirhunt) Web爬虫, 针对搜索和分析路径做了优化
    - 重复区段: [工具/扫描器&&安全扫描&&App扫描&&漏洞扫描/未分类-Scanner](#de63a029bda6a7e429af272f291bb769) |


***


## <a id="609214b7c4d2f9bb574e2099313533a2"></a>wordlist


### <a id="af1d71122d601229dc4aa9d08f4e3e15"></a>未分类-wordlist


- [**1668**星][7m] [Py] [guelfoweb/knock](https://github.com/guelfoweb/knock) 使用 Wordlist 枚举子域名
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/子域名枚举&&爆破](#e945721056c78a53003e01c3d2f3b8fe) |
- [**382**星][3m] [Ruby] [digininja/cewl](https://github.com/digininja/cewl) 
- [**328**星][4m] [Py] [initstring/passphrase-wordlist](https://github.com/initstring/passphrase-wordlist) 
- [**251**星][1y] [Py] [berzerk0/bewgor](https://github.com/berzerk0/bewgor) 


### <a id="3202d8212db5699ea5e6021833bf3fa2"></a>收集


- [**21409**星][14d] [PHP] [danielmiessler/seclists](https://github.com/danielmiessler/seclists) 多种类型资源收集：用户名、密码、URL、敏感数据类型、Fuzzing  Payload、WebShell等
    - 重复区段: [工具/webshell/收集](#e08366dcf7aa021c6973d9e2a8944dff) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload收集](#b5d99a78ddb383c208aae474fc2cb002) |
- [**5955**星][6m] [berzerk0/probable-wordlists](https://github.com/berzerk0/probable-wordlists) 


### <a id="f2c76d99a0b1fda124d210bd1bbc8f3f"></a>Wordlist生成






***


## <a id="96171a80e158b8752595329dd42e8bcf"></a>泄漏&&Breach&&Leak


- [**1358**星][5m] [gitguardian/apisecuritybestpractices](https://github.com/gitguardian/apisecuritybestpractices) 
- [**885**星][21d] [Py] [woj-ciech/leaklooker](https://github.com/woj-ciech/leaklooker) 


***


## <a id="de81f9dd79c219c876c1313cd97852ce"></a>破解&&Crack&&爆破&&BruteForce


- [**3217**星][18d] [C] [vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra) 网络登录破解，支持多种服务
- [**1885**星][1m] [Py] [lanjelot/patator](https://github.com/lanjelot/patator) 
- [**1042**星][3m] [Py] [landgrey/pydictor](https://github.com/landgrey/pydictor) 
- [**875**星][2m] [Py] [trustedsec/hate_crack](https://github.com/trustedsec/hate_crack) hate_crack: 使用HashCat 的自动哈希破解工具
- [**789**星][6m] [C] [brendan-rius/c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker) C 语言编写的 JWT 爆破工具
- [**780**星][10m] [Py] [mak-/parameth](https://github.com/mak-/parameth) 在文件中(例如PHP 文件)暴力搜索GET 和 POST 请求的参数
- [**748**星][4m] [Py] [s0md3v/hash-buster](https://github.com/s0md3v/Hash-Buster) 
- [**679**星][7m] [Shell] [1n3/brutex](https://github.com/1n3/brutex) 
- [**625**星][2m] [JS] [animir/node-rate-limiter-flexible](https://github.com/animir/node-rate-limiter-flexible) 
- [**619**星][4m] [C#] [shack2/snetcracker](https://github.com/shack2/snetcracker) 
- [**606**星][1y] [C] [nfc-tools/mfoc](https://github.com/nfc-tools/mfoc) 
- [**551**星][5m] [PHP] [s3inlc/hashtopolis](https://github.com/s3inlc/hashtopolis) Hashcat wrapper, 用于跨平台分布式Hash破解
- [**546**星][1y] [CSS] [hashview/hashview](https://github.com/hashview/hashview) 密码破解和分析工具
- [**516**星][3m] [C] [nmap/ncrack](https://github.com/nmap/ncrack) 
- [**507**星][1m] [Py] [pure-l0g1c/instagram](https://github.com/pure-l0g1c/instagram) 
- [**499**星][3m] [duyetdev/bruteforce-database](https://github.com/duyetdev/bruteforce-database) 
- [**487**星][1y] [C] [mikeryan/crackle](https://github.com/mikeryan/crackle) 
- [**437**星][1y] [C] [ryancdotorg/brainflayer](https://github.com/ryancdotorg/brainflayer) 
- [**435**星][5m] [JS] [coalfire-research/npk](https://github.com/coalfire-research/npk) 
- [**380**星][25d] [Py] [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) jwt_tool：测试，调整和破解JSON Web Token 的工具包
- [**351**星][2m] [Py] [denyhosts/denyhosts](https://github.com/denyhosts/denyhosts) 
- [**307**星][10m] [C] [e-ago/bitcracker](https://github.com/e-ago/bitcracker) bitcracker：BitLocker密码破解器
- [**287**星][11m] [Shell] [cyb0r9/socialbox](https://github.com/Cyb0r9/SocialBox) 
- [**265**星][11m] [C] [jmk-foofus/medusa](https://github.com/jmk-foofus/medusa) 
- [**256**星][17d] [Shell] [wuseman/emagnet](https://github.com/wuseman/emagnet) 
- [**250**星][1y] [Py] [avramit/instahack](https://github.com/avramit/instahack) 
- [**246**星][6m] [Go] [ropnop/kerbrute](https://github.com/ropnop/kerbrute) 
- [**245**星][11m] [Shell] [thelinuxchoice/instainsane](https://github.com/thelinuxchoice/instainsane) 
- [**225**星][2m] [Py] [evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) 修改NTLMv1/NTLMv1-ESS/MSCHAPv1 Hask, 使其可以在hashcat中用DES模式14000破解
- [**220**星][6m] [Py] [blark/aiodnsbrute](https://github.com/blark/aiodnsbrute) 
- [**220**星][11m] [Py] [chris408/known_hosts-hashcat](https://github.com/chris408/known_hosts-hashcat) 
- [**215**星][7m] [Py] [paradoxis/stegcracker](https://github.com/paradoxis/stegcracker) 
- [**209**星][1m] [C] [hyc/fcrackzip](https://github.com/hyc/fcrackzip) 
- [**203**星][3m] [Py] [isaacdelly/plutus](https://github.com/isaacdelly/plutus) 


***


## <a id="13d067316e9894cc40fe55178ee40f24"></a>OSCP


- [**1710**星][20d] [olivierlaflamme/cheatsheet-god](https://github.com/olivierlaflamme/cheatsheet-god) 
    - 重复区段: [工具/收集&&集合/混合型收集](#664ff1dbdafefd7d856c88112948a65b) |
- [**756**星][1m] [HTML] [rewardone/oscprepo](https://github.com/rewardone/oscprepo) 
- [**667**星][8m] [XSLT] [adon90/pentest_compilation](https://github.com/adon90/pentest_compilation) 
    - 重复区段: [工具/收集&&集合/未分类](#e97d183e67fa3f530e7d0e7e8c33ee62) |
- [**375**星][10m] [Py] [rustyshackleford221/oscp-prep](https://github.com/rustyshackleford221/oscp-prep) 
- [**360**星][8m] [PowerShell] [ferreirasc/oscp](https://github.com/ferreirasc/oscp) 
- [**289**星][14d] [PowerShell] [mantvydasb/redteam-tactics-and-techniques](https://github.com/mantvydasb/RedTeam-Tactics-and-Techniques) 
- [**222**星][7m] [0x4d31/awesome-oscp](https://github.com/0x4d31/awesome-oscp) 
- [**210**星][1y] [foobarto/redteam-notebook](https://github.com/foobarto/redteam-notebook) 


***


## <a id="249c9d207ed6743e412c8c8bcd8a2927"></a>MitreATT&CK


- [**2595**星][12d] [PowerShell] [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) 
- [**1308**星][14d] [Py] [mitre/caldera](https://github.com/mitre/caldera) 自动化 adversary emulation 系统
- [**557**星][5m] [HTML] [nshalabi/attack-tools](https://github.com/nshalabi/attack-tools) 
- [**454**星][2m] [Py] [olafhartong/threathunting](https://github.com/olafhartong/threathunting) 
- [**450**星][12m] [bfuzzy/auditd-attack](https://github.com/bfuzzy/auditd-attack) 
- [**325**星][5m] [teoseller/osquery-attck](https://github.com/teoseller/osquery-attck) 
- [**312**星][10m] [PowerShell] [cyb3rward0g/invoke-attackapi](https://github.com/cyb3rward0g/invoke-attackapi) 
- [**307**星][29d] [Py] [atc-project/atomic-threat-coverage](https://github.com/atc-project/atomic-threat-coverage) 


***


## <a id="76df273beb09f6732b37a6420649179c"></a>浏览器&&browser


- [**4591**星][2m] [JS] [beefproject/beef](https://github.com/beefproject/beef) 
- [**960**星][8m] [Py] [selwin/python-user-agents](https://github.com/selwin/python-user-agents) 
- [**852**星][3m] [escapingbug/awesome-browser-exploit](https://github.com/escapingbug/awesome-browser-exploit) 
- [**450**星][30d] [Py] [globaleaks/tor2web](https://github.com/globaleaks/tor2web) 
- [**446**星][2m] [m1ghtym0/browser-pwn](https://github.com/m1ghtym0/browser-pwn) 
- [**408**星][2m] [Pascal] [felipedaragon/sandcat](https://github.com/felipedaragon/sandcat) 为渗透测试和开发者准备的轻量级浏览器, 基于Chromium和Lua
- [**290**星][2m] [xsleaks/xsleaks](https://github.com/xsleaks/xsleaks) 
- [**215**星][2m] [Py] [icsec/airpwn-ng](https://github.com/icsec/airpwn-ng) force the target's browser to do what we want 
- [**212**星][1y] [C#] [djhohnstein/sharpweb](https://github.com/djhohnstein/sharpweb) 


***


## <a id="ceb90405292daed9bb32ac20836c219a"></a>蓝牙&&Bluetooth


- [**218**星][18d] [Py] [ghostop14/sparrow-wifi](https://github.com/ghostop14/sparrow-wifi) 
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/未分类-Network](#99398a5a8aaf99228829dadff48fb6a7) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |


***


## <a id="7d5d2d22121ed8456f0c79098f5012bb"></a>REST_API&&RESTFUL 


- [**1220**星][8m] [Py] [flipkart-incubator/astra](https://github.com/flipkart-incubator/astra) 自动化的REST API安全测试脚本


***


## <a id="8cb1c42a29fa3e8825a0f8fca780c481"></a>恶意代码&&Malware&&APT


- [**2013**星][1m] [C++] [lordnoteworthy/al-khaser](https://github.com/lordnoteworthy/al-khaser) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |
- [**859**星][2m] [aptnotes/data](https://github.com/aptnotes/data) 


# 贡献
内容为系统自动导出, 有任何问题请提issue