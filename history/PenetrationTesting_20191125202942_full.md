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
- [**2472**星][2y] [Py] [feross/spoofmac](https://github.com/feross/spoofmac) 伪造MAC地址
- [**1992**星][2m] [C++] [darthton/blackbone](https://github.com/darthton/blackbone) 
- [**1879**星][19d] [C] [chipsec/chipsec](https://github.com/chipsec/chipsec) 
- [**1859**星][1y] [C++] [y-vladimir/smartdeblur](https://github.com/y-vladimir/smartdeblur) 
- [**1773**星][5m] [Py] [veil-framework/veil](https://github.com/veil-framework/veil) 
- [**1560**星][1m] [Shell] [internetwache/gittools](https://github.com/internetwache/gittools) 
- [**1440**星][1y] [C++] [acaudwell/logstalgia](https://github.com/acaudwell/logstalgia) 
- [**1400**星][4m] [C] [ettercap/ettercap](https://github.com/ettercap/ettercap) 
- [**1384**星][1y] [Go] [filosottile/whosthere](https://github.com/filosottile/whosthere) 
- [**1339**星][20d] [XSLT] [lolbas-project/lolbas](https://github.com/lolbas-project/lolbas) 
- [**1328**星][12m] [XSLT] [api0cradle/lolbas](https://github.com/api0cradle/lolbas) 
- [**1314**星][1y] [mortenoir1/virtualbox_e1000_0day](https://github.com/mortenoir1/virtualbox_e1000_0day) 
- [**1298**星][2m] [PowerShell] [peewpw/invoke-psimage](https://github.com/peewpw/invoke-psimage) 
- [**1272**星][1y] [JS] [sakurity/securelogin](https://github.com/sakurity/securelogin) 
- [**1218**星][1y] [Go] [cloudflare/redoctober](https://github.com/cloudflare/redoctober) 
- [**1209**星][1m] [Go] [google/martian](https://github.com/google/martian) 
- [**1148**星][2y] [C] [saminiir/level-ip](https://github.com/saminiir/level-ip) a Linux userspace TCP/IP stack, implemented with TUN/TAP devices.
- [**1136**星][3m] [C] [dgiese/dustcloud](https://github.com/dgiese/dustcloud) 
- [**1128**星][2m] [HTML] [cure53/httpleaks](https://github.com/cure53/httpleaks) 
- [**1105**星][2m] [Py] [thoughtfuldev/eagleeye](https://github.com/thoughtfuldev/eagleeye) 
- [**1073**星][14d] [Go] [looterz/grimd](https://github.com/looterz/grimd) 
- [**1052**星][1m] [PHP] [nbs-system/php-malware-finder](https://github.com/nbs-system/php-malware-finder) 
- [**1023**星][13d] [Py] [yelp/detect-secrets](https://github.com/yelp/detect-secrets) 
- [**971**星][3y] [Py] [synack/knockknock](https://github.com/synack/knockknock) 
- [**967**星][25d] [HTML] [n0tr00t/sreg](https://github.com/n0tr00t/sreg) 可对使用者通过输入email、phone、username的返回用户注册的所有互联网护照信息。
- [**962**星][3y] [C] [cybellum/doubleagent](https://github.com/cybellum/doubleagent) 
- [**923**星][7m] [Py] [osirislab/hack-night](https://github.com/osirislab/Hack-Night) 
- [**909**星][1y] [Swift] [skreweverything/swift-keylogger](https://github.com/skreweverything/swift-keylogger) 
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
- [**836**星][2y] [Py] [nccgroup/demiguise](https://github.com/nccgroup/demiguise) 
- [**835**星][13d] [Roff] [slimm609/checksec.sh](https://github.com/slimm609/checksec.sh) checksec.sh: 检查可执行文件(PIE, RELRO, PaX, Canaries, ASLR, Fortify Source)属性的 bash 脚本
- [**832**星][3y] [C] [gurnec/hashcheck](https://github.com/gurnec/hashcheck) 
- [**832**星][7m] [JS] [serpicoproject/serpico](https://github.com/serpicoproject/serpico) 
- [**826**星][4y] [etsy/midas](https://github.com/etsy/midas) 
- [**819**星][10m] [Shell] [thelinuxchoice/userrecon](https://github.com/thelinuxchoice/userrecon) 
- [**818**星][21d] [C#] [borntoberoot/networkmanager](https://github.com/borntoberoot/networkmanager) 
- [**814**星][9m] [Py] [ietf-wg-acme/acme](https://github.com/ietf-wg-acme/acme) 
- [**814**星][16d] [Py] [lylemi/learn-web-hacking](https://github.com/lylemi/learn-web-hacking) 
- [**812**星][14d] [Java] [lamster2018/easyprotector](https://github.com/lamster2018/easyprotector) 
- [**807**星][8m] [Py] [nccgroup/featherduster](https://github.com/nccgroup/featherduster) 
- [**802**星][6m] [Py] [corelan/mona](https://github.com/corelan/mona) 
- [**797**星][2m] [JS] [sindresorhus/is-online](https://github.com/sindresorhus/is-online) 
- [**796**星][2y] [PowerShell] [besimorhino/powercat](https://github.com/besimorhino/powercat) PowerShell实现的Netcat
- [**793**星][1m] [Py] [hellman/xortool](https://github.com/hellman/xortool) 
- [**770**星][4y] [C++] [google/rowhammer-test](https://github.com/google/rowhammer-test) 
- [**769**星][1m] [Go] [dreddsa5dies/gohacktools](https://github.com/dreddsa5dies/gohacktools) 
- [**765**星][12m] [PowerShell] [kevin-robertson/invoke-thehash](https://github.com/kevin-robertson/invoke-thehash) 
- [**761**星][24d] [C++] [shekyan/slowhttptest](https://github.com/shekyan/slowhttptest) 
- [**757**星][9m] [Py] [hlldz/spookflare](https://github.com/hlldz/spookflare) 
- [**757**星][4m] [TSQL] [threathunterx/nebula](https://github.com/threathunterx/nebula) 
- [**747**星][2y] [PHP] [sektioneins/pcc](https://github.com/sektioneins/pcc) pcc：PHP 安全配置检查器
- [**746**星][1y] [Py] [greatsct/greatsct](https://github.com/greatsct/greatsct) 
- [**745**星][1m] [Go] [bishopfox/sliver](https://github.com/bishopfox/sliver) 
- [**739**星][1m] [PHP] [symfony/security-csrf](https://github.com/symfony/security-csrf) 
- [**738**星][2m] [C++] [snort3/snort3](https://github.com/snort3/snort3) 
- [**735**星][7m] [Py] [ricterz/genpass](https://github.com/ricterz/genpass) 
- [**734**星][5m] [Go] [talkingdata/owl](https://github.com/talkingdata/owl) 企业级分布式监控告警系
- [**731**星][1m] [HTML] [m4cs/babysploit](https://github.com/m4cs/babysploit) 
- [**729**星][1y] [C#] [eladshamir/internal-monologue](https://github.com/eladshamir/internal-monologue) 
- [**719**星][5m] [Go] [anshumanbh/git-all-secrets](https://github.com/anshumanbh/git-all-secrets) 结合多个开源 git 搜索工具实现的代码审计工具
- [**718**星][1y] [Perl] [moham3driahi/th3inspector](https://github.com/moham3driahi/th3inspector) All in one tool for Information Gathering
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
- [**672**星][5y] [C] [robertdavidgraham/heartleech](https://github.com/robertdavidgraham/heartleech) 
- [**665**星][1y] [Py] [endgameinc/rta](https://github.com/endgameinc/rta) 
- [**665**星][12m] [PowerShell] [arvanaghi/sessiongopher](https://github.com/Arvanaghi/SessionGopher) 
- [**664**星][2m] [Py] [skelsec/pypykatz](https://github.com/skelsec/pypykatz) 纯Python实现的Mimikatz
- [**664**星][2y] [Py] [trycatchhcf/dumpsterfire](https://github.com/trycatchhcf/dumpsterfire) 
- [**662**星][2m] [Go] [pquerna/otp](https://github.com/pquerna/otp) 
- [**658**星][5m] [Py] [golismero/golismero](https://github.com/golismero/golismero) 
- [**654**星][1y] [Py] [deepzec/bad-pdf](https://github.com/deepzec/bad-pdf) create malicious PDF file to steal NTLM(NTLMv1/NTLMv2) Hashes from windows machines
- [**651**星][4m] [C#] [outflanknl/evilclippy](https://github.com/outflanknl/evilclippy) 
- [**650**星][12d] [ptresearch/attackdetection](https://github.com/ptresearch/attackdetection) 
- [**647**星][8m] [C] [samdenty/wi-pwn](https://github.com/samdenty/Wi-PWN)  performs deauth attacks on cheap Arduino boards
- [**643**星][3y] [C] [rentzsch/mach_inject](https://github.com/rentzsch/mach_inject) 
- [**642**星][11m] [C#] [wwillv/godofhacker](https://github.com/wwillv/godofhacker) 
- [**637**星][3m] [C#] [ghostpack/rubeus](https://github.com/ghostpack/rubeus) 
- [**632**星][4y] [PHP] [emposha/php-shell-detector](https://github.com/emposha/php-shell-detector) 
- [**631**星][2m] [Py] [gquere/pwn_jenkins](https://github.com/gquere/pwn_jenkins) 
- [**628**星][5m] [PHP] [l3m0n/bypass_disable_functions_shell](https://github.com/l3m0n/bypass_disable_functions_shell) 
- [**624**星][3y] [PowerShell] [hlldz/invoke-phant0m](https://github.com/hlldz/invoke-phant0m) 
- [**618**星][2y] [PHP] [duoergun0729/1book](https://github.com/duoergun0729/1book) 
- [**615**星][10m] [Py] [dirkjanm/privexchange](https://github.com/dirkjanm/privexchange) 
- [**614**星][2y] [C] [tgraf/bmon](https://github.com/tgraf/bmon) 
- [**611**星][3y] [C] [quiet/quiet-lwip](https://github.com/quiet/quiet-lwip)  create TCP and UDP connections over an audio channel
- [**606**星][1y] [Shell] [wireghoul/htshells](https://github.com/wireghoul/htshells) 
- [**602**星][2m] [JS] [evilsocket/arc](https://github.com/evilsocket/arc) 可用于管理私密数据的工具. 后端是 Go 语言编写的 RESTful 服务器,  前台是Html + JavaScript
- [**598**星][4y] [Py] [hatriot/clusterd](https://github.com/hatriot/clusterd) 
- [**592**星][3y] [C++] [breakingmalwareresearch/atom-bombing](https://github.com/breakingmalwareresearch/atom-bombing) 
- [**592**星][2m] [PHP] [hongrisec/php-audit-labs](https://github.com/hongrisec/php-audit-labs) 
- [**592**星][1m] [PowerShell] [ramblingcookiemonster/powershell](https://github.com/ramblingcookiemonster/powershell) 
- [**589**星][2y] [Py] [secretsquirrel/sigthief](https://github.com/secretsquirrel/sigthief) 
- [**589**星][3m] [Py] [webrecorder/pywb](https://github.com/webrecorder/pywb) 
- [**588**星][2y] [Py] [eldraco/salamandra](https://github.com/eldraco/salamandra) 
- [**584**星][16d] [YARA] [didierstevens/didierstevenssuite](https://github.com/didierstevens/didierstevenssuite) 
- [**583**星][2y] [Java] [findbugsproject/findbugs](https://github.com/findbugsproject/findbugs) 
- [**575**星][8m] [C#] [0xbadjuju/tokenvator](https://github.com/0xbadjuju/tokenvator) 
- [**575**星][9m] [Py] [romanz/amodem](https://github.com/romanz/amodem) transmit a file between 2 computers, using a simple headset, allowing true air-gapped communication (via a speaker and a microphone), or an audio cable (for higher transmission speed)
- [**574**星][8m] [C] [mrexodia/titanhide](https://github.com/mrexodia/titanhide) 
- [**571**星][4y] [C#] [elevenpaths/evilfoca](https://github.com/elevenpaths/evilfoca) 
- [**570**星][3y] [C] [iagox86/hash_extender](https://github.com/iagox86/hash_extender) 
- [**567**星][1y] [C#] [tyranid/dotnettojscript](https://github.com/tyranid/dotnettojscript) 
- [**561**星][1y] [Solidity] [trailofbits/not-so-smart-contracts](https://github.com/crytic/not-so-smart-contracts) 
- [**558**星][5m] [Py] [nidem/kerberoast](https://github.com/nidem/kerberoast)  a series of tools for attacking MS Kerberos implementations
- [**551**星][7y] [C] [katmagic/shallot](https://github.com/katmagic/shallot) 
- [**550**星][10m] [C] [justinsteven/dostackbufferoverflowgood](https://github.com/justinsteven/dostackbufferoverflowgood) 
- [**548**星][7y] [Py] [sensepost/snoopy](https://github.com/sensepost/snoopy) A distributed tracking and data interception framework
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
- [**519**星][1y] [Py] [jseidl/goldeneye](https://github.com/jseidl/goldeneye) 
- [**515**星][11m] [PowerShell] [a-min3/winspect](https://github.com/a-min3/winspect) 
- [**513**星][1m] [Shell] [trailofbits/twa](https://github.com/trailofbits/twa) 
- [**509**星][11m] [Go] [mthbernardes/gtrs](https://github.com/mthbernardes/gtrs) Google Translator Reverse Shell
- [**507**星][1m] [JS] [mr-un1k0d3r/thundershell](https://github.com/mr-un1k0d3r/thundershell) 
- [**507**星][2y] [CSS] [xapax/security](https://github.com/xapax/security) 
- [**505**星][7m] [Visual Basic] [mr-un1k0d3r/maliciousmacrogenerator](https://github.com/mr-un1k0d3r/maliciousmacrogenerator) 
- [**501**星][24d] [Go] [sensepost/gowitness](https://github.com/sensepost/gowitness) Go 语言编写的网站快照工具
- [**499**星][3y] [OCaml] [trustinsoft/tis-interpreter](https://github.com/trustinsoft/tis-interpreter) 
- [**497**星][2y] [JS] [rptec/squid-pac](https://github.com/rptec/squid-pac) 
- [**493**星][2y] [PowerShell] [danielbohannon/invoke-cradlecrafter](https://github.com/danielbohannon/invoke-cradlecrafter) 
- [**490**星][2y] [Go] [evilsocket/sg1](https://github.com/evilsocket/sg1) 用于数据加密、提取和隐蔽通信的瑞士军刀
- [**489**星][2m] [PHP] [nzedb/nzedb](https://github.com/nzedb/nzedb) a fork of nnplus(2011) | NNTP / Usenet / Newsgroup indexer.
- [**488**星][2y] [C++] [rbei-etas/busmaster](https://github.com/rbei-etas/busmaster) 
- [**487**星][1y] [Py] [xyuanmu/xx-mini](https://github.com/xyuanmu/xx-mini) 
- [**486**星][3y] [PowerShell] [secabstraction/powercat](https://github.com/secabstraction/powercat) 
- [**485**星][2m] [Go] [gen2brain/cam2ip](https://github.com/gen2brain/cam2ip) 将任何网络摄像头转换为IP 摄像机
- [**480**星][1y] [Java] [continuumsecurity/bdd-security](https://github.com/continuumsecurity/bdd-security) 
- [**479**星][11m] [Go] [evanmiller/hecate](https://github.com/evanmiller/hecate) The Hex Editor From Hell
- [**476**星][2y] [PowerShell] [gofetchad/gofetch](https://github.com/gofetchad/gofetch) 
- [**475**星][1m] [C] [m0nad/diamorphine](https://github.com/m0nad/diamorphine) 
- [**474**星][10m] [Shell] [craigz28/firmwalker](https://github.com/craigz28/firmwalker) 
- [**474**星][2m] [Go] [gorilla/csrf](https://github.com/gorilla/csrf) 
- [**470**星][2y] [Py] [4w4k3/beelogger](https://github.com/4w4k3/beelogger) 
- [**470**星][2y] [C++] [jessek/hashdeep](https://github.com/jessek/hashdeep) 
- [**468**星][2m] [Py] [bashfuscator/bashfuscator](https://github.com/bashfuscator/bashfuscator) 
- [**465**星][18d] [Py] [aoii103/darknet_chinesetrading](https://github.com/aoii103/darknet_chinesetrading) 
- [**462**星][2y] [Py] [firstlookmedia/pdf-redact-tools](https://github.com/firstlookmedia/pdf-redact-tools) 
- [**460**星][5y] [Perl] [jbittel/httpry](https://github.com/jbittel/httpry) 
- [**457**星][21d] [LLVM] [jonathansalwan/tigress_protection](https://github.com/jonathansalwan/tigress_protection) 
- [**456**星][12m] [Py] [mehulj94/radium](https://github.com/mehulj94/Radium) 
- [**454**星][5m] [C] [phoenhex/files](https://github.com/phoenhex/files) 
- [**453**星][27d] [Go] [gen0cide/gscript](https://github.com/gen0cide/gscript) 基于运行时参数，动态安装恶意软件
- [**449**星][3m] [C++] [omerya/invisi-shell](https://github.com/omerya/invisi-shell) 
- [**448**星][2m] [Py] [bit4woo/teemo](https://github.com/bit4woo/teemo) 
- [**448**星][2m] [PowerShell] [rvrsh3ll/misc-powershell-scripts](https://github.com/rvrsh3ll/misc-powershell-scripts) 
- [**445**星][13d] [Shell] [wireghoul/graudit](https://github.com/wireghoul/graudit) 简单的脚本和签名集，进行源代码审计
- [**445**星][8y] [Perl] [aoncyberlabs/padbuster](https://github.com/AonCyberLabs/PadBuster) 
- [**444**星][9m] [C] [martinmarinov/tempestsdr](https://github.com/martinmarinov/tempestsdr) 
- [**443**星][2m] [Py] [portantier/habu](https://github.com/portantier/habu) Python 编写的网络工具工具包，主要用于教学/理解网络攻击中的一些概念
- [**443**星][1y] [JS] [simonepri/upash](https://github.com/simonepri/upash) 
- [**438**星][3y] [Py] [jekyc/wig](https://github.com/jekyc/wig) WebApp 信息收集器，可识别多种内容管理系统和其他管理程序
- [**437**星][6m] [PHP] [flozz/p0wny-shell](https://github.com/flozz/p0wny-shell) 
- [**432**星][1m] [PowerShell] [mr-un1k0d3r/redteampowershellscripts](https://github.com/mr-un1k0d3r/redteampowershellscripts) 
- [**429**星][2y] [PHP] [arrexel/phpbash](https://github.com/arrexel/phpbash) 
- [**428**星][6m] [Pascal] [mojtabatajik/robber](https://github.com/mojtabatajik/robber) 
- [**428**星][2y] [Py] [undeadsec/evilurl](https://github.com/undeadsec/evilurl) 
- [**426**星][6m] [Py] [stamparm/fetch-some-proxies](https://github.com/stamparm/fetch-some-proxies) 
- [**423**星][4y] [Py] [laramies/metagoofil](https://github.com/laramies/metagoofil) 
- [**423**星][28d] [Py] [super-l/superl-url](https://github.com/super-l/superl-url) 根据关键词，对搜索引擎内容检索结果的网址内容进行采集的一款轻量级软程序。 程序主要运用于安全渗透测试项目，以及批量评估各类CMS系统0DAY的影响程度，同时也是批量采集自己获取感兴趣的网站的一个小程序~~ 可自动从搜索引擎采集相关网站的真实地址与标题等信息，可保存为文件，自动去除重复URL。同时，也可以自定义忽略多条域名等。
- [**421**星][10m] [Py] [d4vinci/cuteit](https://github.com/d4vinci/cuteit) 
- [**409**星][2y] [Py] [51x/whp](https://github.com/51x/whp) 
- [**408**星][10m] [Py] [powerscript/katanaframework](https://github.com/powerscript/katanaframework) 
- [**407**星][2y] [Py] [cloudburst/libheap](https://github.com/cloudburst/libheap) 
- [**404**星][2m] [C++] [hoshimin/kernel-bridge](https://github.com/hoshimin/kernel-bridge) 
- [**401**星][2y] [PowerShell] [danielbohannon/invoke-dosfuscation](https://github.com/danielbohannon/invoke-dosfuscation) 
- [**401**星][5m] [Py] [ytisf/pyexfil](https://github.com/ytisf/pyexfil) 
- [**396**星][2m] [HTML] [w3c/webappsec](https://github.com/w3c/webappsec) 
- [**394**星][3y] [Py] [sekoialab/fastir_collector](https://github.com/sekoialab/fastir_collector) 
- [**387**星][1y] [C#] [squalr/squalr](https://github.com/squalr/squalr) 
- [**385**星][3y] [C#] [harmj0y/keethief](https://github.com/harmj0y/keethief) 
- [**382**星][4y] [Py] [sensepost/snoopy-ng](https://github.com/sensepost/snoopy-ng) 
- [**381**星][3y] [Py] [funkandwagnalls/ranger](https://github.com/funkandwagnalls/ranger) 
- [**380**星][3y] [Py] [ioactive/jdwp-shellifier](https://github.com/ioactive/jdwp-shellifier) 
- [**378**星][1y] [JS] [empireproject/empire-gui](https://github.com/empireproject/empire-gui) 
- [**376**星][1m] [JS] [nccgroup/tracy](https://github.com/nccgroup/tracy) tracy: 查找web app中所有的sinks and sources, 并以易于理解的方式显示这些结果
- [**375**星][13d] [C++] [simsong/bulk_extractor](https://github.com/simsong/bulk_extractor) 
- [**375**星][8m] [Java] [tiagorlampert/saint](https://github.com/tiagorlampert/saint) a Spyware Generator for Windows systems written in Java
- [**373**星][2y] [PowerShell] [gfoss/psrecon](https://github.com/gfoss/psrecon) 
- [**372**星][8m] [Py] [k4m4/onioff](https://github.com/k4m4/onioff) onioff：url检测器，深度检测网页链接
- [**371**星][4y] [C#] [goliate/hidden-tear](https://github.com/goliate/hidden-tear) hidden-tear：开源勒索软件
- [**370**星][2y] [Java] [nickstadb/barmie](https://github.com/nickstadb/barmie) 
- [**368**星][7y] [C++] [opensecurityresearch/dllinjector](https://github.com/opensecurityresearch/dllinjector) 
- [**365**星][1m] [C++] [crypto2011/idr](https://github.com/crypto2011/idr) 
- [**362**星][17d] [C#] [bloodhoundad/sharphound](https://github.com/bloodhoundad/sharphound) 
- [**361**星][20d] [Py] [emtunc/slackpirate](https://github.com/emtunc/slackpirate) 
- [**360**星][26d] [Ruby] [david942j/seccomp-tools](https://github.com/david942j/seccomp-tools) 
- [**360**星][4m] [Shell] [trimstray/otseca](https://github.com/trimstray/otseca) otseca: 安全审计工具, 搜索并转储系统配置
- [**359**星][2y] [C++] [breenmachine/rottenpotatong](https://github.com/breenmachine/rottenpotatong) 
- [**356**星][3y] [Py] [spender-sandbox/cuckoo-modified](https://github.com/spender-sandbox/cuckoo-modified) 
- [**355**星][1y] [bluscreenofjeff/aggressorscripts](https://github.com/bluscreenofjeff/aggressorscripts) 
- [**355**星][2y] [Erlang] [ernw/ss7maper](https://github.com/ernw/ss7maper) 
- [**354**星][2m] [Py] [fox-it/bloodhound.py](https://github.com/fox-it/bloodhound.py) 
- [**352**星][2y] [Shell] [m4sc3r4n0/evil-droid](https://github.com/m4sc3r4n0/evil-droid) 
- [**351**星][6m] [Py] [tidesec/tidefinger](https://github.com/tidesec/tidefinger) 
- [**350**星][10m] [Py] [secynic/ipwhois](https://github.com/secynic/ipwhois) 
- [**350**星][4y] [Py] [aoncyberlabs/evilabigail](https://github.com/AonCyberLabs/EvilAbigail) 
- [**349**星][3y] [C++] [gamehackingbook/gamehackingcode](https://github.com/gamehackingbook/gamehackingcode) 
- [**348**星][2m] [Py] [lockgit/hacking](https://github.com/lockgit/hacking) 
- [**342**星][30d] [Ruby] [sunitparekh/data-anonymization](https://github.com/sunitparekh/data-anonymization) 
- [**340**星][2y] [C] [hfiref0x/dsefix](https://github.com/hfiref0x/dsefix) 
- [**340**星][5y] [Py] [neohapsis/neopi](https://github.com/neohapsis/neopi) a Python script that uses a variety of statistical methods to detect obfuscated and encrypted content within text/script files
- [**339**星][1m] [C] [nccgroup/phantap](https://github.com/nccgroup/phantap) 
- [**338**星][1y] [Ruby] [srcclr/commit-watcher](https://github.com/srcclr/commit-watcher) 
- [**338**星][1y] [Py] [tophanttechnology/osprey](https://github.com/tophanttechnology/osprey) 由TCC(斗象能力中心)出品并长期维护的开源漏洞检测框架
- [**337**星][2y] [Py] [pepitoh/vbad](https://github.com/pepitoh/vbad) 
- [**336**星][4m] [Perl] [keydet89/regripper2.8](https://github.com/keydet89/regripper2.8) 
- [**331**星][12m] [Assembly] [egebalci/amber](https://github.com/egebalci/amber) 
- [**328**星][8m] [Py] [dirkjanm/ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) 
- [**327**星][28d] [PowerShell] [joelgmsec/autordpwn](https://github.com/joelgmsec/autordpwn) 
- [**327**星][1y] [Py] [leapsecurity/inspy](https://github.com/leapsecurity/InSpy) 
- [**325**星][10m] [C#] [ghostpack/sharpdump](https://github.com/ghostpack/sharpdump) 
- [**323**星][5y] [Py] [byt3bl33d3r/pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit) 
- [**322**星][1y] [Shell] [1n3/goohak](https://github.com/1n3/goohak) 
- [**319**星][3y] [Py] [ius/rsatool](https://github.com/ius/rsatool) 
- [**318**星][22d] [Py] [codingo/interlace](https://github.com/codingo/interlace) 
- [**317**星][6y] [C] [diegocr/netcat](https://github.com/diegocr/netcat) 
- [**317**星][1y] [JS] [nccgroup/wssip](https://github.com/nccgroup/wssip) 服务器和客户端之间通信时自定义 WebSocket 数据的捕获、修改和发送。
- [**316**星][1m] [JS] [meituan-dianping/lyrebird](https://github.com/meituan-dianping/lyrebird) 
- [**316**星][1y] [Java] [ysrc/liudao](https://github.com/ysrc/liudao) 
- [**314**星][1y] [Go] [benjojo/bgp-battleships](https://github.com/benjojo/bgp-battleships) 
- [**312**星][2m] [Py] [circl/lookyloo](https://github.com/circl/lookyloo) 
- [**312**星][11m] [crazywa1ker/darthsidious-chinese](https://github.com/crazywa1ker/darthsidious-chinese) 从0开始你的域渗透之旅
- [**311**星][3y] [Py] [chinoogawa/fbht](https://github.com/chinoogawa/fbht) 
- [**311**星][12d] [C] [vanhauser-thc/aflplusplus](https://github.com/vanhauser-thc/aflplusplus) 
- [**310**星][5m] [YARA] [needmorecowbell/hamburglar](https://github.com/needmorecowbell/hamburglar)  collect useful information from urls, directories, and files
- [**307**星][1m] [Go] [wangyihang/platypus](https://github.com/wangyihang/platypus)  A modern multiple reverse shell sessions/clients manager via terminal written in go
- [**306**星][3m] [PowerShell] [enigma0x3/misc-powershell-stuff](https://github.com/enigma0x3/misc-powershell-stuff) 
- [**306**星][4y] [C] [jvinet/knock](https://github.com/jvinet/knock) 
- [**304**星][2m] [Py] [coalfire-research/slackor](https://github.com/coalfire-research/slackor) 
- [**304**星][6m] [C] [pmem/syscall_intercept](https://github.com/pmem/syscall_intercept) Linux系统调用拦截框架，通过 hotpatching 进程标准C库的机器码实现。
- [**303**星][6y] [TeX] [alobbs/macchanger](https://github.com/alobbs/macchanger) makes the maniputation of MAC addresses of network interfaces easier.
- [**302**星][3y] [Py] [bishopfox/spoofcheck](https://github.com/bishopfox/spoofcheck) 
- [**302**星][7m] [C] [tomac/yersinia](https://github.com/tomac/yersinia) yersinia：layer 2 攻击框架
- [**301**星][2y] [Py] [spritz-research-group/skype-type](https://github.com/spritz-research-group/skype-type) 
- [**301**星][2y] [C] [tomwimmenhove/subarufobrob](https://github.com/tomwimmenhove/subarufobrob) 劫持斯巴鲁汽车的钥匙（Subaru's key fob），偷得它连条裤子都不剩
- [**298**星][26d] [Py] [salls/angrop](https://github.com/salls/angrop) a rop gadget finder and chain builder 
- [**298**星][1m] [Py] [skylined/bugid](https://github.com/skylined/bugid) 
- [**296**星][1y] [PowerShell] [onelogicalmyth/zeroday-powershell](https://github.com/onelogicalmyth/zeroday-powershell) 
- [**295**星][6m] [HTML] [nccgroup/crosssitecontenthijacking](https://github.com/nccgroup/crosssitecontenthijacking) 
- [**295**星][1y] [C++] [nevermoe/unity_metadata_loader](https://github.com/nevermoe/unity_metadata_loader)  load strings and method/class names in global-metadata.dat to IDA
- [**295**星][1y] [JS] [xxxily/fiddler-plus](https://github.com/xxxily/fiddler-plus) 
- [**295**星][1y] [C#] [g-e-n-e-s-i-s/loadlibrayy](https://github.com/vmcall/loadlibrayy) 
- [**294**星][27d] [JS] [doyensec/electronegativity](https://github.com/doyensec/electronegativity) 
- [**294**星][13d] [C++] [squalr/squally](https://github.com/squalr/squally) 
- [**292**星][2y] [PowerShell] [outflanknl/invoke-adlabdeployer](https://github.com/outflanknl/invoke-adlabdeployer) 
- [**290**星][2y] [HTML] [dxa4481/cssinjection](https://github.com/dxa4481/cssinjection) 
- [**290**星][3m] [Shell] [fdiskyou/zines](https://github.com/fdiskyou/zines) 
- [**290**星][1m] [C] [mboehme/aflfast](https://github.com/mboehme/aflfast) 
- [**289**星][3y] [PowerShell] [fortynorthsecurity/wmiops](https://github.com/FortyNorthSecurity/WMIOps) 
- [**288**星][2m] [C] [9176324/shark](https://github.com/9176324/shark) 
- [**288**星][3m] [Visual Basic] [itm4n/vba-runpe](https://github.com/itm4n/vba-runpe) 
- [**286**星][8m] [C] [gianlucaborello/libprocesshider](https://github.com/gianlucaborello/libprocesshider) 
- [**286**星][2y] [Py] [kootenpv/gittyleaks](https://github.com/kootenpv/gittyleaks) Discover where your sensitive data has been leaked.
- [**286**星][1y] [Java] [webgoat/webgoat-legacy](https://github.com/webgoat/webgoat-legacy) 
- [**285**星][3m] [Py] [apache/incubator-spot](https://github.com/apache/incubator-spot) 
- [**284**星][6m] [C#] [matterpreter/offensivecsharp](https://github.com/matterpreter/offensivecsharp) 
- [**279**星][11m] [Py] [justicerage/ffm](https://github.com/justicerage/ffm) 
- [**278**星][1m] [Go] [cruise-automation/fwanalyzer](https://github.com/cruise-automation/fwanalyzer) 
- [**278**星][3m] [Py] [joxeankoret/pyew](https://github.com/joxeankoret/pyew) 
- [**277**星][1y] [HTML] [google/p0tools](https://github.com/googleprojectzero/p0tools) 
- [**277**星][16d] [Shell] [trimstray/mkchain](https://github.com/trimstray/mkchain) sslmerge: 建立从根证书到最终用户证书的有效的SSL证书链, 修复不完整的证书链并下载所有缺少的CA证书
- [**276**星][4m] [geerlingguy/ansible-role-security](https://github.com/geerlingguy/ansible-role-security) 
- [**276**星][4y] [XSLT] [ironbee/ironbee](https://github.com/ironbee/ironbee) 
- [**276**星][2m] [Go] [mdsecactivebreach/o365-attack-toolkit](https://github.com/mdsecactivebreach/o365-attack-toolkit) 
- [**275**星][4m] [Py] [opsdisk/pagodo](https://github.com/opsdisk/pagodo) 
- [**275**星][3y] [Py] [pmsosa/duckhunt](https://github.com/pmsosa/duckhunt) Prevent RubberDucky (or other keystroke injection) attacks
- [**273**星][3y] [Py] [maldevel/ipgeolocation](https://github.com/maldevel/ipgeolocation) 
- [**273**星][3m] [PowerShell] [nullbind/powershellery](https://github.com/nullbind/powershellery) 
- [**272**星][9m] [C++] [anhkgg/superdllhijack](https://github.com/anhkgg/superdllhijack) 
- [**272**星][3m] [Py] [invernizzi/scapy-http](https://github.com/invernizzi/scapy-http) 
- [**271**星][3m] [artsploit/solr-injection](https://github.com/artsploit/solr-injection) 
- [**269**星][3y] [C] [firefart/dirtycow](https://github.com/firefart/dirtycow) 
- [**269**星][5y] [leonardonve/sslstrip2](https://github.com/leonardonve/sslstrip2) 
- [**269**星][3y] [Py] [lgandx/responder-windows](https://github.com/lgandx/responder-windows) 
- [**269**星][6m] [Py] [ropnop/windapsearch](https://github.com/ropnop/windapsearch) 
- [**268**星][4m] [Py] [den1al/jsshell](https://github.com/den1al/jsshell) 
- [**268**星][2y] [Py] [lunarca/simpleemailspoofer](https://github.com/lunarca/simpleemailspoofer) 
- [**265**星][3y] [Py] [inaz2/roputils](https://github.com/inaz2/roputils) 
- [**265**星][1y] [l1k/osxparanoia](https://github.com/l1k/osxparanoia) 
- [**265**星][4y] [C] [leechristensen/unmanagedpowershell](https://github.com/leechristensen/unmanagedpowershell) 
- [**264**星][7m] [s0md3v/mypapers](https://github.com/s0md3v/mypapers) 
- [**264**星][7m] [Py] [s0md3v/breacher](https://github.com/s0md3v/Breacher) 
- [**263**星][3y] [C++] [antire-book/dont_panic](https://github.com/antire-book/dont_panic) 
- [**263**星][1y] [Ruby] [evait-security/envizon](https://github.com/evait-security/envizon) envizon: 网络可视化工具, 在渗透测试中快速识别最可能的目标
- [**262**星][2y] [Visual Basic] [cn33liz/starfighters](https://github.com/cn33liz/starfighters) 
- [**262**星][4y] [Py] [cisco-talos/ropmemu](https://github.com/Cisco-Talos/ROPMEMU) 
- [**261**星][2m] [Shell] [al0ne/linuxcheck](https://github.com/al0ne/linuxcheck) 
- [**260**星][10m] [Py] [ant4g0nist/susanoo](https://github.com/ant4g0nist/susanoo) 
- [**260**星][5m] [C++] [d35ha/callobfuscator](https://github.com/d35ha/callobfuscator) 
- [**260**星][3m] [C] [portcullislabs/linikatz](https://github.com/portcullislabs/linikatz) UNIX版本的Mimikatz
- [**259**星][2m] [C] [eua/wxhexeditor](https://github.com/eua/wxhexeditor) 
- [**258**星][25d] [Py] [frint0/email-enum](https://github.com/frint0/email-enum) 
- [**258**星][4y] [Ruby] [lubyruffy/fofa](https://github.com/lubyruffy/fofa) 针对全球范围的最全的网站数据信息库，提供给网民（更多的是安全技术研究人员）进行查询
- [**256**星][1y] [PowerShell] [fox-it/invoke-aclpwn](https://github.com/fox-it/invoke-aclpwn) 
- [**256**星][8m] [C] [landhb/hideprocess](https://github.com/landhb/hideprocess) 
- [**256**星][1y] [Py] [m4ll0k/galileo](https://github.com/m4ll0k/galileo) 
- [**256**星][11m] [Py] [hysnsec/devsecops-studio](https://github.com/hysnsec/DevSecOps-Studio) 
- [**255**星][3y] [Py] [dorneanu/smalisca](https://github.com/dorneanu/smalisca) 
- [**254**星][3y] [C#] [brandonprry/gray_hat_csharp_code](https://github.com/brandonprry/gray_hat_csharp_code) 
- [**254**星][1m] [Shell] [cytoscape/cytoscape](https://github.com/cytoscape/cytoscape) 
- [**254**星][9m] [C] [p0f/p0f](https://github.com/p0f/p0f) 
- [**254**星][3y] [Py] [thomastjdev/wmd](https://github.com/thomastjdev/wmd) 
- [**253**星][1y] [C] [benjamin-42/trident](https://github.com/benjamin-42/trident) 
- [**253**星][3y] [PHP] [hackademic/hackademic](https://github.com/hackademic/hackademic) 
- [**253**星][1y] [Java] [jackofmosttrades/gadgetinspector](https://github.com/jackofmosttrades/gadgetinspector) 
- [**252**星][2m] [C++] [poweradminllc/paexec](https://github.com/poweradminllc/paexec) 
- [**252**星][3y] [Py] [rickey-g/fancybear](https://github.com/rickey-g/fancybear) 
- [**251**星][6m] [Go] [lavalamp-/ipv666](https://github.com/lavalamp-/ipv666) ipv666: IPV6地址枚举工具. Go编写
- [**250**星][14d] [C++] [fransbouma/injectablegenericcamerasystem](https://github.com/fransbouma/injectablegenericcamerasystem) 
- [**250**星][2m] [Py] [hacktoolspack/hack-tools](https://github.com/hacktoolspack/hack-tools) 
- [**249**星][6m] [Py] [itskindred/procspy](https://github.com/itskindred/procspy) 
- [**247**星][14d] [Py] [rvrsh3ll/findfrontabledomains](https://github.com/rvrsh3ll/findfrontabledomains) 
- [**246**星][4m] [Py] [redteamoperations/pivotsuite](https://github.com/redteamoperations/pivotsuite) 
- [**245**星][7y] [Ruby] [urbanesec/zackattack](https://github.com/urbanesec/ZackAttack) 
- [**244**星][7m] [ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet](https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet) wordpress_plugin_security_testing_cheat_sheet：WordPress插件安全测试备忘录。
- [**243**星][9m] [Py] [wh0ale/src-experience](https://github.com/wh0ale/src-experience) 
- [**241**星][2y] [HTML] [arno0x/embedinhtml](https://github.com/arno0x/embedinhtml) 
- [**241**星][2y] [Shell] [h0nus/roguesploit](https://github.com/h0nus/roguesploit) 
- [**241**星][2y] [PowerShell] [leoloobeek/lapstoolkit](https://github.com/leoloobeek/lapstoolkit) 
- [**239**星][2y] [Py] [nirvik/iwant](https://github.com/nirvik/iwant) 
- [**239**星][7m] [Py] [openstack/syntribos](https://github.com/openstack/syntribos) 自动化的 API 安全测试工具
- [**238**星][1y] [Py] [nettitude/prowl](https://github.com/nettitude/prowl) an email harvesting tool that scrapes Yahoo for Linkedin profiles associated to the users search terms and identifies job titles
- [**237**星][2y] [PowerShell] [und3rf10w/aggressor-scripts](https://github.com/und3rf10w/aggressor-scripts) 
- [**236**星][1y] [Py] [matthewclarkmay/geoip-attack-map](https://github.com/matthewclarkmay/geoip-attack-map) 
- [**236**星][8m] [Py] [mazen160/bfac](https://github.com/mazen160/bfac) 自动化 web app 备份文件测试工具，可检测备份文件是否会泄露 web  app 源代码
- [**234**星][15d] [Py] [cisco-config-analysis-tool/ccat](https://github.com/cisco-config-analysis-tool/ccat) 
- [**234**星][3m] [Rust] [hippolot/anevicon](https://github.com/Hippolot/anevicon) 
- [**233**星][2m] [JS] [martinzhou2015/srcms](https://github.com/martinzhou2015/srcms) 
- [**233**星][3y] [Py] [trustedsec/tap](https://github.com/trustedsec/tap) 
- [**231**星][11m] [xcsh/unity-game-hacking](https://github.com/xcsh/unity-game-hacking) 
- [**230**星][29d] [Py] [timlib/webxray](https://github.com/timlib/webxray) 
- [**228**星][1y] [Py] [susmithhck/torghost](https://github.com/SusmithKrishnan/torghost) 
- [**227**星][2y] [Batchfile] [mdsecactivebreach/rdpinception](https://github.com/mdsecactivebreach/rdpinception) 
- [**227**星][5y] [Shell] [s3jensen/iret](https://github.com/s3jensen/iret) 
- [**226**星][10m] [duoergun0729/2book](https://github.com/duoergun0729/2book) 
- [**226**星][7m] [Shell] [r00t-3xp10it/meterpreter_paranoid_mode-ssl](https://github.com/r00t-3xp10it/meterpreter_paranoid_mode-ssl) 
- [**225**星][4y] [Py] [hood3drob1n/jsrat-py](https://github.com/hood3drob1n/jsrat-py) 
- [**225**星][1y] [Go] [netxfly/sec_check](https://github.com/netxfly/sec_check) 服务器安全检测的辅助工具
- [**225**星][3y] [Py] [uber/focuson](https://github.com/uber/focuson) 查找基于 flask 的 Python Web App 安全问题的工具。
- [**224**星][2y] [PHP] [aszone/avenger-sh](https://github.com/aszone/avenger-sh) 
- [**224**星][6m] [JS] [jesusprubio/strong-node](https://github.com/jesusprubio/strong-node) 
- [**224**星][4y] [Py] [trustedsec/spraywmi](https://github.com/trustedsec/spraywmi) 
- [**222**星][2y] [Perl] [csirtgadgets/massive-octo-spice](https://github.com/csirtgadgets/massive-octo-spice) 
- [**222**星][22d] [Py] [webbreacher/whatsmyname](https://github.com/webbreacher/whatsmyname) 
- [**221**星][2m] [Py] [guimaizi/get_domain](https://github.com/guimaizi/get_domain) 域名收集与监测
- [**218**星][1y] [JS] [roccomuso/kickthemout](https://github.com/roccomuso/kickthemout)  Kick devices off your network by performing an ARP Spoof attack with Node.js.
- [**217**星][6m] [bhdresh/dejavu](https://github.com/bhdresh/dejavu) deception framework which can be used to deploy decoys across the infrastructure
- [**217**星][2y] [Py] [maxwellkoh/2fassassin](https://github.com/maxwellkoh/2fassassin) 
- [**217**星][2y] [Py] [vlall/darksearch](https://github.com/vlall/darksearch) query cached onion sites, irc chatrooms, various pdfs, game chats, blackhat forums etc
- [**216**星][6y] [Shell] [silverfoxx/pwnstar](https://github.com/silverfoxx/pwnstar) 
- [**215**星][9m] [Py] [mckinsey666/vocabs](https://github.com/Mckinsey666/vocabs) A lightweight online dictionary integration to the command line
- [**213**星][2y] [C++] [bromiumlabs/packerattacker](https://github.com/bromiumlabs/packerattacker) 
- [**213**星][3m] [JS] [varchashva/letsmapyournetwork](https://github.com/varchashva/letsmapyournetwork) 
- [**212**星][5y] [Py] [bonsaiviking/nfspy](https://github.com/bonsaiviking/nfspy) 
- [**212**星][4m] [Shell] [cryptolok/crykex](https://github.com/cryptolok/crykex) 
- [**212**星][2y] [Py] [trustedsec/egressbuster](https://github.com/trustedsec/egressbuster) 
- [**212**星][1m] [Py] [wazuh/wazuh-ruleset](https://github.com/wazuh/wazuh-ruleset) ruleset is used to detect attacks, intrusions, software misuse, configuration problems, application errors, malware, rootkits, system anomalies or security policy violations.
- [**212**星][8m] [JS] [zhuyingda/veneno](https://github.com/zhuyingda/veneno) 用Node.js编写的Web安全测试框架
- [**211**星][2y] [PowerShell] [cobbr/psamsi](https://github.com/cobbr/psamsi) 
- [**209**星][1y] [basilfx/tradfri-hacking](https://github.com/basilfx/tradfri-hacking) 
- [**209**星][2y] [C++] [xdnice/pcshare](https://github.com/xdnice/pcshare) 远程控制软件，可以监视目标机器屏幕、注册表、文件系统等。
- [**208**星][2y] [Py] [arno0x/ntlmrelaytoews](https://github.com/arno0x/ntlmrelaytoews) 
- [**208**星][5m] [C#] [erfg12/memory.dll](https://github.com/erfg12/memory.dll) 
- [**208**星][2m] [Py] [jordanpotti/cloudscraper](https://github.com/jordanpotti/cloudscraper) Tool to enumerate targets in search of cloud resources. S3 Buckets, Azure Blobs, Digital Ocean Storage Space.
- [**208**星][2y] [JS] [konklone/shaaaaaaaaaaaaa](https://github.com/konklone/shaaaaaaaaaaaaa) 
- [**206**星][2y] [Py] [kamorin/dhcpig](https://github.com/kamorin/dhcpig) 
- [**205**星][4m] [PowerShell] [harmj0y/damp](https://github.com/harmj0y/damp) 
- [**205**星][1y] [OCaml] [montyly/gueb](https://github.com/montyly/gueb) Static analyzer detecting Use-After-Free on binary
- [**205**星][12m] [Py] [orf/xcat](https://github.com/orf/xcat) 辅助盲 Xpath 注入，检索正在由 Xpath 查询处理的整个 XML 文档，读取主机文件系统上的任意文件，并使用出站 HTTP 请求，使服务器将数据直接发送到xcat
- [**205**星][12m] [C#] [tevora-threat/sharpview](https://github.com/tevora-threat/sharpview) 
- [**204**星][8m] [1hack0/facebook-bug-bounty-write-ups](https://github.com/1hack0/facebook-bug-bounty-write-ups) 
- [**204**星][2y] [C#] [them4hd1/vayne-rat](https://github.com/them4hd1/vayne-rat) 
- [**203**星][14d] [Py] [seahoh/gotox](https://github.com/seahoh/gotox) 
- [**201**星][6y] [C#] [0xd4d/antinet](https://github.com/0xd4d/antinet) 
- [**201**星][12d] [CoffeeScript] [bevry/getmac](https://github.com/bevry/getmac) 
- [**201**星][2y] [Py] [joker25000/devploit](https://github.com/joker25000/devploit) 
- [**201**星][6m] [JS] [wingleung/save-page-state](https://github.com/wingleung/save-page-state) 
- [**200**星][1m] [Py] [nyxgeek/lyncsmash](https://github.com/nyxgeek/lyncsmash) 
- [**199**星][1y] [JS] [jpcertcc/sysmonsearch](https://github.com/jpcertcc/sysmonsearch) 
- [**199**星][7m] [Py] [xhak9x/fbi](https://github.com/xhak9x/fbi) 
- [**198**星][1y] [MATLAB] [lts4/deepfool](https://github.com/lts4/deepfool) 
- [**197**星][2y] [Py] [detuxsandbox/detux](https://github.com/detuxsandbox/detux) 
- [**197**星][2y] [C] [lsds/spectre-attack-sgx](https://github.com/lsds/spectre-attack-sgx) 
- [**197**星][2m] [C++] [oisf/libhtp](https://github.com/oisf/libhtp) 
- [**196**星][3m] [HCL] [byt3bl33d3r/red-baron](https://github.com/byt3bl33d3r/red-baron) 
- [**196**星][5m] [Py] [dirkjanm/krbrelayx](https://github.com/dirkjanm/krbrelayx) 
- [**196**星][2y] [Py] [alienvault-otx/apiv2](https://github.com/AlienVault-OTX/ApiV2) quickly identify related infrastructure and malware
- [**194**星][1y] [Rust] [genet-app/genet](https://github.com/genet-app/genet) 网络分析工具, 界面版, 跨平台
- [**193**星][11m] [Py] [hackatnow/djangohunter](https://github.com/hackatnow/djangohunter) 
- [**193**星][11m] [Py] [hackatnow/djangohunter](https://github.com/hackatnow/djangohunter) 
- [**192**星][1y] [Py] [foospidy/dbdat](https://github.com/foospidy/dbdat) performs numerous checks on a database to evaluate security.
- [**192**星][9m] [HTML] [mxmssh/drltrace](https://github.com/mxmssh/drltrace) 
- [**190**星][11m] [Py] [0xr0/shellver](https://github.com/0xr0/shellver) 
- [**190**星][1y] [Py] [nettitude/scrounger](https://github.com/nettitude/scrounger) 
- [**190**星][2m] [onesecure/shadowagentnotes](https://github.com/onesecure/shadowagentnotes) 
- [**190**星][1m] [PowerShell] [sadprocessor/somestuff](https://github.com/sadprocessor/somestuff) 
- [**190**星][2y] [Py] [abdulrah33m/cl0nemast3r](https://github.com/Abdulrah33m/Cl0neMast3r) 
- [**189**星][1m] [Py] [ghostmanager/ghostwriter](https://github.com/ghostmanager/ghostwriter) 
- [**189**星][2m] [Py] [unipacker/unipacker](https://github.com/unipacker/unipacker) 
- [**188**星][14d] [Jupyter Notebook] [hunters-forge/attack-python-client](https://github.com/hunters-forge/ATTACK-Python-Client) 
- [**187**星][7y] [C++] [hzphreak/vminjector](https://github.com/hzphreak/vminjector) 
- [**187**星][1m] [JS] [sindresorhus/internal-ip](https://github.com/sindresorhus/internal-ip) 
- [**185**星][2y] [C++] [ahxr/ghost](https://github.com/ahxr/ghost) a light RAT that gives the server/attacker full remote access to the user's command-line interprete
- [**185**星][2y] [C] [hashcat/maskprocessor](https://github.com/hashcat/maskprocessor) 
- [**184**星][12m] [Py] [d4vinci/pastejacker](https://github.com/d4vinci/pastejacker) 
- [**184**星][2m] [Shell] [jagerzhang/cckiller](https://github.com/jagerzhang/cckiller) 
- [**183**星][11m] [Visual Basic] [dragokas/hijackthis](https://github.com/dragokas/hijackthis) 
- [**183**星][1y] [Py] [mr-un1k0d3r/unibyav](https://github.com/mr-un1k0d3r/unibyav) 
- [**182**星][5y] [Py] [bishopfox/rickmote](https://github.com/bishopfox/rickmote) 
- [**182**星][4m] [C#] [ghostpack/sharpdpapi](https://github.com/ghostpack/sharpdpapi) 
- [**181**星][2m] [Objective-C] [alexxy/netdiscover](https://github.com/alexxy/netdiscover) a network address discovering tool
- [**181**星][3m] [Py] [boy-hack/hack-requests](https://github.com/boy-hack/hack-requests) 给黑客们使用的http底层网络库
- [**181**星][11m] [Py] [crowecybersecurity/ad-ldap-enum](https://github.com/crowecybersecurity/ad-ldap-enum) 
- [**181**星][5y] [C++] [darkwallet/darkleaks](https://github.com/darkwallet/darkleaks) 
- [**180**星][11m] [Py] [boy-hack/gwhatweb](https://github.com/boy-hack/gwhatweb) 网站CMS识别
- [**179**星][6y] [C] [devttys0/littleblackbox](https://github.com/devttys0/littleblackbox) 
- [**179**星][1y] [Py] [fnk0c/cangibrina](https://github.com/fnk0c/cangibrina) 
- [**179**星][2m] [Py] [spiderlabs/ikeforce](https://github.com/spiderlabs/ikeforce) 
- [**179**星][2m] [Py] [stixproject/python-stix](https://github.com/stixproject/python-stix) 
- [**178**星][4m] [Py] [infosecn1nja/maliciousmacromsbuild](https://github.com/infosecn1nja/maliciousmacromsbuild) 
- [**178**星][5m] [Go] [lc/secretz](https://github.com/lc/secretz) 
- [**178**星][2y] [Py] [ninijay/pycurity](https://github.com/ninijay/pycurity) 
- [**178**星][2y] [Py] [nopernik/sshpry2.0](https://github.com/nopernik/sshpry2.0) 
- [**177**星][3y] [Py] [anantshri/svn-extractor](https://github.com/anantshri/svn-extractor) 
- [**177**星][19d] [Py] [fireeye/pwnauth](https://github.com/fireeye/pwnauth) 
- [**175**星][2y] [Py] [netflix-skunkworks/repulsive-grizzly](https://github.com/netflix-skunkworks/repulsive-grizzly) 
- [**175**星][5y] [JS] [samyk/quickjack](https://github.com/samyk/quickjack) 
- [**174**星][6m] [Py] [metachar/mercury](https://github.com/metachar/mercury) 
- [**174**星][7m] [Go] [knownsec/gsm](https://github.com/knownsec/gsm) 
- [**173**星][2y] [PowerShell] [3gstudent/list-rdp-connections-history](https://github.com/3gstudent/list-rdp-connections-history) 
- [**173**星][6m] [Py] [3xp10it/xcdn](https://github.com/3xp10it/xcdn) 
- [**173**星][3m] [Py] [meliht/mr.sip](https://github.com/meliht/mr.sip) 
- [**173**星][3m] [Dockerfile] [obscuritylabs/rai](https://github.com/obscuritylabs/rai) 
- [**172**星][3y] [PowerShell] [infocyte/pshunt](https://github.com/infocyte/pshunt) 
- [**172**星][2y] [Py] [omergunal/hackerbot](https://github.com/omergunal/hackerbot) chatbot 和 hacking 工具的结合版
- [**171**星][1y] [Go] [ice3man543/hawkeye](https://github.com/ice3man543/hawkeye) 
- [**171**星][2y] [Perl] [portcullislabs/enum4linux](https://github.com/portcullislabs/enum4linux) 
- [**171**星][1y] [PHP] [msg-maniac/mail_fishing](https://github.com/SecurityPaper/mail_fishing) 
- [**170**星][4y] [Ruby] [brav0hax/smbexec](https://github.com/brav0hax/smbexec)  A rapid psexec style attack with samba tools 
- [**170**星][1y] [Objective-C] [objective-see/donotdisturb](https://github.com/objective-see/donotdisturb) 
- [**170**星][3y] [HTML] [purpleteam/snarf](https://github.com/purpleteam/snarf) 
- [**170**星][2y] [Py] [securingsam/krackdetector](https://github.com/securingsam/krackdetector) krackdetector：在网络中检测和预防 KRACK 攻击
- [**169**星][7m] [Py] [critical-start/pastebin_scraper](https://github.com/critical-start/pastebin_scraper) monitor pastebin for interesting information
- [**169**星][9m] [HTML] [jensvoid/lorg](https://github.com/jensvoid/lorg) 
- [**169**星][2m] [Py] [sofianehamlaoui/lockdoor-framework](https://github.com/sofianehamlaoui/lockdoor-framework) 
- [**168**星][2y] [Py] [3gstudent/worse-pdf](https://github.com/3gstudent/worse-pdf) 
- [**168**星][1y] [PowerShell] [mattifestation/pic_bindshell](https://github.com/mattifestation/pic_bindshell) 
- [**168**星][1y] [ramen0x3f/aggressorscripts](https://github.com/ramen0x3f/aggressorscripts) 
- [**168**星][5m] [JS] [sindresorhus/ipify](https://github.com/sindresorhus/ipify) 
- [**167**星][6m] [PowerShell] [decoder-it/psgetsystem](https://github.com/decoder-it/psgetsystem) 
- [**167**星][2m] [Py] [the-useless-one/pywerview](https://github.com/the-useless-one/pywerview) 
- [**167**星][6m] [HTML] [trishmapow/rf-jam-replay](https://github.com/trishmapow/rf-jam-replay) 
- [**164**星][1y] [Java] [k-tamura/easybuggy](https://github.com/k-tamura/easybuggy) 
- [**162**星][2y] [PowerShell] [cyberark/riskyspn](https://github.com/cyberark/riskyspn) 
- [**162**星][2y] [HTML] [threatexpress/metatwin](https://github.com/threatexpress/metatwin) 
- [**161**星][6m] [PowerShell] [alsidofficial/wsuspendu](https://github.com/alsidofficial/wsuspendu) 
- [**161**星][2y] [Py] [rajeshmajumdar/ploitkit](https://github.com/rajeshmajumdar/ploitkit) 
- [**161**星][3m] [C++] [strivexjun/aheadlib-x86-x64](https://github.com/strivexjun/aheadlib-x86-x64) 
- [**161**星][2y] [PowerShell] [ubeeri/invoke-usersimulator](https://github.com/ubeeri/invoke-usersimulator) 
- [**160**星][1y] [HTML] [c4o/chinesedarkwebcrawler](https://github.com/c4o/chinesedarkwebcrawler) 
- [**160**星][2y] [Shell] [danilabs/tools-tbhm](https://github.com/danilabs/tools-tbhm) 
- [**158**星][5y] [Py] [netspi/sshkey-grab](https://github.com/netspi/sshkey-grab) 
- [**157**星][10m] [Java] [anbai-inc/javaweb-codereview](https://github.com/anbai-inc/javaweb-codereview) 演示java代码审计的示例程序
- [**157**星][6m] [Java] [bypass007/nessus_to_report](https://github.com/bypass007/nessus_to_report) 
- [**157**星][1m] [Py] [citizenlab/test-lists](https://github.com/citizenlab/test-lists) 
- [**157**星][1y] [Py] [hadiasghari/pyasn](https://github.com/hadiasghari/pyasn) 
- [**157**星][2y] [Py] [joker25000/optiva-framework](https://github.com/joker25000/optiva-framework) 
- [**157**星][30d] [Rust] [hippolot/finshir](https://github.com/Hippolot/finshir) 
- [**156**星][8m] [HTML] [decal/werdlists](https://github.com/decal/werdlists) 
- [**156**星][8y] [C++] [kavika13/remcom](https://github.com/kavika13/remcom) 
- [**156**星][3y] [Shell] [theresalu/rspiducky](https://github.com/theresalu/rspiducky) 
- [**155**星][1y] [C#] [anthemtotheego/sharpcradle](https://github.com/anthemtotheego/sharpcradle) 
- [**155**星][11m] [C] [soldierx/libhijack](https://github.com/soldierx/libhijack) 
- [**154**星][1y] [TypeScript] [handsomeone/scout](https://github.com/handsomeone/scout) 
- [**153**星][7m] [Visual Basic] [christophetd/spoofing-office-macro](https://github.com/christophetd/spoofing-office-macro) a VBA macro spawning a process with a spoofed parent and command line.
- [**153**星][3m] [Py] [gprmax/gprmax](https://github.com/gprmax/gprmax) 
- [**153**星][9m] [Ruby] [hatlord/snmpwn](https://github.com/hatlord/snmpwn) 
- [**153**星][2y] [Go] [ls0f/gortcp](https://github.com/ls0f/gortcp) 
- [**153**星][2y] [Py] [moyix/creddump](https://github.com/moyix/creddump) 
- [**153**星][6m] [PowerShell] [stealthbits/poshkatz](https://github.com/stealthbits/poshkatz) 
- [**152**星][5y] [C] [arisada/midgetpack](https://github.com/arisada/midgetpack) 
- [**151**星][6m] [C#] [anthemtotheego/sharpexec](https://github.com/anthemtotheego/sharpexec) an offensive security C# tool designed to aid with lateral movement
- [**149**星][2m] [C] [cntools/cnping](https://github.com/cntools/cnping) 
- [**148**星][1y] [Py] [sensepost/userenum](https://github.com/sensepost/userenum) 
- [**148**星][9y] [Shell] [spiderlabs/jboss-autopwn](https://github.com/spiderlabs/jboss-autopwn) 
- [**147**星][3y] [Py] [alschwalm/foresight](https://github.com/alschwalm/foresight) 
- [**146**星][5y] [C++] [blankwall/python_pin](https://github.com/blankwall/python_pin) 
- [**146**星][2y] [Py] [rogerhu/gdb-heap](https://github.com/rogerhu/gdb-heap) 
- [**144**星][6y] [Py] [hiddenillusion/analyzepe](https://github.com/hiddenillusion/analyzepe) 
- [**144**星][4y] [Java] [kantega/notsoserial](https://github.com/kantega/notsoserial) 
- [**143**星][1y] [C#] [codewhitesec/lethalhta](https://github.com/codewhitesec/lethalhta) 
- [**143**星][2y] [Ruby] [conradirwin/dotgpg](https://github.com/conradirwin/dotgpg) 
- [**143**星][2m] [C#] [cyberark/zbang](https://github.com/cyberark/zbang) 
- [**143**星][2y] [Shell] [n0pe-sled/postfix-server-setup](https://github.com/n0pe-sled/postfix-server-setup) 
- [**143**星][4m] [Java] [quentinhardy/jndiat](https://github.com/quentinhardy/jndiat) jndiat: 渗透工具, 通过T3协议攻击Weblogic服务器
- [**143**星][7m] [Py] [vysecurity/linkedint](https://github.com/vysecurity/linkedint) 
- [**142**星][2m] [C] [cyrus-and/zizzania](https://github.com/cyrus-and/zizzania) 
- [**142**星][14d] [C] [wmkhoo/taintgrind](https://github.com/wmkhoo/taintgrind) 
- [**141**星][2m] [C] [fgont/ipv6toolkit](https://github.com/fgont/ipv6toolkit) 
- [**141**星][2m] [CSS] [rubyfu/rubyfu](https://github.com/rubyfu/rubyfu) 
- [**141**星][3y] [PowerShell] [sw4mpf0x/powerlurk](https://github.com/sw4mpf0x/powerlurk) 
- [**140**星][1y] [Py] [aatlasis/chiron](https://github.com/aatlasis/chiron)  An IPv6 Security Assessment framework with advanced IPv6 Extension Headers manipulation capabilities.
- [**140**星][2m] [C++] [cybermaggedon/cyberprobe](https://github.com/cybermaggedon/cyberprobe) 
- [**140**星][2y] [C] [tyranid/windows-logical-eop-workshop](https://github.com/tyranid/windows-logical-eop-workshop) source code for my Windows Logical Privilege Escalation workshop examples
- [**139**星][1y] [Py] [codypierce/hackers-grep](https://github.com/codypierce/hackers-grep) 
- [**139**星][2m] [C] [covertcodes/freqwatch](https://github.com/covertcodes/freqwatch) 
- [**139**星][2m] [CoffeeScript] [furqansoftware/node-whois](https://github.com/furqansoftware/node-whois) 
- [**139**星][3y] [PowerShell] [johnnydep/owa-toolkit](https://github.com/johnnydep/owa-toolkit) 
- [**139**星][4y] [Py] [spiderlabs/cribdrag](https://github.com/spiderlabs/cribdrag) 
- [**139**星][3y] [C] [thispc/psiphon](https://github.com/thispc/psiphon) 
- [**138**星][2y] [Py] [cyberark/shimit](https://github.com/cyberark/shimit) 
- [**138**星][24d] [JS] [securecodebox/securecodebox](https://github.com/securecodebox/securecodebox) 
- [**137**星][2y] [Py] [anhkgg/pyrat](https://github.com/anhkgg/pyrat) 
- [**136**星][4y] [Go] [bearded-web/bearded](https://github.com/bearded-web/bearded) 
- [**136**星][2y] [l3m0n/linux_information](https://github.com/l3m0n/linux_information) 
- [**136**星][2y] [Py] [vysecurity/ipfuscator](https://github.com/vysecurity/IPFuscator) 
- [**135**星][2y] [Py] [ctxis/canape](https://github.com/ctxis/canape) 
- [**135**星][4m] [PowerShell] [leechristensen/random](https://github.com/leechristensen/random) 
- [**134**星][1m] [Py] [arch4ngel/eavesarp](https://github.com/arch4ngel/eavesarp) 
- [**134**星][10m] [Py] [bhavsec/reconspider](https://github.com/bhavsec/reconspider) 
- [**134**星][8m] [Py] [bloodhoundad/bloodhound-tools](https://github.com/bloodhoundad/bloodhound-tools) 
- [**134**星][2y] [Rust] [kpcyrd/rshijack](https://github.com/kpcyrd/rshijack) rshijack: TCP连接劫持
- [**133**星][5m] [PHP] [designsecurity/progpilot](https://github.com/designsecurity/progpilot) 
- [**133**星][7y] [Ruby] [mubix/vt-notify](https://github.com/mubix/vt-notify) 
- [**133**星][2y] [C] [silentsignal/sheep-wolf](https://github.com/silentsignal/sheep-wolf) 现实中早已有MD5 碰撞攻击的实例，然而一些安全软件依然已 MD5 标识恶意样本。此工具用于检测安全工具内部是否使用 MD5 标识样本
- [**133**星][7m] [Py] [wmliang/pe-afl](https://github.com/wmliang/pe-afl) 
- [**132**星][3y] [akibsayyed/safeseven](https://github.com/akibsayyed/safeseven) 
- [**132**星][5y] [Py] [ashdnazg/pyreshark](https://github.com/ashdnazg/pyreshark) 
- [**132**星][2m] [Py] [rhinosecuritylabs/ccat](https://github.com/rhinosecuritylabs/ccat) 
- [**132**星][3m] [Py] [threatexpress/cs2modrewrite](https://github.com/threatexpress/cs2modrewrite) 
- [**131**星][2m] [Py] [defense-cyber-crime-center/dc3-mwcp](https://github.com/defense-cyber-crime-center/dc3-mwcp) 
- [**131**星][6m] [Shell] [itskindred/jalesc](https://github.com/itskindred/jalesc) 
- [**131**星][4y] [Py] [ricterz/websocket-injection](https://github.com/ricterz/websocket-injection) 
- [**130**星][4y] [osandamalith/exe2image](https://github.com/osandamalith/exe2image) 
- [**130**星][7m] [shipcod3/mysapadventures](https://github.com/shipcod3/mysapadventures) 
- [**128**星][1y] [C#] [anthemtotheego/sharpsploitconsole](https://github.com/anthemtotheego/sharpsploitconsole) 
- [**126**星][6m] [OCaml] [plum-umd/redexer](https://github.com/plum-umd/redexer) 
- [**124**星][12m] [Shell] [dtag-dev-sec/t-pot-autoinstall](https://github.com/dtag-dev-sec/t-pot-autoinstall) 
- [**124**星][1y] [C] [emptymonkey/mimic](https://github.com/emptymonkey/mimic) 
- [**124**星][2m] [Go] [ullaakut/camerattack](https://github.com/ullaakut/camerattack) 
- [**123**星][3y] [JS] [antojoseph/diff-gui](https://github.com/antojoseph/diff-gui) 
- [**123**星][7m] [C++] [binspector/binspector](https://github.com/binspector/binspector) 
- [**123**星][3y] [C] [davidbuchanan314/pwn-mbr](https://github.com/davidbuchanan314/pwn-mbr) 
- [**121**星][5y] [Py] [urule99/jsunpack-n](https://github.com/urule99/jsunpack-n) 
- [**120**星][2m] [grrrdog/weird_proxies](https://github.com/grrrdog/weird_proxies) 
- [**119**星][4y] [Py] [synack/dylibhijack](https://github.com/synack/dylibhijack) 
- [**119**星][1y] [Py] [wangyihang/reverse-shell-manager](https://github.com/wangyihang/reverse-shell-manager) 
- [**117**星][8m] [Shell] [a-dma/yubitouch](https://github.com/a-dma/yubitouch) 
- [**117**星][4m] [Py] [renatahodovan/grammarinator](https://github.com/renatahodovan/grammarinator) 
- [**115**星][3m] [k0rz3n/googlehacking-page](https://github.com/k0rz3n/googlehacking-page) 
- [**114**星][4m] [C#] [decoder-it/powershellveryless](https://github.com/decoder-it/powershellveryless) 
- [**114**星][2y] [Ruby] [m4sc3r4n0/avoidz](https://github.com/m4sc3r4n0/avoidz) 
- [**112**星][8m] [Py] [williballenthin/evtxtract](https://github.com/williballenthin/evtxtract) 
- [**111**星][5m] [Py] [sagehack/cloud-buster](https://github.com/sagehack/cloud-buster) 
- [**110**星][5y] [C++] [adamkramer/dll_hijack_detect](https://github.com/adamkramer/dll_hijack_detect) 
- [**110**星][2y] [C++] [earthquake/universaldvc](https://github.com/earthquake/universaldvc) 
- [**110**星][7m] [C] [jwbensley/etherate](https://github.com/jwbensley/etherate) 
- [**110**星][4m] [Shell] [merces/bashacks](https://github.com/merces/bashacks) 
- [**110**星][3y] [JS] [nccgroup/typofinder](https://github.com/nccgroup/typofinder) 
- [**110**星][11m] [Py] [sabri-zaki/easy_hack](https://github.com/sabri-zaki/easy_hack) 
- [**110**星][2y] [Py] [tothi/pwn-hisilicon-dvr](https://github.com/tothi/pwn-hisilicon-dvr) 
- [**109**星][2y] [Py] [orange-cyberdefense/fenrir-ocd](https://github.com/orange-cyberdefense/fenrir-ocd) 
- [**108**星][12m] [Shell] [jsitech/relayer](https://github.com/jsitech/relayer) 
- [**108**星][9m] [Py] [m4cs/darkspiritz](https://github.com/m4cs/darkspiritz) 
- [**107**星][10m] [Py] [b3-v3r/hunner](https://github.com/b3-v3r/hunner) 
- [**107**星][1y] [C] [cr4sh/s6_pcie_microblaze](https://github.com/cr4sh/s6_pcie_microblaze) 
- [**107**星][3y] [C] [emptymonkey/shelljack](https://github.com/emptymonkey/shelljack) 
- [**107**星][14d] [Py] [m8r0wn/crosslinked](https://github.com/m8r0wn/crosslinked) 
- [**107**星][6m] [PowerShell] [r4wd3r/rid-hijacking](https://github.com/r4wd3r/rid-hijacking) 
- [**107**星][3y] [C++] [yanncam/exe2powershell](https://github.com/yanncam/exe2powershell) 
- [**106**星][2m] [Py] [altjx/ipwn](https://github.com/altjx/ipwn) 
- [**106**星][1y] [C#] [malcomvetter/csexec](https://github.com/malcomvetter/csexec) 
- [**106**星][2y] [optixal/cehv10-notes](https://github.com/Optixal/CEHv10-Notes) 
- [**105**星][1m] [JS] [p3nt4/nuages](https://github.com/p3nt4/nuages) 
- [**105**星][2y] [Ruby] [porterhau5/bloodhound-owned](https://github.com/porterhau5/bloodhound-owned) 
- [**105**星][8m] [Py] [rootbsd/fridump3](https://github.com/rootbsd/fridump3) 
- [**105**星][10m] [PHP] [rub-nds/metadata-attacker](https://github.com/rub-nds/metadata-attacker) 
- [**104**星][2y] [C++] [mlghuskie/nobastian](https://github.com/mlghuskie/nobastian) 
- [**103**星][27d] [C++] [josh0xa/threadboat](https://github.com/josh0xA/ThreadBoat) 
- [**102**星][14d] [Py] [m8r0wn/activereign](https://github.com/m8r0wn/activereign) 
- [**101**星][2m] [HTML] [w3c/webappsec-csp](https://github.com/w3c/webappsec-csp) 
- [**100**星][10m] [1hack0/bug-bounty-101](https://github.com/1hack0/bug-bounty-101) 
- [**100**星][28d] [Py] [bishopfox/zigdiggity](https://github.com/bishopfox/zigdiggity) 
- [**99**星][3y] [C] [codelion/pathgrind](https://github.com/codelion/pathgrind) 
- [**99**星][3y] [Py] [tbgsecurity/splunk_shells](https://github.com/tbgsecurity/splunk_shells) 
- [**98**星][3y] [PowerShell] [chango77747/adenumerator](https://github.com/chango77747/adenumerator) 
- [**97**星][2y] [PowerShell] [rhinosecuritylabs/aggressor-scripts](https://github.com/rhinosecuritylabs/aggressor-scripts) 
- [**96**星][3y] [C#] [bitbeans/streamcryptor](https://github.com/bitbeans/streamcryptor) 
- [**96**星][3y] [Py] [williballenthin/shellbags](https://github.com/williballenthin/shellbags) 
- [**95**星][5y] [C++] [clymb3r/misc-windows-hacking](https://github.com/clymb3r/misc-windows-hacking) 
- [**95**星][8m] [C#] [djhohnstein/eventlogparser](https://github.com/djhohnstein/eventlogparser) 
- [**95**星][5y] [Py] [eugeniodelfa/smali-cfgs](https://github.com/eugeniodelfa/smali-cfgs) 
- [**95**星][3m] [Go] [furduhlutur/yar](https://github.com/furduhlutur/yar) 
- [**94**星][6y] [Py] [k3170makan/goodork](https://github.com/k3170makan/goodork) 
- [**94**星][4m] [C] [adamlaurie/chronic](https://github.com/AdamLaurie/ChronIC) 
- [**93**星][3y] [Go] [mauri870/powershell-reverse-http](https://github.com/mauri870/powershell-reverse-http) 
- [**92**星][4y] [C] [osandamalith/ipobfuscator](https://github.com/osandamalith/ipobfuscator) 
- [**92**星][1y] [Jupyter Notebook] [positivetechnologies/seq2seq-web-attack-detection](https://github.com/positivetechnologies/seq2seq-web-attack-detection) 
- [**92**星][2y] [C#] [them4hd1/pencrawler](https://github.com/them4hd1/pencrawler) 
- [**91**星][2m] [Py] [abusesa/abusehelper](https://github.com/abusesa/abusehelper) 
- [**91**星][5y] [JS] [etherdream/https_hijack_demo](https://github.com/etherdream/https_hijack_demo) 
- [**91**星][5m] [Py] [fortynorthsecurity/aggressorassessor](https://github.com/fortynorthsecurity/aggressorassessor) 
- [**91**星][6m] [Py] [michyamrane/okadminfinder3](https://github.com/michyamrane/okadminfinder3) 
- [**91**星][1y] [C#] [stufus/reconerator](https://github.com/stufus/reconerator) 
- [**91**星][17d] [Shell] [seajaysec/cypheroth](https://github.com/seajaysec/cypheroth) 
- [**90**星][6m] [C] [abelcheung/rifiuti2](https://github.com/abelcheung/rifiuti2) 
- [**89**星][6m] [Java] [docbleach/docbleach](https://github.com/docbleach/docbleach) 
- [**89**星][3m] [Py] [tomchop/unxor](https://github.com/tomchop/unxor) 
- [**88**星][1m] [Ruby] [ffleming/timing_attack](https://github.com/ffleming/timing_attack) timing_attack：对 Webapp 执行 timing 攻击
- [**87**星][1m] [Py] [xfreed0m/katzkatz](https://github.com/xfreed0m/katzkatz) 
- [**86**星][12m] [Py] [thelsa/tp5-getshell](https://github.com/thelsa/tp5-getshell) 
- [**84**星][2y] [PowerShell] [kacperszurek/gpg_reaper](https://github.com/kacperszurek/gpg_reaper) gpg_reaper: 从gpg-agent缓存/内存中获取/窃取/恢复GPG私钥
- [**83**星][2y] [Shell] [m4sc3r4n0/astroid](https://github.com/m4sc3r4n0/astroid) 
- [**82**星][2y] [Py] [anssi-fr/tabi](https://github.com/anssi-fr/tabi) 
- [**82**星][1y] [C#] [baibaomen/baibaomen.httphijacker](https://github.com/baibaomen/baibaomen.httphijacker) 
- [**82**星][3m] [C] [brainsmoke/ptrace-burrito](https://github.com/brainsmoke/ptrace-burrito) 
- [**81**星][2y] [C] [hvqzao/foolavc](https://github.com/hvqzao/foolavc) 
- [**81**星][23d] [PHP] [nao-sec/ektotal](https://github.com/nao-sec/ektotal) ektotal: 分析Drive-by Download攻击的集成工具
- [**80**星][9m] [Java] [7ym0n/security](https://github.com/7ym0n/security) 
- [**80**星][4y] [C#] [david-risney/csp-fiddler-extension](https://github.com/david-risney/csp-fiddler-extension) 
- [**80**星][2m] [nightowl131/aapg](https://github.com/nightowl131/aapg) 
- [**80**星][3y] [yeyintminthuhtut/awesome-study-resources-for-kernel-hacking](https://github.com/yeyintminthuhtut/awesome-study-resources-for-kernel-hacking) 
- [**79**星][12m] [C#] [djhohnstein/.net-profiler-dll-hijack](https://github.com/djhohnstein/.net-profiler-dll-hijack) 
- [**79**星][16d] [TeX] [kramse/security-courses](https://github.com/kramse/security-courses) 
- [**79**星][2m] [Py] [pfalcon/scratchablock](https://github.com/pfalcon/scratchablock) 
- [**78**星][1y] [Ruby] [frohoff/ciphr](https://github.com/frohoff/ciphr) 
- [**78**星][1y] [Go] [oftn-oswg/zerodrop](https://github.com/oftn-oswg/zerodrop) 
- [**76**星][28d] [Py] [m8r0wn/pymeta](https://github.com/m8r0wn/pymeta) pymeta: 搜索某域名网站的文件,下载并提取元数据, 例如: 域名、用户名、软件版本号、命名约定等
- [**76**星][2m] [C++] [rjhansen/nsrllookup](https://github.com/rjhansen/nsrllookup) 
- [**75**星][6y] [Py] [hiddenillusion/ipinfo](https://github.com/hiddenillusion/ipinfo) 
- [**75**星][9m] [Py] [ztgrace/red_team_telemetry](https://github.com/ztgrace/red_team_telemetry) 
- [**74**星][2y] [Py] [threatexpress/tinyshell](https://github.com/threatexpress/tinyshell) 
- [**74**星][2y] [Assembly] [zznop/pop-nedry](https://github.com/zznop/pop-nedry) 
- [**72**星][5m] [Py] [milo2012/ipv4bypass](https://github.com/milo2012/ipv4bypass) ipv4Bypass: 利用ipV6绕过安全防护
- [**71**星][5y] [Py] [ksoona/attackvector](https://github.com/ksoona/attackvector) 
- [**71**星][3y] [C] [moyix/panda](https://github.com/moyix/panda) 
- [**71**星][3y] [Py] [scumsec/recon-ng-modules](https://github.com/scumsec/recon-ng-modules) 
- [**70**星][2y] [Py] [n4xh4ck5/rastleak](https://github.com/n4xh4ck5/rastleak) 
- [**69**星][7m] [JS] [aqiongbei/buy_pig_plan](https://github.com/aqiongbei/buy_pig_plan) 
- [**69**星][3y] [Py] [dchrastil/ttsl](https://github.com/dchrastil/ttsl) 
- [**69**星][4y] [Py] [v-p-b/pecloakcapstone](https://github.com/v-p-b/pecloakcapstone) 
- [**68**星][5m] [Java] [c0d3p1ut0s/java-security-manager-bypass](https://github.com/c0d3p1ut0s/java-security-manager-bypass) 
- [**68**星][3m] [Go] [gen0cide/laforge](https://github.com/gen0cide/laforge) 
- [**67**星][5y] [PowerShell] [cheetz/powertools](https://github.com/cheetz/powertools) 
- [**67**星][3m] [PowerShell] [jaredhaight/windowsattackanddefenselab](https://github.com/jaredhaight/windowsattackanddefenselab) 
- [**66**星][12m] [C#] [cobbr/sharpshell](https://github.com/cobbr/sharpshell) 
- [**66**星][4y] [Py] [jpsenior/threataggregator](https://github.com/jpsenior/threataggregator) 
- [**66**星][8y] [JS] [therook/csrf-request-builder](https://github.com/therook/csrf-request-builder) 
- [**65**星][2y] [Py] [mazenelzanaty/twlocation](https://github.com/mazenelzanaty/twlocation) 
- [**65**星][2y] [C++] [not-wlan/driver-hijack](https://github.com/not-wlan/driver-hijack) 
- [**65**星][2y] [Py] [tbarabosch/quincy](https://github.com/tbarabosch/quincy) 在内存转储中检测基于主机的代码注入攻击
- [**65**星][9m] [Py] [phxbandit/scripts-and-tools](https://github.com/phxbandit/scripts-and-tools) 
- [**64**星][2y] [Go] [0c34/govwa](https://github.com/0c34/govwa) 
- [**64**星][1m] [C] [qwaz/solved-hacking-problem](https://github.com/qwaz/solved-hacking-problem) 
- [**63**星][4m] [Py] [itskindred/redviper](https://github.com/itskindred/redviper) 
- [**63**星][2y] [josephlhall/dc25-votingvillage-report](https://github.com/josephlhall/dc25-votingvillage-report) 
- [**63**星][27d] [HTML] [santandersecurityresearch/asvs](https://github.com/santandersecurityresearch/asvs) 
- [**63**星][4y] [Py] [nsacyber/splunk-assessment-of-mitigation-implementations](https://github.com/nsacyber/Splunk-Assessment-of-Mitigation-Implementations) 
- [**62**星][10m] [Py] [cse-assemblyline/assemblyline](https://bitbucket.org/cse-assemblyline/assemblyline) 
- [**62**星][2y] [3gstudent/bitsadminexec](https://github.com/3gstudent/bitsadminexec) 利用bitsadmin 实现驻留，以及自动运行
- [**62**星][1y] [C] [emptymonkey/drinkme](https://github.com/emptymonkey/drinkme) drinkme：从 stdin 读取 ShellCode 并执行。用于部署 ShellCode 之前测试
- [**62**星][3y] [Py] [hackinglab/mobilesf](https://github.com/hackinglab/mobilesf) 
- [**62**星][8m] [PowerShell] [sadprocessor/cypherdog](https://github.com/sadprocessor/cypherdog) 
- [**61**星][4y] [Py] [michael-yip/maltegovt](https://github.com/michael-yip/maltegovt) 
- [**61**星][4y] [C++] [null--/graviton](https://github.com/null--/graviton) 
- [**61**星][1m] [Py] [mazen160/jwt-pwn](https://github.com/mazen160/jwt-pwn) 
- [**60**星][1y] [Py] [anssi-fr/audit-radius](https://github.com/anssi-fr/audit-radius) 
- [**60**星][5y] [Go] [arlolra/meek](https://github.com/arlolra/meek) 
- [**60**星][5y] [PHP] [nccgroup/webfeet](https://github.com/nccgroup/webfeet) 
- [**59**星][3y] [PowerShell] [nettitude/powershell](https://github.com/nettitude/powershell) 
- [**59**星][8y] [Py] [sensepost/anapickle](https://github.com/sensepost/anapickle) 
- [**59**星][11m] [Py] [s0md3v/infinity](https://github.com/ultimatehackers/infinity) 
- [**59**星][20d] [Py] [b17zr/ntlm_challenger](https://github.com/b17zr/ntlm_challenger) 
- [**58**星][5y] [C++] [ivanfratric/ropguard](https://github.com/ivanfratric/ropguard) 
- [**58**星][7m] [Py] [ultrasecurity/telekiller](https://github.com/ultrasecurity/telekiller) 
- [**57**星][1y] [PowerShell] [invokethreatguy/csasc](https://github.com/invokethreatguy/csasc) 
- [**57**星][3m] [m507/awae-preparation](https://github.com/m507/awae-preparation) 
- [**57**星][2y] [Py] [vivami/ms17-010](https://github.com/vivami/ms17-010) 
- [**57**星][1y] [Py] [warflop/whoisleak](https://github.com/warflop/whoisleak) 
- [**57**星][5m] [JS] [doctormckay/node-globaloffensive](https://github.com/doctormckay/node-globaloffensive) 
- [**56**星][9m] [Py] [dogoncouch/logdissect](https://github.com/dogoncouch/logdissect) 
- [**56**星][5y] [Py] [foreni-packages/dhcpig](https://github.com/foreni-packages/dhcpig) 
- [**56**星][5y] [Ruby] [jekil/hostmap](https://github.com/jekil/hostmap) 
- [**54**星][2y] [PowerShell] [whitehat-zero/powenum](https://github.com/whitehat-zero/powenum) 
- [**53**星][14d] [PowerShell] [chef-koch/windows-10-hardening](https://github.com/chef-koch/windows-10-hardening) 
- [**53**星][3m] [Py] [dogoncouch/logesp](https://github.com/dogoncouch/logesp) 
- [**53**星][3m] [Py] [trickster0/enyx](https://github.com/trickster0/enyx) 
- [**53**星][4y] [Py] [zenfish/ipmi](https://github.com/zenfish/ipmi) 
- [**52**星][11m] [chryzsh/practical-hacking](https://github.com/chryzsh/practical-hacking) 
- [**52**星][9m] [Py] [fox-it/bloodhound-import](https://github.com/fox-it/bloodhound-import) 
- [**52**星][2y] [Py] [joker25000/dzjecter](https://github.com/joker25000/dzjecter) 
- [**52**星][1y] [Py] [torque59/garfield](https://github.com/torque59/garfield) 
- [**51**星][1y] [Py] [hiddenillusion/nomorexor](https://github.com/hiddenillusion/nomorexor) 
- [**51**星][4y] [C] [osbock/baldwisdom](https://github.com/osbock/baldwisdom) 
- [**51**星][27d] [Perl] [pepelux/sippts](https://github.com/pepelux/sippts) 
- [**51**星][4m] [Visual Basic] [thesph1nx/slickermaster-rev4](https://github.com/thesph1nx/slickermaster-rev4) 
- [**50**星][9y] [Perl] [spiderlabs/thicknet](https://github.com/spiderlabs/thicknet) 
- [**50**星][3y] [Py] [zengqiu/study](https://github.com/zengqiu/study) 
- [**49**星][8m] [Shell] [mthbernardes/lfi-enum](https://github.com/mthbernardes/lfi-enum) 
- [**49**星][3y] [Py] [n0pe-sled/apache2-mod-rewrite-setup](https://github.com/n0pe-sled/apache2-mod-rewrite-setup) 
- [**49**星][2y] [Py] [steinsgatep001/binary](https://github.com/steinsgatep001/binary) 
- [**48**星][1y] [Shell] [evyatarmeged/stegextract](https://github.com/evyatarmeged/stegextract) 
- [**48**星][7m] [Shell] [screetsec/imr0t](https://github.com/screetsec/imr0t) 
- [**48**星][2y] [JS] [vegabird/prithvi](https://github.com/vegabird/prithvi) 
- [**47**星][2y] [C] [fail0verflow/switch-arm-trusted-firmware](https://github.com/fail0verflow/switch-arm-trusted-firmware) 
- [**47**星][19d] [Py] [snovvcrash/fwdsh3ll](https://github.com/snovvcrash/fwdsh3ll) 
- [**47**星][1y] [C] [squalr/selfhackingapp](https://github.com/squalr/selfhackingapp) 
- [**46**星][20d] [PowerShell] [lkys37en/start-adenum](https://github.com/lkys37en/start-adenum) 
- [**46**星][2y] [JS] [rnehra01/arp-validator](https://github.com/rnehra01/arp-validator) arp-validator: 检测ARP 投毒攻击
- [**46**星][2y] [hdm/2017-bsideslv-modern-recon](https://github.com/hdm/2017-BSidesLV-Modern-Recon) 
- [**45**星][7m] [C#] [im0qianqian/codeforceseduhacking](https://github.com/im0qianqian/codeforceseduhacking) 
- [**44**星][2y] [PowerShell] [3gstudent/windows-user-clone](https://github.com/3gstudent/windows-user-clone) 
- [**44**星][2y] [PowerShell] [attackdebris/babel-sf](https://github.com/attackdebris/babel-sf) 
- [**44**星][3y] [PowerShell] [harmj0y/encryptedstore](https://github.com/harmj0y/encryptedstore) 
- [**44**星][10m] [Java] [portswigger/json-web-token-attacker](https://github.com/portswigger/json-web-token-attacker) 
- [**43**星][3m] [bc-security/defcon27](https://github.com/bc-security/defcon27) 
- [**43**星][4m] [PowerShell] [miladmsft/threathunt](https://github.com/miladmsft/threathunt) 
- [**43**星][5y] [Py] [pun1sh3r/facebot](https://github.com/pun1sh3r/facebot) 
- [**43**星][5m] [Py] [virink/awd_auto_attack_framework](https://github.com/virink/awd_auto_attack_framework) 
- [**41**星][2y] [JS] [bahmutov/ban-sensitive-files](https://github.com/bahmutov/ban-sensitive-files) 
- [**41**星][2y] [HCL] [bneg/redteam-automation](https://github.com/bneg/redteam-automation) 
- [**41**星][1y] [Py] [spiderlabs/firework](https://github.com/spiderlabs/firework) 
- [**40**星][2y] [JS] [agjmills/form-scrape](https://github.com/agjmills/form-scrape) form-scrape：示例chrome 扩展，以演示将JavaScript和html注入页面的危险
- [**40**星][6y] [Py] [nccgroup/lapith](https://github.com/nccgroup/lapith) 
- [**40**星][4y] [Py] [rooklabs/milano](https://github.com/rooklabs/milano) 
- [**39**星][4y] [C] [laginimaineb/waroftheworlds](https://github.com/laginimaineb/waroftheworlds) 
- [**39**星][2y] [Shell] [zephrfish/attackdeploy](https://github.com/zephrfish/attackdeploy) 
- [**38**星][3y] [Py] [0x90/upnp-arsenal](https://github.com/0x90/upnp-arsenal) 
- [**38**星][4y] [C++] [lingerhk/0net](https://github.com/lingerhk/0net) 
- [**38**星][2y] [Py] [mcw0/pwn-hisilicon-dvr](https://github.com/mcw0/pwn-hisilicon-dvr) 
- [**38**星][9m] [PowerShell] [rootup/redteam](https://github.com/rootup/redteam) 
- [**38**星][12m] [Py] [initstring/evil-ssdp](https://gitlab.com/initstring/evil-ssdp) 
- [**37**星][6m] [Py] [coalfire-research/vampire](https://github.com/coalfire-research/vampire) 
- [**37**星][1y] [Ruby] [dreadlocked/ssrfmap](https://github.com/dreadlocked/ssrfmap) 
- [**37**星][12m] [ekoparty/ekolabs](https://github.com/ekoparty/ekolabs) 
- [**37**星][2y] [C++] [mstefanowich/filesignaturehijack](https://github.com/mstefanowich/filesignaturehijack) 
- [**37**星][2m] [Py] [redhatgov/soscleaner](https://github.com/soscleaner/soscleaner) 
- [**36**星][2y] [PHP] [mortedamos/vehicle-hacking](https://github.com/mortedamos/vehicle-hacking) 
- [**36**星][9m] [C++] [nanoric/pkn](https://github.com/nanoric/pkn) 
- [**35**星][2y] [PowerShell] [clr2of8/commentator](https://github.com/clr2of8/commentator) 
- [**35**星][3y] [PowerShell] [machosec/mystique](https://github.com/machosec/mystique) 
- [**35**星][1y] [C] [prodicode/arppd](https://github.com/prodicode/arppd) 
- [**35**星][2y] [ritiek/rat-via-telegram](https://github.com/ritiek/rat-via-telegram) 
- [**35**星][2y] [technicaldada/best-hacking-tools](https://github.com/technicaldada/best-hacking-tools) 
- [**34**星][3y] [CSS] [cysca/cysca2015](https://github.com/cysca/cysca2015) 
- [**34**星][4m] [Rust] [kpcyrd/boxxy-rs](https://github.com/kpcyrd/boxxy-rs) 
- [**34**星][2y] [Py] [peewpw/domainfrontdiscover](https://github.com/peewpw/domainfrontdiscover) 
- [**34**星][2y] [secgroundzero/cs-aggressor-scripts](https://github.com/secgroundzero/cs-aggressor-scripts) 
- [**34**星][2y] [C] [smh17/bitcoin-hacking-tools](https://github.com/smh17/bitcoin-hacking-tools) 
- [**34**星][3y] [Shell] [superkojiman/snuff](https://github.com/superkojiman/snuff) 
- [**34**星][19d] [Py] [x-vector/x-rsa](https://github.com/x-vector/x-rsa) 
- [**33**星][6y] [Py] [averagesecurityguy/twanalyze](https://github.com/averagesecurityguy/twanalyze) 
- [**33**星][11m] [CSS] [nowsecure/r2frida-book](https://github.com/nowsecure/r2frida-book) 
- [**32**星][6m] [Py] [bishopfox/idontspeakssl](https://github.com/bishopfox/idontspeakssl) 
- [**32**星][4y] [C] [dennisaa/patharmor](https://github.com/dennisaa/patharmor) 
- [**32**星][1y] [JS] [notdls/hackbar](https://github.com/notdls/hackbar) 
- [**32**星][1y] [Shell] [securityriskadvisors/redteamsiem](https://github.com/securityriskadvisors/redteamsiem) 
- [**32**星][2y] [PHP] [sjord/jwtdemo](https://github.com/sjord/jwtdemo) 
- [**31**星][2y] [Shell] [bluscreenofjeff/scripts](https://github.com/bluscreenofjeff/scripts) 
- [**31**星][5m] [Py] [charliedean/psexecspray](https://github.com/charliedean/psexecspray) 
- [**31**星][1y] [Go] [naltun/eyes](https://github.com/naltun/eyes) 
- [**31**星][2y] [Py] [redteam-cyberark/google-domain-fronting](https://github.com/redteam-cyberark/google-domain-fronting) 
- [**31**星][2y] [Py] [rurik/java_idx_parser](https://github.com/rurik/java_idx_parser) 
- [**30**星][6y] [Shell] [installation/rkhunter](https://github.com/installation/rkhunter) 
- [**30**星][4m] [C#] [mgeeky/stracciatella](https://github.com/mgeeky/stracciatella) 
- [**30**星][9m] [Java] [secdec/attack-surface-detector-zap](https://github.com/secdec/attack-surface-detector-zap) 
- [**29**星][10m] [c++] [camp0/aiengine](https://bitbucket.org/camp0/aiengine) 
- [**29**星][5y] [Py] [haxorthematrix/loc-nogps](https://github.com/haxorthematrix/loc-nogps) 
- [**29**星][1m] [Shell] [sandrokeil/yubikey-full-disk-encryption-secure-boot-uefi](https://github.com/sandrokeil/yubikey-full-disk-encryption-secure-boot-uefi) 
- [**28**星][1y] [PowerShell] [demonsec666/security-toolkit](https://github.com/demonsec666/security-toolkit) 
- [**28**星][1m] [Py] [dmaasland/mcfridafee](https://github.com/dmaasland/mcfridafee) 
- [**28**星][5y] [C++] [hempnall/broyara](https://github.com/hempnall/broyara) 
- [**28**星][7y] [Ruby] [jjyg/ssh_decoder](https://github.com/jjyg/ssh_decoder) 
- [**28**星][6y] [Py] [kholia/exetractor-clone](https://github.com/kholia/exetractor-clone) 
- [**28**星][2y] [Py] [ne0nd0g/guinevere](https://github.com/ne0nd0g/guinevere) 
- [**28**星][2y] [C++] [vic4key/cat-driver](https://github.com/vic4key/cat-driver) 
- [**27**星][2y] [0x90/nrf24-arsenal](https://github.com/0x90/nrf24-arsenal) 
- [**27**星][2y] [PowerShell] [3gstudent/com-object-hijacking](https://github.com/3gstudent/com-object-hijacking) 
- [**27**星][8y] [Py] [9b/pdfxray_lite](https://github.com/9b/pdfxray_lite) 
- [**27**星][1y] [PowerShell] [danmcinerney/invoke-cats](https://github.com/danmcinerney/invoke-cats) 
- [**27**星][4m] [C] [ispras/qemu](https://github.com/ispras/qemu) 
- [**27**星][3m] [C++] [lianglixin/remotecontrol-x3](https://github.com/lianglixin/remotecontrol-x3) 
- [**27**星][12m] [C] [rapid7/mimikatz](https://github.com/rapid7/mimikatz) 
- [**27**星][10m] [Smali] [strazzere/emacs-smali](https://github.com/strazzere/emacs-smali) 
- [**27**星][2y] [JS] [supersaiyansss/wechatspider](https://github.com/supersaiyansss/wechatspider) 
- [**27**星][4m] [Java] [usdag/cstc](https://github.com/usdag/cstc) 
- [**26**星][4y] [atktgs/blackhat2015arsenal](https://github.com/atktgs/blackhat2015arsenal) 
- [**26**星][8m] [Py] [joda32/got-responded](https://github.com/joda32/got-responded) 
- [**26**星][5y] [JS] [lubyruffy/livemapdemo](https://github.com/lubyruffy/livemapdemo) 
- [**26**星][25d] [Py] [qsecure-labs/overlord](https://github.com/qsecure-labs/overlord) 
- [**26**星][4y] [Py] [williballenthin/python-evt](https://github.com/williballenthin/python-evt) 
- [**25**星][2y] [andrew-morris/presentations](https://github.com/andrew-morris/presentations) 
- [**25**星][5y] [JS] [cryptographrix/hootoo_ht-tm05-hacking](https://github.com/cryptographrix/hootoo_ht-tm05-hacking) 
- [**25**星][5y] [C] [gdbinit/rex_versus_the_romans](https://github.com/gdbinit/rex_versus_the_romans) 
- [**25**星][6y] [Py] [marshyski/sshwatch](https://github.com/marshyski/sshwatch) 
- [**25**星][2y] [Py] [sc0tfree/netbyte](https://github.com/sc0tfree/netbyte) 
- [**25**星][4y] [cure53/publications](https://github.com/cure53/publications) 
- [**24**星][2y] [Py] [0verl0ad/dumb0](https://github.com/0verl0ad/dumb0) 
- [**24**星][6y] [Py] [batteryshark/miasma](https://github.com/batteryshark/miasma) 
- [**24**星][3y] [Py] [bounteous/libenom](https://github.com/bounteous/libenom) 
- [**24**星][4y] [C] [fortiguard-lion/anti-dll-hijacking](https://github.com/fortiguard-lion/anti-dll-hijacking) 
- [**24**星][1m] [infosec-community/apac-meetups](https://github.com/infosec-community/apac-meetups) 
- [**24**星][2m] [Py] [mrwn007/m3m0](https://github.com/mrwn007/m3m0) 
- [**24**星][1y] [Py] [thelsa/ecshop-getshell](https://github.com/thelsa/ecshop-getshell) 
- [**24**星][1y] [C] [wchill/defcon26_badgehacking](https://github.com/wchill/defcon26_badgehacking) 
- [**23**星][3m] [Py] [ghostofgoes/adles](https://github.com/ghostofgoes/adles) 
- [**23**星][2y] [Go] [himei29a/gichidan](https://github.com/himei29a/gichidan) 
- [**23**星][6y] [infosecsmith/mimikatzlite](https://github.com/infosecsmith/mimikatzlite) 
- [**23**星][4y] [Shell] [kisom/surfraw](https://github.com/kisom/surfraw) 
- [**22**星][3y] [Py] [almco/panorama](https://github.com/almco/panorama) 
- [**22**星][3y] [Py] [guelfoweb/fbid](https://github.com/guelfoweb/fbid) 
- [**22**星][3y] [C] [josephjkong/designing-bsd-rootkits](https://github.com/josephjkong/designing-bsd-rootkits) 
- [**22**星][4y] [C#] [leechristensen/offensivepowershelltasking](https://github.com/leechristensen/offensivepowershelltasking) 
- [**22**星][1y] [Py] [nicksanzotta/linkscrape](https://github.com/nicksanzotta/linkscrape) 
- [**22**星][3y] [C++] [sensepost/misc-windows-hacking](https://github.com/sensepost/misc-windows-hacking) 
- [**22**星][2y] [Py] [whitel1st/gp_hijack](https://github.com/whitel1st/gp_hijack) 
- [**22**星][2m] [security-prince/resources-for-application-security](https://github.com/security-prince/Resources-for-Application-Security) 
- [**21**星][2y] [Py] [mdsecresearch/thriftdecoder](https://github.com/mdsecresearch/thriftdecoder) 
- [**21**星][1y] [spchal/hacklu2018](https://github.com/spchal/hacklu2018) 
- [**20**星][7m] [Java] [cryptomator/siv-mode](https://github.com/cryptomator/siv-mode) 
- [**20**星][6y] [Shell] [netspi/binrev](https://github.com/netspi/binrev) 
- [**20**星][10m] [Java] [rub-nds/joseph](https://github.com/rub-nds/joseph) 


### <a id="f34b4da04f2a77a185729b5af752efc5"></a>未分类






***


## <a id="cc80626cfd1f8411b968373eb73bc4ea"></a>人工智能&&机器学习&&深度学习&&神经网络


### <a id="19dd474da6b715024ff44d27484d528a"></a>未分类-AI


- [**4216**星][25d] [Py] [tensorflow/cleverhans](https://github.com/tensorflow/cleverhans) cleverhans：基准测试（benchmark）机器学习系统的漏洞生成（to）对抗样本（adversarial examples）
- [**3542**星][6y] [R] [johnmyleswhite/ml_for_hackers](https://github.com/johnmyleswhite/ml_for_hackers) 
- [**3263**星][18d] [jivoi/awesome-ml-for-cybersecurity](https://github.com/jivoi/awesome-ml-for-cybersecurity) 针对网络安全的机器学习资源列表
- [**2480**星][15d] [Py] [evilsocket/pwnagotchi](https://github.com/evilsocket/pwnagotchi) 
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**1049**星][1m] [Py] [13o-bbr-bbq/machine_learning_security](https://github.com/13o-bbr-bbq/machine_learning_security) 
- [**569**星][20d] [404notf0und/ai-for-security-learning](https://github.com/404notf0und/ai-for-security-learning) 
- [**513**星][21d] [Py] [gyoisamurai/gyoithon](https://github.com/gyoisamurai/gyoithon) 使用机器学习的成长型渗透测试工具
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/渗透多合一&&渗透框架](#2051fd9e171f2698d8e7486e3dd35d87) |
- [**453**星][2y] [Jupyter Notebook] [saurabhmathur96/clickbait-detector](https://github.com/saurabhmathur96/clickbait-detector) 
- [**445**星][4m] [Py] [cchio/deep-pwning](https://github.com/cchio/deep-pwning) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Metasploit/未分类-metasploit](#01be61d5bb9f6f7199208ff0fba86b5d) |
- [**323**星][3y] [Py] [faizann24/fwaf-machine-learning-driven-web-application-firewall](https://github.com/faizann24/fwaf-machine-learning-driven-web-application-firewall) 
    - 重复区段: [工具/防护&&Defense/防火墙&&FireWall](#ce6532938f729d4c9d66a5c75d1676d3) |
- [**283**星][1m] [Py] [bishopfox/eyeballer](https://github.com/bishopfox/eyeballer) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |
- [**235**星][3y] [Py] [ftramer/steal-ml](https://github.com/ftramer/steal-ml) 
- [**197**星][3y] [Py] [faizann24/using-machine-learning-to-detect-malicious-urls](https://github.com/faizann24/using-machine-learning-to-detect-malicious-urls) 
- [**171**星][3y] [Py] [tonybeltramelli/deep-spying](https://github.com/tonybeltramelli/deep-spying) 
- [**134**星][8m] [Py] [jzadeh/aktaion](https://github.com/jzadeh/aktaion) 基于微行为（Micro Behavior）的漏洞检测和自动化GPO策略生成
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞扫描&&挖掘&&发现/漏洞扫描/未分类](#0ed7e90d216a8a5be1dafebaf9eaeb5d) |
- [**134**星][1y] [Py] [packtpublishing/mastering-machine-learning-for-penetration-testing](https://github.com/packtpublishing/mastering-machine-learning-for-penetration-testing) 书：Mastering Machine Learning for Penetration Testing
- [**102**星][2y] [Py] [cylance/introductiontomachinelearningforsecuritypros](https://github.com/cylance/IntroductionToMachineLearningForSecurityPros) 书的示例代码：Introduction to Artificial Intelligence for Security Professionals
- [**92**星][2y] [Py] [lcatro/webshell-detect-by-machine-learning](https://github.com/lcatro/webshell-detect-by-machine-learning) 
    - 重复区段: [工具/webshell/未分类-webshell](#faa91844951d2c29b7b571c6e8a3eb54) |
- [**87**星][28d] [CSS] [uvasrg/evademl](https://github.com/uvasrg/evademl) 
- [**86**星][1y] [C] [cgcl-codes/vuldeepecker](https://github.com/cgcl-codes/vuldeepecker) A Deep Learning-Based System for Vulnerability Detection
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/未分类-Vul](#9d1ce4a40c660c0ce15aec6daf7f56dd) |
- [**34**星][6m] [Py] [claudiugeorgiu/riskindroid](https://github.com/claudiugeorgiu/riskindroid) 
    - 重复区段: [工具/移动&&Mobile/Android](#fe88ee8c0df10870b44c2dedcd86d3d3) |


### <a id="bab8f2640d6c5eb981003b3fd1ecc042"></a>收集






***


## <a id="a4ee2f4d4a944b54b2246c72c037cd2e"></a>收集&&集合


### <a id="e97d183e67fa3f530e7d0e7e8c33ee62"></a>未分类


- [**4097**星][20d] [qazbnm456/awesome-web-security](https://github.com/qazbnm456/awesome-web-security) web 安全资源列表
- [**2898**星][2y] [phith0n/mind-map](https://github.com/phith0n/mind-map) 
- [**2778**星][4m] [C] [juliocesarfort/public-pentesting-reports](https://github.com/juliocesarfort/public-pentesting-reports) 
- [**2747**星][2m] [infosecn1nja/red-teaming-toolkit](https://github.com/infosecn1nja/red-teaming-toolkit) 
- [**2592**星][1m] [rmusser01/infosec_reference](https://github.com/rmusser01/infosec_reference) 
- [**2483**星][2m] [kbandla/aptnotes](https://github.com/kbandla/aptnotes) 
- [**2353**星][22d] [Py] [0xinfection/awesome-waf](https://github.com/0xinfection/awesome-waf) 
- [**2253**星][11m] [yeyintminthuhtut/awesome-red-teaming](https://github.com/yeyintminthuhtut/awesome-red-teaming) 
- [**2058**星][3m] [infoslack/awesome-web-hacking](https://github.com/infoslack/awesome-web-hacking) 
- [**2024**星][1y] [bluscreenofjeff/red-team-infrastructure-wiki](https://github.com/bluscreenofjeff/red-team-infrastructure-wiki) 
- [**2008**星][1m] [tanprathan/mobileapp-pentest-cheatsheet](https://github.com/tanprathan/mobileapp-pentest-cheatsheet) 
- [**1968**星][2y] [dloss/python-pentest-tools](https://github.com/dloss/python-pentest-tools) 可用于渗透测试的Python工具收集
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
- [**916**星][2y] [HTML] [chybeta/software-security-learning](https://github.com/chybeta/software-security-learning) 
- [**908**星][9m] [wtsxdev/penetration-testing](https://github.com/wtsxdev/penetration-testing) 
- [**905**星][6m] [PowerShell] [api0cradle/ultimateapplockerbypasslist](https://github.com/api0cradle/ultimateapplockerbypasslist) 
- [**899**星][6m] [cn0xroot/rfsec-toolkit](https://github.com/cn0xroot/rfsec-toolkit) 
- [**894**星][24d] [tom0li/collection-document](https://github.com/tom0li/collection-document) 
- [**862**星][5m] [Shell] [dominicbreuker/stego-toolkit](https://github.com/dominicbreuker/stego-toolkit) 
- [**848**星][13d] [explife0011/awesome-windows-kernel-security-development](https://github.com/explife0011/awesome-windows-kernel-security-development) 
- [**803**星][4m] [Shell] [danielmiessler/robotsdisallowed](https://github.com/danielmiessler/robotsdisallowed) 
- [**793**星][3y] [shmilylty/awesome-hacking](https://github.com/shmilylty/awesome-hacking) 
- [**769**星][2y] [Py] [dagrz/aws_pwn](https://github.com/dagrz/aws_pwn) 
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
- [**636**星][2y] [harmj0y/cheatsheets](https://github.com/harmj0y/cheatsheets) 
- [**628**星][9m] [webbreacher/offensiveinterview](https://github.com/webbreacher/offensiveinterview) 
- [**627**星][2m] [redhuntlabs/awesome-asset-discovery](https://github.com/redhuntlabs/awesome-asset-discovery) 
- [**619**星][3m] [3gstudent/pentest-and-development-tips](https://github.com/3gstudent/pentest-and-development-tips) 
- [**603**星][2m] [Shell] [ashishb/osx-and-ios-security-awesome](https://github.com/ashishb/osx-and-ios-security-awesome) 
- [**589**星][1y] [jiangsir404/audit-learning](https://github.com/jiangsir404/audit-learning) 
- [**587**星][11m] [pandazheng/ioshackstudy](https://github.com/pandazheng/ioshackstudy) 
- [**575**星][16d] [Py] [hslatman/awesome-industrial-control-system-security](https://github.com/hslatman/awesome-industrial-control-system-security) awesome-industrial-control-system-security：工控系统安全资源列表
- [**552**星][8m] [guardrailsio/awesome-python-security](https://github.com/guardrailsio/awesome-python-security) 
- [**482**星][2y] [sergey-pronin/awesome-vulnerability-research](https://github.com/sergey-pronin/Awesome-Vulnerability-Research) 
- [**452**星][8m] [gradiuscypher/infosec_getting_started](https://github.com/gradiuscypher/infosec_getting_started) 
- [**444**星][7m] [jnusimba/miscsecnotes](https://github.com/jnusimba/miscsecnotes) 
- [**434**星][2y] [magoo/redteam-plan](https://github.com/magoo/redteam-plan) redteam-plan：规划 redteam 练习时要考虑的问题
- [**426**星][1y] [meitar/awesome-lockpicking](https://github.com/meitar/awesome-lockpicking) awesome-lockpicking：有关锁、保险箱、钥匙的指南、工具及其他资源的列表
- [**404**星][19d] [meitar/awesome-cybersecurity-blueteam](https://github.com/meitar/awesome-cybersecurity-blueteam) 
- [**398**星][21d] [Py] [bl4de/security-tools](https://github.com/bl4de/security-tools) 
- [**394**星][3m] [re4lity/hacking-with-golang](https://github.com/re4lity/hacking-with-golang) 
- [**390**星][6m] [HTML] [gexos/hacking-tools-repository](https://github.com/gexos/hacking-tools-repository) 
- [**384**星][1m] [husnainfareed/awesome-ethical-hacking-resources](https://github.com/husnainfareed/Awesome-Ethical-Hacking-Resources) 
- [**380**星][1m] [dsopas/assessment-mindset](https://github.com/dsopas/assessment-mindset) 安全相关的思维导图, 可用于pentesting, bug bounty, red-teamassessments
- [**352**星][3y] [virajkulkarni14/webdevelopersecuritychecklist](https://github.com/virajkulkarni14/webdevelopersecuritychecklist) 
- [**350**星][16d] [fkromer/awesome-ros2](https://github.com/fkromer/awesome-ros2) 
- [**346**星][2y] [PHP] [attackercan/regexp-security-cheatsheet](https://github.com/attackercan/regexp-security-cheatsheet) 
- [**331**星][1m] [softwareunderground/awesome-open-geoscience](https://github.com/softwareunderground/awesome-open-geoscience) 
- [**328**星][27d] [PowerShell] [mgeeky/penetration-testing-tools](https://github.com/mgeeky/penetration-testing-tools) 
- [**308**星][16d] [cryptax/confsec](https://github.com/cryptax/confsec) 
- [**303**星][4m] [trimstray/technical-whitepapers](https://github.com/trimstray/technical-whitepapers) 收集：IT白皮书、PPT、PDF、Hacking、Web应用程序安全性、数据库、逆向等
- [**299**星][1m] [HTML] [eugenekolo/sec-tools](https://github.com/eugenekolo/sec-tools) 
- [**289**星][1m] [hongrisec/web-security-attack](https://github.com/hongrisec/web-security-attack) 
- [**286**星][1y] [Py] [anasaboureada/penetration-testing-study-notes](https://github.com/AnasAboureada/Penetration-Testing-Study-Notes) 
- [**265**星][1y] [JS] [ropnop/serverless_toolkit](https://github.com/ropnop/serverless_toolkit) 
- [**260**星][3m] [mattnotmax/cyber-chef-recipes](https://github.com/mattnotmax/cyber-chef-recipes) 
- [**244**星][2y] [hsis007/useful_websites_for_pentester](https://github.com/hsis007/useful_websites_for_pentester) 
- [**244**星][3y] [misterch0c/awesome-hacking](https://github.com/misterch0c/awesome-hacking) 
- [**243**星][4m] [zhaoweiho/web-sec-interview](https://github.com/zhaoweiho/web-sec-interview) 
- [**241**星][1y] [kinimiwar/penetration-testing](https://github.com/kinimiwar/penetration-testing) 
- [**232**星][21d] [pe3zx/my-infosec-awesome](https://github.com/pe3zx/my-infosec-awesome) 
- [**231**星][2y] [wizardforcel/web-hacking-101-zh](https://github.com/wizardforcel/web-hacking-101-zh) 
- [**224**星][25d] [euphrat1ca/security_w1k1](https://github.com/euphrat1ca/security_w1k1) 
- [**217**星][2y] [sh4hin/mobileapp-pentest-cheatsheet](https://github.com/sh4hin/mobileapp-pentest-cheatsheet) 
- [**211**星][5m] [guardrailsio/awesome-dotnet-security](https://github.com/guardrailsio/awesome-dotnet-security) 
- [**208**星][1y] [Py] [euphrat1ca/fuzzdb-collect](https://github.com/euphrat1ca/fuzzdb-collect) 
- [**207**星][9m] [jeansgit/redteam](https://github.com/jeansgit/redteam) 
- [**205**星][9m] [puresec/awesome-serverless-security](https://github.com/puresec/awesome-serverless-security) 
- [**201**星][1y] [faizann24/resources-for-learning-hacking](https://github.com/faizann24/resources-for-learning-hacking) 
- [**201**星][1y] [sigp/solidity-security-blog](https://github.com/sigp/solidity-security-blog) 
- [**201**星][2y] [Py] [wwong99/pentest-notes](https://github.com/wwong99/pentest-notes) 
- [**199**星][8m] [jesusprubio/awesome-nodejs-pentest](https://github.com/jesusprubio/awesome-nodejs-pentest) 
- [**196**星][5y] [rutkai/pentest-bookmarks](https://github.com/rutkai/pentest-bookmarks) 
- [**193**星][7m] [Py] [lingerhk/hacking_script](https://github.com/lingerhk/hacking_script) 
- [**187**星][19d] [decalage2/awesome-security-hardening](https://github.com/decalage2/awesome-security-hardening) 
- [**183**星][2m] [jdonsec/allthingsssrf](https://github.com/jdonsec/allthingsssrf) 
    - 重复区段: [工具/CTF&&HTB/未分类-CTF&&HTB](#c0fea206256a42e41fd5092cecf54d3e) |
- [**180**星][2y] [Py] [wavestone-cdt/hadoop-attack-library](https://github.com/wavestone-cdt/hadoop-attack-library) 
- [**176**星][2m] [Py] [naategh/pyck](https://github.com/naategh/pyck) 
- [**170**星][8m] [guardrailsio/awesome-java-security](https://github.com/guardrailsio/awesome-java-security) 
- [**158**星][1y] [joychou93/sks](https://github.com/joychou93/sks) 
- [**156**星][4m] [samanl33t/awesome-mainframe-hacking](https://github.com/samanl33t/awesome-mainframe-hacking) 
- [**156**星][2m] [thelsa/cs-checklist](https://github.com/thelsa/cs-checklist) 
- [**149**星][23d] [udpsec/awesome-hacking-lists](https://github.com/udpsec/awesome-hacking-lists) 
- [**142**星][1y] [chryzsh/awesome-windows-security](https://github.com/chryzsh/awesome-windows-security) 
- [**141**星][1y] [brucetg/app_security](https://github.com/brucetg/app_security) 
- [**139**星][1y] [laxa/hackingtools](https://github.com/laxa/hackingtools) 
- [**139**星][2m] [security-cheatsheet/reverse-shell-cheatsheet](https://github.com/security-cheatsheet/reverse-shell-cheatsheet) 
- [**136**星][3y] [kurobeats/pentest-bookmarks](https://github.com/kurobeats/pentest-bookmarks) 
- [**122**星][9m] [leezj9671/offensiveinterview](https://github.com/leezj9671/offensiveinterview) 
- [**104**星][7m] [binject/awesome-go-security](https://github.com/binject/awesome-go-security) 
- [**102**星][6m] [fabionoth/awesome-cyber-security](https://github.com/fabionoth/awesome-cyber-security) 
- [**101**星][7m] [marcosvalle/awesome-windows-red-team](https://github.com/marcosvalle/awesome-windows-red-team) 
- [**98**星][2y] [Py] [leesoh/yams](https://github.com/leesoh/yams) yams：A collectionof Ansible roles for automating infosec builds.
- [**90**星][9m] [Py] [b1n4ry4rms/redteam-pentest-cheatsheets](https://github.com/b1n4ry4rms/redteam-pentest-cheatsheets) 
    - 重复区段: [工具/OSCP](#13d067316e9894cc40fe55178ee40f24) |
- [**90**星][1y] [PowerShell] [rasta-mouse/aggressor-script](https://github.com/rasta-mouse/aggressor-script) 
- [**89**星][8m] [pandazheng/securitysite](https://github.com/pandazheng/securitysite) 
- [**88**星][21d] [smi1esec/web-security-note](https://github.com/Smi1eSEC/Web-Security-Note) 
- [**87**星][17d] [chryzsh/awesome-bloodhound](https://github.com/chryzsh/awesome-bloodhound) 
- [**81**星][13d] [caledoniaproject/awesome-opensource-security](https://github.com/caledoniaproject/awesome-opensource-security) 
- [**81**星][1y] [santosomar/who_and_what_to_follow](https://github.com/santosomar/who_and_what_to_follow) 
- [**80**星][4y] [fabiobaroni/awesome-chinese-infosec-websites](https://github.com/fabiobaroni/awesome-chinese-infosec-websites) 
- [**71**星][3y] [lcatro/hacker_document](https://github.com/lcatro/hacker_document) 
- [**68**星][3m] [pomerium/awesome-security-audits](https://github.com/pomerium/awesome-security-audits) 
- [**67**星][4m] [wbierbower/awesome-physics](https://github.com/wbierbower/awesome-physics) 
- [**66**星][2y] [shmilylty/awesome-malware-analysis](https://github.com/shmilylty/awesome-malware-analysis) 
- [**65**星][9m] [Py] [wstnphx/scripts-n-tools](https://github.com/phxbandit/scripts-and-tools) 
- [**61**星][1y] [im-bug/blockchain-security-list](https://github.com/im-bug/blockchain-security-list) 
- [**58**星][9m] [exitmsconfig/engineering-box](https://github.com/exitmsconfig/engineering-box) 
- [**55**星][2y] [Shell] [kevthehermit/pentest](https://github.com/kevthehermit/pentest) 
- [**55**星][1y] [latestalexey/awesome-web-hacking](https://github.com/latestalexey/awesome-web-hacking) 
- [**55**星][3y] [shmilylty/awesome-application-security](https://github.com/shmilylty/awesome-application-security) 
- [**54**星][2y] [yrzx404/free-security-resources](https://github.com/yrzx404/free-security-resources) 
- [**53**星][1y] [1522402210/blockchain-security-list](https://github.com/1522402210/blockchain-security-list) 
- [**53**星][2y] [Py] [h-j-13/malicious_domain_whois](https://github.com/h-j-13/malicious_domain_whois) 
- [**52**星][9m] [muhammd/awesome-pentest](https://github.com/muhammd/awesome-pentest) 
- [**48**星][23d] [HTML] [brampat/security](https://github.com/brampat/security) 
- [**48**星][14d] [yassergersy/cazador_unr](https://github.com/yassergersy/cazador_unr) 
- [**42**星][11m] [Py] [daddycocoaman/ironpentest](https://github.com/daddycocoaman/ironpentest) 
- [**41**星][1m] [C] [spacial/csirt](https://github.com/spacial/csirt) 
- [**37**星][6m] [mykings/security-study-tutorial](https://github.com/mykings/security-study-tutorial) 
- [**36**星][8m] [Py] [phage-nz/malware-hunting](https://github.com/phage-nz/malware-hunting) 与 Malware Hunting 相关的脚本/信息收集
- [**33**星][3y] [cert-w/hadoop-attack-library](https://github.com/cert-w/hadoop-attack-library) 
- [**31**星][6y] [Ruby] [zeknox/scripts](https://github.com/zeknox/scripts) 
- [**30**星][3y] [Py] [deadbits/shells](https://github.com/deadbits/shells) 
- [**28**星][2y] [Lua] [foxmole/pwnadventure3](https://github.com/foxmole/pwnadventure3) Blog series about Pwn Adventure 3
- [**28**星][28d] [zoranpandovski/awesome-testing-tools](https://github.com/zoranpandovski/awesome-testing-tools) 
- [**26**星][3y] [lucifer1993/awesome-hacking](https://github.com/lucifer1993/awesome-hacking) 
- [**26**星][1m] [hrt/anticheatjs](https://github.com/hrt/anticheatjs) 
- [**25**星][3y] [unexpectedby/awesome-pentest-tools](https://github.com/unexpectedby/awesome-pentest-tools) 
- [**22**星][2m] [security-prince/resources-for-application-security](https://github.com/security-prince/resources-for-application-security) 
- [**21**星][2m] [jmscory/security-tool-chest](https://github.com/jmscory/security-tool-chest) 


### <a id="664ff1dbdafefd7d856c88112948a65b"></a>混合型收集


- [**24225**星][15d] [trimstray/the-book-of-secret-knowledge](https://github.com/trimstray/the-book-of-secret-knowledge) 
- [**10176**星][17d] [enaqx/awesome-pentest](https://github.com/enaqx/awesome-pentest) 渗透测试资源/工具集
- [**5384**星][8m] [carpedm20/awesome-hacking](https://github.com/carpedm20/awesome-hacking) Hacking教程、工具和资源
- [**4994**星][1m] [sbilly/awesome-security](https://github.com/sbilly/awesome-security) 与安全相关的软件、库、文档、书籍、资源和工具等收集
- [**3116**星][20d] [Rich Text Format] [the-art-of-hacking/h4cker](https://github.com/The-Art-of-Hacking/h4cker) 资源收集：hacking、渗透、数字取证、事件响应、漏洞研究、漏洞开发、逆向
- [**1710**星][20d] [olivierlaflamme/cheatsheet-god](https://github.com/olivierlaflamme/cheatsheet-god) 
    - 重复区段: [工具/OSCP](#13d067316e9894cc40fe55178ee40f24) |
- [**573**星][5m] [d30sa1/rootkits-list-download](https://github.com/d30sa1/rootkits-list-download) Rootkit收集
- [**560**星][2y] [hack-with-github/awesome-security-gists](https://github.com/hack-with-github/awesome-security-gists) Gist收集
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
- [**1545**星][4y] [l3m0n/pentest_study](https://github.com/l3m0n/pentest_study) 
- [**1434**星][4m] [hmaverickadams/beginner-network-pentesting](https://github.com/hmaverickadams/beginner-network-pentesting) 
- [**792**星][2y] [vysecurity/redtips](https://github.com/vysecurity/RedTips) 


### <a id="24707dd322098f73c7e450d6b1eddf12"></a>收集类的收集


- [**32197**星][2m] [hack-with-github/awesome-hacking](https://github.com/hack-with-github/awesome-hacking) 


### <a id="9101434a896f20263d09c25ace65f398"></a>教育资源&&课程&&教程&&书籍


- [**10844**星][1m] [CSS] [hacker0x01/hacker101](https://github.com/hacker0x01/hacker101) 
- [**3897**星][3m] [PHP] [paragonie/awesome-appsec](https://github.com/paragonie/awesome-appsec) 
- [**167**星][3y] [JS] [norma-inc/atear](https://github.com/norma-inc/atear) 
- [**136**星][1y] [spoock1024/web-security](https://github.com/spoock1024/web-security) 
- [**43**星][2m] [Jupyter Notebook] [urcuqui/whitehat](https://github.com/urcuqui/whitehat) 


### <a id="8088e46fc533286d88b945f1d472bf57"></a>笔记&&Tips&&Tricks&&Talk&&Conference


#### <a id="f57ccaab4279b60c17a03f90d96b815c"></a>未分类


- [**2786**星][29d] [paulsec/awesome-sec-talks](https://github.com/paulsec/awesome-sec-talks) 
- [**671**星][2m] [uknowsec/active-directory-pentest-notes](https://github.com/uknowsec/active-directory-pentest-notes) 
- [**540**星][9m] [PowerShell] [threatexpress/red-team-scripts](https://github.com/threatexpress/red-team-scripts) 
- [**134**星][11m] [Shell] [b4tc0untry/penetrationtesting-notes](https://github.com/b4tc0untry/PenetrationTesting-Notes) 
- [**92**星][1m] [ihebski/a-red-teamer-diaries](https://github.com/ihebski/a-red-teamer-diaries) 
- [**66**星][2y] [imp0wd3r/active-directory-pentest](https://github.com/imp0wd3r/active-directory-pentest) 
- [**64**星][6m] [pinkp4nther/aws-testing-notes](https://github.com/pinkp4nther/aws-testing-notes) 
- [**57**星][2y] [Py] [tcpiplab/web-app-hacking-notes](https://github.com/tcpiplab/web-app-hacking-notes) 
- [**56**星][2y] [Py] [averagesecurityguy/ptnotes](https://github.com/averagesecurityguy/ptnotes) 
- [**22**星][2m] [abhinavprasad47/bugbounty-starter-notes](https://github.com/abhinavprasad47/bugbounty-starter-notes) 
- [**20**星][1m] [Py] [0x25/useful](https://github.com/0x25/useful) 


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
- [**390**星][3y] [Java] [ac-pm/sslunpinning_xposed](https://github.com/ac-pm/sslunpinning_xposed) 
- [**370**星][1y] [CSS] [nowsecure/secure-mobile-development](https://github.com/nowsecure/secure-mobile-development) 
- [**353**星][3y] [Objective-C] [naituw/hackingfacebook](https://github.com/naituw/hackingfacebook) 
- [**320**星][5m] [Java] [datatheorem/trustkit-android](https://github.com/datatheorem/trustkit-android) 
- [**256**星][7y] [Java] [isecpartners/android-ssl-bypass](https://github.com/isecpartners/android-ssl-bypass) 
- [**198**星][2m] [Java] [virb3/trustmealready](https://github.com/virb3/trustmealready) 
- [**70**星][1y] [Kotlin] [menjoo/android-ssl-pinning-webviews](https://github.com/menjoo/android-ssl-pinning-webviews) 
- [**55**星][2y] [C] [mwpcheung/ssl-kill-switch2](https://github.com/mwpcheung/ssl-kill-switch2) 
- [**43**星][2y] [PHP] [paragonie/hpkp-builder](https://github.com/paragonie/hpkp-builder) 
- [**32**星][2y] [knoobdev/bypass-facebook-ssl-pinning](https://github.com/knoobdev/bypass-facebook-ssl-pinning) 


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
- [**965**星][3y] [Java] [androidvts/android-vts](https://github.com/androidvts/android-vts) 
- [**912**星][7y] [designativedave/androrat](https://github.com/designativedave/androrat) 
- [**894**星][5y] [Java] [wszf/androrat](https://github.com/wszf/androrat) Remote Administration Tool for Android
- [**781**星][2m] [sh4hin/androl4b](https://github.com/sh4hin/androl4b) 用于评估Android应用程序，逆向工程和恶意软件分析的虚拟机
    - 重复区段: [工具/环境配置&&分析系统/未分类-Env](#f5a7a43f964b2c50825f3e2fee5078c8) |
- [**691**星][4y] [Py] [androbugs/androbugs_framework](https://github.com/androbugs/androbugs_framework) 
- [**664**星][17d] [doridori/android-security-reference](https://github.com/doridori/android-security-reference) 
- [**539**星][6y] [Java] [moxie0/androidpinning](https://github.com/moxie0/androidpinning) 
- [**511**星][3m] [JS] [wooyundota/droidsslunpinning](https://github.com/wooyundota/droidsslunpinning) 
- [**488**星][2y] [b-mueller/android_app_security_checklist](https://github.com/b-mueller/android_app_security_checklist) 
- [**468**星][2y] [Smali] [sensepost/kwetza](https://github.com/sensepost/kwetza) Python 脚本，将 Meterpreter payload 注入 Andorid App
- [**462**星][3m] [JS] [lyxhh/lxhtoolhttpdecrypt](https://github.com/lyxhh/lxhtoolhttpdecrypt) 
- [**452**星][3y] [C++] [vusec/drammer](https://github.com/vusec/drammer) 
- [**398**星][6y] [Java] [isecpartners/introspy-android](https://github.com/isecpartners/introspy-android) 
- [**395**星][2y] [Java] [fourbrother/kstools](https://github.com/fourbrother/kstools) 
- [**383**星][1y] [Py] [thehackingsage/hacktronian](https://github.com/thehackingsage/hacktronian) 
- [**379**星][1y] [Java] [davidbuchanan314/nxloader](https://github.com/davidbuchanan314/nxloader) 
- [**372**星][3m] [Java] [megatronking/netbare](https://github.com/megatronking/netbare) 
- [**368**星][3y] [Py] [androidhooker/hooker](https://github.com/androidhooker/hooker) 
- [**358**星][4m] [C] [the-cracker-technology/andrax-mobile-pentest](https://github.com/the-cracker-technology/andrax-mobile-pentest) 
- [**348**星][4m] [Makefile] [crifan/android_app_security_crack](https://github.com/crifan/android_app_security_crack) 
- [**341**星][4m] [b3nac/android-reports-and-resources](https://github.com/b3nac/android-reports-and-resources) 
- [**326**星][14d] [TypeScript] [shroudedcode/apk-mitm](https://github.com/shroudedcode/apk-mitm) 
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/未分类-Network](#99398a5a8aaf99228829dadff48fb6a7) |[工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**280**星][4y] [Py] [fuzzing/mffa](https://github.com/fuzzing/mffa) 
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞扫描&&挖掘&&发现/Fuzzing/未分类-Fuzz](#1c2903ee7afb903ccfaa26f766924385) |
- [**273**星][2y] [Java] [mateuszk87/badintent](https://github.com/mateuszk87/badintent) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Burp/未分类-Burp](#5b761419863bc686be12c76451f49532) |
- [**271**星][2y] [Java] [reoky/android-crackme-challenge](https://github.com/reoky/android-crackme-challenge) 
- [**257**星][2y] [Java] [maxcamillo/android-keystore-password-recover](https://github.com/maxcamillo/android-keystore-password-recover) 
- [**256**星][3y] [Java] [flankerhqd/jaadas](https://github.com/flankerhqd/jaadas) 
- [**248**星][9m] [C] [chef-koch/android-vulnerabilities-overview](https://github.com/chef-koch/android-vulnerabilities-overview) 
- [**248**星][3y] [C] [w-shackleton/android-netspoof](https://github.com/w-shackleton/android-netspoof) 
- [**233**星][1y] [Ruby] [hahwul/droid-hunter](https://github.com/hahwul/droid-hunter) 
- [**198**星][2y] [Java] [ernw/androtickler](https://github.com/ernw/androtickler) 
- [**179**星][2y] [Smali] [sslab-gatech/avpass](https://github.com/sslab-gatech/avpass) 
- [**176**星][3y] [C] [kriswebdev/android_aircrack](https://github.com/kriswebdev/android_aircrack) 
- [**159**星][4y] [Py] [appknox/afe](https://github.com/appknox/AFE) 
- [**157**星][9m] [thehackingsage/hackdroid](https://github.com/thehackingsage/hackdroid) 
- [**155**星][8m] [Py] [sch3m4/androidpatternlock](https://github.com/sch3m4/androidpatternlock) 
- [**122**星][2m] [Py] [technicaldada/hackerpro](https://github.com/technicaldada/hackerpro) 
- [**121**星][5y] [jacobsoo/androidslides](https://github.com/jacobsoo/androidslides) 
- [**121**星][2y] [Shell] [nccgroup/lazydroid](https://github.com/nccgroup/lazydroid) 
- [**94**星][4y] [Shell] [jlrodriguezf/whatspwn](https://github.com/jlrodriguezf/whatspwn) 
- [**93**星][12m] [Py] [integrity-sa/droidstatx](https://github.com/integrity-sa/droidstatx) 
- [**86**星][5y] [Java] [sysdream/fino](https://github.com/sysdream/fino) 
- [**64**星][2y] [Java] [fsecurelabs/drozer-agent](https://github.com/FSecureLABS/drozer-agent) 
- [**61**星][6y] [Java] [isecpartners/android-killpermandsigchecks](https://github.com/isecpartners/android-killpermandsigchecks) 
- [**60**星][1y] [pfalcon/awesome-linux-android-hacking](https://github.com/pfalcon/awesome-linux-android-hacking) 
- [**60**星][6y] [Java] [gat3way/airpirate](https://github.com/gat3way/airpirate) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**58**星][2y] [Java] [geeksonsecurity/android-overlay-malware-example](https://github.com/geeksonsecurity/android-overlay-malware-example) 
- [**56**星][3y] [C++] [stealth/crash](https://github.com/stealth/crash) 
- [**55**星][2m] [Java] [aagarwal1012/image-steganography-library-android](https://github.com/aagarwal1012/image-steganography-library-android) 
- [**53**星][2m] [C] [watf-team/watf-bank](https://github.com/watf-team/watf-bank) 
- [**53**星][2y] [Java] [zyrikby/fsquadra](https://github.com/zyrikby/fsquadra) 
- [**52**星][2y] [Java] [owasp-ruhrpott/owasp-workshop-android-pentest](https://github.com/owasp-ruhrpott/owasp-workshop-android-pentest) 
- [**49**星][3y] [Java] [necst/heldroid](https://github.com/necst/heldroid) Dissect Android Apps Looking for Ransomware Functionalities
- [**47**星][4y] [C] [mobileforensicsresearch/mem](https://github.com/mobileforensicsresearch/mem) 
- [**44**星][5y] [Java] [monstersb/hijackandroidpoweroff](https://github.com/monstersb/hijackandroidpoweroff) 
- [**41**星][2y] [Java] [alepacheco/androrw](https://github.com/alepacheco/androrw) 
- [**39**星][2y] [Java] [tiked/androrw](https://github.com/tiked/androrw) 
- [**34**星][6m] [Py] [claudiugeorgiu/riskindroid](https://github.com/claudiugeorgiu/riskindroid) 
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |
- [**33**星][5y] [Py] [jonmetz/androfuzz](https://github.com/jonmetz/androfuzz) 
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞扫描&&挖掘&&发现/Fuzzing/未分类-Fuzz](#1c2903ee7afb903ccfaa26f766924385) |
- [**33**星][7y] [C] [nwhusted/auditdandroid](https://github.com/nwhusted/auditdandroid) 
- [**32**星][2y] [Shell] [mseclab/ahe17](https://github.com/mseclab/ahe17) 
- [**32**星][5y] [Py] [xurubin/aurasium](https://github.com/xurubin/aurasium) 
- [**27**星][2y] [Java] [coh7eiqu8thabu/slocker](https://github.com/coh7eiqu8thabu/slocker) 
- [**25**星][5y] [wirelesscollege/securitytools](https://github.com/wirelesscollege/securitytools) 
- [**21**星][7y] [brycethomas/liber80211](https://github.com/brycethomas/liber80211) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/802.11](#8863b7ba27658d687a85585e43b23245) |
- [**16**星][6m] [zyrikby/stadyna](https://github.com/zyrikby/stadyna) Addressing the Problem of Dynamic Code Updates in the Security Analysis of Android Applications
- [**3**星][12m] [Py] [51j0/android-storage-extractor](https://github.com/51j0/android-storage-extractor) 


### <a id="dbde77352aac39ee710d3150a921bcad"></a>iOS&&MacOS&&iPhone&&iPad&&iWatch


- [**5299**星][5m] [C] [pwn20wndstuff/undecimus](https://github.com/pwn20wndstuff/undecimus) 
- [**5097**星][2m] [Py] [axi0mx/ipwndfu](https://github.com/axi0mx/ipwndfu) 
- [**4143**星][7m] [Objective-C] [alonemonkey/monkeydev](https://github.com/alonemonkey/monkeydev) 
- [**3411**星][6m] [icodesign/potatso](https://github.com/icodesign/Potatso) 
- [**3072**星][9m] [JS] [jipegit/osxauditor](https://github.com/jipegit/osxauditor) 
- [**1801**星][3y] [Objective-C] [kpwn/yalu102](https://github.com/kpwn/yalu102) 
- [**1685**星][5m] [Py] [yelp/osxcollector](https://github.com/yelp/osxcollector) 
- [**1366**星][6m] [Objective-C] [nabla-c0d3/ssl-kill-switch2](https://github.com/nabla-c0d3/ssl-kill-switch2) 
- [**1276**星][2y] [JS] [icymind/vrouter](https://github.com/icymind/vrouter) 
- [**1259**星][5m] [JS] [feross/spoof](https://github.com/feross/spoof) 
- [**1244**星][2y] [Objective-C] [krausefx/detect.location](https://github.com/krausefx/detect.location) 
- [**1218**星][5m] [Vue] [chaitin/passionfruit](https://github.com/chaitin/passionfruit) iOSapp 黑盒评估工具。功能丰富，自带基于web的 GUI
- [**1214**星][19d] [C] [datatheorem/trustkit](https://github.com/datatheorem/trustkit) 
- [**1174**星][29d] [YARA] [horsicq/detect-it-easy](https://github.com/horsicq/detect-it-easy) 
- [**1170**星][5y] [Py] [hackappcom/ibrute](https://github.com/hackappcom/ibrute) 
- [**1121**星][4m] [JS] [alonemonkey/frida-ios-dump](https://github.com/alonemonkey/frida-ios-dump) 
- [**1094**星][1y] [Objective-C] [neoneggplant/eggshell](https://github.com/neoneggplant/eggshell) 
- [**969**星][1y] [Py] [mwrlabs/needle](https://github.com/FSecureLABS/needle) 
- [**898**星][2m] [Objective-C] [ptoomey3/keychain-dumper](https://github.com/ptoomey3/keychain-dumper) 
- [**849**星][3y] [Py] [hubert3/isniff-gps](https://github.com/hubert3/isniff-gps) 
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/流量嗅探&&监控](#c09843b4d4190dea0bf9773f8114300a) |
- [**808**星][5y] [Objective-C] [isecpartners/ios-ssl-kill-switch](https://github.com/isecpartners/ios-ssl-kill-switch) 
- [**804**星][2y] [Ruby] [dmayer/idb](https://github.com/dmayer/idb) idb：iOS 渗透和研究过程中简化一些常见的任务
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |
- [**781**星][3y] [Go] [summitroute/osxlockdown](https://github.com/summitroute/osxlockdown) 
- [**615**星][5y] [PHP] [pr0x13/idict](https://github.com/pr0x13/idict) 
- [**607**星][3y] [Objective-C] [macmade/keychaincracker](https://github.com/macmade/keychaincracker) 
- [**577**星][2m] [siguza/ios-resources](https://github.com/siguza/ios-resources) 
- [**558**星][3y] [advanced-threat-research/firmware-security-training](https://github.com/advanced-threat-research/firmware-security-training) firmware-security-training：固件安全教程：从攻击者和防卫者的角度看BIOS / UEFI系统固件的安全
- [**530**星][3y] [Objective-C] [herzmut/shadowsocks-ios](https://github.com/herzmut/shadowsocks-ios) 
- [**519**星][4y] [Py] [hackappcom/iloot](https://github.com/hackappcom/iloot) 
- [**515**星][2y] [Shell] [seemoo-lab/mobisys2018_nexmon_software_defined_radio](https://github.com/seemoo-lab/mobisys2018_nexmon_software_defined_radio) 将Broadcom的802.11ac Wi-Fi芯片变成软件定义的无线电，可在Wi-Fi频段传输任意信号
- [**513**星][3y] [Objective-C] [pjebs/obfuscator-ios](https://github.com/pjebs/obfuscator-ios) 
- [**476**星][2y] [Objective-C++] [bishopfox/bfinject](https://github.com/bishopfox/bfinject) 
- [**475**星][1y] [Swift] [icepa/icepa](https://github.com/icepa/icepa) 
- [**428**星][7y] [C] [juuso/keychaindump](https://github.com/juuso/keychaindump) 
- [**386**星][3y] [Objective-C] [kpwn/yalu](https://github.com/kpwn/yalu) 
- [**385**星][3m] [ansjdnakjdnajkd/ios](https://github.com/ansjdnakjdnajkd/ios) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |
- [**321**星][30d] [Objective-C] [auth0/simplekeychain](https://github.com/auth0/simplekeychain) 
- [**295**星][2y] [krausefx/steal.password](https://github.com/krausefx/steal.password) 
- [**287**星][1y] [Py] [manwhoami/mmetokendecrypt](https://github.com/manwhoami/mmetokendecrypt) 
- [**213**星][10m] [AppleScript] [lifepillar/csvkeychain](https://github.com/lifepillar/csvkeychain) 
- [**204**星][7m] [C] [owasp/igoat](https://github.com/owasp/igoat) 
- [**181**星][7m] [Java] [yubico/ykneo-openpgp](https://github.com/yubico/ykneo-openpgp) 
- [**180**星][1m] [Py] [ydkhatri/mac_apt](https://github.com/ydkhatri/mac_apt) 
- [**172**星][1y] [Objective-C] [macmade/filevaultcracker](https://github.com/macmade/filevaultcracker) 
- [**167**星][9m] [Shell] [trustedsec/hardcidr](https://github.com/trustedsec/hardcidr) 
- [**165**星][6m] [C] [octomagon/davegrohl](https://github.com/octomagon/davegrohl) 
- [**139**星][1y] [Shell] [depoon/iosdylibinjectiondemo](https://github.com/depoon/iosdylibinjectiondemo) 
- [**134**星][3m] [Go] [greenboxal/dns-heaven](https://github.com/greenboxal/dns-heaven) 通过/etc/resolv.conf 启用本地 DNS stack 来修复（愚蠢的） macOS DNS stack
- [**132**星][2y] [Py] [google/tcp_killer](https://github.com/google/tcp_killer) 关闭 Linux或 MacOS 的 Tcp 端口
- [**123**星][3y] [JS] [vtky/swizzler2](https://github.com/vtky/swizzler2) 
- [**104**星][4m] [C++] [danielcardeenas/audiostego](https://github.com/danielcardeenas/audiostego) 
- [**89**星][2y] [PowerShell] [netbiosx/digital-signature-hijack](https://github.com/netbiosx/digital-signature-hijack) 
- [**84**星][4y] [Swift] [deniskr/keychainswiftapi](https://github.com/deniskr/keychainswiftapi) 
- [**52**星][8m] [Logos] [zhaochengxiang/ioswechatfakelocation](https://github.com/zhaochengxiang/ioswechatfakelocation) 
- [**50**星][4m] [Py] [n0fate/ichainbreaker](https://github.com/n0fate/ichainbreaker) 
- [**47**星][4y] [Py] [ostorlab/jniostorlab](https://github.com/ostorlab/jniostorlab) 
- [**42**星][1y] [Objective-C] [dineshshetty/ios-sandbox-dumper](https://github.com/dineshshetty/ios-sandbox-dumper) 
- [**21**星][2y] [troydo42/awesome-pen-test](https://github.com/troydo42/awesome-pen-test) 




***


## <a id="c7f35432806520669b15a28161a4d26a"></a>CTF&&HTB


### <a id="c0fea206256a42e41fd5092cecf54d3e"></a>未分类-CTF&&HTB


- [**952**星][2m] [ctfs/resources](https://github.com/ctfs/resources) 
- [**744**星][1m] [Py] [ashutosh1206/crypton](https://github.com/ashutosh1206/crypton) 
- [**634**星][8m] [cryptogenic/exploit-writeups](https://github.com/cryptogenic/exploit-writeups) 
- [**524**星][2y] [vulnhub/ctf-writeups](https://github.com/vulnhub/ctf-writeups) 
- [**474**星][5m] [PHP] [wonderkun/ctf_web](https://github.com/wonderkun/ctf_web) 
- [**472**星][3m] [PHP] [susers/writeups](https://github.com/susers/writeups) 
- [**450**星][8m] [Py] [christhecoolhut/zeratool](https://github.com/christhecoolhut/zeratool) 
- [**410**星][3m] [ctftraining/ctftraining](https://github.com/ctftraining/ctftraining) 
- [**313**星][4y] [Perl] [truongkma/ctf-tools](https://github.com/truongkma/ctf-tools) 
- [**307**星][5m] [C] [sixstars/ctf](https://github.com/sixstars/ctf) 
- [**294**星][28d] [HTML] [balsn/ctf_writeup](https://github.com/balsn/ctf_writeup) 
- [**294**星][3y] [lucyoa/ctf-wiki](https://github.com/lucyoa/ctf-wiki) 
- [**290**星][9m] [HTML] [s1gh/ctf-literature](https://github.com/s1gh/ctf-literature) 
- [**283**星][10m] [Shell] [ctf-wiki/ctf-tools](https://github.com/ctf-wiki/ctf-tools) 
- [**270**星][2y] [Py] [ssooking/ctfdefense](https://github.com/ssooking/ctfdefense) 
- [**260**星][5m] [CSS] [l4wio/ctf-challenges-by-me](https://github.com/l4wio/ctf-challenges-by-me) 
- [**257**星][3y] [Perl] [fuzyll/defcon-vm](https://github.com/fuzyll/defcon-vm) 
- [**253**星][6m] [Shell] [lieanu/libcsearcher](https://github.com/lieanu/libcsearcher) 
- [**233**星][8m] [harmoc/ctftools](https://github.com/harmoc/ctftools) 
- [**209**星][2y] [C++] [nu1lctf/n1ctf-2018](https://github.com/nu1lctf/n1ctf-2018) 
- [**209**星][1y] [Py] [3summer/ctf-rsa-tool](https://github.com/3summer/CTF-RSA-tool) 
- [**189**星][1y] [Dockerfile] [eadom/ctf_xinetd](https://github.com/eadom/ctf_xinetd) 
- [**185**星][1m] [Py] [scwuaptx/ctf](https://github.com/scwuaptx/ctf) 
- [**183**星][2m] [jdonsec/allthingsssrf](https://github.com/jdonsec/allthingsssrf) 
    - 重复区段: [工具/收集&&集合/未分类](#e97d183e67fa3f530e7d0e7e8c33ee62) |
- [**160**星][4y] [PHP] [spiderlabs/cryptomg](https://github.com/spiderlabs/cryptomg) 
- [**156**星][6m] [mrmugiwara/ctf-tools](https://github.com/mrmugiwara/ctf-tools) 
- [**151**星][1y] [css] [eun/ctf.tf](https://github.com/eun/ctf.tf) 
- [**151**星][2y] [Java] [zjlywjh001/phrackctf-platform-team](https://github.com/zjlywjh001/phrackctf-platform-team) 
- [**148**星][12m] [Java] [wnagzihxa1n/ctf-mobile](https://github.com/wnagzihxa1n/CTF-Mobile) 
- [**147**星][2y] [Py] [stfpeak/ctf](https://github.com/stfpeak/ctf) 
- [**146**星][1y] [JS] [gabemarshall/microctfs](https://github.com/gabemarshall/microctfs) 
- [**145**星][2y] [Py] [valardragon/ctf-crypto](https://github.com/valardragon/ctf-crypto) 
- [**142**星][2y] [Py] [balidani/tinyctf-platform](https://github.com/balidani/tinyctf-platform) 
- [**138**星][2m] [Py] [bash-c/pwn_repo](https://github.com/bash-c/pwn_repo) 
- [**136**星][11m] [C] [tharina/35c3ctf](https://github.com/tharina/35c3ctf) 
- [**136**星][6y] [Py] [osirislab/ctf-challenges](https://github.com/osirislab/CTF-Challenges) 
- [**130**星][2y] [Py] [pwning/defcon25-public](https://github.com/pwning/defcon25-public) DEFCON 25 某Talk用到的 反汇编器和 IDA 模块
- [**128**星][4m] [PHP] [zsxsoft/my-rctf-2018](https://github.com/zsxsoft/my-ctf-challenges) 
- [**125**星][5m] [Py] [jinmo/ctfs](https://github.com/jinmo/ctfs) 
- [**119**星][2y] [Java] [zjlywjh001/phrackctf-platform-personal](https://github.com/zjlywjh001/phrackctf-platform-personal) 
- [**118**星][2y] [we5ter/awesome-platforms](https://github.com/we5ter/awesome-platforms) 
- [**117**星][2y] [Ruby] [bsidessf/ctf-2017-release](https://github.com/bsidessf/ctf-2017-release) 
- [**115**星][1m] [Py] [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups) 
- [**110**星][15d] [Py] [p4-team/crypto-commons](https://github.com/p4-team/crypto-commons) 
- [**110**星][5m] [PHP] [m0xiaoxi/ctf_web_docker](https://github.com/m0xiaoxi/ctf_web_docker) 
- [**107**星][5m] [Py] [n4nu/reversing-challenges-list](https://github.com/n4nu/reversing-challenges-list) 
- [**107**星][3y] [vidar-team/hctf2016](https://github.com/vidar-team/HCTF2016) 
- [**106**星][2y] [JS] [eboda/34c3ctf](https://github.com/eboda/34c3ctf) 
- [**105**星][3y] [Py] [picoctf/picoctf-platform-2](https://github.com/picoctf/picoctf-platform-2) 
- [**104**星][4y] [C++] [trailofbits/appjaillauncher](https://github.com/trailofbits/appjaillauncher) 
- [**100**星][1m] [PHP] [sniperoj/attack-defense-challenges](https://github.com/sniperoj/attack-defense-challenges) 
- [**99**星][2m] [Assembly] [platypew/picoctf-2018-writeup](https://github.com/platypew/picoctf-2018-writeup) 
- [**98**星][2y] [Py] [kitctf/writeups](https://github.com/kitctf/writeups) 
- [**98**星][2m] [Py] [phith0n/realworldctf](https://github.com/phith0n/realworldctf) 
- [**90**星][1y] [Py] [wagiro/pintool](https://github.com/wagiro/pintool) 
- [**88**星][2y] [Py] [rk700/attackrsa](https://github.com/rk700/attackrsa) 
- [**83**星][3m] [Shell] [giantbranch/pwn-env-init](https://github.com/giantbranch/pwn-env-init) 
- [**83**星][3m] [Py] [testerting/hacker101-ctf](https://github.com/testerting/hacker101-ctf) 
- [**81**星][12m] [asuri-team/pwn-sandbox](https://github.com/asuri-team/pwn-sandbox) 
- [**81**星][5m] [Py] [scwuaptx/lazyfragmentationheap](https://github.com/scwuaptx/lazyfragmentationheap) 
- [**78**星][2y] [Py] [david942j/defcon-2017-tools](https://github.com/david942j/defcon-2017-tools) 
- [**78**星][3y] [C] [lflare/picoctf_2017_writeup](https://github.com/lflare/picoctf_2017_writeup) 
- [**77**星][4y] [Py] [mncoppola/linux-kernel-ctf](https://github.com/mncoppola/linux-kernel-ctf) 
- [**77**星][4m] [Py] [ray-cp/pwn_debug](https://github.com/ray-cp/pwn_debug) 
- [**76**星][2m] [Py] [escapingbug/ancypwn](https://github.com/escapingbug/ancypwn) 
- [**76**星][4y] [C++] [lcatro/sise_traning_ctf_re](https://github.com/lcatro/sise_traning_ctf_re) 
- [**75**星][4m] [JS] [de1ta-team/de1ctf2019](https://github.com/de1ta-team/de1ctf2019) 
- [**75**星][4y] [PHP] [vidar-team/hctf2015-all-problems](https://github.com/vidar-team/hctf2015-all-problems) 
- [**75**星][3y] [C] [osirislab/csaw-ctf-2016-quals](https://github.com/osirislab/CSAW-CTF-2016-Quals) 
- [**74**星][9m] [Rust] [easyctf/librectf](https://github.com/easyctf/librectf) 
- [**73**星][4y] [Shell] [ctfhacker/ctf-vagrant-64](https://github.com/ctfhacker/ctf-vagrant-64) 
- [**72**星][4m] [HTML] [ph0en1x-xmu/awesome-ctf-book](https://github.com/Ph0en1x-XMU/Awesome-CTF-Book) 
- [**71**星][4y] [Py] [internetwache/internetwache-ctf-2016](https://github.com/internetwache/internetwache-ctf-2016) 
- [**70**星][1y] [C] [shift-crops/escapeme](https://github.com/shift-crops/escapeme) 
- [**70**星][3m] [Py] [acmesec/ctfcracktools-v2](https://github.com/Acmesec/CTFCrackTools-V2) 
- [**68**星][7m] [Py] [l4ys/ctf](https://github.com/l4ys/ctf) 
- [**67**星][2y] [Makefile] [adamdoupe/ctf-training](https://github.com/adamdoupe/ctf-training) 
- [**67**星][2y] [hacker0x01/h1-212-ctf-solutions](https://github.com/hacker0x01/h1-212-ctf-solutions) 
- [**66**星][3y] [oj/bsides-2017-ctf-docker](https://github.com/oj/bsides-2017-ctf-docker) 
- [**66**星][9m] [JS] [saelo/v9](https://github.com/saelo/v9) 
- [**64**星][2y] [HTML] [jianmou/vulnctf](https://github.com/jianmou/vulnctf) 
- [**63**星][1y] [C] [inndy/ctf-writeup](https://github.com/inndy/ctf-writeup) 
- [**62**星][3m] [HTML] [team-su/suctf-2019](https://github.com/team-su/suctf-2019) 
- [**62**星][3y] [Ruby] [zed-0xff/ctf](https://github.com/zed-0xff/ctf) 
- [**61**星][4m] [Py] [integeruser/on-pwning](https://github.com/integeruser/on-pwning) 
- [**60**星][8m] [Py] [grocid/ctf](https://github.com/grocid/ctf) 
- [**60**星][6m] [Py] [pdkt-team/ctf](https://github.com/pdkt-team/ctf) 
- [**60**星][4y] [Py] [phith0n/xdctf2015](https://github.com/phith0n/xdctf2015) 
- [**59**星][2y] [Shell] [abhisek/pwnworks](https://github.com/abhisek/pwnworks) 
- [**58**星][2y] [C++] [eternalsakura/ctf_pwn](https://github.com/eternalsakura/ctf_pwn) 
- [**57**星][2m] [C] [bytebandits/writeups](https://github.com/bytebandits/writeups) 
- [**56**星][3y] [Py] [acama/ctf](https://github.com/acama/ctf) 
- [**56**星][2y] [WebAssembly] [seccon/seccon2017_online_ctf](https://github.com/seccon/seccon2017_online_ctf) 
- [**54**星][2y] [myndtt/ctf-site](https://github.com/myndtt/ctf-site) 
- [**54**星][7m] [MATLAB] [professormahi/ctf](https://github.com/professormahi/ctf) 
- [**54**星][1m] [HTML] [r3kapig/writeup](https://github.com/r3kapig/writeup) 
- [**53**星][2m] [Py] [gray-panda/grayrepo](https://github.com/gray-panda/grayrepo) 
- [**52**星][9m] [C] [bsidessf/ctf-2019-release](https://github.com/bsidessf/ctf-2019-release) 
- [**52**星][11m] [Py] [unamer/pwnsandboxforctf](https://github.com/unamer/pwnsandboxforctf) 
- [**51**星][3y] [JS] [firesuncn/my_ctf_challenges](https://github.com/firesuncn/my_ctf_challenges) 
- [**51**星][2y] [riscure/rhme-2017](https://github.com/riscure/rhme-2017) 
- [**51**星][2y] [Py] [spritz-research-group/ctf-writeups](https://github.com/spritz-research-group/ctf-writeups) 
- [**51**星][2y] [C] [sycloversecurity/ctf](https://github.com/sycloversecurity/ctf) 
- [**48**星][2m] [Ruby] [mcpa-stlouis/hack-the-arch](https://github.com/mcpa-stlouis/hack-the-arch) 
- [**19**星][16d] [Shell] [mzfr/hackthebox-writeups](https://github.com/mzfr/HackTheBox-writeups) 
- [**12**星][5m] [Shell] [edoz90/htb-writeup](https://github.com/edoz90/htb-writeup) 
- [**9**星][2y] [Py] [cn33liz/hackthebox-jail](https://github.com/cn33liz/hackthebox-jail) 
- [**9**星][1m] [Shell] [avi7611/htb-writeup-download](https://github.com/avi7611/htb-writeup-download) 
- [**6**星][5m] [Shell] [0xkiewicz/useful-pentesting-scripts](https://github.com/0xkiewicz/useful-pentesting-scripts) 
- [**1**星][1y] [JS] [mart123p/wordpress-form-lightbox](https://github.com/mart123p/wordpress-form-lightbox) 


### <a id="30c4df38bcd1abaaaac13ffda7d206c6"></a>收集


- [**3857**星][1m] [JS] [apsdehal/awesome-ctf](https://github.com/apsdehal/awesome-ctf) 
- [**3857**星][1m] [JS] [apsdehal/awesome-ctf](https://github.com/apsdehal/awesome-ctf) 
- [**1709**星][1m] [PHP] [orangetw/my-ctf-web-challenges](https://github.com/orangetw/my-ctf-web-challenges) 
- [**945**星][19d] [C] [bt3gl/pentesting-toolkit](https://github.com/bt3gl/Pentesting-Toolkit) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |
- [**358**星][4m] [xtiankisutsa/awesome-mobile-ctf](https://github.com/xtiankisutsa/awesome-mobile-ctf) 
    - 重复区段: [工具/靶机&&漏洞环境&&漏洞App/收集](#383ad9174d3f7399660d36cd6e0b2c00) |
- [**350**星][3y] [Py] [gallopsled/pwntools-write-ups](https://github.com/gallopsled/pwntools-write-ups) 


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
- [**1240**星][4y] [firesuncn/bluelotus_xssreceiver](https://github.com/firesuncn/bluelotus_xssreceiver) 
- [**1132**星][16d] [Py] [p4-team/ctf](https://github.com/p4-team/ctf) 
- [**1034**星][2m] [C] [trailofbits/ctf](https://github.com/trailofbits/ctf) 
- [**1013**星][12m] [naetw/ctf-pwn-tips](https://github.com/naetw/ctf-pwn-tips) 
- [**845**星][1m] [Ruby] [w181496/web-ctf-cheatsheet](https://github.com/w181496/web-ctf-cheatsheet) 
- [**824**星][28d] [ignitetechnologies/privilege-escalation](https://github.com/ignitetechnologies/privilege-escalation) 
- [**780**星][2m] [Py] [acmesec/ctfcracktools](https://github.com/Acmesec/CTFCrackTools) 中国国内首个CTF工具框架,旨在帮助CTFer快速攻克难关
- [**609**星][1m] [Shell] [diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration) 
- [**423**星][6m] [HTML] [ctf-wiki/ctf-challenges](https://github.com/ctf-wiki/ctf-challenges) 
- [**397**星][2m] [Py] [j00ru/ctf-tasks](https://github.com/j00ru/ctf-tasks) 
- [**393**星][3y] [C] [kablaa/ctf-workshop](https://github.com/kablaa/ctf-workshop) 
- [**388**星][1y] [PHP] [wupco/weblogger](https://github.com/wupco/weblogger) 
- [**381**星][14d] [Py] [moloch--/rootthebox](https://github.com/moloch--/rootthebox) 
- [**373**星][4m] [C] [hackgnar/ble_ctf](https://github.com/hackgnar/ble_ctf) 
- [**309**星][2m] [PHP] [nakiami/mellivora](https://github.com/nakiami/mellivora) 
- [**306**星][2y] [Py] [p1kachu/v0lt](https://github.com/p1kachu/v0lt) 
- [**302**星][7m] [Py] [screetsec/brutesploit](https://github.com/screetsec/brutesploit) 
- [**292**星][2m] [Py] [christhecoolhut/pinctf](https://github.com/christhecoolhut/pinctf) 
- [**275**星][11m] [Py] [hongrisec/ctf-training](https://github.com/hongrisec/ctf-training) 
- [**262**星][7y] [Py] [stripe-ctf/stripe-ctf-2.0](https://github.com/stripe-ctf/stripe-ctf-2.0) 
- [**252**星][5m] [Shell] [ctfhacker/epictreasure](https://github.com/ctfhacker/EpicTreasure) Batteries included CTF VM
- [**236**星][12m] [Java] [shiltemann/ctf-writeups-public](https://github.com/shiltemann/ctf-writeups-public) 
- [**218**星][2m] [HTML] [sectalks/sectalks](https://github.com/sectalks/sectalks) 
- [**215**星][1m] [C] [david942j/ctf-writeups](https://github.com/david942j/ctf-writeups) 
- [**197**星][7m] [JS] [sixstars/starctf2019](https://github.com/sixstars/starctf2019) 
- [**189**星][2y] [Py] [xairy/mipt-ctf](https://github.com/xairy/mipt-ctf) 
- [**188**星][4y] [krmaxwell/coding-entertainment](https://github.com/krmaxwell/coding-entertainment) 
- [**180**星][28d] [Py] [rastating/shiva](https://github.com/rastating/shiva) 
- [**173**星][7m] [Py] [osirislab/ctf-solutions](https://github.com/osirislab/CTF-Solutions) 
- [**162**星][3y] [Py] [sourcekris/rsactftool](https://github.com/sourcekris/rsactftool) 
- [**157**星][21d] [JS] [bkimminich/juice-shop-ctf](https://github.com/bkimminich/juice-shop-ctf) Juice Shop CTF 环境配置工具
- [**157**星][2y] [C] [lctf/lctf2017](https://github.com/lctf/lctf2017) 
- [**143**星][2m] [PowerShell] [shiva108/ctf-notes](https://github.com/shiva108/ctf-notes) 
- [**130**星][2y] [PHP] [hcamael/ctf_repo](https://github.com/hcamael/ctf_repo) 
- [**126**星][2y] [vidar-team/hctf2017](https://github.com/vidar-team/hctf2017) 
- [**125**星][2m] [ignitetechnologies/ctf-difficulty](https://github.com/ignitetechnologies/ctf-difficulty) 
- [**125**星][2y] [C#] [m0xiaoxi/ctftools](https://github.com/m0xiaoxi/ctftools) 
- [**125**星][2y] [C#] [m0xiaoxi/ctftools](https://github.com/m0xiaoxi/CTFtools) 
- [**124**星][2m] [Py] [google/ctfscoreboard](https://github.com/google/ctfscoreboard) 
- [**120**星][1m] [Py] [picoctf/picoctf](https://github.com/picoctf/picoctf) 
- [**118**星][4y] [sandysekharan/ctf-tool](https://github.com/sandysekharan/ctf-tool) 
- [**107**星][1y] [Py] [meizjm3i/ctf-challenge](https://github.com/meizjm3i/CTF-Challenge) 
- [**106**星][4m] [PHP] [vvmelody/ctf-web-challenges](https://github.com/vvmelody/ctf-web-challenges) 
- [**101**星][2m] [Py] [nu1lctf/n1ctf-2019](https://github.com/nu1lctf/n1ctf-2019) 
- [**100**星][2y] [Py] [acceis/crypto_identifier](https://github.com/acceis/crypto_identifier) 
- [**99**星][3y] [C] [sciencemanx/ctf_import](https://github.com/sciencemanx/ctf_import) 
- [**98**星][13d] [C++] [cyclops-community/ctf](https://github.com/cyclops-community/ctf) 
- [**97**星][2y] [ktecv2000/how-to-play-ctf](https://github.com/ktecv2000/how-to-play-ctf) 
- [**97**星][2y] [Py] [sonickun/ctf-crypto-writeups](https://github.com/sonickun/ctf-crypto-writeups) 
- [**94**星][3y] [HTML] [sewellding/lfiboomctf](https://github.com/SewellDinG/LFIboomCTF) 
- [**93**星][2y] [Py] [jas502n/2018-qwb-ctf](https://github.com/jas502n/2018-qwb-ctf) 
- [**89**星][20d] [Py] [brieflyx/ctf-pwns](https://github.com/brieflyx/ctf-pwns) 
- [**84**星][2y] [CSS] [cleverbao/webrange](https://github.com/cleverbao/webrange) 
- [**83**星][14d] [C] [wonderkun/ctfenv](https://github.com/wonderkun/ctfenv) 
- [**81**星][2y] [JS] [unrealakama/nightshade](https://github.com/unrealakama/nightshade) 
- [**81**星][1y] [Py] [ctfhacker/ctf-writeups](https://github.com/ctfhacker/ctf-writeups) 
- [**68**星][2m] [opentoallctf/tips](https://github.com/opentoallctf/tips) 
- [**35**星][2m] [Py] [d4mianwayne/alfred](https://github.com/d4mianwayne/alfred) 
- [**28**星][29d] [JS] [iteratec/juicy-ctf](https://github.com/iteratec/juicy-ctf) 
- [**27**星][21d] [Py] [szysec/ctftest](https://github.com/szysec/ctftest) 
- [**22**星][2y] [JS] [team-copper/captar](https://github.com/team-copper/captar) 


#### <a id="0591f47788c6926c482f385b1d71efec"></a>Writeup


- [**1813**星][1y] [CSS] [ctfs/write-ups-2015](https://github.com/ctfs/write-ups-2015) 
- [**1763**星][11m] [Py] [ctfs/write-ups-2017](https://github.com/ctfs/write-ups-2017) 
- [**1623**星][4y] [Py] [ctfs/write-ups-2014](https://github.com/ctfs/write-ups-2014) 
- [**1618**星][4y] [Py] [ctfs/write-ups-2014](https://github.com/ctfs/write-ups-2014) 
- [**1538**星][1y] [C] [ctfs/write-ups-2016](https://github.com/ctfs/write-ups-2016) 
- [**586**星][1m] [Py] [pwning/public-writeup](https://github.com/pwning/public-writeup) 
- [**489**星][8m] [manoelt/50m_ctf_writeup](https://github.com/manoelt/50m_ctf_writeup) 
- [**275**星][7m] [HTML] [bl4de/ctf](https://github.com/bl4de/ctf) 
- [**222**星][1y] [Shell] [ctfs/write-ups-2018](https://github.com/ctfs/write-ups-2018) 
- [**213**星][4y] [Py] [ctfs/write-ups-2013](https://github.com/ctfs/write-ups-2013) 
- [**168**星][3m] [dhaval17/awsome-security-write-ups-and-pocs](https://github.com/dhaval17/awsome-security-write-ups-and-pocs) 
- [**165**星][2y] [Py] [smokeleeteveryday/ctf_writeups](https://github.com/smokeleeteveryday/ctf_writeups) 
- [**160**星][3y] [Py] [ctfs/write-ups-tools](https://github.com/ctfs/write-ups-tools) 
- [**125**星][1y] [C] [lctf/lctf2018](https://github.com/lctf/lctf2018) 
- [**108**星][16d] [Py] [yuawn/ctf](https://github.com/yuawn/CTF) 
- [**106**星][3m] [Haxe] [empirectf/empirectf](https://github.com/empirectf/empirectf) 
- [**92**星][2y] [Shell] [chorankates/h4ck](https://github.com/chorankates/h4ck) 
- [**85**星][8m] [Py] [hackthissite/ctf-writeups](https://github.com/HackThisSite/CTF-Writeups) 
- [**81**星][5m] [Py] [mzfr/ctf-writeups](https://github.com/mzfr/ctf-writeups) 
- [**63**星][7m] [emadshanab/facebook-bug-bounty-writeups](https://github.com/emadshanab/facebook-bug-bounty-writeups) 
- [**60**星][2m] [C] [0e85dc6eaf/ctf-writeups](https://github.com/0e85dc6eaf/CTF-Writeups) 
- [**59**星][28d] [ignitetechnologies/vulnhub-ctf-writeups](https://github.com/ignitetechnologies/vulnhub-ctf-writeups) 
- [**25**星][5m] [Py] [wwkenwong/ctf-writeup](https://github.com/wwkenwong/ctf-writeup) 
- [**19**星][3y] [Py] [abdilahrf/ctfwriteupscrapper](https://github.com/abdilahrf/ctfwriteupscrapper) 
- [**5**星][14d] [Py] [sababasec/ctf-writeups](https://github.com/sababasec/ctf-writeups) 


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
- [**752**星][3y] [Py] [eastee/rebreakcaptcha](https://github.com/eastee/rebreakcaptcha) A logic vulnerability, dubbed ReBreakCaptcha, which lets you easily bypass Google's ReCaptcha v2 anywhere on the web
- [**721**星][1y] [Py] [uber-common/metta](https://github.com/uber-common/metta) 
- [**721**星][3y] [HTML] [xyntax/1000php](https://github.com/xyntax/1000php) 
- [**645**星][5y] [Shell] [hannob/bashcheck](https://github.com/hannob/bashcheck) 
- [**625**星][5m] [Py] [pyupio/safety](https://github.com/pyupio/safety) 检查所有已安装 Python 包, 查找已知的安全漏洞
- [**578**星][7m] [Java] [olacabs/jackhammer](https://github.com/olacabs/jackhammer) 安全漏洞评估和管理工具
- [**570**星][4y] [80vul/phpcodz](https://github.com/80vul/phpcodz) 在php源代码的基础上去分析容易导致php应用程序的一些安全问题的根本所在
- [**567**星][12d] [arkadiyt/bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) 
- [**561**星][3y] [HTML] [salesforce/vulnreport](https://github.com/salesforce/vulnreport) vulnreport：渗透测试管理和自动化平台
- [**541**星][1y] [Java] [mr5m1th/poc-collect](https://github.com/Mr5m1th/POC-Collect) 
- [**540**星][10m] [PHP] [zhuifengshaonianhanlu/pikachu](https://github.com/zhuifengshaonianhanlu/pikachu) 
- [**476**星][1y] [Py] [attify/firmware-analysis-toolkit](https://github.com/attify/firmware-analysis-toolkit) 
- [**462**星][1m] [Java] [joychou93/java-sec-code](https://github.com/joychou93/java-sec-code) 
- [**445**星][5y] [Go] [titanous/heartbleeder](https://github.com/titanous/heartbleeder) 
- [**431**星][2y] [C] [siguza/iohideous](https://github.com/siguza/iohideous) 
- [**430**星][28d] [Py] [google/vulncode-db](https://github.com/google/vulncode-db)  a database for vulnerabilities and their corresponding source code if available
- [**428**星][4m] [Py] [crocs-muni/roca](https://github.com/crocs-muni/roca) 测试公共 RSA 密钥是否存在某些漏洞
- [**413**星][3y] [riusksk/vul_war](https://github.com/riusksk/vul_war) 
- [**409**星][4m] [Java] [nccgroup/freddy](https://github.com/nccgroup/freddy) 自动识别 Java/.NET 应用程序中的反序列化漏洞
- [**401**星][3y] [CSS] [710leo/zvuldrill](https://github.com/710leo/zvuldrill) 
- [**395**星][17d] [Go] [cbeuw/cloak](https://github.com/cbeuw/cloak) 
- [**383**星][4y] [PHP] [spiderlabs/mcir](https://github.com/spiderlabs/mcir) 
- [**379**星][10m] [skyblueeternal/thinkphp-rce-poc-collection](https://github.com/skyblueeternal/thinkphp-rce-poc-collection) 
- [**372**星][6m] [tidesec/tide](https://github.com/tidesec/tide) 
- [**361**星][12m] [hannob/vulns](https://github.com/hannob/vulns) 
- [**357**星][8m] [C] [vulnreproduction/linuxflaw](https://github.com/vulnreproduction/linuxflaw) 
- [**355**星][1y] [Shell] [writeups/ios](https://github.com/writeups/ios) 
- [**354**星][6m] [PHP] [fate0/prvd](https://github.com/fate0/prvd) 
- [**351**星][6m] [Py] [orangetw/awesome-jenkins-rce-2019](https://github.com/orangetw/awesome-jenkins-rce-2019) 
- [**342**星][2m] [snyk/zip-slip-vulnerability](https://github.com/snyk/zip-slip-vulnerability) 
- [**335**星][2m] [Java] [denimgroup/threadfix](https://github.com/denimgroup/threadfix) threadfix：软件漏洞汇总和管理系统，可帮助组织汇总漏洞数据，生成虚拟补丁，并与软件缺陷跟踪系统进行交互
- [**329**星][3y] [Java] [seven456/safewebview](https://github.com/seven456/safewebview) 
- [**314**星][27d] [Java] [sap/vulnerability-assessment-tool](https://github.com/sap/vulnerability-assessment-tool) 
- [**312**星][11m] [cryin/paper](https://github.com/cryin/paper) 
- [**299**星][16d] [Py] [ym2011/poc-exp](https://github.com/ym2011/poc-exp) 
- [**291**星][3m] [Py] [christhecoolhut/firmware_slap](https://github.com/christhecoolhut/firmware_slap) 
- [**286**星][2m] [Py] [fplyth0ner-combie/bug-project-framework](https://github.com/fplyth0ner-combie/bug-project-framework) 
- [**283**星][4m] [C#] [l0ss/grouper2](https://github.com/l0ss/grouper2) 
- [**283**星][7m] [C] [tangsilian/android-vuln](https://github.com/tangsilian/android-vuln) 
- [**275**星][2y] [Py] [iniqua/plecost](https://github.com/iniqua/plecost) plecost：Wordpress 博客引擎的漏洞指纹识别和漏洞查找工具
- [**271**星][21d] [disclose/disclose](https://github.com/disclose/disclose) 
- [**265**星][1y] [Py] [ucsb-seclab/bootstomp](https://github.com/ucsb-seclab/bootstomp) a bootloader vulnerability finder
- [**263**星][2y] [Py] [lightos/panoptic](https://github.com/lightos/panoptic) 
- [**263**星][1y] [JS] [portswigger/hackability](https://github.com/portswigger/hackability) 
- [**249**星][5m] [Py] [jcesarstef/dotdotslash](https://github.com/jcesarstef/dotdotslash) Python脚本, 查找目录遍历漏洞
- [**241**星][2y] [Py] [maian-tool/maian](https://github.com/maian-tool/maian) automatic tool for finding trace vulnerabilities in Ethereum smart contracts
- [**234**星][19d] [HTML] [edoverflow/bugbountyguide](https://github.com/edoverflow/bugbountyguide) 
- [**230**星][2y] [Py] [robotattackorg/robot-detect](https://github.com/robotattackorg/robot-detect) 
- [**223**星][2y] [C] [jas502n/0day-security-software-vulnerability-analysis-technology](https://github.com/jas502n/0day-security-software-vulnerability-analysis-technology) 
- [**220**星][2m] [Py] [ismailtasdelen/hackertarget](https://github.com/pyhackertarget/hackertarget) attack surface discovery and identification of security vulnerabilities
- [**219**星][2y] [C++] [bee13oy/av_kernel_vulns](https://github.com/bee13oy/av_kernel_vulns) 
- [**213**星][4y] [HTML] [musalbas/address-spoofing-poc](https://github.com/musalbas/address-spoofing-poc) 
- [**211**星][2m] [C++] [atxsinn3r/vulncases](https://github.com/atxsinn3r/VulnCases) 
- [**207**星][6m] [Py] [jas502n/cnvd-c-2019-48814](https://github.com/jas502n/cnvd-c-2019-48814) 
- [**202**星][6m] [Py] [greekn/rce-bug](https://github.com/greekn/rce-bug) 
- [**201**星][2m] [Ruby] [appfolio/gemsurance](https://github.com/appfolio/gemsurance) 
- [**201**星][7m] [C++] [j00ru/kfetch-toolkit](https://github.com/googleprojectzero/bochspwn) 
- [**193**星][2y] [C++] [caledoniaproject/xlcloudclient](https://github.com/caledoniaproject/xlcloudclient) 
- [**192**星][5m] [C++] [panda-re/lava](https://github.com/panda-re/lava) 大规模自动化漏洞Addition工具
- [**182**星][1y] [PHP] [yaofeifly/vub_env](https://github.com/yaofeifly/vub_env) 
- [**178**星][2y] [Swift] [nvisium/swift.nv](https://github.com/nvisium/swift.nv) 
- [**177**星][2m] [slowmist/papers](https://github.com/slowmist/papers) 
- [**174**星][2y] [Shell] [ioactive/repossessed](https://github.com/ioactive/repossessed) 
- [**174**星][2y] [sie504/struts-s2-xxx](https://github.com/sie504/struts-s2-xxx) 
- [**173**星][15d] [HTML] [badd1e/disclosures](https://github.com/badd1e/disclosures) 
- [**164**星][8m] [hd421/monitoring-systems-cheat-sheet](https://github.com/hd421/monitoring-systems-cheat-sheet) 
- [**164**星][1y] [C] [jioundai/bluedroid](https://github.com/jioundai/bluedroid) 
- [**160**星][2y] [C] [ninjaprawn/async_wake-fun](https://github.com/ninjaprawn/async_wake-fun) iOS/MacOS 11 内核双释放漏洞 exp
- [**154**星][1m] [C] [airbus-seclab/crashos](https://github.com/airbus-seclab/crashos) crashos：一个极简的操作系统，通过创建畸形的系统配置，导致 hypervisor 崩溃，从而辅助 hypervisor 漏洞研究
- [**153**星][1y] [Java] [lightless233/java-unserialization-study](https://github.com/lightless233/java-unserialization-study) 
- [**153**星][10m] [Py] [vulnerscom/zabbix-threat-control](https://github.com/vulnerscom/zabbix-threat-control) 
- [**152**星][2y] [Py] [laie/worldsfirstsha2vulnerability](https://github.com/laie/worldsfirstsha2vulnerability) 
- [**152**星][14d] [F#] [softsec-kaist/codealchemist](https://github.com/softsec-kaist/codealchemist) 
- [**150**星][2y] [CSS] [m6a-uds/ssrf-lab](https://github.com/m6a-uds/ssrf-lab) 
- [**148**星][1m] [Py] [eth-sri/diffai](https://github.com/eth-sri/diffai) 用于保护神经网络抵御攻击的库
- [**145**星][3y] [C] [ud2/advisories](https://github.com/ud2/advisories) 
- [**142**星][12m] [Py] [jiangsir404/php-code-audit](https://github.com/jiangsir404/php-code-audit) 
- [**140**星][4y] [Py] [dzonerzy/acunetix_0day](https://github.com/dzonerzy/acunetix_0day) 
- [**139**星][4y] [Py] [blackye/jenkins](https://github.com/blackye/jenkins) 
- [**139**星][2m] [Py] [bugcrowd/vulnerability-rating-taxonomy](https://github.com/bugcrowd/vulnerability-rating-taxonomy) 
- [**138**星][2y] [PHP] [bugku/bwvs](https://github.com/bugku/bwvs) 
- [**134**星][2m] [PHP] [jorijn/laravel-security-checker](https://github.com/jorijn/laravel-security-checker) 
- [**133**星][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) 多功能, 带界面,辅助静态分析、漏洞挖掘、动态追踪(Pin)、导入导出等
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**132**星][2m] [Py] [swisskyrepo/vulny-code-static-analysis](https://github.com/swisskyrepo/vulny-code-static-analysis) 
- [**131**星][6y] [ActionScript] [wordpress/secure-swfupload](https://github.com/wordpress/secure-swfupload) 
- [**130**星][2y] [Py] [chrisrimondi/vulntoes](https://github.com/chrisrimondi/vulntoes) 
- [**127**星][4y] [Ruby] [darkarnium/secpub](https://github.com/darkarnium/secpub) 
- [**127**星][3y] [CSS] [shellntel/vcr](https://github.com/shellntel/vcr) 
- [**126**星][2m] [Py] [ivan1ee/struts2-057-exp](https://github.com/ivan1ee/struts2-057-exp) 
- [**123**星][5m] [HTML] [jlleitschuh/zoom_vulnerability_poc](https://github.com/jlleitschuh/zoom_vulnerability_poc) 
- [**121**星][2y] [Java] [ezequielpereira/gae-rce](https://github.com/ezequielpereira/gae-rce) 
- [**119**星][5y] [jyny/pasc2at](https://github.com/jyny/pasc2at) 
- [**117**星][3y] [Py] [fengxuangit/dede_exp_collect](https://github.com/fengxuangit/dede_exp_collect) 
- [**116**星][1m] [Java] [baidu-security/openrasp-testcases](https://github.com/baidu-security/openrasp-testcases) 
- [**116**星][1y] [C#] [vulnerator/vulnerator](https://github.com/vulnerator/vulnerator) 
- [**115**星][8m] [HTML] [edoverflow/proof-of-concepts](https://github.com/edoverflow/proof-of-concepts) 
- [**114**星][10m] [Py] [webbreacher/tilde_enum](https://github.com/webbreacher/tilde_enum) 
- [**111**星][1m] [bugcrowd/disclosure-policy](https://github.com/bugcrowd/disclosure-policy) 
- [**110**星][6y] [CSS] [httphacker/gethead](https://github.com/httphacker/gethead) 
- [**109**星][1m] [Clojure] [rm-hull/lein-nvd](https://github.com/rm-hull/lein-nvd) 
- [**107**星][7m] [C] [mudongliang/linuxflaw](https://github.com/mudongliang/linuxflaw) 
- [**103**星][4m] [Py] [b1eed/vulrec](https://github.com/b1eed/vulrec) 漏洞复现记录
- [**102**星][1y] [funnykun/nessusreportinchinese](https://github.com/funnykun/nessusreportinchinese) 
- [**101**星][1y] [edoverflow/bugbountywiki](https://github.com/edoverflow/bugbountywiki) 
- [**100**星][3y] [C++] [lcatro/vuln_javascript](https://github.com/lcatro/vuln_javascript) 
- [**100**星][3y] [CSS] [nonce-disrespect/nonce-disrespect](https://github.com/nonce-disrespect/nonce-disrespect) 
- [**99**星][1m] [Go] [facebookincubator/nvdtools](https://github.com/facebookincubator/nvdtools) 
- [**98**星][2y] [JS] [avlidienbrunn/bountydash](https://github.com/avlidienbrunn/bountydash) 从所有BugBounty平台收集你获取的奖励信息, 生成进度和漏洞类型信息图表等
- [**98**星][5m] [Py] [hanc00l/some_pocsuite](https://github.com/hanc00l/some_pocsuite) 
- [**96**星][1y] [Py] [mrmtwoj/0day-mikrotik](https://github.com/mrmtwoj/0day-mikrotik) 
- [**92**星][1y] [Java] [sirmordred/angelaroot](https://github.com/sirmordred/angelaroot) 
- [**92**星][2y] [JS] [tinysec/vulnerability](https://github.com/tinysec/vulnerability) vulnerability：作者收集的Windows内核漏洞。
- [**91**星][2y] [jollheef/libreoffice-remote-arbitrary-file-disclosure](https://github.com/jollheef/libreoffice-remote-arbitrary-file-disclosure) 
- [**90**星][1y] [C] [grimm-co/notquite0dayfriday](https://github.com/grimm-co/notquite0dayfriday) 
- [**89**星][8m] [pagalaxylab/vulinfo](https://github.com/pagalaxylab/vulinfo) 
- [**86**星][1y] [C] [cgcl-codes/vuldeepecker](https://github.com/cgcl-codes/vuldeepecker) A Deep Learning-Based System for Vulnerability Detection
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |
- [**85**星][4y] [Py] [knownsec/vxpwn](https://github.com/knownsec/vxpwn) 
- [**85**星][1m] [Ruby] [rtfpessoa/dependency_spy](https://github.com/rtfpessoa/dependency_spy) 
- [**82**星][1y] [HTML] [amolnaik4/bodhi](https://github.com/amolnaik4/bodhi) 
- [**82**星][1m] [Go] [sonatype-nexus-community/nancy](https://github.com/sonatype-nexus-community/nancy) 
- [**80**星][7m] [C] [nowsecure/dirtycow](https://github.com/nowsecure/dirtycow) 
- [**79**星][12m] [PowerShell] [thom-s/docx-embeddedhtml-injection](https://github.com/thom-s/docx-embeddedhtml-injection) 
- [**76**星][2y] [Py] [dtag-dev-sec/explo](https://github.com/dtag-dev-sec/explo) 
- [**76**星][3m] [Py] [githubmaidou/tools](https://github.com/githubmaidou/tools) 
- [**74**星][4y] [Py] [einstein-/poodle](https://github.com/einstein-/poodle) 
- [**73**星][18d] [C] [greenbone/gvmd](https://github.com/greenbone/gvmd) 
- [**70**星][2y] [Py] [tengzhangchao/microsoftspider](https://github.com/tengzhangchao/microsoftspider) 
- [**68**星][1y] [JS] [samhaxr/xxrf-shots](https://github.com/samhaxr/xxrf-shots) 
- [**67**星][19d] [Py] [greenbone/gvm-tools](https://github.com/greenbone/gvm-tools) 
- [**67**星][4m] [Py] [bbva/patton-server](https://github.com/BBVA/patton) 
- [**66**星][3y] [JS] [pythonran/pcap_tools](https://github.com/pythonran/pcap_tools) 
- [**65**星][11m] [HTML] [zadewg/livebox-0day](https://github.com/zadewg/livebox-0day) 
- [**64**星][6m] [Assembly] [cdisselkoen/pitchfork](https://github.com/cdisselkoen/pitchfork) 
- [**64**星][1y] [Lua] [pr4jwal/quick-scripts](https://github.com/pr4jwal/quick-scripts) 
- [**60**星][6m] [Kotlin] [fs0c131y/samsunglocker](https://github.com/fs0c131y/samsunglocker) 
- [**59**星][1m] [Py] [xfreed0m/smtptester](https://github.com/xfreed0m/smtptester) 
- [**58**星][2y] [Ruby] [hammackj/risu](https://github.com/hammackj/risu) 
- [**56**星][3y] [C] [zerosum0x0/shellcodedriver](https://github.com/zerosum0x0/shellcodedriver) 
- [**56**星][21d] [Py] [cve-search/git-vuln-finder](https://github.com/cve-search/git-vuln-finder) 
- [**55**星][2m] [Py] [cleanunicorn/karl](https://github.com/cleanunicorn/karl) 
- [**54**星][1y] [HTML] [gwen001/actarus](https://github.com/gwen001/actarus) 
- [**54**星][4m] [Py] [re4lity/pocorexp](https://github.com/re4lity/PoCorExp) 
- [**53**星][2y] [objective-c] [iabem97/securityd-racer2](https://github.com/iabem97/securityd-racer2) 
- [**53**星][1y] [Py] [wangyihang/find-php-vulnerabilities](https://github.com/wangyihang/find-php-vulnerabilities) 
- [**52**星][3y] [PHP] [northwind6/webbug](https://github.com/northwind6/webbug) 
- [**52**星][2y] [JS] [tyrmars/websafe-steppitguide](https://github.com/tyrmars/websafe-steppitguide) 
- [**51**星][3y] [Py] [secwiki/some-poc-or-exp](https://github.com/secwiki/some-poc-or-exp) 
- [**48**星][4m] [jas502n/cve-2019-11581](https://github.com/jas502n/cve-2019-11581) 
- [**47**星][8m] [Py] [kkamagui/napper-for-tpm](https://github.com/kkamagui/napper-for-tpm) 
- [**44**星][12m] [bugbountyresources/resources](https://github.com/bugbountyresources/resources) 
- [**44**星][2y] [feeicn/wsvd](https://github.com/FeeiCN/WSVD) 
- [**43**星][2y] [C++] [iricartb/buffer-overflow-vulnerability-services-tester-tool](https://github.com/iricartb/buffer-overflow-vulnerability-services-tester-tool) 
- [**43**星][3m] [Shell] [juxhindb/oob-server](https://github.com/juxhindb/oob-server) 
- [**42**星][4y] [Py] [sh1nu11bi/routerhunter-2.0](https://github.com/sh1nu11bi/routerhunter-2.0) 
- [**41**星][1y] [C] [synacktiv/lightspeed](https://github.com/Synacktiv-contrib/lightspeed) 
- [**39**星][7m] [certcc/vulnerability-data-archive](https://github.com/certcc/vulnerability-data-archive) 
- [**39**星][2y] [Py] [vah13/sap_vulnerabilities](https://github.com/vah13/sap_vulnerabilities) 
- [**38**星][4m] [JS] [github/enable-security-alerts-sample](https://github.com/github/enable-security-alerts-sample) 
- [**37**星][3y] [Py] [mthbernardes/strutszeiro](https://github.com/mthbernardes/strutszeiro) 
- [**36**星][4y] [Py] [dionach/codeigniterxor](https://github.com/dionach/codeigniterxor) 
- [**36**星][1y] [JS] [rewanth1997/vuln-headers-extension](https://github.com/rewanth1997/vuln-headers-extension) 
- [**35**星][3y] [Py] [0pc0defr/wordpress-sploit-framework](https://github.com/0pc0defr/wordpress-sploit-framework) 
- [**35**星][2y] [Py] [blazeinfosec/ssrf-ntlm](https://github.com/blazeinfosec/ssrf-ntlm) 
- [**35**星][13d] [PowerShell] [cube0x0/security-assessment](https://github.com/cube0x0/security-assessment) 
- [**35**星][17d] [C] [greenbone/gvm-libs](https://github.com/greenbone/gvm-libs) 
- [**35**星][2y] [Shell] [secfathy/bugzee](https://github.com/secfathy/bugzee) 
- [**34**星][10m] [Py] [nevillegrech/madmax](https://github.com/nevillegrech/madmax) 
- [**34**星][2m] [C#] [ossindex/audit.net](https://github.com/ossindex/audit.net) 
- [**32**星][6y] [Py] [coldheat/quicksec](https://github.com/coldheat/quicksec) 
- [**32**星][2y] [PHP] [leebaird/assessment-manager](https://github.com/leebaird/assessment-manager) 
- [**32**星][1y] [lylemi/dom-vuln-db](https://github.com/lylemi/dom-vuln-db) 
- [**31**星][1y] [edoverflow/legal-bug-bounty](https://github.com/edoverflow/legal-bug-bounty) 
- [**31**星][5y] [Java] [forprevious/attack-analysis](https://github.com/forprevious/attack-analysis) 
- [**31**星][7m] [Py] [maxkrivich/slowloris](https://github.com/maxkrivich/slowloris) 
- [**30**星][4y] [C++] [rootkitsmm/cvexx-xx](https://github.com/rootkitsmm/cvexx-xx) 
- [**29**星][17d] [Py] [aliasrobotics/rvd](https://github.com/aliasrobotics/rvd) 
- [**29**星][3y] [Shell] [tjunxiang92/android-vulnerabilities](https://github.com/tjunxiang92/android-vulnerabilities) 
- [**28**星][1m] [Go] [mondoolabs/mondoo](https://github.com/mondoolabs/mondoo) 
- [**28**星][3y] [uber/bug-bounty-page](https://github.com/uber/bug-bounty-page) 
- [**27**星][2y] [PHP] [blackfan/web-inf-dict](https://github.com/blackfan/web-inf-dict) 
- [**27**星][4y] [C++] [dkemp/vulndev](https://github.com/dkemp/vulndev) 
- [**27**星][7m] [vah13/oraclecve](https://github.com/vah13/oraclecve) 
- [**26**星][2y] [Py] [jlospinoso/unfurl](https://github.com/jlospinoso/unfurl) 
- [**26**星][3y] [Java] [owasp/owaspbugbounty](https://github.com/owasp/owaspbugbounty) 
- [**25**星][2y] [JS] [cybellum/vulnerabilities](https://github.com/cybellum/vulnerabilities) 
- [**25**星][3y] [Go] [maddevsio/telegram_bbbot](https://github.com/maddevsio/telegram_bbbot) 
- [**25**星][7y] [Py] [tosanjay/bopfunctionrecognition](https://github.com/tosanjay/bopfunctionrecognition) 
- [**24**星][1m] [Py] [greenbone/python-gvm](https://github.com/greenbone/python-gvm) 
- [**24**星][1y] [omg2hei/vulnerability-env](https://github.com/omg2hei/vulnerability-env) 
- [**24**星][3y] [polarislab/s2-045](https://github.com/polarislab/s2-045) 
- [**24**星][2y] [Shell] [styx00/apache-vulns](https://github.com/styx00/apache-vulns) 
- [**23**星][3y] [C] [guidovranken/openssl-x509-vulnerabilities](https://github.com/guidovranken/openssl-x509-vulnerabilities) 
- [**23**星][2y] [Shell] [jacksongl/npm-vuln-poc](https://github.com/jacksongl/npm-vuln-poc) 
- [**23**星][6m] [Py] [jpiechowka/zip-shotgun](https://github.com/jpiechowka/zip-shotgun) 
- [**23**星][4m] [Shell] [sap/vulnerability-assessment-kb](https://github.com/sap/vulnerability-assessment-kb) 
- [**23**星][9m] [Perl] [vti/cpan-audit](https://github.com/vti/cpan-audit) 
- [**22**星][3y] [C] [sagi/android_pocs](https://github.com/sagi/android_pocs) 
- [**21**星][2m] [Py] [random-robbie/bugbountydork](https://github.com/random-robbie/bugbountydork) 
- [**21**星][4m] [Shell] [sec0ps/va-pt](https://github.com/sec0ps/va-pt) 


### <a id="750f4c05b5ab059ce4405f450b56d720"></a>资源收集


- [**3444**星][8m] [C] [rpisec/mbe](https://github.com/rpisec/mbe) 
- [**3429**星][4m] [PHP] [hanc00l/wooyun_public](https://github.com/hanc00l/wooyun_public) 
- [**2954**星][8m] [C] [secwiki/linux-kernel-exploits](https://github.com/secwiki/linux-kernel-exploits) 
- [**2600**星][1m] [xairy/linux-kernel-exploitation](https://github.com/xairy/linux-kernel-exploitation) Linux 内核 Fuzz 和漏洞利用的资源收集
- [**2184**星][3y] [enddo/awesome-windows-exploitation](https://github.com/enddo/awesome-windows-exploitation) 
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
- [**735**星][4y] [fabiobaroni/awesome-exploit-development](https://github.com/fabiobaroni/awesome-exploit-development) 
    - 重复区段: [工具/靶机&&漏洞环境&&漏洞App/收集](#383ad9174d3f7399660d36cd6e0b2c00) |
- [**672**星][1y] [C] [billy-ellis/exploit-challenges](https://github.com/billy-ellis/exploit-challenges) 
- [**609**星][7m] [yeyintminthuhtut/awesome-advanced-windows-exploitation-references](https://github.com/yeyintminthuhtut/Awesome-Advanced-Windows-Exploitation-References) 
- [**579**星][3y] [hack-with-github/windows](https://github.com/hack-with-github/windows) 
- [**568**星][1y] [C] [externalist/exploit_playground](https://github.com/externalist/exploit_playground) 
- [**483**星][7m] [C] [jiayy/android_vuln_poc-exp](https://github.com/jiayy/android_vuln_poc-exp) 
- [**424**星][2y] [Py] [coalfire-research/java-deserialization-exploits](https://github.com/coalfire-research/java-deserialization-exploits) 
- [**417**星][9m] [C] [hardenedlinux/linux-exploit-development-tutorial](https://github.com/hardenedlinux/linux-exploit-development-tutorial) 
- [**340**星][2y] [C++] [ele7enxxh/poc-exp](https://github.com/ele7enxxh/poc-exp) 某些 Android 漏洞的poc/exp
- [**329**星][1y] [snyk/vulnerabilitydb](https://github.com/snyk/vulnerabilitydb) 
- [**309**星][1y] [PHP] [grt1st/wooyun_search](https://github.com/grt1st/wooyun_search) 
- [**268**星][10m] [Py] [secwiki/office-exploits](https://github.com/secwiki/office-exploits) 
- [**262**星][2y] [sam-b/windows_kernel_resources](https://github.com/sam-b/windows_kernel_resources) 
- [**245**星][2y] [ludios/unfixed-security-bugs](https://github.com/ludiosarchive/unfixed-security-bugs) unfixed-security-bugs：已公开但未修复的漏洞列表。包括Chrome、VirtualBox、WeeChat、Windows（7-10）等知名软件。
- [**222**星][2m] [Py] [boy-hack/airbug](https://github.com/boy-hack/airbug) 
- [**222**星][1y] [C++] [wnagzihxa1n/browsersecurity](https://github.com/wnagzihxa1n/browsersecurity) 
- [**193**星][1y] [Py] [sec-bit/awesome-buggy-erc20-tokens](https://github.com/sec-bit/awesome-buggy-erc20-tokens) 
- [**174**星][5m] [pochubs/pochubs](https://github.com/pochubs/pochubs) 
- [**158**星][1y] [HTML] [exploitprotocol/mobile-security-wiki](https://github.com/exploitprotocol/mobile-security-wiki) 
- [**140**星][8m] [Py] [kacperszurek/exploits](https://github.com/kacperszurek/exploits) exploits：提权漏洞利用集合
- [**96**星][4m] [houjingyi233/cpu-vulnerability-collections](https://github.com/houjingyi233/CPU-vulnerability-collections) 
- [**93**星][16d] [Assembly] [alanvivona/pwnshop](https://github.com/alanvivona/pwnshop) 
- [**88**星][2y] [C] [secwiki/android-kernel-exploits](https://github.com/secwiki/android-kernel-exploits) 
- [**73**星][1y] [tianjifou/ios-security-attack-and-prevent](https://github.com/tianjifou/ios-security-attack-and-prevent) 


### <a id="605b1b2b6eeb5138cb4bc273a30b28a5"></a>漏洞开发


#### <a id="68a64028eb1f015025d6f5a6ee6f6810"></a>未分类-VulDev


- [**3705**星][10m] [Py] [longld/peda](https://github.com/longld/peda) Python Exploit Development Assistance for GDB
- [**2488**星][13d] [Py] [hugsy/gef](https://github.com/hugsy/gef) gdb增强工具，使用Python API，用于漏洞开发和逆向分析。
- [**2362**星][22d] [Py] [pwndbg/pwndbg](https://github.com/pwndbg/pwndbg) GDB插件，辅助漏洞开发和逆向
- [**563**星][2y] [Py] [nnamon/linux-exploitation-course](https://github.com/nnamon/linux-exploitation-course) 中级 Linux 漏洞开发课程
- [**465**星][10m] [Py] [wapiflapi/villoc](https://github.com/wapiflapi/villoc) 


#### <a id="019cf10dbc7415d93a8d22ef163407ff"></a>ROP


- [**2101**星][27d] [Py] [jonathansalwan/ropgadget](https://github.com/jonathansalwan/ropgadget) 
- [**931**星][13d] [Py] [sashs/ropper](https://github.com/sashs/ropper) 
- [**841**星][3y] [C++] [0vercl0k/rp](https://github.com/0vercl0k/rp) 
- [**677**星][11m] [HTML] [zhengmin1989/myarticles](https://github.com/zhengmin1989/myarticles) 
- [**259**星][6y] [C] [pakt/ropc](https://github.com/pakt/ropc) 
- [**188**星][2y] [Py] [kokjo/universalrop](https://github.com/kokjo/universalrop) universalrop：使用unicorn 和 z3 生成 ROP 链
- [**181**星][5m] [C++] [boyan-milanov/ropgenerator](https://github.com/boyan-milanov/ropgenerator) 
- [**173**星][4m] [C] [acama/xrop](https://github.com/acama/xrop) 
- [**166**星][5m] [C++] [immunant/selfrando](https://github.com/immunant/selfrando) 
- [**158**星][2y] [Py] [jeffball55/rop_compiler](https://github.com/jeffball55/rop_compiler) 
- [**151**星][2y] [Py] [orppra/ropa](https://github.com/orppra/ropa) ROP 链创建工具, 带界面, 基于 Ropper
- [**138**星][3y] [Objective-C] [kpwn/935csbypass](https://github.com/kpwn/935csbypass) 
- [**125**星][2y] [C++] [gpoulios/ropinjector](https://github.com/gpoulios/ropinjector) 
- [**77**星][5y] [C++] [helpsystems/agafi](https://github.com/helpsystems/Agafi) 
- [**64**星][6y] [C] [programa-stic/ropc-llvm](https://github.com/programa-stic/ropc-llvm) 
- [**53**星][2y] [Py] [uzetta27/easyrop](https://github.com/uzetta27/easyrop) 
- [**49**星][2y] [JS] [jpenalbae/rarop](https://github.com/jpenalbae/rarop) 
- [**44**星][2y] [Py] [wizh/rop-chainer](https://github.com/wizh/rop-chainer) 
- [**32**星][2y] [Py] [spiperac/armroper](https://github.com/spiperac/armroper) 
- [**30**星][5y] [Py] [osirislab/catfish](https://github.com/osirislab/Catfish) 




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
- [**468**星][2y] [Ruby] [0xsauby/yasuo](https://github.com/0xsauby/yasuo) ruby 脚本，扫描网络中存在漏洞的第三方 web app
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


- [**351**星][4y] [PHP] [onesourcecat/phpvulhunter](https://github.com/onesourcecat/phpvulhunter) 
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
- [**256**星][4y] [Py] [netxfly/passive_scan](https://github.com/netxfly/passive_scan) 
- [**246**星][4m] [Shell] [peterpt/eternal_scanner](https://github.com/peterpt/eternal_scanner) eternal_scanner：永恒之蓝漏洞的网络扫描器
- [**226**星][1y] [Py] [leapsecurity/libssh-scanner](https://github.com/leapsecurity/libssh-scanner) 
- [**222**星][4y] [PHP] [ripsscanner/rips](https://github.com/ripsscanner/rips) 
- [**222**星][1y] [C++] [ucsb-seclab/dr_checker](https://github.com/ucsb-seclab/dr_checker) 用于Linux 内核驱动程序的漏洞检测工具
- [**218**星][7m] [Py] [skewwg/vulscan](https://github.com/skewwg/vulscan) 
- [**211**星][6m] [Py] [kingkaki/weblogic-scan](https://github.com/kingkaki/weblogic-scan) 
- [**208**星][20d] [Py] [sethsec/celerystalk](https://github.com/sethsec/celerystalk) 
- [**197**星][30d] [Py] [1120362990/vulnerability-list](https://github.com/1120362990/vulnerability-list) 
- [**179**星][3m] [OCaml] [fkie-cad/cwe_checker](https://github.com/fkie-cad/cwe_checker) 
- [**174**星][1y] [random-robbie/bugbounty-scans](https://github.com/random-robbie/bugbounty-scans) 
- [**161**星][5y] [JS] [skycrab/leakscan](https://github.com/skycrab/leakscan) 
- [**161**星][2y] [Py] [tulpar/tulpar](https://github.com/tulpar/tulpar) 
- [**158**星][2y] [HTML] [secmob/pwnfest2016](https://github.com/secmob/pwnfest2016) 
- [**156**星][7m] [Py] [dyboy2017/wtf_scan](https://github.com/dyboy2017/wtf_scan) 
- [**153**星][11m] [C] [sjvermeu/cvechecker](https://github.com/sjvermeu/cvechecker) 
- [**138**星][6m] [0xbug/biu](https://github.com/0xbug/biu) 
- [**137**星][6m] [Py] [jaxbcd/zeebsploit](https://github.com/jaxbcd/zeebsploit) 
- [**134**星][8m] [Py] [jzadeh/aktaion](https://github.com/jzadeh/aktaion) 基于微行为（Micro Behavior）的漏洞检测和自动化GPO策略生成
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |
- [**133**星][2y] [Py] [random-robbie/jira-scan](https://github.com/random-robbie/jira-scan) 
- [**132**星][10m] [Ruby] [bahaabdelwahed/killshot](https://github.com/bahaabdelwahed/killshot) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |[工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |
- [**132**星][1m] [Py] [tuhinshubhra/extanalysis](https://github.com/tuhinshubhra/extanalysis) 
- [**126**星][7m] [C++] [gossip-sjtu/tripledoggy](https://github.com/gossip-sjtu/tripledoggy) 
- [**126**星][4y] [PHP] [lietdai/doom](https://github.com/lietdai/doom) 
- [**124**星][2m] [C++] [detexploit/detexploit](https://github.com/detexploit/detexploit) 
- [**123**星][5m] [PHP] [radenvodka/svscanner](https://github.com/radenvodka/svscanner) 
- [**119**星][12m] [imfht/educn-sqlscan](https://github.com/imfht/educn-sqlScan) 
- [**112**星][4m] [Py] [rabbitmask/weblogicscanlot](https://github.com/rabbitmask/weblogicscanlot) 
- [**111**星][2y] [Py] [hook-s3c/blueborne-scanner](https://github.com/hook-s3c/blueborne-scanner) 
- [**106**星][5m] [Py] [flyingcircusio/vulnix](https://github.com/flyingcircusio/vulnix) 
- [**106**星][5m] [Py] [graph-x/davscan](https://github.com/graph-x/davscan) 
- [**102**星][3m] [boy-hack/w10scan](https://github.com/w-digital-scanner/w10scan) 
- [**101**星][1y] [JS] [rassec/a_scan_framework](https://github.com/rassec/a_scan_framework) 
- [**100**星][12m] [Java] [duo-labs/xray](https://github.com/duo-labs/xray) 
- [**98**星][5y] [Py] [onesourcecat/scan-framework](https://github.com/onesourcecat/scan-framework) 
- [**96**星][2y] [Py] [he1m4n6a/btscan](https://github.com/he1m4n6a/btscan) 
- [**83**星][2y] [Py] [1n3/httpoxyscan](https://github.com/1n3/httpoxyscan) 
- [**83**星][4y] [Py] [huntergregal/scansploit](https://github.com/huntergregal/scansploit) 
- [**83**星][4y] [Py] [youmengxuefei/web_vul_scan](https://github.com/youmengxuefei/web_vul_scan) 
- [**82**星][12m] [Java] [twjitm/afhq](https://github.com/twjitm/afhq) 
- [**81**星][2y] [Py] [lcatro/browser_vuln_check](https://github.com/lcatro/browser_vuln_check) 利用已知的浏览器漏洞PoC 来快速检测Webview 和浏览器环境是否存在安全漏洞,只需要访问run.html 即可获取所有扫描结果,适用场景包含:APP 发布之前的内部安全测试,第三方Webview 漏洞检测等
- [**77**星][2y] [Py] [stasinopoulos/jaidam](https://github.com/stasinopoulos/jaidam) 
- [**75**星][2y] [JS] [polaris64/web_exploit_detector](https://github.com/polaris64/web_exploit_detector) web_exploit_detector：检测 Web hosting 环境中可能的感染、恶意代码和可疑文件。Node.js 应用程序。
- [**75**星][3y] [ywolf/f-middlewarescan](https://github.com/ywolf/f-middlewarescan) 
- [**68**星][1y] [PHP] [philipjohn/exploit-scanner-hashes](https://github.com/philipjohn/exploit-scanner-hashes) 
- [**62**星][7m] [Py] [grayddq/publicsecscan](https://github.com/grayddq/publicsecscan) 
- [**59**星][1y] [Py] [tiaotiaolong/ttlscan](https://github.com/tiaotiaolong/ttlscan) 
- [**55**星][4y] [Py] [az0ne/jboss_autoexploit](https://github.com/az0ne/jboss_autoexploit) 
- [**55**星][4y] [Py] [cc06/dns_transfer_check](https://github.com/cc06/dns_transfer_check) 
- [**52**星][1y] [C#] [them4hd1/jcs](https://github.com/them4hd1/jcs) 
- [**49**星][3y] [C++] [rolisoft/host-scanner](https://github.com/rolisoft/host-scanner) 
- [**47**星][1y] [Py] [zer0yu/zeroscan](https://github.com/zer0yu/zeroscan) 
- [**46**星][4m] [JS] [lwindolf/polscan](https://github.com/lwindolf/polscan) 
- [**40**星][5m] [Perl] [anon6372098/fazscan](https://github.com/anon6372098/fazscan) 
- [**40**星][5y] [Java] [paloaltonetworks/installerhijackingvulnerabilityscanner](https://github.com/PaloAltoNetworks/InstallerHijackingVulnerabilityScanner) 
- [**37**星][3y] [C] [p0cl4bs/thanos](https://github.com/p0cl4bs/thanos) 
- [**37**星][3y] [Py] [programa-stic/marvin-dynamic-analyzer](https://github.com/programa-stic/marvin-dynamic-analyzer) 
- [**37**星][9m] [Py] [raz0r/aemscan](https://github.com/raz0r/aemscan) 
- [**32**星][9y] [Py] [evilsocket/altair](https://github.com/evilsocket/altair) 
- [**31**星][2m] [Py] [monolithworks/trueseeing](https://github.com/monolithworks/trueseeing) 
- [**30**星][3y] [Py] [fkie-cad/iva](https://github.com/fkie-cad/iva) 
- [**29**星][4y] [Py] [xyntax/zzone-transfer](https://github.com/xyntax/zzone-transfer) 
- [**28**星][3y] [Py] [caleb1994/peach](https://github.com/calebstewart/peach) 
- [**27**星][4y] [Py] [cheetz/icmpshock](https://github.com/cheetz/icmpshock) 
- [**24**星][3y] [Py] [fluproject/flunym0us](https://github.com/fluproject/flunym0us) 
- [**22**星][7m] [C++] [zhutoulala/vulnscan](https://github.com/zhutoulala/vulnscan) 


##### <a id="d22e52bd9f47349df896ca85675d1e5c"></a>Web漏洞




##### <a id="060dd7b419423ee644794fccd67c22a8"></a>系统漏洞




##### <a id="67939d66cf2a9d9373cc0a877a8c72c2"></a>App漏洞




##### <a id="2076af46c7104737d06dbe29eb7c9d3a"></a>移动平台漏洞






#### <a id="382aaa11dea4036c5b6d4a8b06f8f786"></a>Fuzzing


##### <a id="1c2903ee7afb903ccfaa26f766924385"></a>未分类-Fuzz


- [**4649**星][29d] [C] [google/oss-fuzz](https://github.com/google/oss-fuzz) oss-fuzz：开源软件fuzzing
- [**4060**星][2y] [Py] [xoreaxeaxeax/sandsifter](https://github.com/xoreaxeaxeax/sandsifter) sandsifter：x86 处理器 Fuzzer，查找 Intel 的隐藏指令和 CPU bug
- [**3992**星][12d] [Py] [google/clusterfuzz](https://github.com/google/clusterfuzz) 
- [**3169**星][1m] [Go] [dvyukov/go-fuzz](https://github.com/dvyukov/go-fuzz) 
- [**1706**星][1y] [PowerShell] [fuzzysecurity/powershell-suite](https://github.com/fuzzysecurity/powershell-suite) 
- [**1335**星][2m] [C] [googleprojectzero/winafl](https://github.com/googleprojectzero/winafl) 
- [**1107**星][1y] [aoh/radamsa](https://github.com/aoh/radamsa) 
- [**1107**星][9m] [Py] [openrce/sulley](https://github.com/openrce/sulley) 
- [**1100**星][28d] [bo0om/fuzz.txt](https://github.com/bo0om/fuzz.txt) 
- [**1006**星][19d] [Py] [thekingofduck/fuzzdicts](https://github.com/thekingofduck/fuzzdicts) 
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/资源收集](#750f4c05b5ab059ce4405f450b56d720) |
- [**990**星][28d] [C] [google/fuzzer-test-suite](https://github.com/google/fuzzer-test-suite) 
- [**859**星][18d] [Py] [swisskyrepo/ssrfmap](https://github.com/swisskyrepo/ssrfmap) 
- [**850**星][25d] [Go] [sahilm/fuzzy](https://github.com/sahilm/fuzzy) 
- [**808**星][1m] [C] [rust-fuzz/afl.rs](https://github.com/rust-fuzz/afl.rs) 
- [**803**星][3y] [Py] [fuzzbunch/fuzzbunch](https://github.com/fuzzbunch/fuzzbunch) 
- [**788**星][17d] [Swift] [googleprojectzero/fuzzilli](https://github.com/googleprojectzero/fuzzilli) 
- [**763**星][2y] [C++] [dor1s/libfuzzer-workshop](https://github.com/dor1s/libfuzzer-workshop) 
- [**748**星][23d] [Py] [jtpereyda/boofuzz](https://github.com/jtpereyda/boofuzz) 网络协议Fuzzing框架, sulley的继任者
- [**736**星][7m] [HTML] [tennc/fuzzdb](https://github.com/tennc/fuzzdb) 
- [**689**星][14d] [Go] [ffuf/ffuf](https://github.com/ffuf/ffuf) 
- [**634**星][28d] [Go] [google/gofuzz](https://github.com/google/gofuzz) 
- [**628**星][4m] [C] [kernelslacker/trinity](https://github.com/kernelslacker/trinity) 
- [**608**星][14d] [C] [google/afl](https://github.com/google/afl) 
- [**588**星][4m] [Py] [nongiach/arm_now](https://github.com/nongiach/arm_now) arm_now: 快速创建并运行不同CPU架构的虚拟机, 用于逆向分析或执行二进制文件. 基于QEMU
- [**569**星][19d] [Py] [1n3/blackwidow](https://github.com/1n3/blackwidow) 
- [**545**星][2y] [C] [mirrorer/afl](https://github.com/mirrorer/afl) 
- [**541**星][8m] [Py] [shellphish/fuzzer](https://github.com/shellphish/fuzzer) fuzzer：Americanfuzzy lop 的 Python 版本接口
- [**535**星][3y] [Py] [marin-m/pbtk](https://github.com/marin-m/pbtk) 
- [**516**星][2m] [C++] [angorafuzzer/angora](https://github.com/angorafuzzer/angora) 
- [**500**星][12d] [Py] [mozillasecurity/funfuzz](https://github.com/mozillasecurity/funfuzz) 
- [**472**星][1y] [Py] [c0ny1/upload-fuzz-dic-builder](https://github.com/c0ny1/upload-fuzz-dic-builder) 
- [**471**星][16d] [Py] [trailofbits/deepstate](https://github.com/trailofbits/deepstate) 
- [**453**星][1m] [Rust] [rust-fuzz/cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) cargo-fuzz：libFuzzer的wrapper
- [**449**星][2y] [C] [nccgroup/triforceafl](https://github.com/nccgroup/triforceafl) 
- [**424**星][2m] [Perl] [wireghoul/dotdotpwn](https://github.com/wireghoul/dotdotpwn) 
- [**404**星][6m] [Ruby] [tidesec/fuzzscanner](https://github.com/tidesec/fuzzscanner) 
- [**398**星][2y] [Py] [rub-syssec/kafl](https://github.com/rub-syssec/kafl) 
- [**398**星][4m] [C] [mykter/afl-training](https://github.com/mykter/afl-training) 
- [**384**星][6m] [C] [coolervoid/0d1n](https://github.com/coolervoid/0d1n) 
- [**383**星][3y] [Ruby] [stephenfewer/grinder](https://github.com/stephenfewer/grinder) 
- [**379**星][27d] [Haskell] [crytic/echidna](https://github.com/crytic/echidna) echidna: Ethereum fuzz testing framework
- [**378**星][3m] [Rust] [microsoft/lain](https://github.com/microsoft/lain) 
- [**370**星][1m] [TypeScript] [fuzzitdev/jsfuzz](https://github.com/fuzzitdev/jsfuzz) 
- [**364**星][1y] [C] [battelle/afl-unicorn](https://github.com/Battelle/afl-unicorn) 
- [**362**星][2y] [C] [k0keoyo/kdriver-fuzzer](https://github.com/k0keoyo/kdriver-fuzzer) 
- [**361**星][1y] [Py] [rc0r/afl-utils](https://github.com/rc0r/afl-utils) 
- [**360**星][3y] [C] [fsecurelabs/kernelfuzzer](https://github.com/FSecureLABS/KernelFuzzer) 
- [**357**星][3m] [C++] [googleprojectzero/brokentype](https://github.com/googleprojectzero/BrokenType) 
- [**342**星][2y] [PowerShell] [fuzzysecurity/pskernel-primitives](https://github.com/fuzzysecurity/pskernel-primitives) 
- [**340**星][4m] [Java] [google/graphicsfuzz](https://github.com/google/graphicsfuzz) 
- [**340**星][1m] [C++] [sslab-gatech/qsym](https://github.com/sslab-gatech/qsym) 
- [**337**星][11m] [Py] [joxeankoret/nightmare](https://github.com/joxeankoret/nightmare) 
- [**335**星][3y] [Shell] [0xm3r/cgpwn](https://github.com/0xm3r/cgpwn) 
- [**311**星][2y] [Py] [ioactive/xdiff](https://github.com/ioactive/xdiff) 
- [**311**星][3m] [lcatro/source-and-fuzzing](https://github.com/lcatro/Source-and-Fuzzing) 
- [**306**星][5m] [Py] [cisco-talos/mutiny-fuzzer](https://github.com/cisco-talos/mutiny-fuzzer) 
- [**306**星][2y] [enzet/symbolic-execution](https://github.com/enzet/symbolic-execution) 图解符号执行进化史
- [**304**星][9m] [Py] [cisco-sas/kitty](https://github.com/cisco-sas/kitty) 
- [**298**星][10m] [Py] [mseclab/pyjfuzz](https://github.com/mseclab/pyjfuzz) 
- [**292**星][5m] [Py] [mozillasecurity/dharma](https://github.com/mozillasecurity/dharma) 
- [**290**星][2y] [Py] [orangetw/tiny-url-fuzzer](https://github.com/orangetw/tiny-url-fuzzer) 
- [**283**星][10m] [C++] [gamozolabs/applepie](https://github.com/gamozolabs/applepie) 
- [**280**星][4y] [Py] [fuzzing/mffa](https://github.com/fuzzing/mffa) 
    - 重复区段: [工具/移动&&Mobile/Android](#fe88ee8c0df10870b44c2dedcd86d3d3) |
- [**278**星][11m] [Py] [mrash/afl-cov](https://github.com/mrash/afl-cov) 
- [**278**星][10m] [C] [samhocevar/zzuf](https://github.com/samhocevar/zzuf) 
- [**277**星][1m] [Py] [tomato42/tlsfuzzer](https://github.com/tomato42/tlsfuzzer) 
- [**273**星][17d] [HTML] [mozillasecurity/fuzzdata](https://github.com/mozillasecurity/fuzzdata) 
- [**272**星][1y] [C++] [dekimir/ramfuzz](https://github.com/dekimir/ramfuzz) 
- [**268**星][17d] [C] [aflsmart/aflsmart](https://github.com/aflsmart/aflsmart) 
- [**263**星][8m] [Py] [mozillasecurity/peach](https://github.com/mozillasecurity/peach) 
- [**250**星][3y] [Py] [census/choronzon](https://github.com/census/choronzon) 
- [**247**星][2y] [Mask] [lcatro/fuzzing-imagemagick](https://github.com/lcatro/fuzzing-imagemagick) 
- [**245**星][7m] [C++] [ucsb-seclab/difuze](https://github.com/ucsb-seclab/difuze) difuze: 针对 Linux 内核驱动的 Fuzzer
- [**239**星][5m] [C] [compsec-snu/razzer](https://github.com/compsec-snu/razzer) 
- [**239**星][1y] [Py] [hgascon/pulsar](https://github.com/hgascon/pulsar) pulsar：具有自动学习、模拟协议功能的网络 fuzzer
- [**235**星][2y] [Py] [battelle/sandsifter](https://github.com/battelle/sandsifter) 
- [**235**星][2y] [C] [ele7enxxh/android-afl](https://github.com/ele7enxxh/android-afl) 
- [**230**星][4m] [HTML] [rootup/bfuzz](https://github.com/rootup/bfuzz) 
- [**222**星][3m] [C] [pagalaxylab/unifuzzer](https://github.com/PAGalaxyLab/uniFuzzer) 
- [**221**星][3m] [C] [dongdongshe/neuzz](https://github.com/dongdongshe/neuzz) 
- [**214**星][27d] [cpuu/awesome-fuzzing](https://github.com/cpuu/awesome-fuzzing) 
- [**213**星][4y] [C] [fuzzysecurity/unix-privesc](https://github.com/fuzzysecurity/unix-privesc) 
- [**212**星][3m] [C++] [lifting-bits/grr](https://github.com/lifting-bits/grr) 
- [**210**星][4m] [C] [hunter-ht-2018/ptfuzzer](https://github.com/hunter-ht-2018/ptfuzzer) 
- [**209**星][2y] [C] [silvermoonsecurity/passivefuzzframeworkosx](https://github.com/silvermoonsecurity/passivefuzzframeworkosx) 
- [**208**星][2y] [k0keoyo/some-kernel-fuzzing-paper](https://github.com/k0keoyo/some-kernel-fuzzing-paper) 
- [**207**星][4m] [HTML] [ajinabraham/droid-application-fuzz-framework](https://github.com/ajinabraham/droid-application-fuzz-framework) 
- [**205**星][2y] [C] [fsecurelabs/osxfuzz](https://github.com/FSecureLABS/OSXFuzz) 
- [**203**星][2m] [Py] [jwilk/python-afl](https://github.com/jwilk/python-afl) 
- [**197**星][4m] [OCaml] [bitblaze-fuzzball/fuzzball](https://github.com/bitblaze-fuzzball/fuzzball) 
- [**197**星][3m] [C++] [delcypher/jfs](https://github.com/mc-imperial/jfs) jfs: an experimental constraint solverdesigned to investigate using coverage guided fuzzing as an incomplete strategyfor solving boolean, BitVector, and floating-point constraints.
- [**195**星][1m] [C] [denandz/fuzzotron](https://github.com/denandz/fuzzotron) 
- [**192**星][3y] [tuuunya/fuzz_dict](https://github.com/TuuuNya/fuzz_dict) 
- [**191**星][2m] [C#] [jakobbotsch/fuzzlyn](https://github.com/jakobbotsch/fuzzlyn) 
- [**188**星][9m] [Haskell] [cifasis/quickfuzz](https://github.com/cifasis/quickfuzz) 
- [**186**星][13d] [Py] [mozillasecurity/grizzly](https://github.com/mozillasecurity/grizzly) 
- [**184**星][7m] [Py] [certcc/certfuzz](https://github.com/certcc/certfuzz) 
- [**181**星][3m] [C] [aflgo/aflgo](https://github.com/aflgo/aflgo) 
- [**178**星][12m] [Py] [hexhive/t-fuzz](https://github.com/hexhive/t-fuzz) 
- [**172**星][2m] [C++] [google/libprotobuf-mutator](https://github.com/google/libprotobuf-mutator) 
- [**170**星][1y] [Py] [niloofarkheirkhah/nili](https://github.com/niloofarkheirkhah/nili) nili：网络扫描工具，中间人，协议逆向工程和 Fuzzing
- [**166**星][10m] [C] [carolemieux/afl-rb](https://github.com/carolemieux/afl-rb) afl-rb：AFL Fuzz 工具的修改版，针对 Rare Branches
- [**166**星][3m] [Rust] [phra/rustbuster](https://github.com/phra/rustbuster) 
- [**164**星][2m] [rust-fuzz/trophy-case](https://github.com/rust-fuzz/trophy-case) 
- [**163**星][4y] [C] [jdbirdwell/afl](https://github.com/jdbirdwell/afl) 
- [**160**星][1m] [Py] [fgsect/unicorefuzz](https://github.com/fgsect/unicorefuzz) 
- [**160**星][1y] [Py] [walkerfuz/morph](https://github.com/walkerfuz/morph) 
- [**159**星][2m] [Py] [d0c-s4vage/gramfuzz](https://github.com/d0c-s4vage/gramfuzz) 
- [**157**星][1m] [Java] [rohanpadhye/jqf](https://github.com/rohanpadhye/jqf) 
- [**155**星][2y] [Py] [alephsecurity/abootool](https://github.com/alephsecurity/abootool) abootool：基于静态知识（从bootloader 镜像中提取的字符串）动态 fuzz 隐藏的 fastboot OEM 指令
- [**152**星][3m] [Py] [renatahodovan/fuzzinator](https://github.com/renatahodovan/fuzzinator) 
- [**152**星][1m] [Py] [sxcurity/theftfuzzer](https://github.com/lc/theftfuzzer) 
- [**151**星][5y] [C++] [mothran/aflpin](https://github.com/mothran/aflpin) 
- [**150**星][8m] [Py] [k0retux/fuddly](https://github.com/k0retux/fuddly) fuddly: Fuzzing/数据操纵(Data Manipulation)框架
- [**149**星][1m] [CSS] [7dog7/bottleneckosmosis](https://github.com/7dog7/bottleneckosmosis) 
- [**149**星][2y] [Py] [ga-ryo/idafuzzy](https://github.com/ga-ryo/idafuzzy) 模糊搜索: 命令/函数/结构体
- [**149**星][4m] [Rust] [rust-fuzz/honggfuzz-rs](https://github.com/rust-fuzz/honggfuzz-rs) 
- [**148**星][3m] [Py] [trailofbits/protofuzz](https://github.com/trailofbits/protofuzz) 
- [**146**星][2m] [Perl] [henshin/filebuster](https://github.com/henshin/filebuster) 
- [**146**星][4m] [C] [hfiref0x/ntcall64](https://github.com/hfiref0x/ntcall64) 
- [**145**星][3y] [C] [nccgroup/triforcelinuxsyscallfuzzer](https://github.com/nccgroup/triforcelinuxsyscallfuzzer) 
- [**143**星][2y] [Py] [tr3jer/dnsautorebinding](https://github.com/tr3jer/dnsautorebinding) 
- [**139**星][11m] [C++] [guidovranken/libfuzzer-gv](https://github.com/guidovranken/libfuzzer-gv) 加强版 libFuzzer：超快速Fuzzing 的新技巧
- [**138**星][2y] [Py] [julieeen/kleefl](https://github.com/julieeen/kleefl) kleefl：结合了符号执行的Fuzzer，针对普通 C/C++ 应用程序
- [**137**星][2y] [C++] [talos-vulndev/afl-dyninst](https://github.com/talos-vulndev/afl-dyninst) 
- [**136**星][1m] [C] [grimm-co/killerbeez](https://github.com/grimm-co/killerbeez) 
- [**136**星][3y] [C] [koutto/ioctlbf](https://github.com/koutto/ioctlbf) 
- [**134**星][2m] [C++] [mxmssh/manul](https://github.com/mxmssh/manul) 
- [**133**星][1y] [Py] [brain-research/tensorfuzz](https://github.com/brain-research/tensorfuzz) 
- [**132**星][14d] [bin2415/fuzzing_paper](https://github.com/bin2415/fuzzing_paper) 
- [**132**星][3m] [Py] [nccgroup/fuzzowski](https://github.com/nccgroup/fuzzowski) 
- [**132**星][2y] [C++] [nezha-dt/nezha](https://github.com/nezha-dt/nezha) nezha：高效的domain-independent differential fuzzer
- [**130**星][9m] [Rust] [shnatsel/libdiffuzz](https://github.com/shnatsel/libdiffuzz) 
- [**125**星][3y] [Java] [chora10/fuzzdomain](https://github.com/chora10/fuzzdomain) 
- [**123**星][5y] [Py] [ring04h/dirfuzz](https://github.com/ring04h/dirfuzz) 
- [**123**星][2y] [Py] [riverloopsec/tumblerf](https://github.com/riverloopsec/tumblerf) 
- [**123**星][1m] [Go] [yahoo/yfuzz](https://github.com/yahoo/yfuzz) yfuzz: 利用 Kubernetes 实现分布式 fuzzing
- [**122**星][2y] [Py] [blazeinfosec/pcrappyfuzzer](https://github.com/blazeinfosec/pcrappyfuzzer) pcrappyfuzzer：Scapy+ radamsa 的简单组合，从 pcap 文件中提取数据，执行快速 Fuzz
- [**121**星][1m] [HTML] [mozillasecurity/fuzzmanager](https://github.com/mozillasecurity/fuzzmanager) 
- [**118**星][8y] [C] [cr4sh/ioctlfuzzer](https://github.com/cr4sh/ioctlfuzzer) 
- [**117**星][2y] [Java] [isstac/kelinci](https://github.com/isstac/kelinci) 
- [**116**星][3y] [Py] [nccgroup/hodor](https://github.com/nccgroup/hodor) 
- [**115**星][4y] [JS] [demi6od/chromefuzzer](https://github.com/demi6od/chromefuzzer) 
- [**114**星][1m] [Py] [chrispetrou/fdsploit](https://github.com/chrispetrou/fdsploit) 
- [**113**星][6m] [Visual Basic] [dzzie/comraider](https://github.com/dzzie/comraider) 
- [**113**星][5y] [Py] [nccgroup/zulu](https://github.com/nccgroup/zulu) 
- [**112**星][14d] [Go] [fuzzitdev/fuzzit](https://github.com/fuzzitdev/fuzzit) 
- [**111**星][2m] [C#] [metalnem/sharpfuzz](https://github.com/metalnem/sharpfuzz) 
- [**108**星][3y] [JS] [sensepost/wadi](https://github.com/sensepost/wadi) 
- [**108**星][2y] [C++] [vegard/prog-fuzz](https://github.com/vegard/prog-fuzz) 
- [**107**星][5y] [C] [ioactive/melkor_elf_fuzzer](https://github.com/ioactive/melkor_elf_fuzzer) 
- [**107**星][4y] [Py] [mit-ll/ll-fuzzer](https://github.com/mit-ll/ll-fuzzer) 
- [**107**星][11m] [C] [zombiecraig/uds-server](https://github.com/zombiecraig/uds-server) 
- [**106**星][4y] [C] [rootkitsmm/win32k-fuzzer](https://github.com/rootkitsmm/win32k-fuzzer) 
- [**105**星][3y] [JS] [attekett/nodefuzz](https://github.com/attekett/nodefuzz) 
- [**105**星][5y] [Py] [fooying/3102](https://github.com/fooying/3102) 
- [**105**星][2y] [Java] [mindmac/intentfuzzer](https://github.com/mindmac/intentfuzzer) 
- [**105**星][28d] [3had0w/fuzzing-dicts](https://github.com/3had0w/Fuzzing-Dicts) 
- [**104**星][3m] [C] [zyw-200/firmafl](https://github.com/zyw-200/firmafl) 
- [**101**星][10m] [C] [x41sec/x41-smartcard-fuzzing](https://github.com/x41sec/x41-smartcard-fuzzing) 
- [**99**星][26d] [C++] [oxagast/ansvif](https://github.com/oxagast/ansvif) 
- [**97**星][20d] [C] [rohanpadhye/fuzzfactory](https://github.com/rohanpadhye/fuzzfactory) 
- [**95**星][3y] [PHP] [jas502n/fuzz-wooyun-org](https://github.com/jas502n/fuzz-wooyun-org) 
- [**93**星][7m] [Rust] [rub-syssec/nautilus](https://github.com/rub-syssec/nautilus) 
- [**92**星][1y] [Py] [andresriancho/websocket-fuzzer](https://github.com/andresriancho/websocket-fuzzer) 
- [**92**星][3y] [Hack] [oracle/kernel-fuzzing](https://github.com/oracle/kernel-fuzzing) 
- [**92**星][8m] [C++] [trailofbits/sienna-locomotive](https://github.com/trailofbits/sienna-locomotive) 
- [**91**星][6m] [Py] [localh0t/backfuzz](https://github.com/localh0t/backfuzz) 
- [**91**星][10m] [HTML] [nytrorst/xssfuzzer](https://github.com/nytrorst/xssfuzzer) 
- [**90**星][2m] [Rust] [loiclec/fuzzcheck-rs](https://github.com/loiclec/fuzzcheck-rs) 
- [**87**星][4y] [C++] [piscou/fuzzwin](https://github.com/piscou/fuzzwin) 
- [**87**星][10m] [C++] [nccgroup/dibf](https://github.com/nccgroup/DIBF) 
- [**86**星][1y] [JS] [fgsect/fexm](https://github.com/fgsect/fexm) 
- [**86**星][8m] [JS] [mozillasecurity/octo](https://github.com/mozillasecurity/octo) 
- [**84**星][13d] [C] [guidovranken/cryptofuzz](https://github.com/guidovranken/cryptofuzz) 
- [**83**星][2y] [Py] [sogeti-esec-lab/rpcforge](https://github.com/sogeti-esec-lab/rpcforge) 
- [**83**星][9m] [C++] [zhunki/superion](https://github.com/zhunki/superion) 
- [**81**星][28d] [C++] [vusec/vuzzer64](https://github.com/vusec/vuzzer64) 
- [**80**星][3y] [Py] [coffeehb/ocift](https://github.com/coffeehb/ocift) 
- [**80**星][2y] [PHP] [nixawk/fuzzdb](https://github.com/nixawk/fuzzdb) 
- [**80**星][9m] [C++] [fsecurelabs/viridianfuzzer](https://github.com/FSecureLABS/ViridianFuzzer) 
- [**79**星][1y] [JS] [vspandan/ifuzzer](https://github.com/vspandan/ifuzzer) 
- [**78**星][1m] [Py] [fuzzitdev/pythonfuzz](https://github.com/fuzzitdev/pythonfuzz) 
- [**77**星][2y] [Py] [softsec-kaist/imf](https://github.com/softsec-kaist/imf) 
- [**75**星][1y] [Py] [peterpt/fuzzbunch](https://github.com/peterpt/fuzzbunch) 
- [**74**星][1m] [Py] [bannsec/autopwn](https://github.com/bannsec/autopwn) 
- [**74**星][1y] [Py] [dobin/ffw](https://github.com/dobin/ffw) 
- [**74**星][3m] [Py] [lazorfuzz/python-hacklib](https://github.com/lazorfuzz/python-hacklib) 
- [**73**星][3y] [Py] [carlosgprado/brundlefuzz](https://github.com/carlosgprado/brundlefuzz) 
- [**72**星][8m] [C++] [niklasb/bspfuzz](https://github.com/niklasb/bspfuzz) 
- [**72**星][3m] [vanhauser-thc/afl-patches](https://github.com/vanhauser-thc/afl-patches) 
- [**71**星][3y] [Py] [antojoseph/droid-ff](https://github.com/antojoseph/droid-ff) 
- [**71**星][3y] [JS] [attekett/surku](https://github.com/attekett/surku) 
- [**71**星][10m] [C] [forte-research/untracer-afl](https://github.com/forte-research/untracer-afl) 
- [**71**星][3y] [C] [rcvalle/vmmfuzzer](https://github.com/rcvalle/vmmfuzzer) 
- [**70**星][2y] [Ruby] [dyjakan/interpreter-bugs](https://github.com/dyjakan/interpreter-bugs) 
- [**69**星][3y] [C] [payatu/emffuzzer](https://github.com/payatu/emffuzzer) 
- [**68**星][6m] [Rust] [phayes/sidefuzz](https://github.com/phayes/sidefuzz) 
- [**68**星][2y] [richinseattle/evolutionarykernelfuzzing](https://github.com/richinseattle/evolutionarykernelfuzzing) 
- [**66**星][13d] [Py] [lylemi/browser-fuzz-summarize](https://github.com/lylemi/browser-fuzz-summarize) 
- [**65**星][2y] [Py] [debasishm89/openxmolar](https://github.com/debasishm89/openxmolar) 
- [**65**星][16d] [C] [puppet-meteor/mopt-afl](https://github.com/puppet-meteor/mopt-afl) 
- [**65**星][3y] [Py] [plantdaddy/fuzzap](https://github.com/PlantDaddy/FuzzAP) 
- [**64**星][4y] [Py] [halit/isip](https://github.com/halit/isip) 
- [**64**星][5y] [Py] [hikerell/bfuzzer](https://github.com/hikerell/bfuzzer) 
- [**63**星][1y] [C] [ioactive/fuzzndis](https://github.com/ioactive/fuzzndis) 
- [**63**星][5m] [Rust] [trailofbits/siderophile](https://github.com/trailofbits/siderophile) 
- [**61**星][11m] [Py] [graniet/operative-framework-hd](https://github.com/graniet/operative-framework-hd) 
- [**60**星][10m] [Py] [cisco-sas/katnip](https://github.com/cisco-sas/katnip) 
- [**59**星][3y] [Py] [sirusdv/edgehttp2fuzzer](https://github.com/sirusdv/edgehttp2fuzzer) 
- [**58**星][3y] [Py] [nopernik/fuzzbunch_wrapper](https://github.com/nopernik/fuzzbunch_wrapper) 
- [**57**星][2y] [C] [hbowden/nextgen](https://github.com/hbowden/nextgen) 
- [**56**星][2y] [ouspg/fuzz-testing-beginners-guide](https://github.com/ouspg/fuzz-testing-beginners-guide) 
- [**56**星][7m] [HTML] [leonwxqian/lucky-js-fuzz](https://github.com/leonwxqian/lucky-js-fuzz) 
- [**55**星][2y] [mrash/afl-cve](https://github.com/mrash/afl-cve) 
- [**55**星][3y] [Shell] [ouspg/libfuzzerfication](https://github.com/ouspg/libfuzzerfication) 
- [**55**星][4m] [C] [rub-syssec/antifuzz](https://github.com/rub-syssec/antifuzz) 
- [**53**星][2y] [Py] [coffeehb/sstif](https://github.com/coffeehb/sstif) 
- [**52**星][2y] [C] [fuzzstati0n/fuzzgoat](https://github.com/fuzzstati0n/fuzzgoat) 
- [**52**星][1y] [C] [rc0r/afl-fuzz](https://github.com/rc0r/afl-fuzz) 
- [**52**星][3m] [motherfuzzers/meetups](https://github.com/motherfuzzers/meetups) 
- [**51**星][1y] [JS] [danigargu/urlfuzz](https://github.com/danigargu/urlfuzz) 
- [**51**星][3m] [CSS] [mobsf/capfuzz](https://github.com/mobsf/capfuzz) 
- [**51**星][3y] [Py] [test-pipeline/orthrus](https://github.com/test-pipeline/orthrus) 
- [**50**星][7y] [Py] [0xd012/wifuzzit](https://github.com/0xd012/wifuzzit) 
- [**50**星][1y] [Py] [alexknvl/fuzzball](https://github.com/alexknvl/fuzzball) 
- [**49**星][6y] [Py] [debasishm89/iofuzz](https://github.com/debasishm89/iofuzz) 
- [**49**星][6y] [Py] [isecpartners/rtspfuzzer](https://github.com/isecpartners/rtspfuzzer) 
- [**49**星][9m] [C] [riscure/optee_fuzzer](https://github.com/riscure/optee_fuzzer) 
- [**48**星][6y] [C++] [cr4sh/msfontsfuzz](https://github.com/cr4sh/msfontsfuzz) 
- [**48**星][2y] [Py] [debasishm89/iefuzz](https://github.com/debasishm89/iefuzz) 
- [**48**星][2y] [Py] [softscheck/scff](https://github.com/softscheck/scff) 
- [**48**星][1m] [Py] [ripxorip/aerojump.nvim](https://github.com/ripxorip/aerojump.nvim) 
- [**47**星][2y] [JS] [hackvertor/visualfuzzer](https://github.com/hackvertor/visualfuzzer) 
- [**47**星][1m] [Py] [demantz/frizzer](https://github.com/demantz/frizzer) 
- [**46**星][4y] [Py] [signalsec/kirlangic-ttf-fuzzer](https://github.com/signalsec/kirlangic-ttf-fuzzer) 
- [**46**星][2y] [silvermoonsecurity/security-misc](https://github.com/silvermoonsecurity/security-misc) 
- [**46**星][1y] [C] [zznop/flyr](https://github.com/zznop/flyr) 
- [**45**星][4y] [C] [laginimaineb/fuzz_zone](https://github.com/laginimaineb/fuzz_zone) 
- [**44**星][6m] [Erlang] [darkkey/erlamsa](https://github.com/darkkey/erlamsa) 
- [**44**星][8m] [C] [sslab-gatech/perf-fuzz](https://github.com/sslab-gatech/perf-fuzz) 
- [**43**星][1y] [Py] [christhecoolhut/easy-pickings](https://github.com/christhecoolhut/easy-pickings) 
- [**43**星][20d] [Py] [kisspeter/apifuzzer](https://github.com/kisspeter/apifuzzer) 
- [**42**星][1y] [C] [hannob/bignum-fuzz](https://github.com/hannob/bignum-fuzz) 
- [**42**星][5m] [C++] [vanhauser-thc/afl-pin](https://github.com/vanhauser-thc/afl-pin) 
- [**42**星][2y] [C] [z4ziggy/zigfrid](https://github.com/z4ziggy/zigfrid) 
- [**41**星][9m] [Shell] [forte-research/forte-fuzzbench](https://github.com/forte-research/forte-fuzzbench) 
- [**41**星][3y] [C] [kanglictf/afl-qai](https://github.com/kanglictf/afl-qai) 
- [**41**星][2y] [Py] [talos-vulndev/fuzzflow](https://github.com/talos-vulndev/fuzzflow) 
- [**40**星][3y] [C] [nccgroup/triforceopenbsdfuzzer](https://github.com/nccgroup/triforceopenbsdfuzzer) 
- [**40**星][11m] [Perl] [wireghoul/doona](https://github.com/wireghoul/doona) 
- [**39**星][1y] [Py] [debasishm89/dotnetfuzz](https://github.com/debasishm89/dotnetfuzz) 
- [**39**星][6y] [Py] [proteansec/fuzzyftp](https://github.com/proteansec/fuzzyftp) 
- [**39**星][3y] [Py] [xiphosresearch/phuzz](https://github.com/xiphosresearch/phuzz) 
- [**38**星][3y] [C++] [attackercan/cpp-sql-fuzzer](https://github.com/attackercan/cpp-sql-fuzzer) 
- [**38**星][5y] [Julia] [danluu/fuzz.jl](https://github.com/danluu/fuzz.jl) 
- [**38**星][23d] [JS] [lydell/eslump](https://github.com/lydell/eslump) 
- [**38**星][2y] [Py] [walkerfuz/pydbgeng](https://github.com/walkerfuz/PyDbgEng) 
- [**37**星][1y] [C] [abiondo/afl](https://github.com/abiondo/afl) 
- [**37**星][1y] [Py] [jpcertcc/impfuzzy](https://github.com/jpcertcc/impfuzzy) 
- [**36**星][3y] [Py] [exploitx3/fuzzbunch](https://github.com/exploitx3/fuzzbunch) 
- [**35**星][2y] [Shell] [seanheelan/funserialize](https://github.com/seanheelan/funserialize) 
- [**35**星][30d] [C++] [verizondigital/waflz](https://github.com/verizondigital/waflz) 
- [**34**星][15d] [Go] [fuzzitdev/example-go](https://github.com/fuzzitdev/example-go) 
- [**33**星][4y] [cz-nic/dns-fuzzing](https://github.com/cz-nic/dns-fuzzing) 
- [**33**星][5y] [Py] [jonmetz/androfuzz](https://github.com/jonmetz/androfuzz) 
    - 重复区段: [工具/移动&&Mobile/Android](#fe88ee8c0df10870b44c2dedcd86d3d3) |
- [**32**星][7y] [Py] [isecpartners/fuzzbox](https://github.com/isecpartners/fuzzbox) 
- [**31**星][2y] [C] [jaybosamiya/fuzzing-numpy](https://github.com/jaybosamiya/fuzzing-numpy) 
- [**31**星][2y] [Rust] [nikomatsakis/cargo-incremental](https://github.com/nikomatsakis/cargo-incremental) 
- [**31**星][2m] [JS] [ronomon/mime](https://github.com/ronomon/mime) 
- [**31**星][1m] [C++] [rust-fuzz/libfuzzer-sys](https://github.com/rust-fuzz/libfuzzer-sys) 
- [**31**星][2m] [C++] [vanhauser-thc/afl-dyninst](https://github.com/vanhauser-thc/afl-dyninst) 
- [**30**星][11m] [C] [hfiref0x/rocall](https://github.com/hfiref0x/rocall) 
- [**30**星][3m] [Py] [teebytes/tnt-fuzzer](https://github.com/teebytes/tnt-fuzzer) 
- [**29**星][2m] [Py] [amossys/fragscapy](https://github.com/amossys/fragscapy) 
- [**29**星][1y] [Py] [andresriancho/jwt-fuzzer](https://github.com/andresriancho/jwt-fuzzer) 
- [**29**星][6m] [Py] [fkie-cad/luckycat](https://github.com/fkie-cad/luckycat) 
- [**29**星][9m] [C] [ivanfratric/winafl](https://github.com/ivanfratric/winafl) Windows 二进制文件fuzz工具
- [**29**星][7m] [C] [mboehme/pythia](https://github.com/mboehme/pythia) 
- [**29**星][4y] [Ruby] [nahamsec/cmsfuzz](https://github.com/nahamsec/cmsfuzz) 
- [**29**星][2y] [C] [tigerpuma/afl_unicorn](https://github.com/tigerpuma/afl_unicorn) 
- [**28**星][3y] [Py] [3gstudent/fuzzbunch](https://github.com/3gstudent/fuzzbunch) 
- [**28**星][2y] [Java] [barro/java-afl](https://github.com/barro/java-afl) 
- [**28**星][4y] [Go] [bnagy/afl-launch](https://github.com/bnagy/afl-launch) 
- [**28**星][3y] [Py] [bshastry/afl-sancov](https://github.com/bshastry/afl-sancov) 
- [**28**星][10y] [C] [dmolnar/smartfuzz](https://github.com/dmolnar/smartfuzz) 
- [**28**星][1y] [C] [mxmssh/netafl](https://github.com/mxmssh/netafl) 
- [**27**星][3y] [brandonprry/clamav-fuzz](https://github.com/brandonprry/clamav-fuzz) 
- [**27**星][3y] [PureBasic] [dadido3/d3hex](https://github.com/dadido3/d3hex) 
- [**27**星][4y] [C] [hannob/selftls](https://github.com/hannob/selftls) 
- [**27**星][27d] [C++] [regehr/opt-fuzz](https://github.com/regehr/opt-fuzz) 
- [**26**星][2y] [JS] [0xsobky/regaxor](https://github.com/0xsobky/regaxor) 
- [**26**星][6y] [Py] [bl4ckic3/modbus-fuzzer](https://github.com/bl4ckic3/modbus-fuzzer) 
- [**25**星][8y] [JS] [hdm/axman](https://github.com/hdm/axman) 
- [**25**星][11m] [C] [intelpt/winafl-intelpt](https://github.com/intelpt/winafl-intelpt) 
- [**25**星][3y] [C] [leetchicken/afl](https://github.com/leetchicken/afl) 
- [**24**星][4y] [C] [arizvisa/afl-cygwin](https://github.com/arizvisa/afl-cygwin) 
- [**24**星][10m] [C++] [blitz/baresifter](https://github.com/blitz/baresifter) 
- [**24**星][6y] [Java] [thypon/androidfuzz](https://github.com/thypon/androidfuzz) 
- [**23**星][4y] [C++] [certcc/dranzer](https://github.com/certcc/dranzer) 
- [**23**星][2m] [C++] [curl/curl-fuzzer](https://github.com/curl/curl-fuzzer) 
- [**23**星][1y] [C] [logicaltrust/minerva_lib](https://github.com/logicaltrust/minerva_lib) 
- [**23**星][2y] [proteas/afl-swift](https://github.com/proteas/afl-swift) 
- [**22**星][2y] [Shell] [aflgo/oss-fuzz](https://github.com/aflgo/oss-fuzz) 
- [**22**星][4y] [Py] [camoufl4g3/sqli-payload-fuzz3r](https://github.com/camoufl4g3/sqli-payload-fuzz3r) 
- [**22**星][5m] [C] [junxzm1990/afl-pt](https://github.com/junxzm1990/afl-pt) 
- [**22**星][3y] [Py] [markusteufelberger/afl-ddmin-mod](https://github.com/markusteufelberger/afl-ddmin-mod) 
- [**22**星][2y] [Py] [saulty4ish/fuzzsafedog](https://github.com/saulty4ish/fuzzsafedog) 
- [**21**星][10y] [C] [bringhurst/xnufuzz](https://github.com/bringhurst/xnufuzz) 
- [**21**星][3y] [Py] [reflare/afl-monitor](https://github.com/reflare/afl-monitor) 
- [**20**星][6m] [rootup/phdays9](https://github.com/rootup/phdays9) 
- [**17**星][2y] [C] [deanjerkovich/rage_fuzzer](https://github.com/deanjerkovich/rage_fuzzer) 
- [**14**星][3y] [Shell] [ouspg/cloudfuzzer](https://github.com/ouspg/cloudfuzzer) 
- [**12**星][2m] [Scala] [satelliteapplicationscatapult/tribble](https://github.com/satelliteapplicationscatapult/tribble) 
- [**9**星][4m] [JS] [strongcourage/fuzzing-corpus](https://github.com/strongcourage/fuzzing-corpus) 


##### <a id="a9a8b68c32ede78eee0939cf16128300"></a>资源收集


- [**3792**星][1m] [PHP] [fuzzdb-project/fuzzdb](https://github.com/fuzzdb-project/fuzzdb) 通过动态App安全测试来查找App安全漏洞, 算是不带扫描器的漏洞扫描器
- [**2864**星][5m] [secfigo/awesome-fuzzing](https://github.com/secfigo/awesome-fuzzing) 


##### <a id="ff703caa7c3f7b197608abaa76b1a263"></a>Fuzzer


- [**2629**星][17d] [Go] [google/syzkaller](https://github.com/google/syzkaller) 一个unsupervised、以 coverage 为导向的Linux 系统调用fuzzer
- [**2346**星][1m] [Py] [xmendez/wfuzz](https://github.com/xmendez/wfuzz) 
- [**1699**星][21d] [C] [google/honggfuzz](https://github.com/google/honggfuzz) 
- [**1051**星][2m] [Py] [googleprojectzero/domato](https://github.com/googleprojectzero/domato) ProjectZero 开源的 DOM fuzzer
- [**162**星][2y] [Ruby] [fuzzapi/api-fuzzer](https://github.com/fuzzapi/api-fuzzer) 
- [**120**星][1m] [Py] [mdiazcl/fuzzbunch-debian](https://github.com/mdiazcl/fuzzbunch-debian) 
- [**55**星][5y] [C] [anestisb/melkor-android](https://github.com/anestisb/melkor-android) 
- [**51**星][11m] [C] [anestisb/radamsa-android](https://github.com/anestisb/radamsa-android) 






### <a id="41ae40ed61ab2b61f2971fea3ec26e7c"></a>漏洞利用


#### <a id="c83f77f27ccf5f26c8b596979d7151c3"></a>漏洞利用


- [**3933**星][3m] [Py] [nullarray/autosploit](https://github.com/nullarray/autosploit) 
- [**3364**星][1m] [C] [shellphish/how2heap](https://github.com/shellphish/how2heap) how2heap：学习各种堆利用技巧的repo
- [**2803**星][2y] [CSS] [maxchehab/css-keylogging](https://github.com/maxchehab/css-keylogging) 
- [**2175**星][10m] [JS] [secgroundzero/warberry](https://github.com/secgroundzero/warberry) 
- [**1448**星][3m] [Py] [epinna/tplmap](https://github.com/epinna/tplmap) 代码注入和服务器端模板注入（Server-Side Template Injection）漏洞利用，若干沙箱逃逸技巧。
- [**1300**星][3y] [Py] [joaomatosf/jexboss](https://github.com/joaomatosf/jexboss) Jboss (and Java Deserialization Vulnerabilities) verify and EXploitation Tool
- [**1180**星][15d] [Py] [codingo/nosqlmap](https://github.com/codingo/NoSQLMap) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |[工具/数据库&&SQL攻击&&SQL注入/NoSQL/未分类-NoSQL](#af0aaaf233cdff3a88d04556dc5871e0) |
- [**1080**星][6m] [Go] [sensepost/ruler](https://github.com/sensepost/ruler) ruler：自动化利用Exchange 服务的repo
- [**849**星][1y] [Ruby] [enjoiz/xxeinjector](https://github.com/enjoiz/xxeinjector) 
- [**822**星][1m] [Py] [nil0x42/phpsploit](https://github.com/nil0x42/phpsploit) 
- [**818**星][7m] [Shell] [niklasb/libc-database](https://github.com/niklasb/libc-database) 
- [**797**星][28d] [Ruby] [rastating/wordpress-exploit-framework](https://github.com/rastating/wordpress-exploit-framework) wordpress-exploit-framework：WordPress 漏洞利用框架
- [**792**星][12d] [cveproject/cvelist](https://github.com/cveproject/cvelist) 
- [**790**星][3y] [Py] [empireproject/empyre](https://github.com/empireproject/empyre) 
- [**750**星][2y] [Py] [redballoonshenanigans/monitordarkly](https://github.com/redballoonshenanigans/monitordarkly) 
- [**665**星][10m] [JS] [theori-io/pwnjs](https://github.com/theori-io/pwnjs) 辅助开发浏览器exploit 的 JS 模块
- [**600**星][5m] [Java] [sigploiter/sigploit](https://github.com/sigploiter/sigploit) Telecom Signaling Exploitation Framework - SS7, GTP, Diameter & SIP
- [**568**星][1y] [Py] [spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop) 内核提权枚举和漏洞利用框架
- [**538**星][2y] [C] [scwuaptx/hitcon-training](https://github.com/scwuaptx/hitcon-training) 
- [**510**星][8m] [Py] [dark-lbp/isf](https://github.com/dark-lbp/isf) 工控漏洞利用框架，基于Python
- [**474**星][25d] [C] [r0hi7/binexp](https://github.com/r0hi7/binexp) 
- [**449**星][5m] [Py] [shellphish/rex](https://github.com/shellphish/rex) 
- [**429**星][11m] [Py] [neohapsis/bbqsql](https://github.com/neohapsis/bbqsql) 
- [**398**星][1y] [C] [fuzion24/androidkernelexploitationplayground](https://github.com/fuzion24/androidkernelexploitationplayground) 
- [**394**星][20d] [Py] [corkami/collisions](https://github.com/corkami/collisions) 
- [**379**星][2y] [Assembly] [sgayou/kindle-5.6.5-jailbreak](https://github.com/sgayou/kindle-5.6.5-jailbreak) 
- [**378**星][2m] [Py] [sab0tag3d/siet](https://github.com/sab0tag3d/siet) 
- [**352**星][4y] [HTML] [mubix/post-exploitation-wiki](https://github.com/mubix/post-exploitation-wiki) 
- [**346**星][9m] [C] [wapiflapi/exrs](https://github.com/wapiflapi/exrs) 
- [**345**星][29d] [JS] [fsecurelabs/dref](https://github.com/FSecureLABS/dref) DNS 重绑定利用框架
- [**338**星][1y] [C] [bretley/how2exploit_binary](https://github.com/bretley/how2exploit_binary) 
- [**315**星][2y] [Py] [census/shadow](https://github.com/census/shadow) 
- [**315**星][3y] [Py] [j91321/rext](https://github.com/j91321/rext) 
- [**315**星][1y] [C] [tharina/blackhoodie-2018-workshop](https://github.com/tharina/blackhoodie-2018-workshop) 
- [**314**星][13d] [Shell] [zmarch/orc](https://github.com/zmarch/orc) 
- [**305**星][3y] [Shell] [safebreach-labs/pwndsh](https://github.com/safebreach-labs/pwndsh) 
- [**300**星][4m] [JS] [vngkv123/asiagaming](https://github.com/vngkv123/asiagaming) 
- [**297**星][2y] [Py] [hellman/libformatstr](https://github.com/hellman/libformatstr) 
- [**288**星][9m] [Py] [immunit/drupwn](https://github.com/immunit/drupwn) 
- [**284**星][1m] [xairy/vmware-exploitation](https://github.com/xairy/vmware-exploitation) 
- [**282**星][12m] [C] [str8outtaheap/heapwn](https://github.com/str8outtaheap/heapwn) 
- [**280**星][1y] [Py] [novicelive/bintut](https://github.com/novicelive/bintut) 
- [**273**星][12m] [Py] [fox-it/aclpwn.py](https://github.com/fox-it/aclpwn.py) 与BloodHound交互, 识别并利用基于ACL的提权路径
- [**266**星][22d] [Py] [0xinfection/xsrfprobe](https://github.com/0xinfection/xsrfprobe) 
- [**262**星][3y] [Java] [matthiaskaiser/jmet](https://github.com/matthiaskaiser/jmet) 
- [**257**星][3m] [HTML] [sp1d3r/swf_json_csrf](https://github.com/sp1d3r/swf_json_csrf) swf_json_csrf：简化基于 SWF的 JSON CSRF exploitation
- [**253**星][2y] [PowerShell] [xorrior/randomps-scripts](https://github.com/xorrior/randomps-scripts) 
- [**250**星][7m] [Py] [xairy/easy-linux-pwn](https://github.com/xairy/easy-linux-pwn) 
- [**243**星][26d] [Py] [0xinfection/xsrfprobe](https://github.com/0xInfection/XSRFProbe) 
- [**240**星][3y] [Py] [sensepost/autodane](https://github.com/sensepost/autodane) 
- [**238**星][2y] [C] [zerosum0x0/defcon-25-workshop](https://github.com/zerosum0x0/defcon-25-workshop) 
- [**231**星][10m] [C] [r3x/how2kernel](https://github.com/r3x/how2kernel) 
- [**222**星][2y] [Py] [beetlechunks/redsails](https://github.com/beetlechunks/redsails) 
- [**189**星][2y] [Py] [francisck/danderspritz_docs](https://github.com/francisck/danderspritz_docs) 
- [**183**星][2y] [PowerShell] [xtr4nge/fruityc2](https://github.com/xtr4nge/fruityc2) 
- [**176**星][4y] [Py] [mossberg/poet](https://github.com/mossberg/poet) 
- [**176**星][4y] [Py] [offlinevx/poet](https://github.com/offlinevx/poet) 
- [**173**星][2y] [C++] [0x09al/dns-persist](https://github.com/0x09al/dns-persist) 
- [**173**星][2y] [C] [xerub/extra_recipe](https://github.com/xerub/extra_recipe) extra_recipe：Exception-orientedexploitation
- [**171**星][12m] [Py] [apt55/google_explorer](https://github.com/APT55/google_explorer) 
- [**170**星][3y] [C++] [cr4sh/fwexpl](https://github.com/cr4sh/fwexpl) 
- [**168**星][3m] [Py] [mzfr/liffy](https://github.com/mzfr/liffy) 
- [**164**星][2m] [cptgibbon/house-of-corrosion](https://github.com/cptgibbon/house-of-corrosion) 
- [**159**星][6m] [C#] [xorrior/random-csharptools](https://github.com/xorrior/random-csharptools) 
- [**157**星][3y] [HTML] [jonnyhightower/neet](https://github.com/jonnyhightower/neet) 
- [**154**星][2m] [Py] [busescanfly/pretty](https://github.com/busescanfly/pretty) 
- [**143**星][1y] [Py] [andresriancho/race-condition-exploit](https://github.com/andresriancho/race-condition-exploit) 
- [**141**星][3y] [Shell] [nccgroup/chuckle](https://github.com/nccgroup/chuckle) 
- [**140**星][2y] [Java] [nickstadb/deserlab](https://github.com/nickstadb/deserlab) 
- [**137**星][5m] [C] [akayn/demos](https://github.com/akayn/demos) 
- [**130**星][1y] [Py] [0x09al/dropboxc2c](https://github.com/0x09al/dropboxc2c) 
- [**130**星][2y] [sashs/arm_exploitation](https://github.com/sashs/arm_exploitation) 
- [**130**星][12m] [PowerShell] [xor-function/fathomless](https://github.com/xor-function/fathomless) 
- [**124**星][5y] [Java] [mogwaisec/mjet](https://github.com/mogwaisec/mjet) 
- [**121**星][2y] [Py] [alephsecurity/firehorse](https://github.com/alephsecurity/firehorse) 漏洞开发与利用之: 在紧急加载模式(EDM,Emergency Download Mode)下刷机时使用的固件包(高通)
- [**121**星][3y] [C] [nsacyber/control-flow-integrity](https://github.com/nsacyber/Control-Flow-Integrity) 
- [**120**星][6m] [JS] [pownjs/pown](https://github.com/pownjs/pown) 
- [**119**星][2m] [Py] [ctxis/beemka](https://github.com/ctxis/beemka) 
- [**119**星][14d] [Py] [m8r0wn/enumdb](https://github.com/m8r0wn/enumdb) MySQL/MSSQL 爆破和后渗透工具, 搜索数据库并提取敏感信息
- [**114**星][4y] [C] [kpwn/nullguard](https://github.com/kpwn/nullguard) 
- [**111**星][9m] [C] [a13xp0p0v/kernel-hack-drill](https://github.com/a13xp0p0v/kernel-hack-drill) 
- [**111**星][11m] [Py] [saaramar/35c3_modern_windows_userspace_exploitation](https://github.com/saaramar/35c3_modern_windows_userspace_exploitation) 
- [**104**星][10m] [Py] [w3h/isf](https://github.com/w3h/isf) 
- [**102**星][2y] [C++] [sensepost/gdi-palettes-exp](https://github.com/sensepost/gdi-palettes-exp) 滥用 GDI 对象来揭示内核漏洞利用
- [**98**星][4y] [Shell] [reider-roque/linpostexp](https://github.com/reider-roque/linpostexp) 
- [**96**星][2y] [Py] [unix-ninja/shellfire](https://github.com/unix-ninja/shellfire) 
- [**95**星][1y] [Py] [danmcinerney/msf-autopwn](https://github.com/danmcinerney/msf-autopwn) 
- [**94**星][3y] [Py] [donnchac/ubuntu-apport-exploitation](https://github.com/donnchac/ubuntu-apport-exploitation) 
- [**92**星][3y] [PowerShell] [thepaulbenoit/winpirate](https://github.com/thepaulbenoit/winpirate) 
- [**91**星][4y] [Py] [hvqzao/liffy](https://github.com/hvqzao/liffy) 
- [**90**星][3y] [C] [hacksysteam/exploitation](https://github.com/hacksysteam/exploitation) 
- [**89**星][2y] [PHP] [graniet/gshark-framework](https://github.com/graniet/gshark-framework) gshark-framework：执行web post exploitation，可与多个 Web 后门交互，并执行自定义脚本
- [**87**星][2y] [HTML] [0xcl/clang-cfi-bypass-techniques](https://github.com/0xcl/clang-cfi-bypass-techniques) 三种利用漏洞绕过Clang Control Flow Integrity (CFI)的技巧(应用于Chromium时)
- [**87**星][1y] [PowerShell] [nettitude/invoke-powerthief](https://github.com/nettitude/invoke-powerthief) 
- [**84**星][2y] [Go] [0x09al/browser-c2](https://github.com/0x09al/browser-c2) 
- [**83**星][7y] [Py] [dc414/upnp-exploiter](https://github.com/dc414/upnp-exploiter) 
- [**83**星][1y] [Ruby] [enjoiz/bsqlinjector](https://github.com/enjoiz/bsqlinjector) 
- [**83**星][6y] [k33nteam/ie9-ie11-vulnerability-advanced-exploitation](https://github.com/k33nteam/ie9-ie11-vulnerability-advanced-exploitation) 
- [**81**星][13d] [Py] [ziconius/fudgec2](https://github.com/ziconius/fudgec2) 
- [**80**星][29d] [Shell] [sysdevploit/put2win](https://github.com/devploit/put2win) 
- [**79**星][3m] [C++] [thewhiteh4t/flashsploit](https://github.com/thewhiteh4t/flashsploit) 
- [**76**星][5y] [ActionScript] [sethsec/crossdomain-exploitation-framework](https://github.com/sethsec/crossdomain-exploitation-framework) 
- [**75**星][10m] [Py] [siberas/sjet](https://github.com/siberas/sjet) 
- [**72**星][1y] [Py] [lixmk/concierge](https://github.com/lixmk/concierge) Physical Access Control Identification and Exploitation
- [**70**星][3y] [Py] [coldfusion39/domi-owned](https://github.com/coldfusion39/domi-owned) domi-owned：IBM/LotusDomino 服务器漏洞利用工具
- [**68**星][6m] [Py] [incredibleindishell/windows-ad-environment-related](https://github.com/incredibleindishell/windows-ad-environment-related) 
- [**68**星][3y] [C++] [rwfpl/rewolf-gogogadget](https://github.com/rwfpl/rewolf-gogogadget) 
- [**67**星][1y] [C++] [leeqwind/holicpoc](https://github.com/leeqwind/holicpoc) 
- [**66**星][11m] [Py] [r3vn/punk.py](https://github.com/r3vn/punk.py) 
- [**64**星][1y] [C] [seanheelan/heaplayout](https://github.com/seanheelan/heaplayout) 
- [**61**星][3y] [Py] [n00py/post-ex](https://github.com/n00py/post-ex) 
- [**58**星][3y] [Py] [deadbits/intersect-2.5](https://github.com/deadbits/Intersect-2.5) 
- [**57**星][6m] [HTML] [dobin/yookiterm-slides](https://github.com/dobin/yookiterm-slides) 
- [**57**星][4m] [C] [lazenca/kernel-exploit-tech](https://github.com/lazenca/kernel-exploit-tech) 
- [**57**星][3y] [JS] [xtr4nge/fruityc2-client](https://github.com/xtr4nge/fruityc2-client) 
- [**54**星][2y] [C++] [census/windows_10_rs2_rs3_exploitation_primitives](https://github.com/census/windows_10_rs2_rs3_exploitation_primitives) 
- [**32**星][1m] [Py] [kaorz/exploits_challenges](https://github.com/kaorz/exploits_challenges) 
- [**24**星][1y] [Shell] [shawnduong/pxenum](https://github.com/shawnduong/pxenum) 
- [**7**星][5m] [henryhoggard/awesome-arm-exploitation](https://github.com/henryhoggard/awesome-arm-exploitation) 


#### <a id="5c1af335b32e43dba993fceb66c470bc"></a>Exp&&PoC


- [**2214**星][6y] [C++] [codebutler/firesheep](https://github.com/codebutler/firesheep) 
- [**1539**星][2y] [C] [samyk/pwnat](https://github.com/samyk/pwnat) 
- [**1412**星][8y] [Py] [moxie0/sslstrip](https://github.com/moxie0/sslstrip) 
- [**1363**星][1m] [Py] [bitsadmin/wesng](https://github.com/bitsadmin/wesng) 
- [**1353**星][6m] [Py] [vulnerscom/getsploit](https://github.com/vulnerscom/getsploit) 
- [**1328**星][6y] [Perl] [intelisecurelabs/linux_exploit_suggester](https://github.com/InteliSecureLabs/Linux_Exploit_Suggester) 
- [**1322**星][4m] [Py] [lijiejie/githack](https://github.com/lijiejie/githack) git泄露利用脚本，通过泄露的.git文件夹下的文件，重建还原工程源代码
- [**1120**星][4m] [Py] [qyriad/fusee-launcher](https://github.com/Qyriad/fusee-launcher) NVIDIA Tegra X1处理器Fusée Gelée漏洞exploit的launcher. (Fusée Gelée: 冷启动漏洞，允许在bootROM早期, 通过NVIDIA Tegra系列嵌入式处理器上的Tegra恢复模式(RCM)执行完整、未经验证的任意代码)
- [**944**星][3y] [Py] [abatchy17/windowsexploits](https://github.com/abatchy17/windowsexploits) 
- [**930**星][10m] [Shell] [1n3/findsploit](https://github.com/1n3/findsploit) 
- [**918**星][5m] [JS] [reswitched/pegaswitch](https://github.com/reswitched/pegaswitch) 
- [**881**星][3m] [C] [theofficialflow/h-encore](https://github.com/theofficialflow/h-encore) 
- [**872**星][2y] [PowerShell] [windowsexploits/exploits](https://github.com/windowsexploits/exploits) 
- [**870**星][2y] [C] [paboldin/meltdown-exploit](https://github.com/paboldin/meltdown-exploit) Meltdown exploit
- [**785**星][3y] [C++] [bwall/hashpump](https://github.com/bwall/hashpump) 
- [**753**星][3y] [Py] [mubix/shellshocker-pocs](https://github.com/mubix/shellshocker-pocs) 
- [**711**星][1y] [Py] [rfunix/pompem](https://github.com/rfunix/pompem) 
- [**707**星][11m] [HTML] [juansacco/exploitpack](https://github.com/juansacco/exploitpack) 
- [**703**星][4m] [Py] [rhinosecuritylabs/security-research](https://github.com/rhinosecuritylabs/security-research) 
- [**701**星][3y] [PowerShell] [gimini/powermemory](https://github.com/gimini/powermemory) 
- [**695**星][6m] [C] [unamer/vmware_escape](https://github.com/unamer/vmware_escape) VMwareWorkStation 12.5.5 之前版本的逃逸 Exploit
- [**681**星][1y] [C] [saelo/pwn2own2018](https://github.com/saelo/pwn2own2018) Pwn2Own 2018 Safari+macOS 漏洞利用链
- [**651**星][2y] [C] [fail0verflow/shofel2](https://github.com/fail0verflow/shofel2) Tegra X1 bootrom exploit
- [**636**星][4m] [smgorelik/windows-rce-exploits](https://github.com/smgorelik/windows-rce-exploits) 
- [**621**星][4m] [C++] [eliboa/tegrarcmgui](https://github.com/eliboa/tegrarcmgui) 
- [**617**星][4m] [Perl] [jondonas/linux-exploit-suggester-2](https://github.com/jondonas/linux-exploit-suggester-2) 
- [**608**星][3m] [C] [matheus-garbelini/esp32_esp8266_attacks](https://github.com/matheus-garbelini/esp32_esp8266_attacks) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**607**星][8m] [Py] [al-azif/ps4-exploit-host](https://github.com/al-azif/ps4-exploit-host) 
- [**584**星][3y] [C] [cr4sh/thinkpwn](https://github.com/cr4sh/thinkpwn) 
- [**580**星][2y] [Py] [ant4g0nist/lisa.py](https://github.com/ant4g0nist/lisa.py) 
- [**580**星][1y] [JS] [cryptogenic/ps4-5.05-kernel-exploit](https://github.com/cryptogenic/ps4-5.05-kernel-exploit) 
- [**580**星][10m] [mtivadar/windows10_ntfs_crash_dos](https://github.com/mtivadar/windows10_ntfs_crash_dos) Windows NTFS文件系统崩溃漏洞PoC
- [**555**星][3y] [Py] [edwardz246003/iis_exploit](https://github.com/edwardz246003/iis_exploit) 
- [**552**星][9m] [C] [t00sh/rop-tool](https://github.com/t00sh/rop-tool) binary exploits编写辅助脚本
- [**544**星][2m] [Py] [tarunkant/gopherus](https://github.com/tarunkant/gopherus) 
- [**523**星][5m] [Py] [bignerd95/chimay-red](https://github.com/bignerd95/chimay-red) 
- [**512**星][2y] [JS] [cryptogenic/ps4-4.05-kernel-exploit](https://github.com/cryptogenic/ps4-4.05-kernel-exploit) 
- [**494**星][2y] [Py] [chybeta/cmspoc](https://github.com/chybeta/cmspoc) CMS渗透测试框架
- [**489**星][6m] [Py] [danigargu/heap-viewer](https://github.com/danigargu/heap-viewer) 查看glibc堆, 主要用于漏洞开发
- [**489**星][5m] [Py] [metachar/phonesploit](https://github.com/metachar/phonesploit) 
- [**488**星][7m] [Py] [lijiejie/ds_store_exp](https://github.com/lijiejie/ds_store_exp) 
- [**487**星][2y] [C++] [turbo/kpti-poc-collection](https://github.com/turbo/kpti-poc-collection) 
- [**482**星][3y] [Py] [erevus-cn/pocscan](https://github.com/erevus-cn/pocscan) 
- [**481**星][5m] [PHP] [cfreal/exploits](https://github.com/cfreal/exploits) 
- [**481**星][3y] [Py] [lgandx/poc](https://github.com/lgandx/poc) 
- [**479**星][2y] [Py] [armissecurity/blueborne](https://github.com/armissecurity/blueborne) 
- [**473**星][2m] [JS] [acmesec/pocbox](https://github.com/Acmesec/PoCBox) 赏金猎人的脆弱性测试辅助平台
- [**472**星][9m] [Py] [insecurityofthings/jackit](https://github.com/insecurityofthings/jackit) Exploit Code for Mousejack
- [**452**星][3y] [C] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 
- [**435**星][1y] [Py] [jfoote/exploitable](https://github.com/jfoote/exploitable) 
- [**434**星][4y] [Py] [foxglovesec/javaunserializeexploits](https://github.com/foxglovesec/javaunserializeexploits) 
- [**431**星][9m] [Shell] [r00t-3xp10it/fakeimageexploiter](https://github.com/r00t-3xp10it/fakeimageexploiter) 
- [**418**星][11m] [Shell] [nilotpalbiswas/auto-root-exploit](https://github.com/nilotpalbiswas/auto-root-exploit) 
- [**412**星][4y] [C++] [demi6od/smashing_the_browser](https://github.com/demi6od/smashing_the_browser) 
- [**412**星][3m] [Py] [misterch0c/malsploitbase](https://github.com/misterch0c/malsploitbase) 
- [**402**星][1y] [C] [ww9210/linux_kernel_exploits](https://github.com/ww9210/linux_kernel_exploits) 
- [**390**星][7m] [Py] [jm33-m0/massexpconsole](https://github.com/jm33-m0/mec) 
- [**383**星][12m] [JS] [linushenze/webkit-regex-exploit](https://github.com/linushenze/webkit-regex-exploit) 
- [**378**星][12m] [PHP] [bo0om/php_imap_open_exploit](https://github.com/bo0om/php_imap_open_exploit) 
- [**375**星][5y] [C++] [clymb3r/kdexploitme](https://github.com/clymb3r/kdexploitme) 
- [**372**星][2m] [PHP] [mm0r1/exploits](https://github.com/mm0r1/exploits) 
- [**349**星][1m] [Shell] [th3xace/sudo_killer](https://github.com/th3xace/sudo_killer) 
- [**348**星][8m] [C] [p0cl4bs/kadimus](https://github.com/p0cl4bs/kadimus) 
- [**339**星][4m] [C] [theofficialflow/trinity](https://github.com/theofficialflow/trinity) 
- [**335**星][4y] [PowerShell] [kevin-robertson/tater](https://github.com/kevin-robertson/tater) 
- [**331**星][6m] [C++] [thezdi/poc](https://github.com/thezdi/poc) 
- [**318**星][2y] [Objective-C] [doadam/ziva](https://github.com/doadam/ziva) 
- [**305**星][1y] [Shell] [jas502n/st2-057](https://github.com/jas502n/st2-057) 
- [**302**星][3m] [PowerShell] [kevin-robertson/powermad](https://github.com/kevin-robertson/powermad) 
- [**300**星][1m] [Py] [admintony/svnexploit](https://github.com/admintony/svnexploit) 
- [**278**星][9y] [Py] [ptoomey3/evilarc](https://github.com/ptoomey3/evilarc) 
- [**276**星][1m] [C] [0xdea/exploits](https://github.com/0xdea/exploits) 研究员 0xdeadbeef 的公开exploits 收集
- [**276**星][3y] [HTML] [buddhalabs/packetstorm-exploits](https://github.com/buddhalabs/packetstorm-exploits) 
- [**275**星][3m] [Shell] [cryptolok/aslray](https://github.com/cryptolok/aslray) 
- [**269**星][1y] [Py] [mwrlabs/wepwnise](https://github.com/FSecureLABS/wePWNise) 
- [**266**星][4m] [Java] [c0ny1/fastjsonexploit](https://github.com/c0ny1/fastjsonexploit) 
- [**264**星][4y] [Py] [rpp0/aggr-inject](https://github.com/rpp0/aggr-inject) 
- [**263**星][12m] [Py] [c0rel0ader/east](https://github.com/c0rel0ader/east) 
- [**256**星][3y] [jmpews/pwn2exploit](https://github.com/jmpews/pwn2exploit) 
- [**254**星][1y] [PHP] [mrsqar-ye/badmod](https://github.com/mrsqar-ye/badmod) 
- [**252**星][2y] [Py] [1n3/wordpress-xmlrpc-brute-force-exploit](https://github.com/1n3/wordpress-xmlrpc-brute-force-exploit) 
- [**251**星][4m] [C] [bcoles/kernel-exploits](https://github.com/bcoles/kernel-exploits) 
- [**246**星][2y] [JS] [cryptogenic/ps4-4.55-kernel-exploit](https://github.com/cryptogenic/ps4-4.55-kernel-exploit) 
- [**245**星][9m] [Visual Basic] [houjingyi233/office-exploit-case-study](https://github.com/houjingyi233/office-exploit-case-study) 
- [**245**星][4y] [Py] [n0tr00t/beebeeto-framework](https://github.com/n0tr00t/beebeeto-framework) 规范化POC/EXP平台
- [**234**星][19d] [C#] [tyranid/exploitremotingservice](https://github.com/tyranid/exploitremotingservice) 
- [**229**星][1y] [Py] [nccgroup/shocker](https://github.com/nccgroup/shocker) 
- [**222**星][4y] [Py] [mwielgoszewski/python-paddingoracle](https://github.com/mwielgoszewski/python-paddingoracle) 
- [**219**星][3y] [1u4nx/exploit-exercises-nebula](https://github.com/1u4nx/exploit-exercises-nebula) 
- [**219**星][8m] [Py] [coalfire-research/deathmetal](https://github.com/coalfire-research/deathmetal) 
- [**218**星][3y] [axi0mx/alloc8](https://github.com/axi0mx/alloc8) 
- [**218**星][3m] [PowerShell] [byt3bl33d3r/offensivedlr](https://github.com/byt3bl33d3r/offensivedlr) 
- [**218**星][1m] [C++] [soarqin/finalhe](https://github.com/soarqin/finalhe) 
- [**215**星][3m] [C] [semmle/securityexploits](https://github.com/semmle/securityexploits) 
- [**210**星][1y] [Py] [kurobeats/fimap](https://github.com/kurobeats/fimap) 
- [**210**星][1y] [PHP] [wofeiwo/webcgi-exploits](https://github.com/wofeiwo/webcgi-exploits) 
- [**209**星][1y] [Py] [mazen160/server-status_pwn](https://github.com/mazen160/server-status_pwn) 
- [**207**星][1y] [C] [crozone/spectrepoc](https://github.com/crozone/spectrepoc) 
- [**201**星][6m] [Py] [invictus1306/beebug](https://github.com/invictus1306/beebug) 
- [**198**星][4y] [JS] [cturt/ps4-playground](https://github.com/cturt/ps4-playground) 
- [**197**星][2y] [Objective-C] [siguza/v0rtex](https://github.com/siguza/v0rtex) 
- [**193**星][3y] [Go] [vesche/lonely-shell](https://github.com/vesche/lonely-shell) 
- [**189**星][2y] [Py] [neex/gifoeb](https://github.com/neex/gifoeb) 
- [**187**星][2m] [04x/icg-autoexploiterbot](https://github.com/04x/icg-autoexploiterbot) 
- [**187**星][6m] [C++] [linushenze/keysteal](https://github.com/linushenze/keysteal) 
- [**186**星][4y] [Py] [paulsec/hqlmap](https://github.com/paulsec/hqlmap) 
- [**185**星][6m] [Py] [tintinweb/pub](https://github.com/tintinweb/pub) 
- [**180**星][2y] [Py] [0x09al/wordsteal](https://github.com/0x09AL/WordSteal) 
- [**178**星][2y] [aozhimin/mosec-2017](https://github.com/aozhimin/mosec-2017) 盘古团队和 POC 主办的移动安全技术峰会
- [**176**星][2y] [Shell] [ha71/whatcms](https://github.com/ha71/whatcms) 
- [**174**星][10m] [Java] [aalhuz/navex](https://github.com/aalhuz/navex) is an exploit generation framework for web applications.
- [**171**星][4y] [Py] [osandamalith/lfifreak](https://github.com/osandamalith/lfifreak) 
- [**170**星][3y] [kayrus/kubelet-exploit](https://github.com/kayrus/kubelet-exploit) 
- [**167**星][3y] [Py] [comsecuris/shannonre](https://github.com/comsecuris/shannonre) 
- [**164**星][1y] [Py] [hanc00l/weblogic_unserialize_exploit](https://github.com/hanc00l/weblogic_unserialize_exploit) 
- [**164**星][3y] [C] [jedisct1/blacknurse](https://github.com/jedisct1/blacknurse) 
- [**163**星][4y] [C] [vlad902/hacking-team-windows-kernel-lpe](https://github.com/vlad902/hacking-team-windows-kernel-lpe) 
- [**163**星][5y] [Py] [q2h1cg/cms-exploit-framework](https://github.com/Q2h1Cg/CMS-Exploit-Framework) 
- [**161**星][9m] [winmin/awesome-vm-exploit](https://github.com/winmin/awesome-vm-exploit) 
- [**160**星][2m] [JS] [mrgeffitas/ironsquirrel](https://github.com/mrgeffitas/ironsquirrel) 
- [**159**星][1y] [Py] [belane/linux-soft-exploit-suggester](https://github.com/belane/linux-soft-exploit-suggester) linux-soft-exploit-suggester：通过 exploit database 搜索 Linux 系统中有漏洞的软件
- [**159**星][1y] [Py] [boy-hack/poc-t](https://github.com/boy-hack/poc-t) 
- [**159**星][10m] [Py] [mpgn/poodle-poc](https://github.com/mpgn/poodle-poc) 
- [**159**星][7m] [C++] [momo5502/cod-exploits](https://github.com/momo5502/cod-exploits) 
- [**158**星][12d] [Shell] [offensive-security/exploitdb-papers](https://github.com/offensive-security/exploitdb-papers) 
- [**157**星][2m] [C] [fullmetal5/bluebomb](https://github.com/fullmetal5/bluebomb) 
- [**155**星][4y] [Py] [crown-prince/python_poc](https://github.com/crown-prince/python_poc) 
- [**155**星][4y] [Py] [n0tr00t/beehive](https://github.com/n0tr00t/beehive) 
- [**154**星][3y] [Py] [theevilbit/exploit_generator](https://github.com/theevilbit/exploit_generator) 
- [**152**星][2y] [PHP] [paralax/lfi-labs](https://github.com/paralax/lfi-labs) 
- [**151**星][2y] [JS] [alexzzz9/ps4-5.01-webkit-exploit-poc](https://github.com/alexzzz9/ps4-5.01-webkit-exploit-poc) 
- [**151**星][3m] [Assembly] [smealum/butthax](https://github.com/smealum/butthax) 
- [**149**星][3m] [Go] [jollheef/out-of-tree](https://github.com/jollheef/out-of-tree) 
- [**148**星][1y] [Py] [raminfp/linux_exploit_development](https://github.com/raminfp/linux_exploit_development) 
- [**147**星][11m] [Py] [649/crashcast-exploit](https://github.com/649/crashcast-exploit) 
- [**146**星][1y] [Py] [vanpersiexp/expcamera](https://github.com/vanpersiexp/expcamera) 
- [**144**星][2y] [Py] [mpgn/padding-oracle-attack](https://github.com/mpgn/padding-oracle-attack)  An exploit for the Padding Oracle Attack
- [**144**星][2y] [JS] [theori-io/zer0con2018_bpak](https://github.com/theori-io/zer0con2018_bpak) 为Google Chrome创建1-dayExploit(Zer0Con)
- [**143**星][3y] [CSS] [sensepost/jack](https://github.com/sensepost/jack) 
- [**142**星][2y] [C] [salls/kernel-exploits](https://github.com/salls/kernel-exploits) 
- [**139**星][1y] [Py] [c0r3dump3d/osueta](https://github.com/c0r3dump3d/osueta) 
- [**139**星][8m] [JS] [exodusintel/chromium-941743](https://github.com/exodusintel/chromium-941743) 
- [**138**星][6m] [Perl] [caledoniaproject/jenkins-cli-exploit](https://github.com/caledoniaproject/jenkins-cli-exploit) 
- [**138**星][2y] [C] [saleemrashid/ledger-mcu-backdoor](https://github.com/saleemrashid/ledger-mcu-backdoor) 
- [**138**星][12m] [Py] [santatic/web2attack](https://github.com/santatic/web2attack) 
- [**137**星][7m] [Py] [iphelix/ida-sploiter](https://github.com/iphelix/ida-sploiter) 辅助漏洞研究
- [**137**星][1y] [Py] [quentinhardy/scriptsandexploits](https://github.com/quentinhardy/scriptsandexploits) 
- [**136**星][3m] [Py] [mgeeky/expdevbadchars](https://github.com/mgeeky/expdevbadchars) 
- [**136**星][1y] [C] [xvortex/ps4-hen-vtx](https://github.com/xvortex/ps4-hen-vtx) 
- [**134**星][10m] [Py] [bignerd95/winboxexploit](https://github.com/bignerd95/winboxexploit) 
- [**133**星][3m] [Py] [1n3/exploits](https://github.com/1n3/exploits) 
- [**132**星][5y] [C] [smealum/ninjhax](https://github.com/smealum/ninjhax) 
- [**132**星][2y] [PowerShell] [tevora-threat/eternal_blue_powershell](https://github.com/tevora-threat/eternal_blue_powershell) 
- [**131**星][2y] [HTML] [4b5f5f4b/exploits](https://github.com/4b5f5f4b/exploits) 
- [**131**星][10m] [C] [regehr/ub-canaries](https://github.com/regehr/ub-canaries) 
- [**130**星][6y] [Java] [fuzion24/androidziparbitrage](https://github.com/fuzion24/androidziparbitrage) 
- [**130**星][1y] [Py] [youngyangyang04/nosqlattack](https://github.com/youngyangyang04/nosqlattack) 
- [**129**星][2y] [C] [smeso/mtpwn](https://github.com/smeso/mtpwn) 
- [**129**星][2m] [Py] [svenito/exploit-pattern](https://github.com/svenito/exploit-pattern) 
- [**129**星][2y] [Py] [zcutlip/bowcaster](https://github.com/zcutlip/bowcaster)  Exploit Development Framework
- [**127**星][2y] [C] [hardenedlinux/offensive_poc](https://github.com/hardenedlinux/offensive_poc) 
- [**127**星][3y] [PHP] [malwares/exploitkit](https://github.com/malwares/exploitkit) 
- [**126**星][4y] [Py] [jakecooper/oneplustwobot](https://github.com/jakecooper/oneplustwobot) 
- [**125**星][6m] [Py] [tuuunya/webpocket](https://github.com/tuuunya/webpocket) 
- [**125**星][1m] [C] [jollheef/lpe](https://github.com/jollheef/lpe) 
- [**124**星][4y] [Py] [davidoren/cuckoosploit](https://github.com/davidoren/cuckoosploit) 
- [**124**星][3m] [theofficialflow/h-encore-2](https://github.com/theofficialflow/h-encore-2) 
- [**123**星][10m] [Py] [niklasb/3dpwn](https://github.com/niklasb/3dpwn) 
- [**121**星][7y] [pwnwiki/webappdefaultsdb](https://github.com/pwnwiki/webappdefaultsdb) 
- [**120**星][4y] [Py] [breenmachine/javaunserializeexploits](https://github.com/breenmachine/javaunserializeexploits) 
- [**120**星][8m] [Py] [wangyihang/exploit-framework](https://github.com/wangyihang/exploit-framework) 
- [**119**星][6m] [C++] [0vercl0k/blazefox](https://github.com/0vercl0k/blazefox) 
- [**119**星][6y] [Py] [infodox/exploits](https://github.com/infodox/exploits) 
- [**118**星][1y] [PowerShell] [itm4n/ikeext-privesc](https://github.com/itm4n/ikeext-privesc) 
- [**115**星][1y] [Py] [graniet/inspector](https://github.com/graniet/inspector) 
- [**115**星][2y] [C] [harsaroopdhillon/spectreexploit](https://github.com/harsaroopdhillon/spectreexploit) 
- [**115**星][3m] [Py] [kmkz/exploit](https://github.com/kmkz/exploit) 
- [**115**星][3y] [Java] [njfox/java-deserialization-exploit](https://github.com/njfox/java-deserialization-exploit) 
- [**114**星][7m] [C] [govolution/avepoc](https://github.com/govolution/avepoc) avepoc：一些免杀的 poc
- [**113**星][2y] [C++] [waryas/eupmaccess](https://github.com/waryas/eupmaccess) 
- [**112**星][2m] [HTML] [sundaysec/android-exploits](https://github.com/sundaysec/android-exploits) 
- [**110**星][8m] [Py] [ambionics/magento-exploits](https://github.com/ambionics/magento-exploits) 
- [**110**星][17d] [Batchfile] [pr0cf5/kernel-exploit-practice](https://github.com/pr0cf5/kernel-exploit-practice) 
- [**106**星][2y] [Py] [hansesecure/exploitdev](https://github.com/hansesecure/exploitdev) 
- [**105**星][2m] [Perl] [gottburgm/exploits](https://github.com/gottburgm/exploits) 
- [**105**星][3y] [C++] [secmob/mosec2016](https://github.com/secmob/mosec2016) 
- [**101**星][2y] [C] [benjibobs/async_wake](https://github.com/benjibobs/async_wake) 
- [**101**星][8y] [C] [djrbliss/libplayground](https://github.com/djrbliss/libplayground) 
- [**100**星][4y] [Py] [cr4sh/uefi_boot_script_expl](https://github.com/cr4sh/uefi_boot_script_expl) 
- [**100**星][3y] [C++] [tandasat/exploitcapcom](https://github.com/tandasat/exploitcapcom) 
- [**99**星][4y] [C] [sploitfun/lsploits](https://github.com/sploitfun/lsploits) 
- [**98**星][2y] [Java] [irsl/jackson-rce-via-spel](https://github.com/irsl/jackson-rce-via-spel) 
- [**95**星][4m] [JS] [w00dl3cs/exploit_playground](https://github.com/w00dl3cs/exploit_playground) 
- [**94**星][3m] [JS] [beepfelix/csgo-crash-exploit](https://github.com/beepfelix/csgo-crash-exploit) 
- [**94**星][1m] [C++] [dzzie/vs_libemu](https://github.com/dzzie/vs_libemu) 
- [**93**星][2y] [Py] [invictus1306/workshop-bsidesmunich2018](https://github.com/invictus1306/workshop-bsidesmunich2018) 
- [**93**星][4y] [Py] [zachriggle/peda](https://github.com/zachriggle/peda) 
- [**92**星][4y] [C] [kr105-zz/ps4-dlclose](https://github.com/kr105-zz/ps4-dlclose) 
- [**89**星][28d] [Py] [xct/ropstar](https://github.com/xct/ropstar) 
- [**87**星][8m] [Py] [johntroony/blisqy](https://github.com/johntroony/blisqy) 
- [**87**星][4y] [Py] [laginimaineb/msm8974_exploit](https://github.com/laginimaineb/msm8974_exploit) 
- [**86**星][11m] [Py] [0x00-0x00/fakepip](https://github.com/0x00-0x00/fakepip) 
- [**86**星][6y] [C] [shjalayeri/drivecrypt](https://github.com/shjalayeri/drivecrypt) 
- [**86**星][2y] [HTML] [illikainen/exploits](https://github.com/illikainen/exploits) 
- [**85**星][1y] [Java] [cunninglogic/dumlracer](https://github.com/cunninglogic/dumlracer) 
- [**85**星][3y] [exp-sky/hitcon-2016-windows-10-x64-edge-0day-and-exploit](https://github.com/exp-sky/hitcon-2016-windows-10-x64-edge-0day-and-exploit) 
- [**85**星][2y] [Ruby] [mavproxyuser/p0vsredherring](https://github.com/mavproxyuser/p0vsredherring) 
- [**85**星][2y] [C] [maximehip/safari-ios10.3.2-macos-10.12.4-exploit-bugs](https://github.com/maximehip/safari-ios10.3.2-macos-10.12.4-exploit-bugs) 
- [**85**星][4y] [HTML] [secmob/cansecwest2016](https://github.com/secmob/cansecwest2016) 
- [**85**星][3y] [C] [sensepost/ms16-098](https://github.com/sensepost/ms16-098) 
- [**84**星][11m] [Py] [naivenom/exploiting](https://github.com/naivenom/exploiting) 
- [**83**星][2y] [C] [pannzh/hidemyass](https://github.com/pannzh/hidemyass) 
- [**82**星][1y] [exp-sky/asiasecwest-2018-chakra-vulnerability-and-exploit-bypass-all-system-mitigation](https://github.com/exp-sky/asiasecwest-2018-chakra-vulnerability-and-exploit-bypass-all-system-mitigation) 
- [**82**星][5m] [Java] [magiczer0/fastjson-rce-exploit](https://github.com/magiczer0/fastjson-rce-exploit) 
- [**82**星][3y] [Py] [ratty3697/hackspy-trojan-exploit](https://github.com/ratty3697/hackspy-trojan-exploit) 
- [**82**星][1y] [C] [rlarabee/exploits](https://github.com/rlarabee/exploits) 
- [**81**星][7y] [shjalayeri/sysret](https://github.com/shjalayeri/sysret) 
- [**81**星][6y] [CSS] [talater/chrome-is-listening](https://github.com/talater/chrome-is-listening) 
- [**81**星][4y] [Py] [zcutlip/exploit-poc](https://github.com/zcutlip/exploit-poc) 
- [**80**星][4m] [Py] [theevilbit/kex](https://github.com/theevilbit/kex) kex: python kernel exploit library
- [**80**星][1y] [Py] [am0nsec/exploit](https://github.com/am0nsec/exploit) 
- [**79**星][4y] [PHP] [coderpirata/xpl-search](https://github.com/coderpirata/xpl-search) 
- [**79**星][3y] [C] [smealum/udsploit](https://github.com/smealum/udsploit) 
- [**77**星][4y] [HTML] [f47h3r/hackingteam_exploits](https://github.com/f47h3r/hackingteam_exploits) 
- [**77**星][3y] [HTML] [szimeus/evalyzer](https://github.com/szimeus/evalyzer) 
- [**77**星][4y] [Java] [zerothoughts/spring-jndi](https://github.com/zerothoughts/spring-jndi) 
- [**77**星][1y] [C] [contionmig/kernelmode-bypass](https://github.com/ContionMig/KernelMode-Bypass) 
- [**76**星][4y] [PHP] [fakhrizulkifli/defeating-php-gd-imagecreatefromgif](https://github.com/fakhrizulkifli/defeating-php-gd-imagecreatefromgif) 
- [**76**星][5m] [Java] [incredibleindishell/exploit-code-by-me](https://github.com/incredibleindishell/exploit-code-by-me) 
- [**76**星][4m] [Py] [nccgroup/requests-racer](https://github.com/nccgroup/requests-racer) 
- [**75**星][22d] [Py] [momika233/clamav_0day_exploit](https://github.com/momika233/clamav_0day_exploit) 
- [**74**星][1m] [Ruby] [david942j/heapinfo](https://github.com/david942j/heapinfo) 
- [**74**星][11m] [JS] [j0nathanj/publications](https://github.com/j0nathanj/publications) 
- [**74**星][2y] [C] [suhubdy/meltdown](https://github.com/deeptechlabs/meltdown) 
- [**73**星][1y] [C] [alpha1ab/win2016lpe](https://github.com/alpha1ab/win2016lpe) 
- [**73**星][3y] [PHP] [nmalcolm/ipcamshell](https://github.com/nmalcolm/ipcamshell) 
- [**71**星][2y] [Py] [mgeeky/exploit-development-tools](https://github.com/mgeeky/exploit-development-tools) 
- [**71**星][9m] [sevagas/windowsdefender_asr_bypass-offensivecon2019](https://github.com/sevagas/windowsdefender_asr_bypass-offensivecon2019) 
- [**69**星][1y] [Java] [1135/equationexploit](https://github.com/1135/equationexploit) 
- [**69**星][7m] [Py] [itsmehacker/ducky-exploit](https://github.com/itsmehacker/ducky-exploit) 
- [**69**星][2y] [Py] [odensc/janus](https://github.com/odensc/janus) 
- [**69**星][2y] [Py] [r0oth3x49/xpath](https://github.com/r0oth3x49/xpath) 
- [**68**星][3y] [CSS] [enddo/cjexploiter](https://github.com/enddo/cjexploiter) 
- [**68**星][2y] [Perl] [mobrine-mob/m0b-tool](https://github.com/mobrine-mob/m0b-tool) 
- [**66**星][7m] [Py] [chipik/sap_gw_rce_exploit](https://github.com/chipik/sap_gw_rce_exploit) 
- [**66**星][5y] [Assembly] [yifanlu/spider3dstools](https://github.com/yifanlu/spider3dstools) 
- [**65**星][4y] [PHP] [fakhrizulkifli/defeating-php-gd-imagecreatefromjpeg](https://github.com/fakhrizulkifli/defeating-php-gd-imagecreatefromjpeg) 
- [**65**星][2y] [Py] [switchbrew/nx-hbexploit300-obf](https://github.com/switchbrew/nx-hbexploit300-obf) Homebrew exploit for 3.0.0
- [**64**星][2m] [Py] [blackarch/sploitctl](https://github.com/blackarch/sploitctl) 
- [**64**星][1y] [JS] [nccgroup/goatcasino](https://github.com/nccgroup/goatcasino) 
- [**64**星][5m] [Py] [orleven/tentacle](https://github.com/orleven/tentacle) 
- [**64**星][2y] [JS] [switchbrew/nx-hbexploit300](https://github.com/switchbrew/nx-hbexploit300) 
- [**64**星][6y] [C++] [coresecurity/sentinel](https://github.com/helpsystems/sentinel) 
- [**63**星][2y] [C] [georgeargyros/snowflake](https://github.com/georgeargyros/snowflake) 
- [**63**星][1y] [Py] [kasperskylab/vbscriptinternals](https://github.com/kasperskylab/vbscriptinternals) 
- [**63**星][3y] [C] [mrrraou/waithax](https://github.com/mrrraou/waithax) 
- [**61**星][8m] [Py] [3lackrush/poc-bank](https://github.com/3lackrush/poc-bank) 
- [**61**星][2y] [Shell] [m4lv0id/lare](https://github.com/m4lv0id/LARE) 
- [**59**星][1y] [Py] [esmog/nodexp](https://github.com/esmog/nodexp) 
- [**59**星][4m] [Py] [josue87/boomer](https://github.com/josue87/boomer) 
- [**59**星][11m] [Py] [reptilehaus/eternal-blue](https://github.com/reptilehaus/eternal-blue) 
- [**59**星][2y] [secwiki/macos-kernel-exploits](https://github.com/secwiki/macos-kernel-exploits) 
- [**58**星][4y] [C] [dev-zzo/exploits-nt-privesc](https://github.com/dev-zzo/exploits-nt-privesc) 
- [**58**星][6y] [Java] [pwntester/xmldecoder](https://github.com/pwntester/xmldecoder) 
- [**58**星][4y] [C++] [rootkitsmm/win10pcap-exploit](https://github.com/rootkitsmm/win10pcap-exploit) 
- [**58**星][3y] [Py] [sensepost/xrdp](https://github.com/sensepost/xrdp) 
- [**57**星][15d] [Py] [anon-exploiter/suid3num](https://github.com/anon-exploiter/suid3num) 
- [**57**星][2y] [JS] [coincoin7/wireless-router-vulnerability](https://github.com/coincoin7/wireless-router-vulnerability) 
- [**57**星][9y] [C++] [cr4sh/drvhide-poc](https://github.com/cr4sh/drvhide-poc) 
- [**57**星][3y] [JS] [cryptogenic/ps4-4.0x-code-execution-poc](https://github.com/cryptogenic/ps4-4.0x-code-execution-poc) 
- [**56**星][3y] [Py] [siberas/arpwn](https://github.com/siberas/arpwn) 
- [**50**星][7m] [Py] [hack-hut/crabstick](https://github.com/hack-hut/crabstick) 
- [**50**星][2y] [Py] [neargle/pil-rce-by-ghostbutt](https://github.com/neargle/pil-rce-by-ghostbutt) 
- [**48**星][3y] [C++] [enigma0x3/messagebox](https://github.com/enigma0x3/messagebox) 
- [**48**星][2y] [JS] [sola-da/redos-vulnerabilities](https://github.com/sola-da/redos-vulnerabilities) 
- [**47**星][2y] [Py] [vah13/sap_exploit](https://github.com/vah13/sap_exploit) 
- [**47**星][7m] [Py] [ctf-o-matic/capture-the-flag](https://github.com/ctf-o-matic/capture-the-flag) 
- [**43**星][1y] [Py] [ambionics/prestashop-exploits](https://github.com/ambionics/prestashop-exploits) 
- [**42**星][6m] [hook-s3c/cve-2019-0708-poc](https://github.com/hook-s3c/cve-2019-0708-poc) 
- [**39**星][3y] [Shell] [superkojiman/rfishell](https://github.com/superkojiman/rfishell) 
- [**38**星][7y] [C] [commonexploits/icmpsh](https://github.com/commonexploits/icmpsh) 
- [**38**星][6m] [Py] [turr0n/firebase](https://github.com/turr0n/firebase) 
- [**37**星][4y] [Py] [exploit-install/shellsploit-framework](https://github.com/exploit-install/shellsploit-framework) 
- [**33**星][2y] [Py] [alexbers/exploit_farm](https://github.com/alexbers/exploit_farm) 
- [**33**星][2y] [C++] [siberas/cve-2016-3309_reloaded](https://github.com/siberas/cve-2016-3309_reloaded) 
- [**30**星][4y] [C] [211217613/c-hacking](https://github.com/211217613/c-hacking) 
- [**30**星][2y] [JS] [ret2got/ethereum-jsonrpc-dns-rebinding](https://github.com/ret2got/Ethereum-JSONRPC-DNS-Rebinding) 
- [**29**星][26d] [Shell] [mainframed/enumeration](https://github.com/mainframed/enumeration) 
- [**27**星][23d] [Py] [k8gege/solrexp](https://github.com/k8gege/solrexp) 
- [**26**星][3y] [Go] [egebalci/ticketbleed](https://github.com/egebalci/ticketbleed) 
- [**26**星][2m] [Perl] [t00sh/ctf](https://github.com/t00sh/ctf) 
- [**26**星][24d] [Py] [3xploit-db/pentest-tools-framework](https://github.com/3xploit-db/pentest-tools-framework) 
- [**24**星][4y] [exp-sky/hitcon-2015-spartan-0day-exploit](https://github.com/exp-sky/hitcon-2015-spartan-0day-exploit) 
- [**23**星][5y] [exp-sky/hitcon-2014-ie-11-0day-windows-8.1-exploit](https://github.com/exp-sky/hitcon-2014-ie-11-0day-windows-8.1-exploit) 
- [**23**星][2y] [Py] [s3xy/cve-2017-10271](https://github.com/s3xy/cve-2017-10271) 
- [**22**星][3m] [C] [ww9210/kernel4.20_bpf_lpe](https://github.com/ww9210/kernel4.20_bpf_lpe) 
- [**21**星][7m] [C] [djhohnstein/wlbsctrl_poc](https://github.com/djhohnstein/wlbsctrl_poc) 
- [**20**星][1m] [Py] [brianlam38/sec-cheatsheets](https://github.com/brianlam38/sec-cheatsheets) 
- [**1**星][6y] [C++] [mheistermann/hashpump-partialhash](https://github.com/mheistermann/hashpump-partialhash) 




### <a id="5d7191f01544a12bdaf1315c3e986dff"></a>XSS&&XXE


#### <a id="493e36d0ceda2fb286210a27d617c44d"></a>收集


- [**2671**星][5m] [JS] [s0md3v/awesomexss](https://github.com/s0md3v/AwesomeXSS) 
- [**2209**星][1y] [JS] [cure53/h5sc](https://github.com/cure53/h5sc) 
- [**486**星][1y] [Py] [shawarkhanethicalhacker/brutexss](https://github.com/shawarkhanethicalhacker/brutexss) 
- [**454**星][1y] [HTML] [metnew/uxss-db](https://github.com/metnew/uxss-db) 
- [**384**星][3y] [pgaijin66/xss-payloads](https://github.com/pgaijin66/xss-payloads) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload收集](#b5d99a78ddb383c208aae474fc2cb002) |
- [**36**星][4y] [7iosecurity/xss-payloads](https://github.com/7iosecurity/xss-payloads) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload收集](#b5d99a78ddb383c208aae474fc2cb002) |


#### <a id="648e49b631ea4ba7c128b53764328c39"></a>未分类-XSS


- [**7288**星][25d] [Py] [s0md3v/xsstrike](https://github.com/s0md3v/XSStrike) 
    - 重复区段: [工具/扫描器&&安全扫描&&App扫描&&漏洞扫描/未分类-Scanner](#de63a029bda6a7e429af272f291bb769) |
- [**1641**星][10m] [JS] [evilcos/xssor2](https://github.com/evilcos/xssor2) 
- [**1318**星][3m] [Go] [microcosm-cc/bluemonday](https://github.com/microcosm-cc/bluemonday) a fast golang HTML sanitizer (inspired by the OWASP Java HTML Sanitizer) to scrub user generated content of XSS
- [**1204**星][5y] [cure53/xsschallengewiki](https://github.com/cure53/xsschallengewiki) 
- [**1204**星][5y] [cure53/xsschallengewiki](https://github.com/cure53/XSSChallengeWiki) 
- [**991**星][2y] [Py] [danmcinerney/xsscrapy](https://github.com/danmcinerney/xsscrapy) 
- [**986**星][3y] [JS] [yahoo/xss-filters](https://github.com/YahooArchive/xss-filters) 
- [**731**星][3y] [masatokinugawa/filterbypass](https://github.com/masatokinugawa/filterbypass) 浏览器XSS 过滤绕过清单
- [**724**星][3y] [C++] [ionescu007/lxss](https://github.com/ionescu007/lxss) Win10 Linux 子系统相关
- [**705**星][2m] [JS] [mandatoryprogrammer/xsshunter](https://github.com/mandatoryprogrammer/xsshunter) 
- [**683**星][18d] [C#] [mganss/htmlsanitizer](https://github.com/mganss/htmlsanitizer) 
- [**674**星][21d] [PHP] [ssl/ezxss](https://github.com/ssl/ezxss) 
- [**638**星][10m] [HTML] [bl4de/security_whitepapers](https://github.com/bl4de/security_whitepapers) 
- [**539**星][2y] [Py] [bsmali4/xssfork](https://github.com/bsmali4/xssfork) 新一代xss漏洞探测工具
- [**504**星][4m] [Py] [opensec-cn/vtest](https://github.com/opensec-cn/vtest) 
- [**495**星][4m] [PHP] [nettitude/xss_payloads](https://github.com/nettitude/xss_payloads) 
- [**477**星][1y] [JS] [koto/xsschef](https://github.com/koto/xsschef) 
- [**460**星][12m] [C] [laruence/taint](https://github.com/laruence/taint) 
- [**411**星][2y] [JS] [evilcos/xssor](https://github.com/evilcos/xssor) 
- [**410**星][1y] [JS] [chokcoco/httphijack](https://github.com/chokcoco/httphijack) 
- [**404**星][2y] [JS] [cagataycali/xss-listener](https://github.com/cagataycali/xss-listener) 
- [**364**星][2y] [Py] [ajinabraham/owasp-xenotix-xss-exploit-framework](https://github.com/ajinabraham/owasp-xenotix-xss-exploit-framework) 
- [**334**星][12m] [Py] [varbaek/xsser](https://github.com/varbaek/xsser) 
- [**325**星][7m] [Py] [s0md3v/jshell](https://github.com/s0md3v/JShell) 
- [**315**星][2y] [Py] [c0ny1/xxe-lab](https://github.com/c0ny1/xxe-lab) 
- [**289**星][1m] [JS] [wicg/trusted-types](https://github.com/w3c/webappsec-trusted-types) 
- [**287**星][13d] [Py] [stamparm/dsxs](https://github.com/stamparm/dsxs) 
- [**286**星][13d] [PHP] [voku/anti-xss](https://github.com/voku/anti-xss) 
- [**284**星][2y] [Py] [gbrindisi/xsssniper](https://github.com/gbrindisi/xsssniper) 
- [**271**星][2y] [JS] [bugbountyforum/xss-radar](https://github.com/bugbountyforum/xss-radar) 
- [**261**星][2y] [HTML] [wisec/domxsswiki](https://github.com/wisec/domxsswiki) 
- [**251**星][3m] [PHP] [dotboris/vuejs-serverside-template-xss](https://github.com/dotboris/vuejs-serverside-template-xss) 
- [**243**星][4m] [JS] [lewisardern/bxss](https://github.com/lewisardern/bxss) 
- [**241**星][2m] [JS] [antswordproject/ant](https://github.com/antswordproject/ant) 
- [**218**星][2y] [Py] [thetwitchy/xxer](https://github.com/thetwitchy/xxer) 
- [**210**星][3y] [Py] [rajeshmajumdar/brutexss](https://github.com/rajeshmajumdar/brutexss) 
- [**201**星][4y] [Py] [gdssecurity/xxe-recursive-download](https://github.com/AonCyberLabs/xxe-recursive-download) 
- [**199**星][12m] [Go] [raz-varren/xsshell](https://github.com/raz-varren/xsshell) XSS反向Shell框架
- [**191**星][1y] [HTML] [xsscx/commodity-injection-signatures](https://github.com/xsscx/commodity-injection-signatures) 
- [**168**星][5m] [PHP] [blackhole1/webrtcxss](https://github.com/blackhole1/webrtcxss) 
- [**167**星][6y] [JS] [evilcos/xssprobe](https://github.com/evilcos/xssprobe) 
- [**158**星][10m] [HTML] [yaph/domxssscanner](https://github.com/yaph/domxssscanner) 
- [**155**星][6m] [PHP] [78778443/xssplatform](https://github.com/78778443/xssplatform) 
- [**151**星][7y] [evilcos/xss.swf](https://github.com/evilcos/xss.swf) 
- [**141**星][3y] [Py] [blackye/lalascan](https://github.com/blackye/lalascan) 
- [**140**星][6y] [Tcl] [koto/mosquito](https://github.com/koto/mosquito) 
- [**134**星][17d] [JS] [fcavallarin/domdig](https://github.com/fcavallarin/domdig) 
- [**131**星][4y] [PHP] [phith0n/xsshtml](https://github.com/phith0n/xsshtml) 
- [**128**星][3y] [HTML] [danladi/httppwnly](https://github.com/danladi/httppwnly) 
- [**122**星][3y] [JS] [salesforce/secure-filters](https://github.com/salesforce/secure-filters) 
- [**120**星][3m] [C] [matrixssl/matrixssl](https://github.com/matrixssl/matrixssl) 
- [**118**星][3m] [PHP] [spidermate/b-xssrf](https://github.com/spidermate/b-xssrf) 
- [**117**星][3m] [Ruby] [hahwul/xspear](https://github.com/hahwul/xspear) 
- [**117**星][27d] [JS] [mazen160/xless](https://github.com/mazen160/xless) 
- [**115**星][6y] [caomulaodao/xss-filter-evasion-cheat-sheet-cn](https://github.com/caomulaodao/xss-filter-evasion-cheat-sheet-cn) 
- [**115**星][5y] [JS] [hadynz/xss-keylogger](https://github.com/hadynz/xss-keylogger) 
- [**113**星][4y] [Py] [mandatoryprogrammer/xsshunter_client](https://github.com/mandatoryprogrammer/xsshunter_client) 
- [**109**星][4y] [Py] [1n3/xsstracer](https://github.com/1n3/xsstracer) 
- [**108**星][3y] [HTML] [dxa4481/xssjacking](https://github.com/dxa4481/xssjacking) 
- [**104**星][3y] [Py] [phith0n/python-xss-filter](https://github.com/phith0n/python-xss-filter) 
- [**103**星][2y] [Py] [sparksharly/dl_for_xss](https://github.com/sparksharly/dl_for_xss) 
- [**101**星][1y] [JS] [blackhole1/autofindxssandcsrf](https://github.com/blackhole1/autofindxssandcsrf) 
- [**100**星][5y] [Py] [ajinabraham/static-dom-xss-scanner](https://github.com/ajinabraham/static-dom-xss-scanner) 
- [**99**星][5y] [Java] [finn-no/xss-html-filter](https://github.com/finn-no/xss-html-filter) 
- [**97**星][3y] [Ruby] [joernchen/xxeserve](https://github.com/joernchen/xxeserve) 
- [**88**星][4y] [dantaler/detectionstring](https://github.com/dantaler/detectionstring) 
- [**86**星][3y] [Py] [yehia-mamdouh/xssya](https://github.com/yehia-mamdouh/xssya) 
- [**85**星][4y] [Java] [mauro-g/snuck](https://github.com/mauro-g/snuck) 
- [**84**星][1m] [Py] [m4cs/traxss](https://github.com/m4cs/traxss) 
- [**82**星][3y] [Py] [yehia-mamdouh/xssya-v-2.0](https://github.com/yehia-mamdouh/xssya-v-2.0) 
- [**78**星][8m] [Py] [sxcurity/230-oob](https://github.com/lc/230-OOB) 
- [**77**星][1y] [Py] [ekultek/xanxss](https://github.com/ekultek/xanxss) 
- [**77**星][3m] [Py] [menkrep1337/xsscon](https://github.com/menkrep1337/xsscon) Simple XSS Scanner tool
- [**77**星][2y] [nhoya/pastebinmarkdownxss](https://github.com/nhoya/pastebinmarkdownxss) 
- [**75**星][7y] [JS] [evilpacket/xss.io](https://github.com/evilpacket/xss.io) 
- [**74**星][6y] [l3m0n/xss-filter-evasion-cheat-sheet-cn](https://github.com/l3m0n/xss-filter-evasion-cheat-sheet-cn) 
- [**73**星][1y] [Py] [damian89/xssfinder](https://github.com/damian89/xssfinder) 
- [**72**星][2y] [Py] [ropnop/xxetimes](https://github.com/ropnop/xxetimes) 
- [**69**星][6y] [Py] [q2h1cg/xss_scan](https://github.com/Q2h1Cg/xss_scan) 
- [**65**星][5y] [Java] [ssexxe/xxebugfind](https://github.com/ssexxe/xxebugfind) 
- [**63**星][1y] [Haskell] [snoyberg/markdown](https://github.com/snoyberg/markdown) 
- [**61**星][11m] [JS] [dxa4481/xssoauthpersistence](https://github.com/dxa4481/xssoauthpersistence) 
- [**59**星][28d] [JS] [rastating/xss-chef](https://github.com/rastating/xss-chef) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload生成](#ad92f6b801a18934f1971e2512f5ae4f) |
- [**58**星][1y] [Py] [coalfire-research/sqlinator](https://github.com/coalfire-research/sqlinator) 
- [**55**星][18d] [s9mf/xss_test](https://github.com/s9mf/xss_test) 
- [**52**星][6m] [JS] [ollseg/ttt-ext](https://github.com/ollseg/ttt-ext) 
- [**45**星][7y] [JS] [sofish/imagexss.js](https://github.com/sofish/imagexss.js) 
- [**44**星][1m] [r0x4r/d4rkxss](https://github.com/r0x4r/d4rkxss) 
- [**43**星][2y] [Py] [secdec/xssmap](https://github.com/secdec/xssmap) 
- [**41**星][6y] [Py] [flyr4nk/xssscaner](https://github.com/flyr4nk/xssscaner) 
- [**40**星][3y] [PHP] [ambulong/phpmyxss](https://github.com/ambulong/phpmyxss) 
- [**40**星][3y] [PHP] [lcatro/xss-hunter](https://github.com/lcatro/xss-hunter) 
- [**40**星][4y] [JS] [moloch--/cve-2016-1764](https://github.com/moloch--/cve-2016-1764) 
- [**39**星][3y] [ActionScript] [riusksk/flashscanner](https://github.com/riusksk/flashscanner) 
- [**39**星][6y] [Py] [shadsidd/automated-xss-finder](https://github.com/shadsidd/automated-xss-finder) 
- [**38**星][3y] [PHP] [keyus/xss](https://github.com/keyus/xss) 
- [**38**星][7y] [Py] [matthewdfuller/intellifuzz-xss](https://github.com/matthewdfuller/intellifuzz-xss) 
- [**37**星][2y] [Py] [medicean/sublimexssencode](https://github.com/medicean/sublimexssencode) 
- [**37**星][1y] [Py] [neverlovelynn/chrome_headless_xss](https://github.com/neverlovelynn/chrome_headless_xss) 
- [**36**星][1y] [JS] [blackhole1/fecm](https://github.com/blackhole1/fecm) 
- [**36**星][4y] [C#] [cweb/unicode-hax](https://github.com/cweb/unicode-hax) 
- [**36**星][2y] [JS] [jamiebuilds/guarded-string](https://github.com/jamiebuilds/guarded-string) 
- [**35**星][11m] [brianwrf/cve-2018-11788](https://github.com/brianwrf/cve-2018-11788) 
- [**35**星][3y] [JS] [yxhsea/xss](https://github.com/yxhsea/xss) 
- [**33**星][2m] [JS] [digitalinterruption/vulnerable-xss-app](https://github.com/digitalinterruption/vulnerable-xss-app) 
- [**33**星][7m] [Ruby] [k8gege/zimbraexploit](https://github.com/k8gege/zimbraexploit) 
- [**32**星][4m] [Py] [jasonhinds13/hackable](https://github.com/jasonhinds13/hackable) 
- [**31**星][1y] [JS] [akalankauk/foxss-xss-penetration-testing-tool](https://github.com/akalankauk/foxss-xss-penetration-testing-tool) 
- [**31**星][1m] [HTML] [egebalci/xss-flare](https://github.com/egebalci/xss-flare) 
- [**30**星][1y] [Py] [aurainfosec/xss_payloads](https://github.com/aurainfosec/xss_payloads) XSS payloads for edge cases
- [**30**星][4y] [dhamuharker/xss-](https://github.com/dhamuharker/xss-) 
- [**30**星][4y] [PHP] [echo-devim/xbackdoor](https://github.com/echo-devim/xbackdoor) 
- [**30**星][1y] [karelorigin/xss-problems](https://github.com/karelorigin/xss-problems) 
- [**29**星][5m] [hahwul/xss-payload-without-anything](https://github.com/hahwul/xss-payload-without-anything) 
- [**27**星][9m] [HTML] [cainiaocome/xssgun](https://github.com/cainiaocome/xssgun) 
- [**27**星][6y] [C] [gwroblew/detectxsslib](https://github.com/gwroblew/detectxsslib) 
- [**27**星][9m] [Py] [xajkep/xpt](https://github.com/xajkep/xpt) 
- [**26**星][6m] [CSS] [hackeryunen/django-xss-platform](https://github.com/hackeryunen/django-xss-platform) 
- [**26**星][3y] [Py] [toxic-ig/sql-xss](https://github.com/toxic-ig/sql-xss) 
    - 重复区段: [工具/数据库&&SQL攻击&&SQL注入/SQL/未分类-SQL](#1cfe1b2a2c88cd92a414f81605c8d8e7) |
- [**25**星][5y] [Go] [rverton/xssmap](https://github.com/rverton/xssmap) 
- [**25**星][3y] [PHP] [symphonycms/xssfilter](https://github.com/symphonycms/xssfilter) 
- [**24**星][23d] [Py] [mhaskar/xssradare](https://github.com/mhaskar/xssradare) 
- [**23**星][1y] [JS] [0xsobky/xssbuster](https://github.com/0xsobky/xssbuster) 
- [**23**星][2m] [JS] [devwerks/xss-cheatsheet](https://github.com/devwerks/xss-cheatsheet) 
- [**23**星][4y] [Py] [immunio/immunio-xss-fuzzer](https://github.com/immunio/immunio-xss-fuzzer) 
- [**23**星][4y] [JS] [rwestergren/simple-hash-xss](https://github.com/rwestergren/simple-hash-xss) 
- [**23**星][2y] [Java] [techguy-bhushan/xssrequestfilters](https://github.com/techguy-bhushan/xssrequestfilters) 
- [**23**星][1y] [Py] [the404hacking/xsscan](https://github.com/the404hacking/xsscan) 
- [**23**星][3y] [Py] [ptonewreckin/blindref](https://github.com/ptonewreckin/blindref) 
- [**22**星][3y] [PHP] [0x584a/fuzzxssphp](https://github.com/0x584a/fuzzxssphp) 
- [**22**星][6y] [C#] [brandonprry/vulnerable_xxe](https://github.com/brandonprry/vulnerable_xxe) 
- [**22**星][3y] [JS] [techgaun/xss-payloads](https://github.com/techgaun/xss-payloads) 
- [**21**星][3y] [55-aa/cve-2015-0057](https://github.com/55-aa/cve-2015-0057) 
- [**16**星][4y] [lucabongiorni/xss.png](https://github.com/lucabongiorni/xss.png) 




### <a id="f799ff186643edfcf7ac1e94f08ba018"></a>知名漏洞&&CVE&&特定产品


#### <a id="309751ccaee413cbf35491452d80480f"></a>未分类


- [**1266**星][2y] [Py] [worawit/ms17-010](https://github.com/worawit/ms17-010) 
- [**1066**星][28d] [Go] [neex/phuip-fpizdam](https://github.com/neex/phuip-fpizdam) 
- [**886**星][1y] [Py] [nixawk/labs](https://github.com/nixawk/labs) 漏洞分析实验室。包含若干CVE 漏洞（CVE-2016-6277、CVE-2017-5689…）
- [**728**星][2y] [Py] [toolswatch/vfeed](https://github.com/toolswatch/vfeed) 
- [**601**星][1y] [C] [scottybauer/android_kernel_cve_pocs](https://github.com/scottybauer/android_kernel_cve_pocs) 
- [**598**星][2y] [Py] [bhdresh/cve-2017-0199](https://github.com/bhdresh/cve-2017-0199) 
- [**562**星][10m] [Py] [fs0c131y/esfileexploreropenportvuln](https://github.com/fs0c131y/esfileexploreropenportvuln) 
- [**544**星][4y] [Py] [fjserna/cve-2015-7547](https://github.com/fjserna/cve-2015-7547) 
- [**456**星][3m] [Py] [blacknbunny/libssh-authentication-bypass](https://github.com/blacknbunny/CVE-2018-10933) 
- [**454**星][2y] [Py] [embedi/cve-2017-11882](https://github.com/embedi/cve-2017-11882) 
- [**449**星][6m] [Py] [n1xbyte/cve-2019-0708](https://github.com/n1xbyte/cve-2019-0708) 
- [**419**星][4y] [Shell] [imagetragick/pocs](https://github.com/imagetragick/pocs) 
- [**417**星][1y] [C++] [unamer/cve-2018-8120](https://github.com/unamer/cve-2018-8120) 
- [**406**星][2y] [Py] [ridter/cve-2017-11882](https://github.com/ridter/cve-2017-11882) 
- [**395**星][2y] [Py] [ezelf/cve-2018-9995_dvr_credentials](https://github.com/ezelf/cve-2018-9995_dvr_credentials) 
- [**394**星][9m] [Ruby] [dreadlocked/drupalgeddon2](https://github.com/dreadlocked/drupalgeddon2) 
- [**389**星][4y] [Objective-C] [kpwn/tpwn](https://github.com/kpwn/tpwn) 
- [**371**星][1y] [Py] [rhynorater/cve-2018-15473-exploit](https://github.com/rhynorater/cve-2018-15473-exploit) 
- [**370**星][9m] [Py] [wyatu/cve-2018-20250](https://github.com/wyatu/cve-2018-20250) 
- [**357**星][9m] [Go] [frichetten/cve-2019-5736-poc](https://github.com/frichetten/cve-2019-5736-poc) 
- [**350**星][2y] [C++] [can1357/cve-2018-8897](https://github.com/can1357/cve-2018-8897) 
- [**348**星][2y] [Py] [mazen160/struts-pwn](https://github.com/mazen160/struts-pwn) struts-pwn：Apache Struts CVE-2017-5638 漏洞利用
- [**339**星][1m] [PHP] [opsxcq/exploit-cve-2016-10033](https://github.com/opsxcq/exploit-cve-2016-10033) 
- [**328**星][2y] [Py] [cyberheartmi9/cve-2017-12617](https://github.com/cyberheartmi9/cve-2017-12617) 
- [**327**星][4y] [C#] [koczkatamas/cve-2016-0051](https://github.com/koczkatamas/cve-2016-0051) 
- [**318**星][8m] [Py] [a2u/cve-2018-7600](https://github.com/a2u/cve-2018-7600) 
- [**300**星][10m] [Py] [basucert/winboxpoc](https://github.com/basucert/winboxpoc) 
- [**299**星][1y] [Py] [bhdresh/cve-2017-8759](https://github.com/bhdresh/cve-2017-8759) 
- [**299**星][27d] [Py] [rhinosecuritylabs/cves](https://github.com/rhinosecuritylabs/cves) 
- [**282**星][4m] [Py] [lufeirider/cve-2019-2725](https://github.com/lufeirider/cve-2019-2725) 
- [**281**星][1y] [Py] [mazen160/struts-pwn_cve-2018-11776](https://github.com/mazen160/struts-pwn_cve-2018-11776) 
- [**280**星][4m] [marcinguy/cve-2019-2107](https://github.com/marcinguy/cve-2019-2107) 
- [**276**星][11m] [Py] [wyatu/cve-2018-8581](https://github.com/wyatu/cve-2018-8581) 
- [**269**星][5m] [Py] [ridter/exchange2domain](https://github.com/ridter/exchange2domain) 
- [**268**星][3y] [C] [laginimaineb/extractkeymaster](https://github.com/laginimaineb/extractkeymaster) 
- [**259**星][1y] [C++] [alpha1ab/cve-2018-8120](https://github.com/alpha1ab/cve-2018-8120) 
- [**256**星][2y] [voulnet/cve-2017-8759-exploit-sample](https://github.com/voulnet/cve-2017-8759-exploit-sample) 
- [**254**星][2y] [Py] [unamer/cve-2017-11882](https://github.com/unamer/cve-2017-11882) 
- [**253**星][1m] [C] [a2nkf/macos-kernel-exploit](https://github.com/a2nkf/macos-kernel-exploit) 
- [**253**星][1y] [C] [v-e-o/poc](https://github.com/v-e-o/poc) 
- [**252**星][29d] [Vue] [nluedtke/linux_kernel_cves](https://github.com/nluedtke/linux_kernel_cves) 
- [**251**星][2y] [C] [hfiref0x/cve-2015-1701](https://github.com/hfiref0x/cve-2015-1701) 
- [**248**星][2y] [C] [dosomder/iovyroot](https://github.com/dosomder/iovyroot) 
- [**247**星][2y] [Py] [rxwx/cve-2018-0802](https://github.com/rxwx/cve-2018-0802) 
- [**244**星][3y] [C] [hyln9/vikiroot](https://github.com/hyln9/vikiroot) 
- [**243**星][3m] [Shell] [projectzeroindia/cve-2019-11510](https://github.com/projectzeroindia/cve-2019-11510) 
- [**238**星][8m] [JS] [exodusintel/cve-2019-5786](https://github.com/exodusintel/cve-2019-5786) 
- [**238**星][1y] [Py] [preempt/credssp](https://github.com/preempt/credssp) CVE-2018-0886(Windows CredSSP协议验证过程中的RCE漏洞)PoC
- [**237**星][3y] [Shell] [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh) 
- [**237**星][10m] [C] [geosn0w/osirisjailbreak12](https://github.com/geosn0w/osirisjailbreak12) 
- [**234**星][9m] [JS] [adamyordan/cve-2019-1003000-jenkins-rce-poc](https://github.com/adamyordan/cve-2019-1003000-jenkins-rce-poc) 
- [**226**星][2y] [Py] [mazen160/struts-pwn_cve-2017-9805](https://github.com/mazen160/struts-pwn_cve-2017-9805) 
- [**225**星][2y] [Py] [fortunec00kie/bug-monitor](https://github.com/fortunec00kie/bug-monitor) 
- [**219**星][2y] [Py] [artkond/cisco-snmp-rce](https://github.com/artkond/cisco-snmp-rce) Cisco SNMP 服务 REC 漏洞 PoC(CVE-2017-6736)
- [**214**星][2y] [C] [opsxcq/exploit-cve-2017-7494](https://github.com/opsxcq/exploit-cve-2017-7494) 
- [**211**星][12m] [Py] [evict/poc_cve-2018-1002105](https://github.com/evict/poc_cve-2018-1002105) 
- [**206**星][2y] [Py] [danigargu/explodingcan](https://github.com/danigargu/explodingcan) Python 版本的CVE-2017-7269 漏洞利用代码. NSA 泄露工具中的 ExplodingCan 即是利用此漏洞
- [**203**星][8m] [C++] [rogue-kdc/cve-2019-0841](https://github.com/rogue-kdc/cve-2019-0841) 
- [**200**星][1y] [C] [bazad/blanket](https://github.com/bazad/blanket) 
- [**200**星][2m] [Go] [kotakanbe/go-cve-dictionary](https://github.com/kotakanbe/go-cve-dictionary) 
- [**196**星][2y] [C] [saaramar/execve_exploit](https://github.com/saaramar/execve_exploit) 
- [**193**星][2y] [Py] [f3d0x0/gpon](https://github.com/f3d0x0/gpon) 
- [**192**星][4m] [C] [jas502n/cve-2019-13272](https://github.com/jas502n/cve-2019-13272) 
- [**190**星][12m] [Go] [gravitational/cve-2018-1002105](https://github.com/gravitational/cve-2018-1002105) 
- [**189**星][4y] [Py] [jduck/cve-2015-1538-1](https://github.com/jduck/cve-2015-1538-1) 
- [**189**星][2y] [C] [nongiach/cve](https://github.com/nongiach/cve) 
- [**188**星][9m] [Py] [mpgn/cve-2019-0192](https://github.com/mpgn/cve-2019-0192) 
- [**187**星][3m] [Py] [milo2012/cve-2018-13379](https://github.com/milo2012/cve-2018-13379) 
- [**186**星][6y] [C] [saelo/cve-2014-0038](https://github.com/saelo/cve-2014-0038) 
- [**183**星][2y] [Py] [joxeankoret/cve-2017-7494](https://github.com/joxeankoret/cve-2017-7494) 
- [**181**星][10m] [Py] [0x27/ciscorv320dump](https://github.com/0x27/ciscorv320dump) 
- [**173**星][9m] [HTML] [cryptogenic/ps4-6.20-webkit-code-execution-exploit](https://github.com/cryptogenic/ps4-6.20-webkit-code-execution-exploit) 
- [**172**星][5m] [JS] [0vercl0k/cve-2019-9810](https://github.com/0vercl0k/cve-2019-9810) 
- [**171**星][9m] [Shell] [lcashdol/exploits](https://github.com/lcashdol/exploits) 
- [**171**星][2y] [vysecurity/cve-2017-8759](https://github.com/vysecurity/CVE-2017-8759) 
- [**170**星][2y] [Py] [omri9741/cve-2017-7494](https://github.com/omri9741/cve-2017-7494) Samba 漏洞（CVE-2017-7494）PoC
- [**170**星][10m] [C] [q3k/cve-2019-5736-poc](https://github.com/q3k/cve-2019-5736-poc) 
- [**169**星][4y] [Go] [filosottile/cve-2016-2107](https://github.com/filosottile/cve-2016-2107) 
- [**169**星][6m] [C] [kira-cxy/qemu-vm-escape](https://github.com/kira-cxy/qemu-vm-escape)  an exploit for CVE-2019-6778
- [**168**星][11m] [Py] [ridter/cve-2018-15982_exp](https://github.com/ridter/cve-2018-15982_exp) 
- [**166**星][2y] [C++] [bigric3/cve-2018-8120](https://github.com/bigric3/cve-2018-8120) 
- [**164**星][1y] [Dockerfile] [kozmic/laravel-poc-cve-2018-15133](https://github.com/kozmic/laravel-poc-cve-2018-15133) 
- [**162**星][2y] [Py] [rxwx/cve-2017-8570](https://github.com/rxwx/cve-2017-8570) 
- [**158**星][3y] [Py] [artkond/cisco-rce](https://github.com/artkond/cisco-rce) 
- [**157**星][6m] [Batchfile] [pyn3rd/cve-2019-0232](https://github.com/pyn3rd/cve-2019-0232) 
- [**157**星][6m] [Py] [yassineaboukir/cve-2018-0296](https://github.com/yassineaboukir/cve-2018-0296) 
- [**156**星][2y] [PHP] [bo0om/cve-2017-5124](https://github.com/bo0om/cve-2017-5124) 
- [**153**星][6m] [Objective-C] [chichou/sploits](https://github.com/chichou/sploits) CVE-2018-4310 
- [**152**星][2y] [Ruby] [0x09al/cve-2018-8174-msf](https://github.com/0x09al/cve-2018-8174-msf) 
- [**150**星][1m] [Scala] [albuch/sbt-dependency-check](https://github.com/albuch/sbt-dependency-check) 
- [**150**星][3y] [C++] [gbonacini/cve-2016-5195](https://github.com/gbonacini/cve-2016-5195) 
- [**146**星][3y] [Py] [risksense-ops/cve-2016-6366](https://github.com/risksense-ops/cve-2016-6366) 
- [**146**星][1y] [JS] [saelo/cve-2018-4233](https://github.com/saelo/cve-2018-4233) 
- [**143**星][8m] [mpgn/cve-2019-5418](https://github.com/mpgn/cve-2019-5418) 
- [**143**星][3y] [HTML] [secmob/badkernel](https://github.com/secmob/badkernel) 
- [**141**星][2y] [Py] [ridter/rtf_11882_0802](https://github.com/ridter/rtf_11882_0802) 
- [**140**星][5y] [Java] [retme7/cve-2014-7911_poc](https://github.com/retme7/cve-2014-7911_poc) 
- [**139**星][3y] [C] [clearlinux/cve-check-tool](https://github.com/clearlinux/cve-check-tool) 
- [**137**星][2m] [Py] [frint0/mass-pwn-vbulletin](https://github.com/frint0/mass-pwn-vbulletin) 
- [**137**星][2y] [greymd/cve-2017-1000117](https://github.com/greymd/cve-2017-1000117) 
- [**137**星][5m] [Py] [ridter/cve-2019-1040](https://github.com/ridter/cve-2019-1040) 
- [**134**星][1y] [Py] [soledad208/cve-2018-10933](https://github.com/soledad208/cve-2018-10933) 
- [**134**星][8m] [Py] [yt1g3r/cve-2019-3396_exp](https://github.com/yt1g3r/cve-2019-3396_exp) 
- [**133**星][3m] [Py] [hannob/optionsbleed](https://github.com/hannob/optionsbleed)  a proof of concept code to test for the Optionsbleed bug in Apache httpd (CVE-2017-9798)
- [**132**星][3y] [HTML] [theori-io/chakra-2016-11](https://github.com/theori-io/chakra-2016-11) 
- [**130**星][7m] [Py] [jas502n/cve-2019-2618](https://github.com/jas502n/cve-2019-2618) 
- [**127**星][4y] [C] [fi01/cve-2015-3636](https://github.com/fi01/cve-2015-3636) 
- [**126**星][3m] [Java] [shack2/javaserializetools](https://github.com/shack2/javaserializetools) 
- [**125**星][1y] [Py] [pyn3rd/cve-2018-3245](https://github.com/pyn3rd/cve-2018-3245) 
- [**124**星][1y] [Py] [c0mmand3ropsec/cve-2017-10271](https://github.com/c0mmand3ropsec/cve-2017-10271) 
- [**123**星][1y] [TeX] [maxking/linux-vulnerabilities-10-years](https://github.com/maxking/linux-vulnerabilities-10-years) 
- [**118**星][3y] [C] [timwr/cve-2014-3153](https://github.com/timwr/cve-2014-3153) 
- [**117**星][1y] [Py] [yt1g3r/cve-2018-8174_exp](https://github.com/yt1g3r/cve-2018-8174_exp) 
- [**116**星][8m] [C++] [ze0r/cve-2018-8639-exp](https://github.com/ze0r/cve-2018-8639-exp) 
- [**115**星][2y] [C] [c0d3z3r0/sudo-cve-2017-1000367](https://github.com/c0d3z3r0/sudo-cve-2017-1000367) 
- [**114**星][1y] [C] [jas502n/cve-2018-17182](https://github.com/jas502n/cve-2018-17182) 
- [**114**星][1y] [Py] [landgrey/cve-2018-2894](https://github.com/landgrey/cve-2018-2894) 
- [**114**星][8m] [C#] [linhlhq/cve-2019-0604](https://github.com/linhlhq/cve-2019-0604) 
- [**113**星][2y] [JS] [fsecurelabs/cve-2018-4121](https://github.com/FSecureLABS/CVE-2018-4121) 
- [**112**星][1y] [Py] [victims/victims-cve-db](https://github.com/victims/victims-cve-db) 
- [**111**星][1y] [Py] [hook-s3c/cve-2018-11776-python-poc](https://github.com/hook-s3c/cve-2018-11776-python-poc) 
- [**111**星][8m] [HTML] [xuechiyaobai/cve-2017-7092-poc](https://github.com/xuechiyaobai/CVE-2017-7092-PoC) 
- [**109**星][2m] [C++] [barakat/cve-2019-16098](https://github.com/barakat/cve-2019-16098) 
- [**108**星][6m] [Py] [leoid/cve-2019-0708](https://github.com/leoid/cve-2019-0708) 
- [**108**星][9m] [Py] [mpgn/cve-2019-7238](https://github.com/mpgn/cve-2019-7238) 
- [**108**星][3y] [HTML] [theori-io/cve-2016-0189](https://github.com/theori-io/cve-2016-0189) 
- [**107**星][6m] [Java] [c0d3p1ut0s/cve-2019-12086-jackson-databind-file-read](https://github.com/c0d3p1ut0s/cve-2019-12086-jackson-databind-file-read) 
- [**107**星][2y] [Java] [realbearcat/oracle-weblogic-cve-2017-10271](https://github.com/RealBearcat/Oracle-WebLogic-CVE-2017-10271) 
- [**106**星][2y] [Java] [caledoniaproject/cve-2018-1270](https://github.com/caledoniaproject/cve-2018-1270) 
- [**106**星][1y] [HTML] [lz1y/cve-2018-8420](https://github.com/lz1y/cve-2018-8420) 
- [**105**星][2y] [Py] [anbai-inc/cve-2018-4878](https://github.com/anbai-inc/cve-2018-4878) 
- [**105**星][2y] [Py] [kkirsche/cve-2017-10271](https://github.com/kkirsche/cve-2017-10271) 
- [**103**星][1y] [C++] [nmulasmajic/syscall_exploit_cve-2018-8897](https://github.com/nmulasmajic/syscall_exploit_cve-2018-8897) 
- [**103**星][4y] [C++] [secmob/pocforcve-2015-1528](https://github.com/secmob/pocforcve-2015-1528) 
- [**103**星][2y] [Java] [secureskytechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095](https://github.com/secureskytechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095) 
- [**102**星][1y] [C++] [cbayet/exploit-cve-2017-6008](https://github.com/cbayet/exploit-cve-2017-6008) 
- [**102**星][2m] [C#] [padovah4ck/cve-2019-1253](https://github.com/padovah4ck/cve-2019-1253) 
- [**102**星][3y] [Py] [violentshell/rover](https://github.com/violentshell/rover) 
- [**101**星][12m] [Go] [milo2012/cve-2018-0296](https://github.com/milo2012/cve-2018-0296) 
- [**100**星][3m] [Py] [0xdezzy/cve-2019-11539](https://github.com/0xdezzy/cve-2019-11539) 
- [**100**星][2y] [C] [hc0d3r/sudohulk](https://github.com/hc0d3r/sudohulk) 使用ptraceHook系统调用execve, 监控并修改sudo命令的参数
- [**99**星][17d] [Py] [adulau/cve-search](https://github.com/adulau/cve-search) 
- [**99**星][1y] [C#] [atredispartners/cve-2018-0952-systemcollector](https://github.com/atredispartners/cve-2018-0952-systemcollector) 
- [**99**星][2y] [Py] [g0rx/cve-2018-7600-drupal-rce](https://github.com/g0rx/cve-2018-7600-drupal-rce) 
- [**98**星][4m] [Shell] [trimstray/massh-enum](https://github.com/trimstray/massh-enum) 
- [**96**星][3m] [Py] [milo2012/cve-2018-13382](https://github.com/milo2012/cve-2018-13382) 
- [**94**星][3y] [Ruby] [zcgonvh/cve-2017-7269](https://github.com/zcgonvh/cve-2017-7269) cve-2017-7269：修订版msf模块
- [**93**星][2y] [C] [hdm/juniper-cve-2015-7755](https://github.com/hdm/juniper-cve-2015-7755) 
- [**93**星][2y] [Java] [tdy218/ysoserial-cve-2018-2628](https://github.com/tdy218/ysoserial-cve-2018-2628) 
- [**93**星][10m] [C++] [ze0r/cve-2018-8453-exp](https://github.com/ze0r/cve-2018-8453-exp) 
- [**90**星][2y] [nccgroup/cve-2017-8759](https://github.com/nccgroup/cve-2017-8759) 
- [**90**星][1y] [C] [renorobert/virtualbox-cve-2018-2844](https://github.com/renorobert/virtualbox-cve-2018-2844) 
- [**89**星][5y] [C] [retme7/cve-2014-4322_poc](https://github.com/retme7/cve-2014-4322_poc) 
- [**88**星][6m] [C++] [adalenv/cve-2019-0708-tool](https://github.com/adalenv/cve-2019-0708-tool) 
- [**87**星][4y] [JS] [bishopfox/cve-2016-1764](https://github.com/bishopfox/cve-2016-1764) 
- [**85**星][4m] [Py] [balika011/selfblow](https://github.com/balika011/selfblow) 
- [**85**星][1y] [Py] [pyn3rd/cve-2018-3191](https://github.com/pyn3rd/cve-2018-3191) 
- [**83**星][3y] [C] [laginimaineb/cve-2015-6639](https://github.com/laginimaineb/cve-2015-6639) 
- [**83**星][7y] [C] [realtalk/cve-2013-2094](https://github.com/realtalk/cve-2013-2094) 
- [**82**星][4y] [C] [abdsec/cve-2016-0801](https://github.com/abdsec/cve-2016-0801) 
- [**82**星][1y] [Dockerfile] [hackerhouse-opensource/cve-2018-10933](https://github.com/hackerhouse-opensource/cve-2018-10933) 
- [**82**星][2y] [Py] [lz1y/cve-2017-8759](https://github.com/lz1y/cve-2017-8759) 
- [**81**星][3y] [C] [derrekr/android_security](https://github.com/derrekr/android_security) 
- [**81**星][12m] [Py] [r3dxpl0it/apache-superset-remote-code-execution-poc-cve-2018-8021](https://github.com/r3dxpl0it/apache-superset-remote-code-execution-poc-cve-2018-8021) 
- [**80**星][1y] [Py] [lcatro/cve-2017-7269-echo-poc](https://github.com/lcatro/cve-2017-7269-echo-poc) 
- [**80**星][9m] [Java] [yunxu1/jboss-_cve-2017-12149](https://github.com/yunxu1/jboss-_cve-2017-12149) 
- [**79**星][4y] [C] [gdbinit/mach_race](https://github.com/gdbinit/mach_race) 
- [**78**星][10m] [Py] [fs0c131y/cve-2018-20555](https://github.com/fs0c131y/cve-2018-20555) 
- [**78**星][6y] [Go] [gabrielg/cve-2014-1266-poc](https://github.com/gabrielg/cve-2014-1266-poc) 
- [**78**星][21d] [Java] [jenkinsci/dependency-check-plugin](https://github.com/jenkinsci/dependency-check-plugin) 
- [**78**星][1y] [Py] [pyn3rd/cve-2018-2893](https://github.com/pyn3rd/cve-2018-2893) 
- [**77**星][3y] [C] [jndok/pegasusx](https://github.com/jndok/pegasusx) 
- [**76**星][2y] [Py] [tezukanice/office8570](https://github.com/tezukanice/office8570) 
- [**76**星][3y] [C#] [zcgonvh/cve-2017-7269-tool](https://github.com/zcgonvh/cve-2017-7269-tool) 
- [**76**星][3y] [C++] [fsecurelabs/cve-2016-7255](https://github.com/FSecureLABS/CVE-2016-7255) 
- [**75**星][3y] [C] [viralsecuritygroup/knoxout](https://github.com/viralsecuritygroup/knoxout) 
- [**74**星][12m] [foolmitah/cve-2018-14729](https://github.com/foolmitah/cve-2018-14729) 
- [**74**星][24d] [Py] [jas502n/cve-2019-3396](https://github.com/jas502n/cve-2019-3396) 
- [**74**星][10m] [Shell] [ttffdd/xbadmanners](https://github.com/ttffdd/xbadmanners) 
- [**73**星][9m] [C++] [doublelabyrinth/sdokeycrypt-sys-local-privilege-elevation](https://github.com/doublelabyrinth/sdokeycrypt-sys-local-privilege-elevation) 
- [**73**星][2y] [JS] [mtjailed/unjailme](https://github.com/mtjailed/unjailme) 
- [**72**星][1m] [C] [awakened1712/cve-2019-11932](https://github.com/awakened1712/cve-2019-11932) 
- [**72**星][5m] [Py] [cve-search/via4cve](https://github.com/cve-search/via4cve) 
- [**72**星][5y] [Py] [feliam/cve-2014-4377](https://github.com/feliam/cve-2014-4377) 
- [**72**星][2y] [Py] [skelsec/cve-2017-12542](https://github.com/skelsec/cve-2017-12542) 
- [**72**星][3y] [C++] [zcgonvh/ms16-032](https://github.com/zcgonvh/ms16-032) 
- [**70**星][4y] [C++] [laginimaineb/cve-2014-7920-7921](https://github.com/laginimaineb/cve-2014-7920-7921) 
- [**70**星][2y] [C++] [nmulasmajic/cve-2018-8897](https://github.com/nmulasmajic/cve-2018-8897) 
- [**70**星][3y] [JS] [saelo/jscpwn](https://github.com/saelo/jscpwn) 
- [**69**星][6m] [Py] [biggerwing/cve-2019-0708-poc](https://github.com/biggerwing/cve-2019-0708-poc) 
- [**69**星][2y] [C] [hfiref0x/stryker](https://github.com/hfiref0x/stryker) 
- [**69**星][9m] [Dockerfile] [rancher/runc-cve](https://github.com/rancher/runc-cve) 
- [**68**星][1y] [Py] [shengqi158/cve-2018-2628](https://github.com/shengqi158/cve-2018-2628) 
- [**68**星][2y] [Py] [zldww2011/cve-2018-0802_poc](https://github.com/zldww2011/cve-2018-0802_poc) 
- [**67**星][2y] [abazhaniuk/publications](https://github.com/abazhaniuk/publications) 
- [**67**星][3m] [JS] [cveproject/automation-working-group](https://github.com/cveproject/automation-working-group) 
- [**67**星][6m] [JS] [exodusintel/cve-2019-0808](https://github.com/exodusintel/cve-2019-0808) 
- [**67**星][10m] [Objective-C] [synacktiv-contrib/cve-2018-4193](https://github.com/Synacktiv-contrib/CVE-2018-4193) 
- [**67**星][2y] [vysecurity/cve-2018-4878](https://github.com/vysecurity/CVE-2018-4878) 
- [**66**星][11m] [C] [0x36/cve-pocs](https://github.com/0x36/cve-pocs) 
- [**66**星][3y] [Py] [circl/cve-portal](https://github.com/circl/cve-portal) 
- [**66**星][1y] [C++] [codewhitesec/unmarshalpwn](https://github.com/codewhitesec/unmarshalpwn) 
- [**66**星][2y] [Py] [firefart/cve-2018-7600](https://github.com/firefart/cve-2018-7600) 
- [**66**星][2m] [Py] [jas502n/cve-2018-2628](https://github.com/jas502n/cve-2018-2628) 
- [**66**星][2m] [PHP] [markri/wp-sec](https://github.com/markri/wp-sec) 
- [**66**星][2y] [Shell] [opsxcq/exploit-cve-2014-6271](https://github.com/opsxcq/exploit-cve-2014-6271) 
- [**66**星][12m] [Java] [pyn3rd/cve-2018-3252](https://github.com/pyn3rd/cve-2018-3252) 
- [**66**星][14d] [Ruby] [spiderlabs/cve_server](https://github.com/spiderlabs/cve_server) 
- [**65**星][3y] [redhatproductsecurity/cve-howto](https://github.com/redhatproductsecurity/cve-howto) 
- [**65**星][2y] [Py] [temesgeny/ppsx-file-generator](https://github.com/temesgeny/ppsx-file-generator) 
- [**64**星][2y] [Java] [realbearcat/s2-055](https://github.com/RealBearcat/S2-055) 
- [**64**星][7m] [Py] [s0md3v/shiva](https://github.com/s0md3v/Shiva) 
- [**61**星][2y] [breaktoprotect/cve-2017-12615](https://github.com/breaktoprotect/cve-2017-12615) 
- [**61**星][5m] [C] [maldiohead/cve-2019-6207](https://github.com/maldiohead/cve-2019-6207) 
- [**61**星][4y] [HTML] [payatu/cve-2015-6086](https://github.com/payatu/cve-2015-6086) 
- [**61**星][3y] [Lua] [waffles-2/sambacry](https://github.com/waffles-2/sambacry) 
- [**60**星][1y] [Py] [anbai-inc/cve-2018-2893](https://github.com/anbai-inc/cve-2018-2893) 
- [**60**星][4y] [Py] [hood3drob1n/cve-2016-3714](https://github.com/hood3drob1n/cve-2016-3714) 
- [**60**星][6m] [Py] [jas502n/cve-2019-6340](https://github.com/jas502n/cve-2019-6340) 
- [**60**星][2y] [Py] [pimps/cve-2018-7600](https://github.com/pimps/cve-2018-7600) 
- [**60**星][2y] [Py] [wazehell/cve-2018-6389](https://github.com/wazehell/cve-2018-6389) 
- [**60**星][1m] [Py] [landgrey/cve-2019-7609](https://github.com/landgrey/cve-2019-7609) 
- [**59**星][1y] [Py] [gunnerstahl/jqshell](https://github.com/gunnerstahl/jqshell) 
- [**59**星][4m] [Py] [jas502n/cve-2019-11580](https://github.com/jas502n/cve-2019-11580) 
- [**59**星][5y] [Objective-C] [kpwn/vpwn](https://github.com/kpwn/vpwn) 
- [**59**星][4y] [C] [robertdavidgraham/cve-2015-5477](https://github.com/robertdavidgraham/cve-2015-5477) 
- [**58**星][2y] [3gstudent/cve-2017-8464-exp](https://github.com/3gstudent/cve-2017-8464-exp) 
- [**58**星][6m] [C++] [explife0011/cve-2019-0803](https://github.com/explife0011/cve-2019-0803) 
- [**58**星][5y] [Go] [mikkolehtisalo/cvesync](https://github.com/mikkolehtisalo/cvesync) 
- [**58**星][1y] [C] [sourceincite/cve-2018-8440](https://github.com/sourceincite/cve-2018-8440) 
- [**58**星][3m] [C++] [vlad-tri/cve-2019-1132](https://github.com/vlad-tri/cve-2019-1132) 
- [**57**星][2y] [HTML] [bo0om/cve-2017-7089](https://github.com/bo0om/cve-2017-7089) 
- [**57**星][1y] [Shell] [cyb0r9/dvr-exploiter](https://github.com/Cyb0r9/DVR-Exploiter) 
- [**56**星][1y] [Py] [jas502n/cve-2018-3191](https://github.com/jas502n/cve-2018-3191) 
- [**56**星][2y] [Py] [mzeyong/cve-2017-13089](https://github.com/mzeyong/cve-2017-13089) 
- [**56**星][7m] [HTML] [sophoslabs/cve-2018-18500](https://github.com/sophoslabs/cve-2018-18500) 
- [**55**星][3y] [C] [bazad/physmem](https://github.com/bazad/physmem) 
- [**55**星][3y] [Py] [nonenotnull/ssrfx](https://github.com/nonenotnull/ssrfx) 
- [**55**星][9m] [Objective-C] [rani-i/bluetoothdpoc](https://github.com/rani-i/bluetoothdpoc) 
- [**53**星][5m] [Py] [bao7uo/dp_crypto](https://github.com/bao7uo/dp_crypto) 
- [**53**星][11m] [Py] [payatu/cve-2018-14442](https://github.com/payatu/cve-2018-14442) 
- [**52**星][1y] [Py] [libraggbond/cve-2018-3191](https://github.com/libraggbond/cve-2018-3191) 
- [**51**星][2m] [Shell] [bishopfox/pwn-pulse](https://github.com/bishopfox/pwn-pulse) 
- [**51**星][3y] [C] [jianqiangzhao/cve-2016-2434](https://github.com/jianqiangzhao/cve-2016-2434) 
- [**51**星][2y] [Shell] [r1b/cve-2017-13089](https://github.com/r1b/cve-2017-13089) 
- [**49**星][2y] [Shell] [alephsecurity/initroot](https://github.com/alephsecurity/initroot) 
- [**41**星][3m] [Py] [jas502n/cve-2019-7238](https://github.com/jas502n/cve-2019-7238) 
- [**38**星][2y] [Py] [jpiechowka/jenkins-cve-2016-0792](https://github.com/jpiechowka/jenkins-cve-2016-0792) 


#### <a id="33386e1e125e0653f7a3c8b8aa75c921"></a>CVE


- [**1058**星][3m] [C] [zerosum0x0/cve-2019-0708](https://github.com/zerosum0x0/cve-2019-0708) 


#### <a id="67f7ce74d12e16cdee4e52c459afcba2"></a>Spectre&&Meltdown


- [**3728**星][29d] [C] [iaik/meltdown](https://github.com/iaik/meltdown) 
- [**2999**星][2m] [Shell] [speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker) 检查 Linux 主机是否受处理器漏洞Spectre & Meltdown 的影响
- [**645**星][2y] [C] [eugnis/spectre-attack](https://github.com/eugnis/spectre-attack) 
- [**550**星][2y] [C++] [raphaelsc/am-i-affected-by-meltdown](https://github.com/raphaelsc/am-i-affected-by-meltdown) 
- [**531**星][1y] [C] [ionescu007/specucheck](https://github.com/ionescu007/specucheck) 
- [**342**星][2y] [hannob/meltdownspectre-patches](https://github.com/hannob/meltdownspectre-patches) 
- [**249**星][5m] [nsacyber/hardware-and-firmware-security-guidance](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance) 
- [**222**星][2y] [C] [lgeek/spec_poc_arm](https://github.com/lgeek/spec_poc_arm) (AArch64 硬件平台)Meltdown PoC(变种3a): 从用户模式读取所有的 ARM 系统寄存器
- [**194**星][4y] [Clojure] [clojurewerkz/meltdown](https://github.com/clojurewerkz/meltdown) 
- [**136**星][2y] [C] [gkaindl/meltdown-poc](https://github.com/gkaindl/meltdown-poc) 
- [**126**星][2y] [C++] [gitmirar/meltdown-poc](https://github.com/gitmirar/meltdown-poc) 
- [**119**星][2y] [C] [mniip/spectre-meltdown-poc](https://github.com/mniip/spectre-meltdown-poc) spectre meltdown poc
- [**79**星][2y] [Py] [viralmaniar/in-spectre-meltdown](https://github.com/viralmaniar/in-spectre-meltdown) 
- [**76**星][2y] [C] [bazad/x18-leak](https://github.com/bazad/x18-leak) 
- [**52**星][2y] [C] [gentilkiwi/spectre_meltdown](https://github.com/gentilkiwi/spectre_meltdown) 
- [**39**星][2y] [C++] [feruxmax/meltdown](https://github.com/feruxmax/meltdown) 
- [**21**星][2y] [Shell] [linuxlite/spectre-meltdown-checker-automated](https://github.com/linuxlite/spectre-meltdown-checker-automated) 


#### <a id="10baba9b8e7a2041ad6c55939cf9691f"></a>BlueKeep


- [**973**星][3m] [Py] [ekultek/bluekeep](https://github.com/ekultek/bluekeep) 
- [**633**星][6m] [C] [robertdavidgraham/rdpscan](https://github.com/robertdavidgraham/rdpscan) 
- [**303**星][4m] [Py] [algo7/bluekeep_cve-2019-0708_poc_to_exploit](https://github.com/algo7/bluekeep_cve-2019-0708_poc_to_exploit) 
- [**267**星][6m] [Py] [k8gege/cve-2019-0708](https://github.com/k8gege/cve-2019-0708) 
- [**132**星][4m] [Shell] [nccgroup/bkscan](https://github.com/nccgroup/bkscan) 
- [**96**星][3m] [Ruby] [naxg/cve_2019_0708_bluekeep_rce](https://github.com/naxg/cve_2019_0708_bluekeep_rce) 
- [**45**星][2m] [Ruby] [tintoser/bluekeep-exploit](https://github.com/tintoser/bluekeep-exploit) 


#### <a id="a6ebcba5cc1b4d2e3a72509b47b84ade"></a>Heartbleed


- [**2227**星][5y] [Go] [filosottile/heartbleed](https://github.com/filosottile/heartbleed) 
- [**569**星][4y] [Py] [musalbas/heartbleed-masstest](https://github.com/musalbas/heartbleed-masstest) 
- [**301**星][4y] [Py] [lekensteyn/pacemaker](https://github.com/lekensteyn/pacemaker) 
- [**110**星][5y] [Ruby] [sensepost/heartbleed-poc](https://github.com/sensepost/heartbleed-poc) 


#### <a id="d84e7914572f626b338beeb03ea613de"></a>DirtyCow


- [**2517**星][3y] [HTML] [dirtycow/dirtycow.github.io](https://github.com/dirtycow/dirtycow.github.io) 
- [**809**星][2y] [C] [timwr/cve-2016-5195](https://github.com/timwr/cve-2016-5195) 
- [**314**星][3y] [C] [scumjr/dirtycow-vdso](https://github.com/scumjr/dirtycow-vdso) 
- [**192**星][2y] [C] [bindecy/hugedirtycowpoc](https://github.com/bindecy/hugedirtycowpoc) 
- [**131**星][3y] [C] [jcadduono/android_external_dirtycow](https://github.com/jcadduono/android_external_dirtycow) 
- [**98**星][3y] [Shell] [gebl/dirtycow-docker-vdso](https://github.com/gebl/dirtycow-docker-vdso) 
- [**39**星][3y] [C] [arinerron/cve-2016-5195](https://github.com/arinerron/cve-2016-5195) 
- [**32**星][3y] [C] [tlgyt/dirtycowandroid](https://github.com/tlgyt/dirtycowandroid) 
- [**27**星][3y] [C] [matteoserva/dirtycow-arm32](https://github.com/matteoserva/dirtycow-arm32) 


#### <a id="dacdbd68d9ca31cee9688d6972698f63"></a>Blueborne


- [**406**星][2y] [Py] [ojasookert/cve-2017-0785](https://github.com/ojasookert/cve-2017-0785) 
- [**65**星][2y] [Py] [ojasookert/cve-2017-0781](https://github.com/ojasookert/cve-2017-0781) 
- [**26**星][2y] [Py] [alfa100001/-cve-2017-0785-blueborne-poc](https://github.com/alfa100001/-cve-2017-0785-blueborne-poc) 




### <a id="79ed781159b7865dc49ffb5fe2211d87"></a>CSRF


- [**1668**星][4m] [JS] [expressjs/csurf](https://github.com/expressjs/csurf) 
- [**951**星][4y] [pillarjs/understanding-csrf](https://github.com/pillarjs/understanding-csrf) 
- [**220**星][11m] [PHP] [paragonie/anti-csrf](https://github.com/paragonie/anti-csrf) 
- [**194**星][8m] [JS] [pillarjs/csrf](https://github.com/pillarjs/csrf) 
- [**174**星][7m] [Py] [s0md3v/bolt](https://github.com/s0md3v/bolt) 
- [**171**星][2m] [JS] [hapijs/crumb](https://github.com/hapijs/crumb) 
- [**170**星][5y] [Py] [paulsec/csrft](https://github.com/paulsec/csrft) 
- [**148**星][4m] [PHP] [mebjas/csrf-protector-php](https://github.com/mebjas/csrf-protector-php) 
- [**146**星][7m] [PHP] [dunglas/dunglasangularcsrfbundle](https://github.com/dunglas/dunglasangularcsrfbundle) 
- [**127**星][2y] [Py] [0ang3el/easycsrf](https://github.com/0ang3el/easycsrf) 
- [**127**星][2m] [JS] [electrode-io/electrode-csrf-jwt](https://github.com/electrode-io/electrode-csrf-jwt) 
- [**117**星][17d] [Java] [aramrami/owasp-csrfguard](https://github.com/aramrami/owasp-csrfguard) 
- [**106**星][2y] [Py] [mozilla/django-session-csrf](https://github.com/mozilla/django-session-csrf) 
- [**56**星][4m] [PHP] [nextras/secured-links](https://github.com/nextras/secured-links) 
- [**51**星][1y] [Py] [cytopia/crawlpy](https://github.com/cytopia/crawlpy) 
- [**51**星][1y] [Py] [tgianko/deemon](https://github.com/tgianko/deemon) 
- [**49**星][3y] [CSS] [dxa4481/whatsinmyredis](https://github.com/dxa4481/whatsinmyredis) 
- [**44**星][2y] [Py] [twtrubiks/csrf-tutorial](https://github.com/twtrubiks/csrf-tutorial) 
- [**37**星][2y] [ActionScript] [appsecco/json-flash-csrf-poc](https://github.com/appsecco/json-flash-csrf-poc) 
- [**31**星][9m] [Java] [alexatiks/spring-security-jwt-csrf](https://github.com/alexatiks/spring-security-jwt-csrf) 
- [**30**星][4y] [PHP] [ezyang/csrf-magic](https://github.com/ezyang/csrf-magic) 


### <a id="edbf1e5f4d570ed44080b30bc782c350"></a>容器&&Docker


- [**5906**星][13d] [Go] [quay/clair](https://github.com/quay/clair) 
- [**5905**星][13d] [Go] [quay/clair](https://github.com/quay/clair) clair：容器（appc、docker）漏洞静态分析工具。
- [**661**星][1y] [Shell] [c0ny1/vulstudy](https://github.com/c0ny1/vulstudy) 
- [**636**星][13d] [Go] [ullaakut/gorsair](https://github.com/ullaakut/gorsair) 
- [**602**星][6m] [Py] [eliasgranderubio/dagda](https://github.com/eliasgranderubio/dagda) Docker安全套件
- [**475**星][5m] [Go] [arminc/clair-scanner](https://github.com/arminc/clair-scanner) 
- [**332**星][6m] [Dockerfile] [mykings/docker-vulnerability-environment](https://github.com/mykings/docker-vulnerability-environment) 
- [**299**星][1y] [Dockerfile] [ston3o/docker-hacklab](https://github.com/ston3o/docker-hacklab) 
- [**268**星][1y] [Shell] [zephrfish/dockerattack](https://github.com/zephrfish/dockerattack) 
- [**265**星][2y] [Shell] [superkojiman/pwnbox](https://github.com/superkojiman/pwnbox) pwnbox：包含逆向和漏洞利用工具的Docker容器
- [**193**星][27d] [Py] [khast3x/redcloud](https://github.com/khast3x/redcloud) 
- [**167**星][1m] [TSQL] [baidu-security/app-env-docker](https://github.com/baidu-security/app-env-docker) 
- [**139**星][3y] [JS] [atiger77/dionaea](https://github.com/atiger77/dionaea) 
- [**139**星][1y] [Go] [target/portauthority](https://github.com/target/portauthority) 
- [**133**星][1y] [ellerbrock/docker-security-images](https://github.com/ellerbrock/docker-security-images) 
- [**101**星][5m] [Py] [skysider/vulnpoc](https://github.com/skysider/vulnpoc) 
- [**97**星][2y] [Go] [mxi4oyu/dockerxscan](https://github.com/mxi4oyu/dockerxscan) 
- [**78**星][10m] [Py] [phantom0301/vulcloud](https://github.com/phantom0301/vulcloud) 
- [**63**星][1y] [Shell] [bcapptain/dockernymous](https://github.com/bcapptain/dockernymous) 
- [**60**星][4y] [Py] [tycx2ry/docker_api_vul](https://github.com/tycx2ry/docker_api_vul) 
- [**34**星][1y] [Shell] [jay-johnson/owasp-jenkins](https://github.com/jay-johnson/owasp-jenkins) 
- [**24**星][26d] [Java] [jenkinsci/aqua-microscanner-plugin](https://github.com/jenkinsci/aqua-microscanner-plugin) 


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
- [**555**星][2y] [PowerShell] [411hall/jaws](https://github.com/411hall/jaws) 
- [**536**星][3y] [PHP] [dotcppfile/daws](https://github.com/dotcppfile/daws) 
- [**525**星][25d] [Ruby] [stelligent/cfn_nag](https://github.com/stelligent/cfn_nag) 
- [**490**星][16d] [Py] [salesforce/policy_sentry](https://github.com/salesforce/policy_sentry) 
- [**480**星][6m] [Py] [netflix-skunkworks/diffy](https://github.com/netflix-skunkworks/diffy) 
- [**433**星][7m] [Py] [ustayready/fireprox](https://github.com/ustayready/fireprox) 
- [**391**星][3m] [Py] [duo-labs/cloudtracker](https://github.com/duo-labs/cloudtracker) 
- [**382**星][20d] [Py] [riotgames/cloud-inquisitor](https://github.com/riotgames/cloud-inquisitor) 
- [**365**星][6m] [Py] [carnal0wnage/weirdaal](https://github.com/carnal0wnage/weirdaal) 
- [**363**星][10m] [Py] [awslabs/aws-security-automation](https://github.com/awslabs/aws-security-automation) 
- [**353**星][2y] [Py] [ustayready/credking](https://github.com/ustayready/credking) 
- [**311**星][1y] [Py] [securing/dumpsterdiver](https://github.com/securing/dumpsterdiver) 
- [**294**星][6y] [Py] [andresriancho/nimbostratus](https://github.com/andresriancho/nimbostratus) 
- [**273**星][7m] [Py] [cesar-rodriguez/terrascan](https://github.com/cesar-rodriguez/terrascan) 
- [**264**星][23d] [Py] [nccgroup/pmapper](https://github.com/nccgroup/pmapper) 
- [**244**星][2y] [Py] [mindpointgroup/cloudfrunt](https://github.com/mindpointgroup/cloudfrunt) 
- [**224**星][29d] [HCL] [nozaq/terraform-aws-secure-baseline](https://github.com/nozaq/terraform-aws-secure-baseline) 
- [**216**星][26d] [Dockerfile] [thinkst/canarytokens-docker](https://github.com/thinkst/canarytokens-docker) 
- [**213**星][2y] [Ruby] [nahamsec/lazys3](https://github.com/nahamsec/lazys3) 
- [**211**星][1y] [Py] [threatresponse/aws_ir](https://github.com/threatresponse/aws_ir) 
- [**202**星][2m] [Py] [voulnet/barq](https://github.com/voulnet/barq) The AWS Cloud Post Exploitation framework!
- [**190**星][3m] [Shell] [lateralblast/lunar](https://github.com/lateralblast/lunar) 
- [**182**星][14d] [Py] [skyscanner/lambdaguard](https://github.com/skyscanner/lambdaguard) AWS Serverless Security
- [**179**星][1y] [Py] [iagcl/watchmen](https://github.com/iagcl/watchmen) 
- [**177**星][1m] [Go] [hehnope/slurp](https://github.com/hehnope/slurp) 
- [**176**星][13d] [TypeScript] [tensult/cloud-reports](https://github.com/tensult/cloud-reports) 
- [**173**星][20d] [Go] [liamg/tfsec](https://github.com/liamg/tfsec) 
- [**164**星][17d] [Py] [skyscanner/cfripper](https://github.com/skyscanner/cfripper) 
- [**159**星][1m] [JS] [puresec/serverless-puresec-cli](https://github.com/puresec/serverless-puresec-cli) 
- [**137**星][2m] [Py] [andresriancho/enumerate-iam](https://github.com/andresriancho/enumerate-iam) 
- [**128**星][1y] [Py] [threatresponse/margaritashotgun](https://github.com/threatresponse/margaritashotgun) 
- [**119**星][1y] [nagwww/s3-leaks](https://github.com/nagwww/s3-leaks) 
- [**117**星][1y] [PHP] [gwen001/s3-buckets-finder](https://github.com/gwen001/s3-buckets-finder) 
- [**100**星][1y] [C#] [chrismaddalena/sharpcloud](https://github.com/chrismaddalena/sharpcloud) 
- [**98**星][2m] [Py] [flosell/trailscraper](https://github.com/flosell/trailscraper) 
- [**88**星][3m] [Go] [smiegles/mass3](https://github.com/smiegles/mass3) 使用DNS和一堆DNS解析器, 快速枚举预定义的AWS S3 bucket
- [**82**星][8m] [Go] [glen-mac/gogetbucket](https://github.com/glen-mac/gogetbucket) 
- [**78**星][2m] [PowerShell] [cyberark/skyark](https://github.com/cyberark/skyark) 
- [**76**星][2m] [Go] [koenrh/s3enum](https://github.com/koenrh/s3enum) 
- [**66**星][3y] [Py] [bear/s3scan](https://github.com/bear/s3scan) 
- [**60**星][8m] [Py] [jaksi/awslog](https://github.com/jaksi/awslog) 
- [**56**星][2y] [Py] [brianwarehime/insp3ctor](https://github.com/brianwarehime/insp3ctor) 
- [**51**星][2y] [Py] [disruptops/cred_scanner](https://github.com/disruptops/cred_scanner) 
- [**48**星][1y] [Py] [virtuesecurity/aws-extender-cli](https://github.com/virtuesecurity/aws-extender-cli) 
- [**43**星][17d] [Rust] [whitfin/s3-meta](https://github.com/whitfin/s3-meta) 
- [**42**星][1y] [btkrausen/aws](https://github.com/btkrausen/aws) 
- [**42**星][9m] [Py] [sendgrid/krampus](https://github.com/sendgrid/krampus) 
- [**41**星][7m] [Shell] [sonofagl1tch/awsdetonationlab](https://github.com/sonofagl1tch/awsdetonationlab) 
- [**40**星][2m] [Py] [turnerlabs/antiope](https://github.com/turnerlabs/antiope) 
- [**36**星][6y] [Ruby] [fishermansenemy/bucket_finder](https://github.com/fishermansenemy/bucket_finder) 
- [**36**星][23d] [Py] [static-flow/cloudcopy](https://github.com/static-flow/cloudcopy) 
- [**33**星][2y] [Py] [disruptops/resource-counter](https://github.com/disruptops/resource-counter) 
- [**31**星][1y] [Py] [prevade/cloudjack](https://github.com/prevade/cloudjack) 
- [**30**星][10m] [Py] [parasimpaticki/sandcastle](https://github.com/parasimpaticki/sandcastle) 
- [**28**星][1m] [Py] [duo-labs/cloudtrail-partitioner](https://github.com/duo-labs/cloudtrail-partitioner) 
- [**25**星][1y] [Py] [ansorren/gdpatrol](https://github.com/ansorren/gdpatrol) 
- [**25**星][3y] [Py] [threatresponse/mad-king](https://github.com/threatresponse/mad-king) 
- [**24**星][2y] [Shell] [jchrisfarris/aws-service-control-policies](https://github.com/jchrisfarris/aws-service-control-policies) 
- [**22**星][11m] [Py] [puresec/lambda-proxy](https://github.com/puresec/lambda-proxy) 
- [**22**星][1m] [Py] [quikko/buquikker](https://github.com/quikko/buquikker) 
- [**21**星][1y] [Py] [ucnt/aws-s3-bruteforce](https://github.com/ucnt/aws-s3-bruteforce) 
- [**15**星][15d] [Py] [sanderknape/assume](https://github.com/sanderknape/assume) 
- [**14**星][4m] [Py] [darkarnium/perimeterator](https://github.com/darkarnium/perimeterator) 
- [**12**星][1y] [asecurityteam/spacecrab](https://bitbucket.org/asecurityteam/spacecrab) 
- [**12**星][2y] [Go] [magisterquis/s3finder](https://github.com/magisterquis/s3finder) 
- [**12**星][1y] [Py] [vr00n/amazon-web-shenanigans](https://github.com/vr00n/amazon-web-shenanigans) 
- [**11**星][2y] [Py] [abhn/s3scan](https://github.com/abhn/s3scan) 
- [**9**星][2y] [Py] [securing/bucketscanner](https://github.com/securing/bucketscanner) 
- [**8**星][2y] [Go] [random-robbie/slurp](https://github.com/random-robbie/slurp) 
- [**5**星][1y] [Py] [prolsen/aws_responder](https://github.com/prolsen/aws_responder) 
- [**3**星][1y] [Py] [atticuss/bucketcat](https://github.com/atticuss/bucketcat) 
- [**2**星][3y] [Ruby] [aaparmeggiani/s3find](https://github.com/aaparmeggiani/s3find) 
- [**0**星][6m] [skyscanner/halflife](https://github.com/skyscanner/halflife) 


### <a id="88716f4591b1df2149c2b7778d15d04e"></a>Phoenix


- [**810**星][16d] [Elixir] [nccgroup/sobelow](https://github.com/nccgroup/sobelow) Phoenix 框架安全方面的静态分析工具（Phoenix  框架：支持对webUI,接口, web性能,mobile app 或 mobile browser 进行自动化测试和监控的平台）


### <a id="4fd96686a470ff4e9e974f1503d735a2"></a>Kubernetes


- [**1761**星][27d] [Py] [aquasecurity/kube-hunter](https://github.com/aquasecurity/kube-hunter) 
- [**379**星][2m] [Shell] [kabachook/k8s-security](https://github.com/kabachook/k8s-security) 


### <a id="786201db0bcc40fdf486cee406fdad31"></a>Azure


- [**173**星][2y] [PowerShell] [fsecurelabs/azurite](https://github.com/FSecureLABS/Azurite) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |


### <a id="40dbffa18ec695a618eef96d6fd09176"></a>Nginx


- [**6164**星][1m] [Py] [yandex/gixy](https://github.com/yandex/gixy) Nginx 配置静态分析工具，防止配置错误导致安全问题，自动化错误配置检测


### <a id="6b90a3993f9846922396ec85713dc760"></a>ELK


- [**1875**星][18d] [CSS] [cyb3rward0g/helk](https://github.com/cyb3rward0g/helk) 对ELK栈进行分析，具备多种高级功能，例如SQL声明性语言，图形，结构化流，机器学习等




***


## <a id="d55d9dfd081aa2a02e636b97ca1bad0b"></a>物联网(IoT)&&嵌入式设备&&路由器&&交换机&&智能设备&&打印机


### <a id="cda63179d132f43441f8844c5df10024"></a>未分类-IoT


- [**8371**星][2y] [brannondorsey/wifi-cracking](https://github.com/brannondorsey/wifi-cracking) 破解WPA/WPA2 Wi-Fi 路由器
    - 重复区段: [工具/破解&&Crack&&爆破&&BruteForce](#de81f9dd79c219c876c1313cd97852ce) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/WPS&&WPA&&WPA2](#8d233e2d068cce2b36fd0cf44d10f5d8) |
- [**1119**星][6m] [nebgnahz/awesome-iot-hacks](https://github.com/nebgnahz/awesome-iot-hacks) 
- [**817**星][14d] [v33ru/iotsecurity101](https://github.com/v33ru/iotsecurity101) 
- [**791**星][30d] [Py] [ct-open-source/tuya-convert](https://github.com/ct-open-source/tuya-convert) 
- [**582**星][8m] [Py] [woj-ciech/danger-zone](https://github.com/woj-ciech/danger-zone) 
- [**494**星][2y] [Java] [nsacyber/grassmarlin](https://github.com/nsacyber/GRASSMARLIN) 
- [**465**星][2m] [Py] [iti/ics-security-tools](https://github.com/iti/ics-security-tools) 
- [**462**星][2y] [adi0x90/attifyos](https://github.com/adi0x90/attifyos) IoT 安全评估/渗透测试工具包
- [**437**星][18d] [Py] [rabobank-cdc/dettect](https://github.com/rabobank-cdc/dettect) 
- [**412**星][3y] [Py] [ciscocsirt/malspider](https://github.com/ciscocsirt/malspider) 
- [**330**星][1y] [Py] [vmware/liota](https://github.com/vmware/liota) 
- [**307**星][1m] [Java] [erudika/para](https://github.com/erudika/para) 
- [**191**星][7m] [JS] [or3stis/apparatus](https://github.com/or3stis/apparatus) 
- [**176**星][10m] [Go] [fnzv/net-shield](https://github.com/fnzv/net-Shield) 
- [**167**星][1y] [HTML] [yaseng/iot-security-wiki](https://github.com/yaseng/iot-security-wiki) 
- [**157**星][2m] [Py] [staticafi/symbiotic](https://github.com/staticafi/symbiotic) 
- [**153**星][3m] [fkie-cad/awesome-embedded-and-iot-security](https://github.com/fkie-cad/awesome-embedded-and-iot-security) 
- [**153**星][14d] [Pascal] [passbyyou888/zserver4d](https://github.com/passbyyou888/zserver4d) 
- [**151**星][13d] [Py] [jymcheong/autottp](https://github.com/jymcheong/autottp) 
- [**149**星][8m] [Py] [safebreach-labs/sireprat](https://github.com/safebreach-labs/sireprat) 
- [**126**星][6m] [Py] [tarlogicsecurity/chankro](https://github.com/tarlogicsecurity/chankro) 
- [**90**星][11m] [Py] [6ix7ine/stretcher](https://github.com/6ix7ine/stretcher) 
- [**80**星][3m] [Py] [samsung/cotopaxi](https://github.com/samsung/cotopaxi) 
- [**73**星][2m] [C++] [noddos/noddos](https://github.com/noddos/noddos) noddos：Noddos 客户端，监视家庭或企业网络中的网络流量，识别 IoT 和其他设备，并将特定设备的ACL应用于已识别设备的流量。 其目标是识别并阻止来自已被黑客控制的设备的流氓流量（例如在 DDOS 攻击的流量）
- [**67**星][5m] [Py] [marco-lancini/docker_offensive_elk](https://github.com/marco-lancini/docker_offensive_elk) 
- [**66**星][24d] [C] [scriptingxss/iotgoat](https://github.com/scriptingxss/iotgoat) 
- [**62**星][18d] [Py] [akamai-threat-research/mqtt-pwn](https://github.com/akamai-threat-research/mqtt-pwn) 
- [**62**星][5y] [Py] [xipiter/idiotic](https://github.com/xipiter/idiotic) 
- [**59**星][11m] [aliasrobotics/rsf](https://github.com/aliasrobotics/rsf) 
- [**59**星][1y] [Py] [arthastang/iot-home-guard](https://github.com/arthastang/iot-home-guard) 
- [**55**星][2y] [Shell] [moki-ics/moki](https://github.com/moki-ics/moki) 
- [**53**星][2y] [Py] [nezza/scada-stuff](https://github.com/nezza/scada-stuff) 
- [**45**星][1m] [C++] [ms-iot/imx-iotcore](https://github.com/ms-iot/imx-iotcore) 
- [**44**星][10m] [Py] [expliot_framework/expliot](https://gitlab.com/expliot_framework/expliot) 
- [**42**星][1y] [Py] [chrismaddalena/fox](https://github.com/chrismaddalena/fox) 
- [**42**星][7m] [Py] [anouarbensaad/honeypot-iot](https://github.com/anouarbensaad/honeypot-iot) 
- [**40**星][2y] [Py] [mxmssh/idametrics](https://github.com/mxmssh/idametrics) 收集x86体系结构的二进制可执行文件的静态软件复杂性度量
- [**39**星][6m] [C++] [peperunas/pasticciotto](https://github.com/peperunas/pasticciotto) 
- [**25**星][6m] [hardenedlinux/embedded-iot_profile](https://github.com/hardenedlinux/embedded-iot_profile) 
- [**25**星][5y] [Py] [zhengmin1989/droidanalytics](https://github.com/zhengmin1989/droidanalytics) 
- [**23**星][2m] [C++] [vulcainreo/dvid](https://github.com/vulcainreo/dvid) 
- [**21**星][3m] [acutronicrobotics/mara_threat_model](https://github.com/acutronicrobotics/mara_threat_model) 
- [**21**星][4y] [Py] [peterfillmore/rfidiot](https://github.com/peterfillmore/rfidiot) 
- [**21**星][3y] [C] [newbee119/iot_bot](https://github.com/NewBee119/IoT_bot) 


### <a id="72bffacc109d51ea286797a7d5079392"></a>打印机 


- [**2089**星][1y] [Py] [rub-nds/pret](https://github.com/rub-nds/pret) 


### <a id="c9fd442ecac4e22d142731165b06b3fe"></a>路由器&&交换机


- [**237**星][5y] [C] [jduck/asus-cmd](https://github.com/jduck/asus-cmd) 
- [**109**星][2y] [C] [xiphosresearch/netelf](https://github.com/xiphosresearch/netelf) 
- [**55**星][19d] [C] [secureauthcorp/sap-dissection-plug-in-for-wireshark](https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark) 
- [**28**星][4y] [C] [rfdslabs/mimosa-framework](https://github.com/rfdslabs/mimosa-framework) 


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
- [**2499**星][3y] [C] [dhavalkapil/icmptunnel](https://github.com/dhavalkapil/icmptunnel) 
- [**2468**星][3m] [C] [yrutschle/sslh](https://github.com/yrutschle/sslh) 
- [**2450**星][17d] [Shell] [teddysun/across](https://github.com/teddysun/across) This is a shell script for configure and start WireGuard VPN server
- [**2352**星][6m] [Lua] [snabbco/snabb](https://github.com/snabbco/snabb) Simple and fast packet networking
- [**2156**星][6y] [Ruby] [plamoni/siriproxy](https://github.com/plamoni/siriproxy) 
- [**2133**星][1m] [Go] [mmatczuk/go-http-tunnel](https://github.com/mmatczuk/go-http-tunnel) 
- [**1874**星][4m] [C] [darkk/redsocks](https://github.com/darkk/redsocks) 
- [**1844**星][1y] [Py] [aploium/zmirror](https://github.com/aploium/zmirror) 
- [**1813**星][3m] [C] [tinyproxy/tinyproxy](https://github.com/tinyproxy/tinyproxy) a light-weight HTTP/HTTPS proxy daemon for POSIX operating systems
- [**1725**星][2y] [Go] [vzex/dog-tunnel](https://github.com/vzex/dog-tunnel) 
- [**1678**星][9m] [Py] [constverum/proxybroker](https://github.com/constverum/proxybroker) 
- [**1665**星][4m] [C] [networkprotocol/netcode.io](https://github.com/networkprotocol/netcode.io) 
- [**1611**星][6m] [Go] [sipt/shuttle](https://github.com/sipt/shuttle) 
- [**1522**星][2y] [Py] [awolfly9/ipproxytool](https://github.com/awolfly9/ipproxytool) 
- [**1495**星][1m] [C] [ntop/n2n](https://github.com/ntop/n2n) 
- [**1448**星][7m] [C++] [wangyu-/tinyfecvpn](https://github.com/wangyu-/tinyfecvpn) 
- [**1334**星][1m] [Go] [davrodpin/mole](https://github.com/davrodpin/mole) 
- [**1308**星][12m] [C] [madeye/proxydroid](https://github.com/madeye/proxydroid) 
- [**1222**星][4m] [JS] [bubenshchykov/ngrok](https://github.com/bubenshchykov/ngrok) 
- [**1199**星][21d] [Objective-C] [onionbrowser/onionbrowser](https://github.com/onionbrowser/onionbrowser) 
- [**1180**星][3y] [Roff] [matiasinsaurralde/facebook-tunnel](https://github.com/matiasinsaurralde/facebook-tunnel) 
- [**1048**星][5m] [C] [tcurdt/iproxy](https://github.com/tcurdt/iproxy) 
- [**1042**星][28d] [Go] [pusher/oauth2_proxy](https://github.com/pusher/oauth2_proxy) 
- [**999**星][7m] [Go] [adtac/autovpn](https://github.com/adtac/autovpn) 
- [**946**星][9m] [JS] [lukechilds/reverse-shell](https://github.com/lukechilds/reverse-shell) 
- [**927**星][3m] [Py] [christophetd/cloudflair](https://github.com/christophetd/cloudflair) a tool to find origin servers of websites protected by CloudFlare who are publicly exposed and don't restrict network access to the CloudFlare IP ranges as they should
- [**914**星][2y] [C++] [securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf) 网络工具包：TCP 和 UDP 端口转发、SOCKS 代理、远程 shell，跨平台
- [**836**星][2m] [Py] [anorov/pysocks](https://github.com/anorov/pysocks) 
- [**810**星][1m] [Go] [henson/proxypool](https://github.com/henson/proxypool) 
- [**790**星][3m] [Py] [secforce/tunna](https://github.com/secforce/tunna) 
- [**768**星][2y] [TypeScript] [uwnetworkslab/uproxy-p2p](https://github.com/uwnetworkslab/uproxy-p2p) 
- [**753**星][1m] [C#] [justcoding121/titanium-web-proxy](https://github.com/justcoding121/titanium-web-proxy) 
- [**738**星][30d] [Shell] [zfl9/ss-tproxy](https://github.com/zfl9/ss-tproxy) 
- [**737**星][1m] [C#] [damianh/proxykit](https://github.com/damianh/proxykit) 
- [**674**星][1m] [Go] [dliv3/venom](https://github.com/dliv3/venom) 
- [**674**星][24d] [JS] [mellow-io/mellow](https://github.com/mellow-io/mellow) 
- [**664**星][19d] [Kotlin] [mygod/vpnhotspot](https://github.com/mygod/vpnhotspot) 
- [**660**星][2y] [Ruby] [igrigorik/em-proxy](https://github.com/igrigorik/em-proxy) 
- [**651**星][27d] [Py] [abhinavsingh/proxy.py](https://github.com/abhinavsingh/proxy.py) 
- [**616**星][4m] [JS] [derhuerst/tcp-over-websockets](https://github.com/derhuerst/tcp-over-websockets) 
- [**574**星][4m] [Py] [trustedsec/trevorc2](https://github.com/trustedsec/trevorc2) trevorc2：通过正常的可浏览的网站隐藏 C&C 指令的客户端/服务器模型，因为时间间隔不同，检测变得更加困难，并且获取主机数据时不会使用 POST 请求
- [**568**星][12d] [Go] [cloudflare/cloudflared](https://github.com/cloudflare/cloudflared) 
- [**558**星][8m] [JS] [blinksocks/blinksocks](https://github.com/blinksocks/blinksocks) 
- [**556**星][27d] [clarketm/proxy-list](https://github.com/clarketm/proxy-list) 
- [**554**星][9y] [Ruby] [mojombo/proxymachine](https://github.com/mojombo/proxymachine) 
- [**545**星][1y] [Py] [fate0/getproxy](https://github.com/fate0/getproxy) 是一个抓取发放代理网站，获取 http/https 代理的程序
- [**513**星][10m] [Erlang] [heroku/vegur](https://github.com/heroku/vegur) HTTP Proxy Library
- [**473**星][1y] [Go] [yinqiwen/gsnova](https://github.com/yinqiwen/gsnova) 
- [**449**星][28d] [Py] [aidaho12/haproxy-wi](https://github.com/aidaho12/haproxy-wi) 
- [**397**星][9m] [Go] [evilsocket/shellz](https://github.com/evilsocket/shellz) 
- [**388**星][2y] [Py] [mricon/rev-proxy-grapher](https://github.com/mricon/rev-proxy-grapher) 
- [**382**星][1y] [Ruby] [aphyr/tund](https://github.com/aphyr/tund) 
- [**380**星][3y] [Py] [sensepost/dns-shell](https://github.com/sensepost/dns-shell) 
- [**372**星][3y] [Go] [q3k/crowbar](https://github.com/q3k/crowbar) 
- [**361**星][1m] [Py] [lyft/metadataproxy](https://github.com/lyft/metadataproxy) 
- [**359**星][2y] [Py] [roglew/pappy-proxy](https://github.com/roglew/pappy-proxy) 
- [**355**星][1y] [C] [emptymonkey/revsh](https://github.com/emptymonkey/revsh) 
- [**346**星][2y] [udpsec/awesome-vpn](https://github.com/udpsec/awesome-vpn) 
- [**345**星][6m] [Go] [coreos/jwtproxy](https://github.com/coreos/jwtproxy) 
- [**343**星][4y] [Py] [ahhh/reverse_dns_shell](https://github.com/ahhh/reverse_dns_shell) 
- [**340**星][2y] [C++] [usb-tools/usbproxy-legacy](https://github.com/usb-tools/USBProxy-legacy) 
- [**336**星][8m] [Py] [iphelix/dnschef](https://github.com/iphelix/dnschef) dnschef：DNS 代理，用于渗透测试和恶意代码分析
- [**331**星][6m] [Py] [fbkcs/thunderdns](https://github.com/fbkcs/thunderdns) 使用DNS协议转发TCP流量. Python编写, 无需编译客户端, 支持socks5
- [**325**星][3y] [JS] [qgy18/pangolin](https://github.com/qgy18/pangolin) 
- [**325**星][4m] [Go] [sysdream/hershell](https://github.com/sysdream/hershell) Go 语言编写的反向 Shell
- [**320**星][9m] [JS] [mhzed/wstunnel](https://github.com/mhzed/wstunnel) 
- [**301**星][4m] [Py] [rootviii/proxy_requests](https://github.com/rootviii/proxy_requests) 
- [**293**星][2m] [JS] [bettercap/caplets](https://github.com/bettercap/caplets) 使用.cap脚本, 自动化bettercap的交互式会话
- [**293**星][3y] [Py] [n1nj4sec/pr0cks](https://github.com/n1nj4sec/pr0cks) 
- [**290**星][8m] [C] [basil00/reqrypt](https://github.com/basil00/reqrypt) reqrypt：HTTP 请求 tunneling 工具
- [**289**星][2m] [Py] [covertcodes/multitun](https://github.com/covertcodes/multitun) 
- [**284**星][2y] [evilsocket/bettercap-proxy-modules](https://github.com/evilsocket/bettercap-proxy-modules) 
- [**278**星][11m] [C] [dgoulet/torsocks](https://github.com/dgoulet/torsocks) 
- [**276**星][5m] [Py] [mthbernardes/rsg](https://github.com/mthbernardes/rsg) 多种方式生成反向Shell
- [**273**星][12d] [a2u/free-proxy-list](https://github.com/a2u/free-proxy-list) 
- [**273**星][9m] [Py] [chenjiandongx/async-proxy-pool](https://github.com/chenjiandongx/async-proxy-pool) 
- [**272**星][4m] [Go] [suyashkumar/ssl-proxy](https://github.com/suyashkumar/ssl-proxy) 
- [**261**星][1y] [Py] [earthquake/xfltreat](https://github.com/earthquake/xfltreat) 
- [**260**星][5y] [C] [mysql/mysql-proxy](https://github.com/mysql/mysql-proxy) 
- [**257**星][8m] [C] [rofl0r/microsocks](https://github.com/rofl0r/microsocks) 
- [**254**星][3m] [Py] [fwkz/riposte](https://github.com/fwkz/riposte) 
- [**246**星][2y] [Py] [spaze/oprah-proxy](https://github.com/spaze/oprah-proxy) 
- [**245**星][4m] [Shell] [thesecondsun/revssl](https://github.com/thesecondsun/revssl) 
- [**242**星][17d] [Go] [adguardteam/dnsproxy](https://github.com/adguardteam/dnsproxy) 
- [**242**星][4m] [Go] [lesnuages/hershell](https://github.com/lesnuages/hershell) 
- [**241**星][9m] [C] [pegasuslab/ghosttunnel](https://github.com/PegasusLab/GhostTunnel) 
- [**240**星][2y] [Py] [leonardonve/dns2proxy](https://github.com/leonardonve/dns2proxy) 
- [**236**星][11m] [Go] [fardog/secureoperator](https://github.com/fardog/secureoperator) 
- [**235**星][3y] [C] [jamesbarlow/icmptunnel](https://github.com/jamesbarlow/icmptunnel) 
- [**229**星][4y] [Py] [danmcinerney/elite-proxy-finder](https://github.com/danmcinerney/elite-proxy-finder) 
- [**226**星][3y] [Py] [praetorian-inc/pyshell](https://github.com/praetorian-code/pyshell) 
- [**224**星][1m] [Ruby] [zt2/sqli-hunter](https://github.com/zt2/sqli-hunter) 
- [**221**星][3y] [Smarty] [analytically/haproxy-ddos](https://github.com/analytically/haproxy-ddos) 
- [**216**星][1y] [PHP] [softius/php-cross-domain-proxy](https://github.com/softius/php-cross-domain-proxy) 
- [**213**星][3y] [C#] [dxflatline/flatpipes](https://github.com/dxflatline/flatpipes) 
- [**213**星][8m] [Go] [joncooperworks/judas](https://github.com/joncooperworks/judas) a phishing proxy
- [**207**星][9m] [Go] [justmao945/mallory](https://github.com/justmao945/mallory) 
- [**202**星][1y] [C#] [damonmohammadbagher/nativepayload_dns](https://github.com/damonmohammadbagher/nativepayload_dns) 
- [**201**星][2y] [Go] [netxfly/xsec-proxy-scanner](https://github.com/netxfly/xsec-proxy-scanner) 速度超快、小巧的代理服务器扫描器
- [**199**星][3y] [Go] [praetorian-inc/trudy](https://github.com/praetorian-code/trudy) 
- [**196**星][2m] [Py] [cisco-talos/decept](https://github.com/cisco-talos/decept) 
- [**195**星][2y] [Py] [linw1995/lightsocks-python](https://github.com/linw1995/lightsocks-python) 
- [**194**星][3y] [JS] [mhils/honeyproxy](https://github.com/mhils/honeyproxy) 
- [**190**星][1m] [Rust] [jedisct1/rust-doh](https://github.com/jedisct1/rust-doh) 
- [**183**星][3y] [Go] [eahydra/socks](https://github.com/eahydra/socks) 
- [**177**星][1m] [Java] [sensepost/mallet](https://github.com/sensepost/mallet) 
- [**173**星][1m] [Go] [asciimoo/morty](https://github.com/asciimoo/morty) morty：去除恶意HTML标签和属性，去除外部资源引用以防止第三方信息泄露
- [**173**星][3m] [C] [cloudflare/mmproxy](https://github.com/cloudflare/mmproxy) 
- [**170**星][2y] [Go] [arwmq9b6/dnsproxy](https://github.com/arwmq9b6/dnsproxy) 
- [**170**星][2y] [Java] [fengyouchao/sockslib](https://github.com/fengyouchao/sockslib) 
- [**169**星][8m] [Go] [mimah/gomet](https://github.com/mimah/gomet) 
- [**167**星][3y] [C] [hugsy/proxenet](https://github.com/hugsy/proxenet) 
- [**167**星][2y] [Py] [mdsecactivebreach/chameleon](https://github.com/mdsecactivebreach/chameleon) A tool for evading Proxy categorisation
- [**163**星][1m] [Shell] [duy13/vddos-protection](https://github.com/duy13/vddos-protection) 
- [**163**星][3m] [C] [dyne/dnscrypt-proxy](https://github.com/dyne/dnscrypt-proxy) 
- [**162**星][20d] [Go] [gavinguan24/ahri](https://github.com/gavinguan24/ahri) 
- [**159**星][3y] [Shell] [hiroshimanrise/anonym8](https://github.com/hiroshimanrise/anonym8) 
- [**156**星][6y] [C] [defuse/sockstress](https://github.com/defuse/sockstress) 
- [**155**星][3y] [Ruby] [waterlink/rack-reverse-proxy](https://github.com/waterlink/rack-reverse-proxy) 
- [**154**星][2y] [Py] [tintinweb/striptls](https://github.com/tintinweb/striptls) 
- [**153**星][3y] [Makefile] [0x36/vpnpivot](https://github.com/0x36/vpnpivot) 
- [**152**星][6m] [JS] [tidesec/proxy_pool](https://github.com/tidesec/proxy_pool) 
- [**150**星][1m] [Rust] [net-reflow/reflow](https://github.com/net-reflow/reflow) 
- [**148**星][4y] [C++] [hiwincn/htran](https://github.com/hiwincn/htran) 
- [**146**星][1m] [Py] [nucypher/pyumbral](https://github.com/nucypher/pyumbral) 
- [**143**星][1y] [Shell] [adi90x/rancher-active-proxy](https://github.com/adi90x/rancher-active-proxy) 
- [**142**星][4y] [C] [valdikss/openvpn-fix-dns-leak-plugin](https://github.com/valdikss/openvpn-fix-dns-leak-plugin) 
- [**142**星][4y] [C] [valdikss/p0f-mtu](https://github.com/valdikss/p0f-mtu) 
- [**141**星][3y] [Py] [safebreach-labs/pacdoor](https://github.com/safebreach-labs/pacdoor) 
- [**140**星][2y] [Py] [gumblex/ptproxy](https://github.com/gumblex/ptproxy) 
- [**140**星][2y] [Ruby] [nccgroup/binproxy](https://github.com/nccgroup/binproxy) 
- [**139**星][9m] [Shell] [essandess/macos-openvpn-server](https://github.com/essandess/macos-openvpn-server) 
- [**138**星][25d] [Py] [chrispetrou/hrshell](https://github.com/chrispetrou/hrshell) 
- [**135**星][3m] [C++] [pichi-router/pichi](https://github.com/pichi-router/pichi) 
- [**132**星][8m] [Go] [snail007/shadowtunnel](https://github.com/snail007/shadowtunnel) 
- [**131**星][5m] [Go] [fanpei91/gap-proxy](https://github.com/fanpei91/gap-proxy) 
- [**130**星][2m] [PowerShell] [antoniococo/conptyshell](https://github.com/antoniococo/conptyshell) 
- [**130**星][3y] [Py] [safebreach-labs/pyekaboo](https://github.com/safebreach-labs/pyekaboo) 
- [**130**星][2y] [JS] [oyyd/encryptsocks](https://github.com/oyyd/encryptsocks) 
- [**128**星][12m] [Py] [blacknbunny/mcreator](https://github.com/blacknbunny/mcreator) 反向Shell生成器, 自带AV绕过技术
- [**127**星][1y] [Py] [deepzec/grok-backdoor](https://github.com/deepzec/grok-backdoor) 
- [**122**星][1y] [Py] [qiyeboy/baseproxy](https://github.com/qiyeboy/baseproxy) 
- [**122**星][3m] [Go] [stalkr/dns-reverse-proxy](https://github.com/stalkr/dns-reverse-proxy) 
- [**119**星][1y] [Go] [cllunsford/aws-signing-proxy](https://github.com/cllunsford/aws-signing-proxy) 
- [**117**星][1y] [Py] [teamhg-memex/aquarium](https://github.com/teamhg-memex/aquarium) 
- [**116**星][11m] [CSS] [rootkiter/earthworm](https://github.com/rootkiter/earthworm) 
- [**115**星][4y] [Go] [tutumcloud/ngrok](https://github.com/tutumcloud/ngrok) 
- [**114**星][2m] [PowerShell] [jcqsteven/ghosttunnel](https://github.com/jcqsteven/ghosttunnel) 
- [**113**星][5y] [Py] [h01/proxyscanner](https://github.com/h01/proxyscanner) 
- [**113**星][6m] [C#] [tyranid/canape.core](https://github.com/tyranid/canape.core) 
- [**112**星][5m] [C#] [nettitude/sharpsocks](https://github.com/nettitude/sharpsocks) 
- [**111**星][6m] [PowerShell] [audibleblink/gorsh](https://github.com/audibleblink/gorsh) 
- [**111**星][3y] [PHP] [dhayalanb/windows-php-reverse-shell](https://github.com/dhayalanb/windows-php-reverse-shell) 
- [**110**星][2y] [JS] [voidsec/webrtc-leak](https://github.com/voidsec/webrtc-leak) 
- [**108**星][5m] [Java] [mkopylec/charon-spring-boot-starter](https://github.com/mkopylec/charon-spring-boot-starter) 
- [**107**星][5m] [Swift] [tuluobo/leiter](https://github.com/tuluobo/leiter) 
- [**106**星][1y] [PHP] [walkor/php-http-proxy](https://github.com/walkor/php-http-proxy) 
- [**104**星][4y] [Go] [netxfly/transparent-proxy-scanner](https://github.com/netxfly/transparent-proxy-scanner) 
- [**103**星][2y] [Java] [ggrandes/bouncer](https://github.com/ggrandes/bouncer) 
- [**102**星][2m] [Py] [ickerwx/tcpproxy](https://github.com/ickerwx/tcpproxy) 
- [**102**星][5m] [Py] [roglew/guppy-proxy](https://github.com/roglew/guppy-proxy) 用于WebApp安全测试的拦截代理(intercepting proxy)
- [**102**星][2y] [Go] [sakeven/httpproxy](https://github.com/sakeven/httpproxy) 
- [**101**星][4y] [Shell] [cornerpirate/socat-shell](https://github.com/cornerpirate/socat-shell) 
- [**98**星][29d] [Py] [t0thkr1s/revshellgen](https://github.com/t0thkr1s/revshellgen) 
- [**91**星][2y] [C++] [liulilittle/paperairplane](https://github.com/liulilittle/paperairplane) 
- [**91**星][2y] [Py] [pry0cc/proxydock](https://github.com/pry0cc/proxydock) 
- [**90**星][1y] [Shell] [jedisct1/bitbar-dnscrypt-proxy-switcher](https://github.com/jedisct1/bitbar-dnscrypt-proxy-switcher) 
- [**90**星][4y] [Py] [pdjstone/wsuspect-proxy](https://github.com/pdjstone/wsuspect-proxy) 
- [**90**星][6y] [C++] [stealth/fraud-bridge](https://github.com/stealth/fraud-bridge) 
- [**90**星][1y] [Go] [tarlogicsecurity/sasshimi](https://github.com/tarlogicsecurity/sasshimi) 
- [**86**星][7y] [Py] [iamultra/ssrfsocks](https://github.com/iamultra/ssrfsocks) 
- [**86**星][3m] [C++] [leoloobeek/comproxy](https://github.com/leoloobeek/comproxy) 
- [**80**星][5y] [C] [chokepoint/crypthook](https://github.com/chokepoint/crypthook) 
- [**80**星][2y] [Go] [netxfly/xsec-dns-proxy](https://github.com/netxfly/xsec-dns-proxy) xsec-dns-proxy：DNS代理服务器，可以将DNS请求代理到后端的DNS服务器中，在代理的过程中会将dns log写入到数据库中
- [**78**星][2y] [Go] [asciimoo/filtron](https://github.com/asciimoo/filtron) filtron：反向HTTP代码
- [**77**星][5y] [C] [bishopfox/firecat](https://github.com/bishopfox/firecat) 
- [**75**星][18d] [Py] [ab77/black.box](https://github.com/ab77/black.box) 
- [**75**星][1y] [Shell] [kolargol/openvpn](https://github.com/kolargol/openvpn) openvpn：Shell 脚本，5分钟建立个人 VPN
- [**72**星][6y] [C] [jtripper/sslnuke](https://github.com/jtripper/sslnuke) 
- [**71**星][6m] [Go] [audibleblink/letsproxy](https://github.com/audibleblink/letsproxy) 
- [**71**星][4m] [Go] [netxfly/x-proxy](https://github.com/netxfly/x-proxy) 
- [**69**星][2m] [Shell] [edu4rdshl/tor-router](https://github.com/edu4rdshl/tor-router) 
- [**68**星][2y] [JS] [chrisyer/lightsocks-nodejs](https://github.com/chrisyer/lightsocks-nodejs) 
- [**68**星][2y] [JS] [kureev/react-native-network-proxy](https://github.com/kureev/react-native-network-proxy) 
- [**67**星][1y] [C++] [oyyd/nysocks](https://github.com/oyyd/nysocks) 
- [**66**星][1y] [Shell] [thelinuxchoice/keydroid](https://github.com/thelinuxchoice/keydroid) 
- [**65**星][1y] [Py] [lukebaggett/google_socks](https://github.com/lukebaggett/google_socks) 
- [**65**星][5m] [Shell] [tasket/qubes-vpn-support](https://github.com/tasket/qubes-vpn-support) 
- [**64**星][24d] [Java] [lmax-exchange/disruptor-proxy](https://github.com/LMAX-Exchange/disruptor-proxy) 
- [**60**星][4y] [Py] [dotcppfile/serbot](https://github.com/dotcppfile/serbot) 
- [**60**星][13d] [Lua] [yelp/casper](https://github.com/yelp/casper) 
- [**59**星][7m] [JS] [try-to/electron-proxy](https://github.com/try-to/electron-proxy) 
- [**58**星][6m] [Go] [dsnet/udptunnel](https://github.com/dsnet/udptunnel) 
- [**58**星][3y] [Py] [epinna/stegosip](https://github.com/epinna/stegosip) 
- [**58**星][3y] [nidom/buff](https://github.com/nidom/buff) 
- [**58**星][6m] [JS] [pownjs/pown-proxy](https://github.com/pownjs/pown-proxy) 
- [**57**星][6m] [JS] [mdslab/wstun](https://github.com/mdslab/wstun) 
- [**56**星][2m] [C] [lnslbrty/ptunnel-ng](https://github.com/lnslbrty/ptunnel-ng) 
- [**53**星][2y] [Shell] [mempodippy/snodew](https://github.com/mempodippy/snodew) 
- [**53**星][3m] [C] [sonertari/sslproxy](https://github.com/sonertari/sslproxy) 
- [**52**星][3y] [PHP] [httpoxy/php-fpm-httpoxy-poc](https://github.com/httpoxy/php-fpm-httpoxy-poc) 
- [**52**星][1y] [Go] [netflix-skunkworks/aws-metadata-proxy](https://github.com/netflix-skunkworks/aws-metadata-proxy) 
- [**49**星][11m] [C] [acoinfo/kidvpn](https://github.com/acoinfo/kidvpn) 
- [**46**星][7m] [Dockerfile] [jmg87/redteam-k8spwn](https://github.com/jmg87/redteam-k8spwn) 
- [**45**星][1y] [Shell] [qiang-yu/shadowsocksvpn-openwrt](https://github.com/qiang-yu/shadowsocksvpn-openwrt) 
- [**43**星][5m] [Shell] [infosecn1nja/ycsm](https://github.com/infosecn1nja/ycsm) 
- [**43**星][2y] [Shell] [taherio/redi](https://github.com/taherio/redi) 
- [**40**星][3m] [Py] [4n4nk3/tinkerershell](https://github.com/4n4nk3/tinkerershell) 
- [**38**星][4m] [Java] [coveros/zap-sonar-plugin](https://github.com/coveros/zap-sonar-plugin) 
- [**36**星][4y] [Assembly] [sh3llc0d3r1337/windows_reverse_shell_1](https://github.com/sh3llc0d3r1337/windows_reverse_shell_1) 
- [**33**星][6m] [flyfishsec/rsgen](https://github.com/flyfishsec/rsgen) 
- [**33**星][3m] [Shell] [hromie/obfs4proxy-openvpn](https://github.com/hromie/obfs4proxy-openvpn) 
- [**32**星][2y] [Shell] [dlshad/openvpn-shapeshifter](https://github.com/dlshad/openvpn-shapeshifter) 
- [**28**星][1y] [Shell] [cryptolok/ghostinthechaos](https://github.com/cryptolok/ghostinthechaos) 
- [**27**星][2y] [C] [johndoe31415/ratched](https://github.com/johndoe31415/ratched) 
- [**26**星][8m] [Py] [byt3bl33d3r/dnschef](https://github.com/byt3bl33d3r/dnschef) 
- [**25**星][1y] [Tcl] [fruho/fruhoapp](https://github.com/fruho/fruhoapp) 
- [**23**星][2y] [C] [p4p1/p4p1](https://github.com/p4p1/p4p1) 
- [**22**星][1m] [Shell] [samuelhbne/vpn-launchpad](https://github.com/samuelhbne/vpn-launchpad) 
- [**21**星][6y] [Go] [mikkolehtisalo/gssapi-proxy](https://github.com/mikkolehtisalo/gssapi-proxy) 
- [**10**星][3m] [JS] [zaproxy/zap-api-nodejs](https://github.com/zaproxy/zap-api-nodejs) 


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
- [**2782**星][2y] [C] [seclab-ucr/intang](https://github.com/seclab-ucr/intang) research project for circumventing the "TCP reset attack" from the Great Firewall of China (GFW) by disrupting/desynchronizing the TCP Control Block (TCB) on the censorship devices.
- [**2482**星][2m] [C++] [trojan-gfw/trojan](https://github.com/trojan-gfw/trojan) 
- [**1185**星][7y] [Py] [mothran/mongol](https://github.com/mothran/mongol) 
- [**614**星][4y] [JS] [n0wa11/gfw_whitelist](https://github.com/n0wa11/gfw_whitelist) 
- [**202**星][16d] [Shell] [zfl9/gfwlist2privoxy](https://github.com/zfl9/gfwlist2privoxy) 
- [**112**星][2y] [gfwlist/tinylist](https://github.com/gfwlist/tinylist) 
- [**100**星][11m] [searking/ggfwzs_in_hack](https://github.com/searking/ggfwzs_in_hack) 




### <a id="21cbd08576a3ead42f60963cdbfb8599"></a>代理


- [**7936**星][3y] [Go] [cyfdecyf/cow](https://github.com/cyfdecyf/cow) 
- [**7149**星][14d] [Go] [snail007/goproxy](https://github.com/snail007/goproxy) 
- [**5971**星][14d] [JS] [avwo/whistle](https://github.com/avwo/whistle) 基于Node实现的跨平台抓包调试代理工具（HTTP, HTTP2, HTTPS, Websocket）
- [**1380**星][1m] [C] [z3apa3a/3proxy](https://github.com/z3apa3a/3proxy) 
- [**304**星][17d] [Shell] [brainfucksec/kalitorify](https://github.com/brainfucksec/kalitorify) 
- [**24**星][7y] [Java] [akdeniz/mitmsocks4j](https://github.com/akdeniz/mitmsocks4j) 
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |


### <a id="a136c15727e341b9427b6570910a3a1f"></a>反向代理&&穿透


- [**29549**星][23d] [Go] [fatedier/frp](https://github.com/fatedier/frp) 快速的反向代理, 将NAT或防火墙之后的本地服务器暴露到公网
- [**17394**星][3y] [Go] [inconshreveable/ngrok](https://github.com/inconshreveable/ngrok) 反向代理，在公网终端和本地服务之间创建安全的隧道
- [**9114**星][2m] [JS] [localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) 
- [**8706**星][2m] [Go] [cnlh/nps](https://github.com/cnlh/nps) 
- [**4887**星][10m] [Go] [bitly/oauth2_proxy](https://github.com/bitly/oauth2_proxy) 反向代理，静态文件服务器，提供Providers(Google/Github)认证
- [**3521**星][1m] [Java] [ffay/lanproxy](https://github.com/ffay/lanproxy) 
- [**2586**星][1m] [C++] [fanout/pushpin](https://github.com/fanout/pushpin) 
- [**2476**星][5m] [Go] [drk1wi/modlishka](https://github.com/drk1wi/modlishka) 
- [**802**星][7y] [C] [inquisb/icmpsh](https://github.com/inquisb/icmpsh) 
- [**656**星][4m] [Py] [aploium/shootback](https://github.com/aploium/shootback) 
- [**326**星][3y] [Py] [nccgroup/abptts](https://github.com/nccgroup/abptts) 
- [**282**星][1y] [Py] [klsecservices/rpivot](https://github.com/klsecservices/rpivot) 
- [**28**星][4y] [PowerShell] [ahhh/wifi_trojans](https://github.com/ahhh/wifi_trojans) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |


### <a id="e996f5ff54050629de0d9d5e68fcb630"></a>隧道


- [**3271**星][4m] [C++] [wangyu-/udp2raw-tunnel](https://github.com/wangyu-/udp2raw-tunnel) udp2raw-tunnel：udp 打洞。通过raw socket给UDP包加上TCP或ICMP header，进而绕过UDP屏蔽或QoS，或在UDP不稳定的环境下提升稳定性
- [**3131**星][3m] [C] [yarrick/iodine](https://github.com/yarrick/iodine) 通过DNS服务器传输(tunnel)IPV4数据
- [**1779**星][5m] [C++] [iagox86/dnscat2](https://github.com/iagox86/dnscat2) dnscat2：在 DNS 协议上创建加密的 C&C channel
- [**463**星][3y] [Py] [trustedsec/meterssh](https://github.com/trustedsec/meterssh) 
- [**301**星][2y] [JS] [arno0x/dnsexfiltrator](https://github.com/arno0x/dnsexfiltrator) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/数据渗透](#3ae4408f4ab03f99bab9ef9ee69642a8) |
- [**111**星][3y] [PowerShell] [arno0x/dnsdelivery](https://github.com/arno0x/dnsdelivery) 
- [**41**星][2y] [JS] [arno0x/reflectivednsexfiltrator](https://github.com/arno0x/reflectivednsexfiltrator) 
- [**38**星][2y] [Visual Basic] [arno0x/webdavdelivery](https://github.com/arno0x/webdavdelivery) 


### <a id="b2241c68725526c88e69f1d71405c6b2"></a>代理爬取&&代理池


- [**4882**星][1y] [Go] [yinghuocho/firefly-proxy](https://github.com/yinghuocho/firefly-proxy) 
- [**3628**星][2y] [Py] [qiyeboy/ipproxypool](https://github.com/qiyeboy/ipproxypool) 


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
- [**267**星][2y] [Py] [dirtyfilthy/freshonions-torscraper](https://github.com/dirtyfilthy/freshonions-torscraper) 
- [**261**星][9m] [C++] [wbenny/mini-tor](https://github.com/wbenny/mini-tor) mini-tor：使用 MSCNG/CryptoAPI 实现的 Tor 协议
- [**252**星][3y] [Haskell] [galoisinc/haskell-tor](https://github.com/galoisinc/haskell-tor) 
- [**250**星][30d] [C] [basil00/torwall](https://github.com/basil00/torwall) 
- [**250**星][4y] [Py] [whitepacket/zib-trojan](https://github.com/whitepacket/zib-trojan) 
- [**240**星][3y] [Py] [donnchac/onionbalance](https://github.com/donnchac/onionbalance) 
- [**219**星][5m] [Py] [ruped24/toriptables2](https://github.com/ruped24/toriptables2) 
- [**192**星][2m] [Py] [meejah/txtorcon](https://github.com/meejah/txtorcon) 
- [**176**星][2m] [C] [cathugger/mkp224o](https://github.com/cathugger/mkp224o) 
- [**127**星][11m] [Py] [blueudp/deep-explorer](https://github.com/blueudp/deep-explorer) 
- [**119**星][2y] [Ruby] [ehloonion/onionmx](https://github.com/ehloonion/onionmx) 
- [**107**星][11m] [C] [opsxcq/docker-tor-hiddenservice-nginx](https://github.com/opsxcq/docker-tor-hiddenservice-nginx) 
- [**102**星][6m] [HTML] [ahmia/search](https://github.com/ahmia/search) 
- [**102**星][1m] [ajvb/awesome-tor](https://github.com/ajvb/awesome-tor) 
- [**89**星][8m] [Shell] [jseidl/multi-tor](https://github.com/jseidl/multi-tor) 
- [**77**星][3y] [C++] [torps/torps](https://github.com/torps/torps) 
- [**73**星][4y] [Go] [dlion/guesstor](https://github.com/dlion/guesstor) 
- [**60**星][5y] [Go] [jgrahamc/torhoney](https://github.com/jgrahamc/torhoney) 
- [**56**星][2m] [Py] [gosecure/freshonions-torscraper](https://github.com/gosecure/freshonions-torscraper) 
- [**54**星][1y] [Java] [mirsamantajbakhsh/onionharvester](https://github.com/mirsamantajbakhsh/onionharvester) 
- [**52**星][2y] [Py] [inurlx/cloudkill3r](https://github.com/inurlx/cloudkill3r) 
- [**47**星][4y] [C++] [sri-csl/stegotorus](https://github.com/sri-csl/stegotorus) 
- [**43**星][2y] [Py] [mthbernardes/ipchecker](https://github.com/mthbernardes/ipchecker) 
- [**40**星][2m] [Shell] [security-onion-solutions/securityonion-saltstack](https://github.com/security-onion-solutions/securityonion-saltstack) 
- [**39**星][9m] [PHP] [danwin/onion-link-list](https://github.com/danwin/onion-link-list) 
- [**39**星][4y] [Shell] [jivoi/ansible-pentest-with-tor](https://github.com/jivoi/ansible-pentest-with-tor) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/nmap](#94c01f488096fafc194b9a07f065594c) |
- [**38**星][2y] [Java] [adrianbzg/twitter-follow-exploit](https://github.com/adrianbzg/twitter-follow-exploit) 
- [**37**星][28d] [JS] [loki-project/loki-messenger](https://github.com/loki-project/loki-messenger) 
- [**36**星][3y] [Java] [onionmail/onionmail](https://github.com/onionmail/onionmail) 
- [**32**星][4m] [Py] [mikemeliz/torcrawl.py](https://github.com/mikemeliz/torcrawl.py) 
- [**31**星][4y] [Py] [glamrock/stormy](https://github.com/glamrock/stormy) 
- [**31**星][1m] [Shell] [itshaadi/torbox](https://github.com/itshaadi/torbox) 
- [**30**星][5y] [Shell] [patrickod/docker-tor-hidden-services](https://github.com/patrickod/docker-tor-hidden-services) 
- [**28**星][5y] [C++] [yawning/obfsclient](https://github.com/yawning/obfsclient) 
- [**27**星][8m] [Go] [nullhypothesis/sybilhunter](https://github.com/nullhypothesis/sybilhunter) 
- [**26**星][3y] [Py] [duk3luk3/onion-py](https://github.com/duk3luk3/onion-py) 
- [**23**星][2y] [Shell] [oniondecoy/installer](https://github.com/oniondecoy/installer) 
- [**22**星][4y] [Go] [jgrahamc/torexit](https://github.com/jgrahamc/torexit) 
- [**22**星][2y] [Py] [mdegrazia/onionpeeler](https://github.com/mdegrazia/onionpeeler) 
- [**21**星][4m] [Java] [guardianproject/jtorctl](https://github.com/guardianproject/jtorctl) 




### <a id="f932418b594acb6facfc35c1ec414188"></a>Socks&&ShadowSocksXx


- [**25047**星][14d] [Swift] [shadowsocks/shadowsocksx-ng](https://github.com/shadowsocks/shadowsocksx-ng) 
- [**12355**星][1m] [C] [shadowsocks/shadowsocks-libev](https://github.com/shadowsocks/shadowsocks-libev) 
- [**7879**星][4y] [Objective-C] [shadowsocks/shadowsocks-ios](https://github.com/shadowsocks/shadowsocks-ios) 
- [**7061**星][7m] [Shell] [teddysun/shadowsocks_install](https://github.com/teddysun/shadowsocks_install) 
- [**5613**星][1y] [qinyuhang/shadowsocksx-ng-r](https://github.com/qinyuhang/shadowsocksx-ng-r) 
- [**4893**星][4y] [Py] [shadowsocksr-backup/shadowsocksr](https://github.com/shadowsocksr-backup/shadowsocksr) 
- [**4154**星][15d] [Swift] [yanue/v2rayu](https://github.com/yanue/v2rayu) 
- [**3797**星][29d] [JS] [shadowsocks/shadowsocks-manager](https://github.com/shadowsocks/shadowsocks-manager) 
- [**3785**星][2y] [C#] [shadowsocksr-backup/shadowsocksr-csharp](https://github.com/shadowsocksr-backup/shadowsocksr-csharp) 
- [**3578**星][4y] [shadowsocksr-backup/shadowsocks-rss](https://github.com/shadowsocksr-backup/shadowsocks-rss) 
- [**3286**星][2y] [shadowsocksrr/shadowsocks-rss](https://github.com/shadowsocksrr/shadowsocks-rss) 
- [**3174**星][15d] [Smarty] [anankke/sspanel-uim](https://github.com/anankke/sspanel-uim) 专为 Shadowsocks / ShadowsocksR / V2Ray 设计的多用户管理面板
- [**3074**星][2y] [shadowsocksr-backup/shadowsocksr-android](https://github.com/shadowsocksr-backup/shadowsocksr-android) 
- [**2946**星][1m] [Go] [gwuhaolin/lightsocks](https://github.com/gwuhaolin/lightsocks) 轻量级网络混淆代理，基于 SOCKS5 协议，可用来代替 Shadowsocks
- [**2751**星][24d] [Makefile] [shadowsocks/openwrt-shadowsocks](https://github.com/shadowsocks/openwrt-shadowsocks) 
- [**2300**星][10m] [C] [haad/proxychains](https://github.com/haad/proxychains) a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4, SOCKS5 or HTTP(S) proxy. Supported auth-types: "user/pass" for SOCKS4/5, "basic" for HTTP.
- [**2029**星][15d] [C#] [netchx/netch](https://github.com/netchx/netch) 
- [**2018**星][5y] [CoffeeScript] [shadowsocks/shadowsocks-gui](https://github.com/shadowsocks/shadowsocks-gui) 
- [**1821**星][3m] [C] [shadowsocks/simple-obfs](https://github.com/shadowsocks/simple-obfs) 
- [**1683**星][1y] [Swift] [haxpor/potatso](https://github.com/haxpor/potatso) 
- [**1621**星][17d] [Py] [ehco1996/django-sspanel](https://github.com/ehco1996/django-sspanel) 
- [**1567**星][16d] [C#] [hmbsbige/shadowsocksr-windows](https://github.com/hmbsbige/shadowsocksr-windows) 
- [**1470**星][3y] [Py] [sensepost/regeorg](https://github.com/sensepost/regeorg) 
- [**1306**星][4m] [Rust] [shadowsocks/shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) 
- [**1213**星][3y] [CoffeeScript] [shadowsocks/shadowsocks-nodejs](https://github.com/shadowsocks/shadowsocks-nodejs) 
- [**1177**星][6m] [ssrbackup/shadowsocks-rss](https://github.com/ssrarchive/shadowsocks-rss) 
- [**1068**星][1m] [jadagates/shadowsocksbio](https://github.com/jadagates/shadowsocksbio) 
- [**922**星][1y] [Shell] [ywb94/openwrt-ssr](https://github.com/ywb94/openwrt-ssr) 
- [**900**星][1y] [Go] [huacnlee/flora-kit](https://github.com/huacnlee/flora-kit) 基于 shadowsocks-go 做的完善实现，完全兼容 Surge 的配置文件
- [**899**星][2m] [zhaoweih/shadowsocks-tutorial](https://github.com/zhaoweih/shadowsocks-tutorial) 
- [**840**星][11m] [PHP] [walkor/shadowsocks-php](https://github.com/walkor/shadowsocks-php) 
- [**838**星][2y] [CoffeeScript] [onplus/shadowsocks-heroku](https://github.com/onplus/shadowsocks-heroku) 
- [**830**星][1m] [C] [shadowsocksr-live/shadowsocksr-native](https://github.com/shadowsocksr-live/shadowsocksr-native) 
- [**825**星][2y] [PHP] [zhufaner/shadowsocks-manage-system](https://github.com/zhufaner/shadowsocks-manage-system) 
- [**770**星][3y] [Go] [armon/go-socks5](https://github.com/armon/go-socks5) 
- [**730**星][6m] [Go] [cbeuw/goquiet](https://github.com/cbeuw/goquiet) 
- [**701**星][2y] [yichengchen/shadowsocksx-r](https://github.com/yichengchen/shadowsocksx-r) 
- [**650**星][2y] [shadowsocksr-backup/shadowsocksx-ng](https://github.com/shadowsocksr-backup/shadowsocksx-ng) 
- [**576**星][2y] [JS] [shadowsocks-plus/shadowsocks-plus](https://github.com/shadowsocks-plus/shadowsocks-plus) 
- [**517**星][9m] [JS] [mrluanma/shadowsocks-heroku](https://github.com/mrluanma/shadowsocks-heroku) 
- [**473**星][3y] [JS] [vincentchanx/shadowsocks-over-websocket](https://github.com/vincentchanx/shadowsocks-over-websocket) 
- [**447**星][4y] [clowwindy/shadowsocks-libev](https://github.com/clowwindy/shadowsocks-libev) 
- [**421**星][2m] [PowerShell] [p3nt4/invoke-socksproxy](https://github.com/p3nt4/invoke-socksproxy) 
- [**413**星][3y] [Py] [mengskysama/shadowsocks-rm](https://github.com/mengskysama/shadowsocks-rm) 
- [**408**星][3y] [C] [robertyim/shadowsocksx](https://github.com/RobertYim/ShadowsocksX) 
- [**402**星][3m] [JS] [lolimay/shadowsocks-deepin](https://github.com/lolimay/shadowsocks-deepin) 
- [**374**星][1y] [Go] [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2) 
- [**361**星][1y] [Java] [zc-zh-001/shadowsocks-share](https://github.com/zc-zh-001/shadowsocks-share) 
- [**337**星][16d] [Py] [leitbogioro/ssr.go](https://github.com/leitbogioro/ssr.go) 
- [**318**星][3m] [Py] [qwj/python-proxy](https://github.com/qwj/python-proxy) 
- [**304**星][4y] [shadowsocksr-rm/shadowsocks-rss](https://github.com/shadowsocksr-rm/shadowsocks-rss) 
- [**301**星][13d] [Shell] [loyess/shell](https://github.com/loyess/shell) 
- [**250**星][4m] [Py] [fsgmhoward/shadowsocks-py-mu](https://github.com/fsgmhoward/shadowsocks-py-mu) 
- [**210**星][7y] [haohaolee/shadowsocks-openwrt](https://github.com/haohaolee/shadowsocks-openwrt) 
- [**203**星][1y] [Go] [sun8911879/shadowsocksr](https://github.com/sun8911879/shadowsocksr) 
- [**188**星][3m] [Shell] [unbinilium/twist](https://github.com/unbinilium/twist) 
- [**181**星][7y] [CoffeeScript] [shadowsocks/shadowsocks-dotcloud](https://github.com/shadowsocks/shadowsocks-dotcloud) 
- [**180**星][4y] [JS] [gamexg/shadowsocks_admin](https://github.com/gamexg/shadowsocks_admin) 
- [**167**星][2y] [Rust] [loggerhead/shadowsocks-rust](https://github.com/loggerhead/shadowsocks-rust) 
- [**135**星][3y] [Swift] [kidneyband/potatso-ios](https://github.com/kidneyband/potatso-ios) 
- [**134**星][2y] [Shell] [junbaor/shell_script](https://github.com/junbaor/shell_script) 
- [**127**星][2m] [Py] [v3aqb/fwlite](https://github.com/v3aqb/fwlite) 
- [**123**星][3y] [JS] [openmarshall/shortcutss](https://github.com/openmarshall/shortcutss) 
- [**111**星][6m] [JS] [wzdnzd/shadowsocksx-ng-r](https://github.com/wzdnzd/shadowsocksx-ng-r) 
- [**107**星][3y] [liuchenx/surgeconfig](https://github.com/liuchenx/surgeconfig) 
- [**106**星][3m] [Shell] [immmx/ubnt-mips-shadowsocks-libev](https://github.com/immmx/ubnt-mips-shadowsocks-libev) 
- [**95**星][26d] [Makefile] [honwen/openwrt-shadowsocksr](https://github.com/honwen/openwrt-shadowsocksr) 
- [**93**星][3m] [Py] [guyingbo/shadowproxy](https://github.com/guyingbo/shadowproxy) 
- [**92**星][5y] [JS] [nihgwu/nevermore](https://github.com/nihgwu/nevermore) 
- [**89**星][3y] [JS] [lovetingyuan/fq](https://github.com/lovetingyuan/fq) 
- [**85**星][2y] [Py] [wanjunzh/ssct](https://github.com/wanjunzh/ssct) ssct：shadowsocks 包装器，用于持续绕过防火墙
- [**83**星][7m] [Shell] [honwen/luci-app-shadowsocksr](https://github.com/honwen/luci-app-shadowsocksr) 
- [**81**星][1y] [Py] [justsoos/ss-ssr-v2ray-gadget](https://github.com/justsoos/ss-ssr-v2ray-gadget) 
- [**75**星][7m] [Py] [huaisha1224/shadowsocks-client](https://github.com/huaisha1224/shadowsocks-client) 
- [**71**星][2y] [HTML] [onplus/shadowsocks-websocket-python](https://github.com/onplus/shadowsocks-websocket-python) 
- [**65**星][8m] [Dockerfile] [hangim/kcp-shadowsocks-docker](https://github.com/hangim/kcp-shadowsocks-docker) 
- [**65**星][2y] [Go] [ihciah/inner-shadowsocks](https://github.com/ihciah/inner-shadowsocks) 
- [**57**星][5y] [CoffeeScript] [lupino/shadowsocks-gui](https://github.com/lupino/shadowsocks-gui) 
- [**57**星][13d] [JS] [paradiseduo/shadowsocksx-ng-r8](https://github.com/paradiseduo/shadowsocksx-ng-r8) 
- [**54**星][1y] [PHP] [ahref-group/superpanel](https://github.com/ahref-group/superpanel) 
- [**53**星][2y] [HTML] [jm33-m0/gfw_scripts](https://github.com/jm33-m0/gfw_scripts) 
- [**53**星][6m] [JS] [yzyjim/shadowsocks-back-china-pac](https://github.com/yzyjim/shadowsocks-back-china-pac) 
- [**51**星][18d] [C] [ixzzving/ssr-vpn](https://github.com/ixzzving/ssr-vpn) 
- [**41**星][4m] [C++] [lianglixin/sksocks](https://github.com/lianglixin/sksocks) 


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
- [**82**星][8m] [Py] [npist/v2rayms](https://github.com/npist/v2rayms) 
- [**78**星][2y] [nanqinlang-mogic/v2ray](https://github.com/nanqinlang-mogic/v2ray) 
- [**77**星][20d] [Objective-C] [gssdromen/v2rayc](https://github.com/gssdromen/v2rayc) 
- [**61**星][21d] [Py] [boypt/vmess2json](https://github.com/boypt/vmess2json) 


### <a id="891b953fda837ead9eff17ff2626b20a"></a>VPN


- [**446**星][3y] [Py] [vpnguy-zz/ntpdos](https://github.com/vpnguy-zz/ntpdos) 
- [**419**星][19d] [hugetiny/awesome-vpn](https://github.com/hugetiny/awesome-vpn) 




***


## <a id="1233584261c0cd5224b6e90a98cc9a94"></a>渗透&&offensive&&渗透框架&&后渗透框架


### <a id="2e40f2f1df5d7f93a7de47bf49c24a0e"></a>未分类-Pentest


- [**5721**星][2y] [Py] [newsapps/beeswithmachineguns](https://github.com/newsapps/beeswithmachineguns) 创建多个micro EC2实例, 攻击指定Web App
- [**3005**星][3m] [Py] [spiderlabs/responder](https://github.com/spiderlabs/responder) LLMNR/NBT-NS/MDNS投毒，内置HTTP/SMB/MSSQL/FTP/LDAP认证服务器, 支持NTLMv1/NTLMv2/LMv2
- [**2013**星][1m] [C++] [lordnoteworthy/al-khaser](https://github.com/lordnoteworthy/al-khaser) 
    - 重复区段: [工具/恶意代码&&Malware&&APT](#8cb1c42a29fa3e8825a0f8fca780c481) |
- [**1820**星][3y] [Java] [chora10/cknife](https://github.com/chora10/cknife) 
- [**1721**星][1m] [Go] [chaitin/xray](https://github.com/chaitin/xray) 
- [**1444**星][1m] [C] [ufrisk/pcileech](https://github.com/ufrisk/pcileech) 直接内存访问（DMA：Direct Memory Access）攻击工具。通过 PCIe 硬件设备使用 DMA，直接读写目标系统的内存。目标系统不需要安装驱动。
- [**1393**星][4m] [yadox666/the-hackers-hardware-toolkit](https://github.com/yadox666/the-hackers-hardware-toolkit) 
- [**1361**星][2m] [Py] [ekultek/whatwaf](https://github.com/ekultek/whatwaf) 
- [**1212**星][3m] [Py] [owtf/owtf](https://github.com/owtf/owtf) 进攻性 Web 测试框架。着重于 OWASP + PTES，尝试统合强大的工具，提高渗透测试的效率。大部分以Python 编写
- [**1125**星][3y] [PowerShell] [powershellempire/powertools](https://github.com/powershellempire/powertools) 
- [**1024**星][2y] [PowerShell] [nccgroup/redsnarf](https://github.com/nccgroup/redsnarf) redsnarf：渗透测试工具，使用OpSec Safe 技术从 Windows 工作站，服务器和域控制器提取 hash 和凭据
- [**945**星][19d] [C] [bt3gl/pentesting-toolkit](https://github.com/bt3gl/Pentesting-Toolkit) 
    - 重复区段: [工具/CTF&&HTB/收集](#30c4df38bcd1abaaaac13ffda7d206c6) |
- [**943**星][4m] [Py] [hatriot/zarp](https://github.com/hatriot/zarp) 网络攻击工具，主要是本地网络攻击
- [**934**星][2y] [Perl] [infobyte/evilgrade](https://github.com/infobyte/evilgrade) 供应链攻击: 注入虚假的update
- [**918**星][1m] [Py] [d4vinci/one-lin3r](https://github.com/d4vinci/one-lin3r) 轻量级框架，提供在渗透测试中需要的所有one-liners
- [**808**星][1m] [Py] [jeffzh3ng/fuxi](https://github.com/jeffzh3ng/fuxi) 
- [**804**星][2y] [Ruby] [dmayer/idb](https://github.com/dmayer/idb) idb：iOS 渗透和研究过程中简化一些常见的任务
    - 重复区段: [工具/移动&&Mobile/iOS&&MacOS&&iPhone&&iPad&&iWatch](#dbde77352aac39ee710d3150a921bcad) |
- [**784**星][6m] [Py] [jivoi/pentest](https://github.com/jivoi/pentest) 
- [**728**星][7m] [Py] [gkbrk/slowloris](https://github.com/gkbrk/slowloris) 
- [**698**星][2y] [PowerShell] [samratashok/kautilya](https://github.com/samratashok/kautilya) 
- [**692**星][2y] [Py] [sensepost/det](https://github.com/sensepost/det) 
- [**687**星][16d] [voorivex/pentest-guide](https://github.com/voorivex/pentest-guide) 
- [**666**星][5m] [leezj9671/pentest_interview](https://github.com/leezj9671/pentest_interview) 
- [**652**星][4y] [Py] [praetorian-code/pentestly](https://github.com/praetorian-code/pentestly) 
- [**610**星][9m] [Py] [epsylon/ufonet](https://github.com/epsylon/ufonet) 
- [**492**星][5y] [Py] [offensivepython/nscan](https://github.com/offensivepython/nscan) Fast internet-wide scanner
- [**489**星][13d] [netbiosx/checklists](https://github.com/netbiosx/checklists) 
- [**487**星][16d] [Ruby] [hackplayers/evil-winrm](https://github.com/hackplayers/evil-winrm) 
- [**487**星][1y] [Shell] [leonteale/pentestpackage](https://github.com/leonteale/pentestpackage) 
- [**479**星][10m] [Ruby] [sidaf/homebrew-pentest](https://github.com/sidaf/homebrew-pentest) 
- [**464**星][7m] [Java] [alpha1e0/pentestdb](https://github.com/alpha1e0/pentestdb) 
- [**459**星][2m] [C++] [fsecurelabs/c3](https://github.com/FSecureLABS/C3) 
- [**457**星][10m] [PHP] [l3m0n/pentest_tools](https://github.com/l3m0n/pentest_tools) 
- [**455**星][3y] [valvesoftware/csgo-osx-linux](https://github.com/ValveSoftware/csgo-osx-linux) 
- [**454**星][2y] [Py] [yukinoshita47/yuki-chan-the-auto-pentest](https://github.com/yukinoshita47/yuki-chan-the-auto-pentest) 
- [**444**星][15d] [C++] [danielkrupinski/osiris](https://github.com/danielkrupinski/osiris) 
- [**439**星][7m] [C++] [rek7/mxtract](https://github.com/rek7/mxtract) Offensive Memory Extractor & Analyzer
- [**438**星][3y] [Py] [brianwrf/hackutils](https://github.com/brianwrf/hackutils) 
- [**437**星][3y] [aptive/penetration-testing-tools](https://github.com/aptive/penetration-testing-tools) 
- [**436**星][3y] [CSS] [graniet/chromebackdoor](https://github.com/graniet/chromebackdoor) 
- [**432**星][3m] [mel0day/redteam-bcs](https://github.com/mel0day/redteam-bcs) 
- [**414**星][18d] [PHP] [gwen001/pentest-tools](https://github.com/gwen001/pentest-tools) 
- [**414**星][2y] [Py] [kvasirsecurity/kvasir](https://github.com/kvasirsecurity/kvasir) Penetration Test Data Management
- [**414**星][3y] [Py] [x3omdax/penbox](https://github.com/x3omdax/penbox) 
- [**404**星][1m] [Py] [admintony/prepare-for-awd](https://github.com/admintony/prepare-for-awd) 
- [**401**星][9m] [Py] [christruncer/pentestscripts](https://github.com/christruncer/pentestscripts) 
- [**398**星][27d] [PowerShell] [s3cur3th1ssh1t/winpwn](https://github.com/S3cur3Th1sSh1t/WinPwn) 
- [**388**星][12m] [Py] [cr4shcod3/pureblood](https://github.com/cr4shcod3/pureblood) 
- [**386**星][9m] [Go] [amyangxyz/assassingo](https://github.com/amyangxyz/assassingo) 
- [**385**星][3m] [ansjdnakjdnajkd/ios](https://github.com/ansjdnakjdnajkd/ios) 
    - 重复区段: [工具/移动&&Mobile/iOS&&MacOS&&iPhone&&iPad&&iWatch](#dbde77352aac39ee710d3150a921bcad) |
- [**385**星][23d] [Py] [clr2of8/dpat](https://github.com/clr2of8/dpat) 
- [**384**星][3y] [Py] [mandatoryprogrammer/cloudflare_enum](https://github.com/mandatoryprogrammer/cloudflare_enum) 
- [**378**星][6m] [unprovable/pentesthardware](https://github.com/unprovable/pentesthardware) 
- [**372**星][3y] [georgiaw/smartphone-pentest-framework](https://github.com/georgiaw/smartphone-pentest-framework) 
- [**371**星][8m] [C] [ridter/pentest](https://github.com/ridter/pentest) 
- [**368**星][4m] [C#] [bitsadmin/nopowershell](https://github.com/bitsadmin/nopowershell) 使用C#"重写"的PowerShell, 支持执行与PowerShell类似的命令, 然而对所有的PowerShell日志机制都不可见
- [**350**星][2m] [Shell] [maldevel/pentestkit](https://github.com/maldevel/pentestkit) 
- [**346**星][10m] [Py] [darkspiritz/darkspiritz](https://github.com/darkspiritz/darkspiritz) 
- [**343**星][2y] [Go] [propervillain/moistpetal](https://github.com/propervillain/moistpetal) 模块化的 RedTeam 恶意代码框架
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
- [**294**星][1y] [PHP] [interference-security/empire-web](https://github.com/interference-security/empire-web) PowerShell Empire 的Web界面,
- [**292**星][27d] [Lua] [pentesteracademy/patoolkit](https://github.com/pentesteracademy/patoolkit) 
- [**286**星][1y] [C++] [paranoidninja/pandoras-box](https://github.com/paranoidninja/pandoras-box) 
- [**283**星][1m] [Py] [bishopfox/eyeballer](https://github.com/bishopfox/eyeballer) 
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |
- [**267**星][18d] [Go] [rmikehodges/hidensneak](https://github.com/rmikehodges/hidensneak) 
- [**263**星][2y] [Py] [enddo/smod](https://github.com/enddo/smod) 
- [**252**星][13d] [anyeduke/enterprise-security-skill](https://github.com/anyeduke/enterprise-security-skill) 
- [**252**星][1y] [PowerShell] [mdsecresearch/lyncsniper](https://github.com/mdsecresearch/lyncsniper) A tool for penetration testing Skype for Business and Lync deployments
- [**251**星][3m] [Py] [giantbranch/python-hacker-code](https://github.com/giantbranch/python-hacker-code) 
- [**250**星][2y] [PowerShell] [killswitch-gui/pentesting-scripts](https://github.com/killswitch-gui/pentesting-scripts) 
- [**248**星][5y] [Py] [allfro/sploitego](https://github.com/allfro/sploitego) 
- [**248**星][2y] [JS] [jesusprubio/bluebox-ng](https://github.com/jesusprubio/bluebox-ng) 
- [**246**星][2y] [Go] [dzonerzy/gowapt](https://github.com/dzonerzy/gowapt) 
- [**240**星][2m] [Shell] [leviathan36/kaboom](https://github.com/leviathan36/kaboom) 
- [**238**星][25d] [PowerShell] [sdcampbell/internal-pentest-playbook](https://github.com/sdcampbell/internal-pentest-playbook) 
- [**225**星][8m] [Go] [stevenaldinger/decker](https://github.com/stevenaldinger/decker) 
- [**216**星][5m] [Py] [mgeeky/tomcatwardeployer](https://github.com/mgeeky/tomcatwardeployer) 
- [**211**星][19d] [JS] [giper45/dockersecurityplayground](https://github.com/giper45/dockersecurityplayground) 
- [**199**星][10m] [Py] [infamoussyn/rogue](https://github.com/infamoussyn/rogue) 
- [**198**星][2y] [C#] [jaredhaight/psattackbuildtool](https://github.com/jaredhaight/psattackbuildtool) 
- [**195**星][5y] [C#] [nccgroup/upnp-pentest-toolkit](https://github.com/nccgroup/upnp-pentest-toolkit) 
- [**193**星][2m] [Shell] [keepwannabe/remot3d](https://github.com/keepwannabe/remot3d) is a simple tool created for large pentesters as well as just for the pleasure of defacers to control server by backdoors
- [**192**星][11m] [JS] [zer4tul/hacker-howto](https://github.com/zer4tul/hacker-howto) 
- [**185**星][11m] [JS] [78778443/permeate](https://github.com/78778443/permeate) 
- [**182**星][4y] [rmusser01/cheatsheets](https://github.com/rmusser01/cheatsheets) 
- [**179**星][2y] [PowerShell] [cobbr/obfuscatedempire](https://github.com/cobbr/obfuscatedempire) 
- [**177**星][2y] [Py] [brucetg/pentest-tools](https://github.com/brucetg/pentest-tools) 
- [**176**星][2y] [Shell] [bitvijays/pentest-scripts](https://github.com/bitvijays/pentest-scripts) 渗透用脚本
- [**172**星][7y] [Py] [grutz/h3c-pt-tools](https://github.com/grutz/h3c-pt-tools) 
- [**172**星][6m] [Java] [ota4j-team/opentest4j](https://github.com/ota4j-team/opentest4j) 
- [**171**星][5m] [Py] [lmco/dart](https://github.com/lmco/dart) 
- [**170**星][3y] [Py] [4shadoww/hakkuframework](https://github.com/4shadoww/hakkuframework) 
- [**169**星][2m] [Ruby] [vonahisec/leprechaun](https://github.com/vonahisec/leprechaun) 
- [**168**星][5y] [Puppet] [garethr/pentesting-playground](https://github.com/garethr/pentesting-playground) 
- [**167**星][1y] [Py] [milo2012/pentest_scripts](https://github.com/milo2012/pentest_scripts) 
- [**164**星][3m] [Py] [adamcaudill/yawast](https://github.com/adamcaudill/yawast) 
- [**163**星][4m] [C++] [creddefense/creddefense](https://github.com/creddefense/creddefense) 
- [**157**星][2y] [PowerShell] [ankh2054/windows-pentest](https://github.com/ankh2054/windows-pentest) 
- [**157**星][24d] [C#] [mr-un1k0d3r/redteamcsharpscripts](https://github.com/mr-un1k0d3r/redteamcsharpscripts) 
- [**154**星][10m] [Py] [epsylon/cintruder](https://github.com/epsylon/cintruder) 
- [**153**星][2y] [Py] [kuburan/txtool](https://github.com/kuburan/txtool) 
- [**152**星][3y] [Ruby] [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy) 
- [**151**星][4m] [Shell] [0xmitsurugi/gimmecredz](https://github.com/0xmitsurugi/gimmecredz) 
- [**150**星][1m] [Py] [c0rvax/project-black](https://github.com/c0rvax/project-black) 
- [**150**星][1y] [Py] [shawarkhanethicalhacker/d-tect](https://github.com/shawarkhanethicalhacker/d-tect) 
- [**150**星][2m] [Py] [swisskyrepo/graphqlmap](https://github.com/swisskyrepo/graphqlmap) 
- [**147**星][1m] [Go] [c-sto/recursebuster](https://github.com/c-sto/recursebuster) 
- [**146**星][2y] [Shell] [madmantm/ubuntu-pentest-tools](https://github.com/madmantm/ubuntu-pentest-tools) 
- [**145**星][2m] [Py] [secdec/adapt](https://github.com/secdec/adapt) WebApp自动化渗透测试工具
- [**143**星][4m] [C#] [mr-un1k0d3r/maliciousclickoncegenerator](https://github.com/Mr-Un1k0d3r/MaliciousClickOnceGenerator) 
- [**139**星][4y] [Py] [lauixdata/wechat_hack](https://github.com/lauixdata/wechat_hack) 
- [**133**星][3y] [PHP] [ksanchezcld/hacking_cheat_sheet](https://github.com/ksanchezcld/hacking_cheat_sheet) 
- [**132**星][10m] [Ruby] [bahaabdelwahed/killshot](https://github.com/bahaabdelwahed/killshot) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |[工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞扫描&&挖掘&&发现/漏洞扫描/未分类](#0ed7e90d216a8a5be1dafebaf9eaeb5d) |
- [**132**星][3m] [Py] [reb311ion/rebel-framework](https://github.com/reb311ion/rebel-framework) 
- [**130**星][2y] [C#] [xiaoxiaoleo/windows_pentest_tools](https://github.com/xiaoxiaoleo/windows_pentest_tools) 
- [**128**星][30d] [Py] [3xpl017/netpwn](https://github.com/3xpl017/netpwn) 
- [**123**星][2y] [HTML] [alienwithin/owasp-mth3l3m3nt-framework](https://github.com/alienwithin/owasp-mth3l3m3nt-framework) 辅助渗透测试与漏洞利用
- [**123**星][9m] [Shell] [weaknetlabs/penetration-testing-grimoire](https://github.com/weaknetlabs/penetration-testing-grimoire) 
- [**122**星][21d] [Py] [elevenpaths/homepwn](https://github.com/elevenpaths/homepwn) 
- [**122**星][2m] [Py] [highmeh/pentest_scripts](https://github.com/highmeh/pentest_scripts) 
- [**122**星][6m] [Py] [wfzsec/awd_attack_framework](https://github.com/wfzsec/awd_attack_framework) 
- [**121**星][4y] [Py] [pentestmonkey/gateway-finder](https://github.com/pentestmonkey/gateway-finder) 
- [**120**星][3y] [Assembly] [yaseng/pentest](https://github.com/yaseng/pentest) 
- [**120**星][13d] [Py] [yuxiaokui/intranet-penetration](https://github.com/yuxiaokui/intranet-penetration) 
- [**118**星][10m] [Py] [ghostmanager/shepherd](https://github.com/ghostmanager/shepherd) 
- [**117**星][1m] [C] [hydrabus/hydrafw](https://github.com/hydrabus/hydrafw) 
- [**117**星][13d] [Java] [mr-xn/penetration_testing_poc](https://github.com/mr-xn/penetration_testing_poc) 
- [**117**星][8m] [Shell] [vishnudxb/automated-pentest](https://github.com/vishnudxb/automated-pentest) 
- [**116**星][1y] [Go] [t94j0/airmaster](https://github.com/t94j0/airmaster) 
- [**115**星][2m] [Py] [hugsy/stuff](https://github.com/hugsy/stuff) 
- [**113**星][27d] [govanguard/list-pentest-tools](https://github.com/govanguard/list-pentest-tools) 
- [**113**星][1y] [Py] [khast3x/offensive-dockerfiles](https://github.com/khast3x/offensive-dockerfiles) 
- [**113**星][4y] [Perl] [reider-roque/pentest-tools](https://github.com/reider-roque/pentest-tools) 
- [**112**星][2y] [JS] [landgrey/dnstricker](https://github.com/landgrey/dnstricker) 
- [**112**星][3y] [netbiosx/pentest-bookmarks](https://github.com/netbiosx/pentest-bookmarks) 
- [**110**星][3y] [C] [jongates/jon](https://github.com/jongates/jon) 
- [**108**星][10m] [Py] [ekultek/graffiti](https://github.com/ekultek/graffiti) 
- [**105**星][10m] [hongrisec/ai-machine-learning-security](https://github.com/hongrisec/ai-machine-learning-security) 
- [**103**星][3y] [Py] [allyshka/pwngitmanager](https://github.com/allyshka/pwngitmanager) 
- [**103**星][3y] [Py] [samratashok/continuousintrusion](https://github.com/samratashok/continuousintrusion) 
- [**101**星][5m] [Py] [anx1ang/poc_pentest](https://github.com/anx1ang/poc_pentest) 
- [**101**星][7m] [PowerShell] [leeberg/bluecommand](https://github.com/leeberg/bluecommand) 
- [**101**星][3y] [Py] [n00py/norknork](https://github.com/n00py/norknork) 
- [**100**星][11m] [Py] [krintoxi/noobsec-toolkit](https://github.com/krintoxi/noobsec-toolkit) 
- [**99**星][9y] [C] [tecknicaltom/dsniff](https://github.com/tecknicaltom/dsniff) 
- [**98**星][5m] [Py] [smythtech/sdnpwn](https://github.com/smythtech/sdnpwn) SDN 渗透测试工具包。（SDN：Software-Defined Networks，软件定义网络）
- [**96**星][8m] [Shell] [baguswiratmaadi/catnip](https://github.com/baguswiratmaadi/catnip) 
- [**94**星][18d] [PowerShell] [awsmhacks/crackmapextreme](https://github.com/awsmhacks/crackmapextreme) 
- [**93**星][3y] [Py] [v1cker/src_edu](https://github.com/v1cker/src_edu) 
- [**92**星][8y] [Ruby] [mubix/not-in-pentesting-class](https://github.com/mubix/not-in-pentesting-class) 
- [**92**星][2y] [PowerShell] [sadprocessor/empiredog](https://github.com/sadprocessor/empiredog) 
- [**91**星][1y] [C] [mrschyte/pentestkoala](https://github.com/mrschyte/pentestkoala) pentestkoala：修改版dropbear SSH 服务器
- [**88**星][1y] [chihebchebbi/internet-of-things-pentesting-framework](https://github.com/chihebchebbi/internet-of-things-pentesting-framework) 
- [**87**星][3y] [Py] [boy-hack/pythonwebhack](https://github.com/boy-hack/pythonwebhack) 
- [**87**星][3y] [Go] [dutchcoders/ares](https://github.com/dutchcoders/ares) 
- [**84**星][10m] [Py] [422926799/python](https://github.com/422926799/python) 
- [**83**星][4m] [C#] [cobbr/elite](https://github.com/cobbr/elite) 
- [**83**星][1y] [Py] [jiangsir404/s7scan](https://github.com/jiangsir404/s7scan) 
- [**82**星][2m] [Py] [kcarretto/arsenal](https://github.com/kcarretto/arsenal) 
- [**82**星][7m] [Py] [viralmaniar/peekaboo](https://github.com/viralmaniar/peekaboo) 
- [**81**星][2y] [diablohorn/yara4pentesters](https://github.com/diablohorn/yara4pentesters) 
- [**80**星][3y] [glinares/hephaestus](https://github.com/glinares/hephaestus) 
- [**77**星][3y] [Shell] [ank1036official/git_pentesting_toolkit](https://github.com/ank1036official/git_pentesting_toolkit) 
- [**77**星][19d] [HTML] [vergl4s/pentesting-dump](https://github.com/vergl4s/pentesting-dump) 
- [**75**星][4y] [Py] [ahhh/reverse_https_bot](https://github.com/ahhh/reverse_https_bot) 
- [**75**星][3y] [Py] [antojoseph/diff-droid](https://github.com/antojoseph/diff-droid) diff-droid：使用 Frida对手机渗透测试的若干脚本
- [**73**星][3y] [Py] [j0bin/pentest-resources](https://github.com/j0bin/pentest-resources) 
- [**72**星][4y] [Visual Basic] [twi1ight/ad-pentest-script](https://github.com/twi1ight/ad-pentest-script) 
- [**71**星][2y] [HTML] [jmortega/python-pentesting](https://github.com/jmortega/python-pentesting) 
- [**69**星][1m] [Py] [takuzoo3868/penta](https://github.com/takuzoo3868/penta) 
- [**68**星][3y] [Py] [kkar/vbs-obfuscator-in-python](https://github.com/kkar/vbs-obfuscator-in-python) 
- [**67**星][7m] [Shell] [baguswiratmaadi/reverie](https://github.com/baguswiratmaadi/reverie) 
- [**66**星][21d] [Shell] [ankh2054/linux-pentest](https://github.com/ankh2054/linux-pentest) 
- [**65**星][2y] [Shell] [bluscreenofjeff/ccdc-scripts](https://github.com/bluscreenofjeff/ccdc-scripts) 
- [**64**星][4m] [C#] [codedx/codepulse](https://github.com/codedx/codepulse) 
- [**64**星][10m] [C#] [leoloobeek/csharp](https://github.com/leoloobeek/csharp) 
- [**64**星][4m] [sh1n0g1/shinobot](https://github.com/sh1n0g1/shinobot) 
- [**63**星][1y] [C#] [rvrsh3ll/sharpfruit](https://github.com/rvrsh3ll/sharpfruit) 
- [**63**星][8m] [weekend-hub/pentest-tools](https://github.com/weekEND-hub/pentest-tools) 
- [**62**星][2y] [Perl] [0x90/vpn-arsenal](https://github.com/0x90/vpn-arsenal) 
- [**61**星][1y] [Py] [ha3mrx/hacking](https://github.com/ha3mrx/hacking) 
- [**61**星][2y] [Py] [iotsec/z3sec](https://github.com/iotsec/z3sec) 
- [**60**星][7m] [JS] [coolervoid/nozes](https://github.com/coolervoid/nozes) 
- [**60**星][6m] [Ruby] [skahwah/automato](https://github.com/skahwah/automato) 
- [**59**星][5y] [PowerShell] [harmj0y/cortana](https://github.com/harmj0y/cortana) 
- [**58**星][3y] [ASP] [merttasci/weapons4pentester](https://github.com/merttasci/weapons4pentester) 
- [**58**星][7y] [Py] [opensecurityresearch/pentest-scripts](https://github.com/opensecurityresearch/pentest-scripts) 
- [**57**星][2y] [Batchfile] [absolomb/pentesting](https://github.com/absolomb/pentesting) 
- [**57**星][4m] [Py] [phackt/pentest](https://github.com/phackt/pentest) 
- [**54**星][3m] [ascotbe/osmographic-brain-mapping](https://github.com/ascotbe/osmographic-brain-mapping) 
- [**54**星][4m] [Py] [dr0op/bufferfly](https://github.com/dr0op/bufferfly) 
- [**54**星][2y] [g-solaria/osintforpentests](https://github.com/g-solaria/osintforpentests) 
- [**54**星][15d] [redteamwing/pentest_wiki](https://github.com/RedTeamWing/Pentest_WiKi) 
- [**52**星][5y] [Py] [x0day/multiproxies](https://github.com/x0day/multiproxies) 
- [**51**星][1y] [Py] [carnal0wnage/pentesty_scripts](https://github.com/carnal0wnage/pentesty_scripts) 
- [**51**星][9m] [Java] [empireproject/empiremobile](https://github.com/empireproject/empiremobile) 
- [**51**星][2y] [harshilpatel007/hackinglabs](https://github.com/harshilpatel007/hackinglabs) 
- [**49**星][9m] [aungthurhahein/red-team-curation-list](https://github.com/aungthurhahein/red-team-curation-list) 
- [**49**星][12m] [opensourcepentest/tools](https://github.com/opensourcepentest/tools) 
- [**49**星][3m] [HTML] [0xbird/0xbird.github.io](https://github.com/0xbird/0xbird.github.io) 
- [**48**星][3y] [Py] [ayoul3/cicspwn](https://github.com/ayoul3/cicspwn) 
- [**48**星][2y] [PHP] [daudmalik06/reconcat](https://github.com/daudmalik06/reconcat) 
- [**47**星][12m] [Shell] [appsecconsulting/pentest-tools](https://github.com/appsecconsulting/pentest-tools) 
- [**47**星][5m] [sekhan/nightpi](https://github.com/sekhan/nightpi) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |
- [**46**星][6m] [Py] [hucmosin/purelove](https://github.com/hucmosin/purelove) 
- [**46**星][7m] [JS] [radenvodka/pentol](https://github.com/radenvodka/pentol) 
- [**46**星][13d] [PowerShell] [s3cur3th1ssh1t/creds](https://github.com/S3cur3Th1sSh1t/Creds) 
    - 重复区段: [工具/事件响应&&取证&&内存取证&&数字取证/取证&&Forensics&&数字取证&&内存取证](#1fc5d3621bb13d878f337c8031396484) |
- [**43**星][8y] [pentestmonkey/timing-attack-checker](https://github.com/pentestmonkey/timing-attack-checker) 
- [**43**星][2y] [Shell] [wh1t3rh1n0/pentest-scripts](https://github.com/wh1t3rh1n0/pentest-scripts) 
- [**43**星][2y] [xazlsec/pentest-project-lists](https://github.com/xazlsec/pentest-project-lists) 
- [**42**星][1y] [tbgsecurity/weaponize_splunk](https://github.com/tbgsecurity/weaponize_splunk) 
- [**41**星][1m] [Shell] [r0bag/pentest](https://github.com/r0bag/pentest) 
- [**40**星][26d] [Py] [n3k/pentest](https://github.com/n3k/pentest) 
- [**40**星][1y] [Py] [v1v1/sleight](https://github.com/v1v1/sleight) 
- [**39**星][10m] [PowerShell] [mburrough/pentestingazureapps](https://github.com/mburrough/pentestingazureapps) 
- [**39**星][2y] [Py] [villanch/g3ar](https://github.com/villanch/g3ar) 
- [**39**星][1y] [Py] [wangyihang/pwnme](https://github.com/wangyihang/pwnme) 
- [**38**星][9m] [PowerShell] [curtbraz/invoke-neutralizeav](https://github.com/curtbraz/invoke-neutralizeav) 
- [**38**星][4y] [HTML] [tevora-threat/splunk_pentest_app](https://github.com/tevora-threat/splunk_pentest_app) 
- [**37**星][6m] [Batchfile] [cervoise/abuse-bash-for-windows](https://github.com/cervoise/abuse-bash-for-windows) 
- [**37**星][8m] [Go] [prsecurity/golang_c2](https://github.com/prsecurity/golang_c2) 
- [**36**星][11m] [C++] [3gstudent/from-system-authority-to-medium-authority](https://github.com/3gstudent/from-system-authority-to-medium-authority) 
- [**36**星][3y] [Py] [a7vinx/swarm](https://github.com/a7vinx/swarm) 
- [**36**星][3y] [C#] [gdssecurity/psattack](https://github.com/gdssecurity/psattack) 
- [**36**星][2y] [PowerShell] [rvrsh3ll/pentesting-scripts](https://github.com/rvrsh3ll/pentesting-scripts) 
- [**36**星][2y] [vduddu/pentestresources](https://github.com/vduddu/pentestresources) 
- [**36**星][1m] [Py] [nerrorsec/googledorker](https://github.com/nerrorsec/GoogleDorker) 
- [**36**星][2y] [vduddu/pentestresources](https://github.com/vduddu/PentestResources) 
- [**35**星][15d] [Py] [entynetproject/arissploit](https://github.com/entynetproject/arissploit) 
- [**35**星][4y] [Py] [ganapati/wpyscan](https://github.com/ganapati/wpyscan) 
- [**35**星][2y] [Go] [tomsteele/pen-utils](https://github.com/tomsteele/pen-utils) 
- [**35**星][1y] [ustayready/cloudburst](https://github.com/ustayready/cloudburst) 
- [**35**星][2y] [HTML] [electroniccats/samykamtools](https://github.com/ElectronicCats/SamyKamTools) 
- [**34**星][2m] [Py] [xuchaoa/ctf_awd_platform](https://github.com/xuchaoa/ctf_awd_platform) 
- [**34**星][13d] [CSS] [fabriziofubelli/black-widow](https://github.com/fabriziofubelli/black-widow) 
- [**33**星][1y] [Py] [fnk0c/organon](https://github.com/fnk0c/organon) 
- [**33**星][2y] [Java] [onurkarasalihoglu/pentest-tools](https://github.com/onurkarasalihoglu/pentest-tools) 
- [**33**星][2y] [ptresearch/pentest-detections](https://github.com/ptresearch/pentest-detections) 
- [**32**星][4y] [Py] [trustedsec/crackmapexec](https://github.com/trustedsec/crackmapexec) 
- [**30**星][2y] [Py] [ffmancera/pentesting-multitool](https://github.com/ffmancera/pentesting-multitool) 
- [**30**星][5y] [Py] [mstsec/mst](https://github.com/mstsec/mst) 
- [**30**星][1y] [HTML] [p3t3rp4rk3r/my_dirty_scripts](https://github.com/p3t3rp4rk3r/my_dirty_scripts) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |
- [**30**星][2y] [Py] [spencerdodd/pysploit](https://github.com/spencerdodd/pysploit) 
- [**29**星][2m] [ahmetgurel/pentest-hints](https://github.com/ahmetgurel/pentest-hints) 
- [**29**星][1y] [Tcl] [mohemiv/tcltools](https://github.com/mohemiv/tcltools) 
- [**29**星][5m] [C] [pentesteracademy/linux-rootkits-red-blue-teams](https://github.com/pentesteracademy/linux-rootkits-red-blue-teams) 
- [**28**星][12m] [Py] [alienwithin/scripts-sploits](https://github.com/alienwithin/scripts-sploits) 
- [**28**星][2y] [Py] [ihebski/pentest-chainsaw](https://github.com/ihebski/pentest-chainsaw) 
- [**28**星][12m] [Py] [jumbo-wjb/jpentest](https://github.com/jumbo-wjb/jpentest) 
- [**28**星][5m] [JS] [virink/as_plugin_godofhacker](https://github.com/virink/as_plugin_godofhacker) 
- [**27**星][2m] [Go] [dharmaofcode/gorp](https://github.com/dharmaofcode/gorp) 
- [**27**星][3y] [Py] [nicksanzotta/smbshakedown](https://github.com/nicksanzotta/smbshakedown) 
- [**27**星][9m] [Py] [noobscode/kalel](https://github.com/noobscode/kalel) 
- [**26**星][2y] [Py] [syslog777/psak](https://github.com/syslog777/psak) 
- [**25**星][3y] [Py] [graniet/domff](https://github.com/graniet/domff) 
- [**25**星][3y] [Py] [kostrin/pillage](https://github.com/kostrin/pillage) 
- [**25**星][2y] [Py] [mgeeky/visualbasicobfuscator](https://github.com/mgeeky/visualbasicobfuscator) 
- [**25**星][1y] [Go] [opennota/hydra](https://github.com/opennota/hydra) 
- [**25**星][2y] [Py] [owtf/ptp](https://github.com/owtf/ptp) 
- [**25**星][3m] [Go] [releasel0ck/nettracer](https://github.com/releasel0ck/nettracer) 
- [**25**星][17d] [PHP] [telnet22/kn0ck](https://github.com/telnet22/kn0ck) 
- [**25**星][5y] [Py] [webstersprodigy/webstersprodigy](https://github.com/webstersprodigy/webstersprodigy) 
- [**25**星][4y] [C] [riswandans/litesploit](https://github.com/riswandans/litesploit) 
- [**24**星][2y] [Py] [thekingofduck/autosploit_chs](https://github.com/thekingofduck/autosploit_chs) 
- [**24**星][3y] [woodspeed/pentest](https://github.com/woodspeed/pentest) 
- [**23**星][5m] [Py] [githacktools/githacktools](https://github.com/githacktools/githacktools) 
- [**23**星][6y] [Py] [nccgroup/xcavator](https://github.com/nccgroup/xcavator) 
- [**23**星][1y] [Visual Basic] [xiaoxiaoleo/pentest-script](https://github.com/xiaoxiaoleo/pentest-script) 
- [**23**星][16d] [Py] [bing0o/python-scripts](https://github.com/bing0o/python-scripts) 
- [**22**星][4y] [Py] [nitscan/inlinux](https://github.com/nitscan/inlinux) 
- [**22**星][2y] [Java] [secdec/pen-test-automation](https://github.com/secdec/pen-test-automation) 
- [**21**星][6m] [Py] [seyptoo/7z-bruteforce](https://github.com/seyptoo/7z-bruteforce) 
- [**20**星][2y] [deepwn/dn2.io](https://github.com/deepwn/dn2.io) 
- [**20**星][2y] [PowerShell] [linuz/powerhungry](https://github.com/linuz/powerhungry) 
- [**20**星][3y] [HTML] [pentestbox/pentest-box-tools](https://github.com/pentestbox/pentest-box-tools) 
- [**1**星][4y] [Py] [rafael-aba/penetrationtesting](https://github.com/rafael-aba/PenetrationTesting) 


### <a id="9081db81f6f4b78d5c263723a3f7bd6d"></a>收集


- [**912**星][2y] [C#] [jaredhaight/psattack](https://github.com/jaredhaight/psattack) 组合知名的PowerShell安全工具，生成自包含/自定义的PowerShell控制台，简化在渗透中PowerShell命令的使用。支持提权、侦查、数据渗透等。
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
- [**3173**星][1y] [Py] [kootenpv/whereami](https://github.com/kootenpv/whereami) 使用Wifi信号和机器学习预测你的位置，精确度2-10米
- [**2915**星][1y] [Py] [danmcinerney/wifijammer](https://github.com/danmcinerney/wifijammer) 持续劫持范围内的Wifi客户端和AP
- [**2723**星][1y] [C] [vanhoefm/krackattacks-scripts](https://github.com/vanhoefm/krackattacks-scripts) 检测客户端和AP是否受KRACK漏洞影响
- [**2706**星][8m] [Py] [p0cl4bs/wifi-pumpkin](https://github.com/P0cL4bs/WiFi-Pumpkin) AP攻击框架, 创建虚假网络, 取消验证攻击、请求和凭证监控、透明代理、Windows更新攻击、钓鱼管理、ARP投毒、DNS嗅探、Pumpkin代理、动态图片捕获等
- [**2480**星][15d] [Py] [evilsocket/pwnagotchi](https://github.com/evilsocket/pwnagotchi) 
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |[工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**2433**星][2m] [C] [martin-ger/esp_wifi_repeater](https://github.com/martin-ger/esp_wifi_repeater) 
- [**2374**星][1y] [Py] [danmcinerney/lans.py](https://github.com/danmcinerney/lans.py) 
- [**2194**星][22d] [Shell] [v1s1t0r1sh3r3/airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) 
- [**2039**星][2y] [Py] [derv82/wifite](https://github.com/derv82/wifite) 自动化无线攻击工具
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/自动化](#fc8737aef0f59c3952d11749fe582dac) |
- [**1816**星][1y] [Py] [derv82/wifite2](https://github.com/derv82/wifite2) 无线网络审计工具wifite 的升级版/重制版
- [**1799**星][4m] [Shell] [arismelachroinos/lscript](https://github.com/arismelachroinos/lscript) 自动化无线渗透和Hacking 任务的脚本
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/自动化](#fc8737aef0f59c3952d11749fe582dac) |
- [**1527**星][1m] [Py] [k4m4/kickthemout](https://github.com/k4m4/kickthemout) 使用ARP欺骗，将设备从网络中踢出去
- [**1525**星][1y] [HTML] [qiwihui/hiwifi-ss](https://github.com/qiwihui/hiwifi-ss) 
- [**1246**星][2y] [JS] [samyk/skyjack](https://github.com/samyk/skyjack) 
- [**1244**星][1m] [C] [seemoo-lab/nexmon](https://github.com/seemoo-lab/nexmon) 
- [**1219**星][12d] [C] [aircrack-ng/aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) 
- [**1022**星][1m] [C] [t6x/reaver-wps-fork-t6x](https://github.com/t6x/reaver-wps-fork-t6x) 攻击 Wi-Fi Protected Setup (WPS)， 恢复 WPA/WPA2 密码
- [**998**星][12m] [Py] [entropy1337/infernal-twin](https://github.com/entropy1337/infernal-twin) 自动化无线Hack 工具
- [**987**星][1y] [Py] [tylous/sniffair](https://github.com/tylous/sniffair) 无线渗透框架. 解析被动收集的无线数据, 执行复杂的无线攻击
- [**983**星][1y] [HTML] [sensepost/mana](https://github.com/sensepost/mana) 
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**977**星][14d] [C] [s0lst1c3/eaphammer](https://github.com/s0lst1c3/eaphammer) 针对WPA2-Enterprise 网络的定向双重攻击（evil twin attacks）
- [**973**星][2y] [C] [wiire-a/pixiewps](https://github.com/wiire-a/pixiewps) 
- [**941**星][5y] [Py] [mothran/bunny](https://github.com/mothran/bunny) 
- [**903**星][1m] [TeX] [ethereum/yellowpaper](https://github.com/ethereum/yellowpaper) 
- [**818**星][2m] [C] [spacehuhn/wifi_ducky](https://github.com/spacehuhn/wifi_ducky) 
- [**796**星][1y] [Objective-C] [igrsoft/kismac2](https://github.com/igrsoft/kismac2) 
- [**792**星][2y] [Go] [schollz/find-lf](https://github.com/schollz/find-lf) 
- [**766**星][22d] [Py] [konradit/gopro-py-api](https://github.com/konradit/gopro-py-api) 
- [**755**星][7m] [Py] [misterbianco/boopsuite](https://github.com/MisterBianco/BoopSuite) 无线审计与安全测试
- [**676**星][10m] [Objective-C] [unixpickle/jamwifi](https://github.com/unixpickle/jamwifi) 
- [**649**星][7m] [C] [wifidog/wifidog-gateway](https://github.com/wifidog/wifidog-gateway) 
- [**608**星][3m] [C] [matheus-garbelini/esp32_esp8266_attacks](https://github.com/matheus-garbelini/esp32_esp8266_attacks) 
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞利用/Exp&&PoC](#5c1af335b32e43dba993fceb66c470bc) |
- [**562**星][1y] [Py] [softscheck/tplink-smartplug](https://github.com/softscheck/tplink-smartplug) 
- [**504**星][2y] [C] [samyk/opensesame](https://github.com/samyk/opensesame) 
- [**502**星][14d] [C++] [cyberman54/esp32-paxcounter](https://github.com/cyberman54/esp32-paxcounter) 
- [**466**星][3y] [Py] [dxa4481/wpa2-halfhandshake-crack](https://github.com/dxa4481/wpa2-halfhandshake-crack) 
- [**463**星][2m] [Shell] [staz0t/hashcatch](https://github.com/staz0t/hashcatch) 
- [**455**星][3m] [Java] [lennartkoopmann/nzyme](https://github.com/lennartkoopmann/nzyme) 直接收集空中的802.11 管理帧，并将其发送到 Graylog，用于WiFi IDS, 监控, 及事件响应。（Graylog：开源的日志管理系统）
- [**450**星][1m] [Py] [savio-code/fern-wifi-cracker](https://github.com/savio-code/fern-wifi-cracker) 无线安全审计和攻击工具, 能破解/恢复 WEP/WPA/WPSkey等
- [**398**星][5y] [vk496/linset](https://github.com/vk496/linset) linset：双面恶魔攻击（EvilTwin Attack）bash 脚本
- [**397**星][5y] [Py] [syworks/waidps](https://github.com/syworks/waidps) 
- [**396**星][18d] [C] [freifunk-gluon/gluon](https://github.com/freifunk-gluon/gluon) 
- [**387**星][1y] [Py] [jpaulmora/pyrit](https://github.com/jpaulmora/pyrit) 
- [**373**星][3m] [C++] [bastibl/gr-ieee802-11](https://github.com/bastibl/gr-ieee802-11) 
- [**349**星][2y] [Makefile] [opensecurityresearch/hostapd-wpe](https://github.com/opensecurityresearch/hostapd-wpe) 
- [**320**星][2m] [Shell] [vanhoefm/modwifi](https://github.com/vanhoefm/modwifi) 
- [**316**星][2m] [Java] [wiglenet/wigle-wifi-wardriving](https://github.com/wiglenet/wigle-wifi-wardriving) 
- [**310**星][3m] [TeX] [chronaeon/beigepaper](https://github.com/chronaeon/beigepaper) 
- [**295**星][4y] [samyk/proxygambit](https://github.com/samyk/proxygambit) 
- [**266**星][6m] [C] [br101/horst](https://github.com/br101/horst) 
- [**265**星][2m] [C] [sensepost/hostapd-mana](https://github.com/sensepost/hostapd-mana) 
- [**260**星][3y] [Py] [ecthros/pina-colada](https://github.com/ecthros/pina-colada) 
- [**256**星][3y] [Py] [rockymeza/wifi](https://github.com/rockymeza/wifi) 
- [**253**星][1y] [Py] [wipi-hunter/pidense](https://github.com/wipi-hunter/pidense) Monitor illegal wireless network activities.
- [**249**星][2y] [Py] [prahladyeri/hotspotd](https://github.com/prahladyeri/hotspotd) 
- [**237**星][7m] [Py] [lionsec/wifresti](https://github.com/lionsec/wifresti) 
- [**234**星][2m] [C] [mame82/logitacker](https://github.com/mame82/logitacker) 
- [**232**星][2y] [d33tah/call-for-wpa3](https://github.com/d33tah/call-for-wpa3) 
- [**228**星][5y] [squonk42/tl-wr703n](https://github.com/squonk42/tl-wr703n) 
- [**218**星][18d] [Py] [ghostop14/sparrow-wifi](https://github.com/ghostop14/sparrow-wifi) 
    - 重复区段: [工具/蓝牙&&Bluetooth](#ceb90405292daed9bb32ac20836c219a) |[工具/浏览嗅探&&流量拦截&&流量分析&&中间人/未分类-Network](#99398a5a8aaf99228829dadff48fb6a7) |
- [**216**星][2y] [Py] [kbdancer/tplinkkey](https://github.com/kbdancer/tplinkkey) 
- [**205**星][2y] [toleda/wireless_half-mini](https://github.com/toleda/wireless_half-mini) 
- [**198**星][2y] [C++] [rfidtool/esp-rfid-tool](https://github.com/rfidtool/esp-rfid-tool) 
- [**197**星][1y] [Shell] [aress31/wirespy](https://github.com/aress31/wirespy) 
- [**196**星][1y] [Py] [wipi-hunter/pikarma](https://github.com/WiPi-Hunter/PiKarma)  Detects wireless network attacks performed by KARMA module
- [**191**星][2y] [Py] [viralmaniar/wifi-dumper](https://github.com/viralmaniar/wifi-dumper) 
- [**178**星][5y] [Py] [rpp0/scapy-fakeap](https://github.com/rpp0/scapy-fakeap) 
- [**171**星][2m] [Py] [comthings/pandwarf](https://github.com/comthings/pandwarf) RF analysis tool with a sub-1 GHz wireless transceiver controlled by a smartphone or
- [**167**星][3y] [Shell] [0x90/wps-scripts](https://github.com/0x90/wps-scripts) 
- [**162**星][2y] [C] [gabrielrcouto/reaver-wps](https://github.com/gabrielrcouto/reaver-wps) 
- [**160**星][3y] [Py] [moha99sa/evilap_defender](https://github.com/moha99sa/evilap_defender) 
- [**158**星][3y] [Py] [hkm/whoishere.py](https://github.com/hkm/whoishere.py) 
- [**153**星][2m] [JS] [friedrith/node-wifi](https://github.com/friedrith/node-wifi) 
- [**149**星][2y] [Py] [cls1991/ng](https://github.com/cls1991/ng) 获取未连接的 Wifi 的密码
- [**149**星][5y] [Py] [devttys0/wps](https://github.com/devttys0/wps) 
- [**149**星][1y] [Shell] [hiruna/wifi-txpower-unlocker](https://github.com/hiruna/wifi-txpower-unlocker) bash 脚本, 从 Central Regulatory Domain Agent 和 Wireles Regulatory Database 获取源, 生成修改版的 regulatory.bin 并 patch 内核, 以解锁 WiFi TX power
- [**142**星][20d] [Py] [mubix/osx-wificleaner](https://github.com/mubix/osx-wificleaner) 
- [**137**星][15d] [Shell] [entynetproject/ehtools](https://github.com/entynetproject/ehtools) 
- [**136**星][7y] [Py] [gdssecurity/wifitap](https://github.com/gdssecurity/wifitap) 
- [**131**星][1y] [wpscanteam/wpscan-v3](https://github.com/wpscanteam/wpscan-v3) 
- [**127**星][3m] [Py] [kootenpv/access_points](https://github.com/kootenpv/access_points) 
- [**124**星][3y] [JS] [bakerface/wireless-tools](https://github.com/bakerface/wireless-tools) 
- [**121**星][4m] [Py] [veerendra2/wifi-deauth-attack](https://github.com/veerendra2/wifi-deauth-attack) 
- [**120**星][1m] [PHP] [binarymaster/3wifi](https://github.com/binarymaster/3wifi) 
- [**118**星][13d] [Py] [jgilhutton/pyxiewps](https://github.com/jgilhutton/PyxieWPS) 
- [**117**星][5y] [Shell] [d4rkcat/handshaker](https://github.com/d4rkcat/handshaker) 
- [**117**星][3y] [Py] [violentshell/rollmac](https://github.com/violentshell/rollmac) 
- [**116**星][3m] [Py] [bastibl/gr-keyfob](https://github.com/bastibl/gr-keyfob) 
- [**113**星][4y] [Py] [danmcinerney/wifi-monitor](https://github.com/danmcinerney/wifi-monitor) 
- [**110**星][11m] [Shell] [mi-al/wifi-autopwner](https://github.com/mi-al/wifi-autopwner) script to automate searching and auditing Wi-Fi networks with weak security
- [**109**星][6y] [edthamm/lootbooty](https://github.com/edthamm/lootbooty) 
- [**104**星][2y] [Py] [mehdilauters/wifiscanmap](https://github.com/mehdilauters/wifiscanmap) 
- [**101**星][2y] [C++] [mfontanini/dot11decrypt](https://github.com/mfontanini/dot11decrypt) 
- [**101**星][4m] [Py] [6e726d/wig](https://github.com/6e726d/wig) 
- [**100**星][1y] [Py] [securestate/eapeak](https://github.com/securestate/eapeak) 
- [**96**星][3y] [singe/wifi-frequency-hacker](https://github.com/singe/wifi-frequency-hacker) 
- [**94**星][5y] [lgrangeia/cupid](https://github.com/lgrangeia/cupid) 
- [**94**星][6y] [Py] [roglew/wifikill](https://github.com/roglew/wifikill) 
- [**90**星][4m] [C] [s0lst1c3/silentbridge](https://github.com/s0lst1c3/silentbridge) 
- [**88**星][3y] [Py] [chrizator/netattack](https://github.com/chrizator/netattack) 
- [**87**星][6y] [Py] [jordan-wright/python-wireless-attacks](https://github.com/jordan-wright/python-wireless-attacks) 
- [**87**星][4y] [Py] [aanarchyy/wifite-mod-pixiewps](https://github.com/aanarchyy/wifite-mod-pixiewps) 
- [**86**星][5y] [Py] [carmaa/nacker](https://github.com/carmaa/nacker) 
- [**83**星][7m] [Shell] [1n3/prism-ap](https://github.com/1n3/prism-ap) 
- [**81**星][3y] [C#] [basic4/widucky](https://github.com/basic4/widucky) 
- [**80**星][4y] [Py] [coresecurity/wiwo](https://github.com/helpsystems/wiwo) 
- [**79**星][8m] [Go] [schollz/find3-cli-scanner](https://github.com/schollz/find3-cli-scanner) 
- [**78**星][3y] [C] [ernacktob/esp8266_wifi_raw](https://github.com/ernacktob/esp8266_wifi_raw) 
- [**77**星][8y] [Py] [ts-way/gerix-wifi-cracker](https://github.com/ts-way/gerix-wifi-cracker) 
- [**75**星][6y] [C] [oblique/wificurse](https://github.com/oblique/wificurse) 
- [**75**星][1y] [Java] [schollz/find3-android-scanner](https://github.com/schollz/find3-android-scanner) 
- [**73**星][8m] [edelahozuah/awesome-wifi-security](https://github.com/edelahozuah/awesome-wifi-security) 
- [**73**星][5y] [Py] [ivanlei/airodump-iv](https://github.com/ivanlei/airodump-iv) 
- [**69**星][5y] [JS] [substack/wit](https://github.com/substack/wit) 
- [**67**星][2y] [Py] [s0lst1c3/sentrygun](https://github.com/s0lst1c3/sentrygun) 
- [**67**星][8y] [Py] [jedahan/haiku-wifi](https://github.com/jedahan/haiku-wifi) 
- [**67**星][4y] [Py] [0x90/wifi-scripts](https://github.com/0x90/wifi-scripts) 
- [**65**星][1y] [Py] [3xp10it/xwifi](https://github.com/3xp10it/xwifi) 
- [**64**星][2y] [Py] [syss-research/nrf24-playset](https://github.com/syss-research/nrf24-playset) 
- [**63**星][2y] [Objective-C] [antoinet/valora](https://github.com/antoinet/valora) valora：利用随机源 MAC 地址和随机 SSID 生成 802.11 探测请求流，以迷惑 WiFi 追踪系统
- [**62**星][2y] [Py] [esser420/eviltwinframework](https://github.com/esser420/eviltwinframework) 
- [**61**星][3y] [Py] [syss-research/radio-hackbox](https://github.com/syss-research/radio-hackbox) 
- [**61**星][5m] [Py] [joshvillbrandt/wireless](https://github.com/joshvillbrandt/wireless) 
- [**60**星][1y] [Py] [blackholesec/wifigod](https://github.com/blackholesec/wifigod) 
- [**60**星][3m] [Py] [hacksysteam/wpadescape](https://github.com/hacksysteam/wpadescape) 
- [**60**星][3y] [Py] [iamckn/mousejack_transmit](https://github.com/iamckn/mousejack_transmit) 
- [**60**星][3y] [C++] [ronangaillard/logitech-mouse](https://github.com/ronangaillard/logitech-mouse) 
- [**60**星][6y] [Java] [gat3way/airpirate](https://github.com/gat3way/airpirate) 
    - 重复区段: [工具/移动&&Mobile/Android](#fe88ee8c0df10870b44c2dedcd86d3d3) |
- [**58**星][2y] [Shell] [p292/nackered](https://github.com/p292/nackered) 
- [**54**星][2y] [Py] [msfidelis/kill-router-](https://github.com/msfidelis/kill-router-) 
- [**54**星][12m] [pegasuslab/pegasusteam](https://github.com/PegasusLab/PegasusTeam) 
- [**52**星][9m] [C] [bmegli/wifi-scan](https://github.com/bmegli/wifi-scan) 
- [**52**星][1m] [HTML] [aravinthpanch/rssi](https://github.com/aravinthpanch/rssi) 
- [**50**星][4m] [Py] [fkasler/dolos_cloak](https://github.com/fkasler/dolos_cloak) 
- [**50**星][2y] [PowerShell] [gobiasinfosec/wireless_query](https://github.com/gobiasinfosec/wireless_query) 
- [**49**星][9m] [Shell] [cyb0r9/network-attacker](https://github.com/Cyb0r9/network-attacker) 
- [**46**星][4y] [securitytube/wifiscanvisualizer](https://github.com/securitytube/wifiscanvisualizer) 
    - 重复区段: [工具/扫描器&&安全扫描&&App扫描&&漏洞扫描/未分类-Scanner](#de63a029bda6a7e429af272f291bb769) |
- [**45**星][7m] [Shell] [damonmohammadbagher/nativepayload_bssid](https://github.com/damonmohammadbagher/nativepayload_bssid) 
- [**45**星][9m] [Py] [stef/wireless-radar](https://github.com/stef/wireless-radar) 
- [**43**星][3y] [Shell] [dominikstyp/auto-reaver](https://github.com/dominikstyp/auto-reaver) 
- [**42**星][24d] [Py] [sh3llcod3/airscript-ng](https://github.com/sh3llcod3/airscript-ng) 
- [**39**星][3y] [Py] [wraith-wireless/wraith](https://github.com/wraith-wireless/wraith) 
- [**38**星][4m] [Py] [arthastang/router-exploit-shovel](https://github.com/arthastang/router-exploit-shovel) 
- [**35**星][5y] [C] [charlesxsh/mdk3-master](https://github.com/charlesxsh/mdk3-master) 
- [**34**星][2y] [Py] [hash3lizer/airpydump](https://github.com/hash3liZer/airpydump) 
- [**34**星][5y] [Py] [hiteshchoudhary/airvengers](https://github.com/hiteshchoudhary/airvengers) 
- [**34**星][1m] [CSS] [koala633/hostbase](https://github.com/koala633/hostbase) 
- [**31**星][1y] [Smarty] [nerdyprojects/hostapd-wpe-extended](https://github.com/nerdyprojects/hostapd-wpe-extended) 
- [**29**星][6y] [Py] [acidprime/wirelessconfig](https://github.com/acidprime/wirelessconfig) 
- [**28**星][6y] [Py] [syworks/wpa-bruteforcer](https://github.com/syworks/wpa-bruteforcer) 
- [**28**星][4y] [PowerShell] [ahhh/wifi_trojans](https://github.com/ahhh/wifi_trojans) 
    - 重复区段: [工具/通信&&代理&&反向代理&&隧道/反向代理&&穿透](#a136c15727e341b9427b6570910a3a1f) |
- [**27**星][6m] [Shell] [chunkingz/vmr-mdk-k2-2017r-012x4](https://github.com/chunkingz/vmr-mdk-k2-2017r-012x4) 
- [**27**星][7y] [Java] [alessiodallapiazza/wpscan](https://github.com/alessiodallapiazza/WPScan) 
- [**27**星][2y] [Py] [dixel/wifi-linux](https://github.com/dixel/wifi-linux) 
- [**26**星][12m] [C] [aircrack-ng/openwips-ng](https://github.com/aircrack-ng/openwips-ng) 
- [**26**星][2y] [Py] [aniketp/network-programming](https://github.com/aniketp/network-programming) 
- [**26**星][4y] [C++] [dfct/inssidious](https://github.com/dfct/inssidious) 
- [**26**星][3m] [Py] [josue87/airopy](https://github.com/josue87/airopy) 
- [**26**星][3y] [Py] [mvondracek/wifimitm](https://github.com/mvondracek/wifimitm) Automation of MitM Attack on Wi-Fi Networks
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**25**星][7m] [C++] [anwi-wips/anwi](https://github.com/anwi-wips/anwi) 新型无线IDS, 基于低成本的Wi-Fi模块(ESP8266)
- [**25**星][4y] [C++] [vivek-ramachandran/wi-door](https://github.com/vivek-ramachandran/wi-door) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/后门&&添加后门](#b6efee85bca01cde45faa45a92ece37f) |
- [**23**星][11m] [Py] [anotherik/rogueap-detector](https://github.com/anotherik/rogueap-detector) 
- [**23**星][6y] [commonexploits/weape](https://github.com/commonexploits/weape) 
- [**23**星][5y] [C] [ctu-iig/802.11p-linux](https://github.com/ctu-iig/802.11p-linux) 
- [**23**星][6m] [Shell] [rithvikvibhu/nh-magisk-wifi-firmware](https://github.com/rithvikvibhu/nh-magisk-wifi-firmware) 
- [**21**星][1y] [C++] [sanketkarpe/anwi](https://github.com/sanketkarpe/anwi) 
- [**21**星][2y] [Py] [swisskyrepo/whid_toolkit](https://github.com/swisskyrepo/whid_toolkit) 
- [**20**星][6y] [Py] [syworks/wifi-harvester](https://github.com/syworks/wifi-harvester) 


#### <a id="8d233e2d068cce2b36fd0cf44d10f5d8"></a>WPS&&WPA&&WPA2


- [**8371**星][2y] [brannondorsey/wifi-cracking](https://github.com/brannondorsey/wifi-cracking) 破解WPA/WPA2 Wi-Fi 路由器
    - 重复区段: [工具/破解&&Crack&&爆破&&BruteForce](#de81f9dd79c219c876c1313cd97852ce) |[工具/物联网(IoT)&&嵌入式设备&&路由器&&交换机&&智能设备&&打印机/未分类-IoT](#cda63179d132f43441f8844c5df10024) |
- [**302**星][4m] [Py] [hash3lizer/wifibroot](https://github.com/hash3lizer/wifibroot) 
- [**176**星][2m] [C] [soxrok2212/pskracker](https://github.com/soxrok2212/pskracker) 
- [**62**星][1y] [Py] [nicksanzotta/wifisuite](https://github.com/nicksanzotta/wifisuite) 
- [**61**星][12m] [C] [joswr1ght/cowpatty](https://github.com/joswr1ght/cowpatty) WPA2-PSK Cracking
- [**36**星][4y] [C] [dadas190/penetrator-wps](https://github.com/dadas190/penetrator-wps) 实时攻击多个启用了WPS的AP
- [**34**星][10m] [Py] [04x/wpscan](https://github.com/04x/wpscan) 渗透+信息收集


#### <a id="8863b7ba27658d687a85585e43b23245"></a>802.11


- [**25**星][3y] [Py] [j4r3tt/gerix-wifi-cracker-2](https://github.com/j4r3tt/gerix-wifi-cracker-2) 
- [**21**星][7y] [brycethomas/liber80211](https://github.com/brycethomas/liber80211) 
    - 重复区段: [工具/移动&&Mobile/Android](#fe88ee8c0df10870b44c2dedcd86d3d3) |




### <a id="80301821d0f5d8ec2dd3754ebb1b4b10"></a>Payload&&远控&&RAT


#### <a id="6602e118e0245c83b13ff0db872c3723"></a>未分类-payload


- [**1231**星][19d] [PowerShell] [hak5/bashbunny-payloads](https://github.com/hak5/bashbunny-payloads) 
- [**962**星][27d] [C] [zardus/preeny](https://github.com/zardus/preeny) 
- [**560**星][10m] [Py] [genetic-malware/ebowla](https://github.com/genetic-malware/ebowla) 
- [**529**星][2m] [C++] [screetsec/brutal](https://github.com/screetsec/brutal) 
- [**438**星][12d] [Py] [ctxis/cape](https://github.com/ctxis/cape) 
- [**339**星][11m] [JS] [gabemarshall/brosec](https://github.com/gabemarshall/brosec) 
- [**265**星][2y] [Py] [hegusung/avsignseek](https://github.com/hegusung/avsignseek) 
- [**259**星][3m] [Py] [felixweyne/imaginaryc2](https://github.com/felixweyne/imaginaryc2) 
- [**234**星][3m] [cujanovic/markdown-xss-payloads](https://github.com/cujanovic/markdown-xss-payloads) 
- [**229**星][17d] [cujanovic/open-redirect-payloads](https://github.com/cujanovic/open-redirect-payloads) 
- [**226**星][5m] [cr0hn/nosqlinjection_wordlists](https://github.com/cr0hn/nosqlinjection_wordlists) 
- [**216**星][2y] [PowerShell] [rsmudge/elevatekit](https://github.com/rsmudge/elevatekit) 
- [**216**星][2m] [Py] [whitel1st/docem](https://github.com/whitel1st/docem) 
- [**213**星][2y] [Shell] [r00t-3xp10it/trojanizer](https://github.com/r00t-3xp10it/trojanizer) 将用户提供的2个可执行文件打包为自解压文件, 自解压文件在执行时会执行可执行文件
- [**210**星][1m] [Py] [brent-stone/can_reverse_engineering](https://github.com/brent-stone/can_reverse_engineering) 
- [**210**星][24d] [C] [shchmue/lockpick_rcm](https://github.com/shchmue/lockpick_rcm) 
- [**210**星][20d] [PHP] [zigoo0/jsonbee](https://github.com/zigoo0/jsonbee) 
- [**175**星][1y] [Go] [staaldraad/xxeserv](https://github.com/staaldraad/xxeserv) 
- [**173**星][2m] [Py] [carlashley/tccprofile](https://github.com/carlashley/tccprofile) 
- [**165**星][1y] [Shell] [tokyoneon/armor](https://github.com/tokyoneon/armor) 
- [**158**星][6y] [Ruby] [resque/resque-loner](https://github.com/resque/resque-loner) 
- [**156**星][3y] [Py] [4w4k3/umbrella](https://github.com/4w4k3/umbrella) 用于渗透的File Dropper
- [**153**星][2y] [Py] [z0noxz/powerstager](https://github.com/z0noxz/powerstager) powerstager：创建可执行文件，用于下载PowerShell Payload，将其加载到内存，并使用混淆的EC方法运行
- [**145**星][2y] [Py] [undeadsec/enigma](https://github.com/undeadsec/enigma) 
- [**128**星][2y] [PHP] [incredibleindishell/sqlite-lab](https://github.com/incredibleindishell/sqlite-lab) 
- [**128**星][1y] [C#] [ustayready/casperstager](https://github.com/ustayready/casperstager) 
- [**118**星][2y] [Py] [klsecservices/bat-armor](https://github.com/klsecservices/bat-armor) 
- [**115**星][1y] [C] [valentinbreiz/ps4-linux-loader](https://github.com/valentinbreiz/ps4-linux-loader) A simple payload that let you run Linux on your 4.05 / 4.55 / 5.01 / 5.05 PS4
- [**113**星][6m] [PowerShell] [dviros/excalibur](https://github.com/dviros/excalibur) 
- [**113**星][8m] [AppleScript] [rtrouton/payload-free-package-creator](https://github.com/rtrouton/payload-free-package-creator) 
- [**109**星][14d] [C] [hasherezade/chimera_pe](https://github.com/hasherezade/chimera_pe) 
- [**105**星][2y] [Py] [shogunlab/shuriken](https://github.com/shogunlab/shuriken) 
- [**103**星][6y] [Py] [secretsquirrel/recomposer](https://github.com/secretsquirrel/recomposer) 
- [**100**星][1y] [cujanovic/crlf-injection-payloads](https://github.com/cujanovic/crlf-injection-payloads) 
- [**98**星][1y] [Py] [wonderqs/blade](https://github.com/wonderqs/blade) 
- [**97**星][2y] [Py] [mr-un1k0d3r/sct-obfuscator](https://github.com/mr-un1k0d3r/sct-obfuscator) 
- [**91**星][11m] [Py] [n00py/hwacha](https://github.com/n00py/hwacha) 
- [**90**星][3y] [C++] [screetsec/pateensy](https://github.com/screetsec/pateensy) 
- [**84**星][2y] [C] [countercept/doublepulsar-usermode-injector](https://github.com/countercept/doublepulsar-usermode-injector) doublepulsar-usermode-injector：使用 DOUBLEPULSAR payload 用户模式的 Shellcode 向其他进程注入任意 DLL
- [**84**星][2y] [realbearcat/fastjson-payload](https://github.com/RealBearcat/Fastjson-Payload) 
- [**78**星][3m] [Batchfile] [op7ic/edr-testing-script](https://github.com/op7ic/edr-testing-script) 
- [**78**星][3y] [Py] [pythonone/ms17-010](https://github.com/pythonone/ms17-010) 
- [**77**星][7m] [Java] [kingsabri/godofwar](https://github.com/kingsabri/godofwar) 
- [**74**星][3m] [C] [oleavr/ios-inject-custom](https://github.com/oleavr/ios-inject-custom) (iOS) 使用Frida注入自定义Payload
- [**74**星][29d] [Batchfile] [tresacton/passwordstealer](https://github.com/tresacton/passwordstealer) 
    - 重复区段: [工具/硬件设备&&USB&树莓派/USB](#48c53d1304b1335d9addf45b959b7d8a) |
- [**74**星][2m] [Py] [zenix-blurryface/sneakyexe](https://github.com/zenix-blurryface/sneakyexe) 
- [**71**星][2y] [HTML] [cyberheartmi9/payloadsallthethings](https://github.com/cyberheartmi9/payloadsallthethings) 
- [**71**星][3y] [Py] [hak5darren/bashbunny-payloads](https://github.com/hak5darren/bashbunny-payloads) 
- [**68**星][3y] [PowerShell] [xillwillx/tricky.lnk](https://github.com/xillwillx/tricky.lnk) 
- [**67**星][1y] [PHP] [xsuperbug/payloads](https://github.com/xsuperbug/payloads) 
- [**66**星][7m] [Py] [toxydose/duckyspark](https://github.com/toxydose/duckyspark) 
- [**66**星][3y] [JS] [ethjs/ethjs-provider-signer](https://github.com/ethjs/ethjs-provider-signer) 
- [**65**星][1m] [Py] [foospidy/web-cve-tests](https://github.com/foospidy/web-cve-tests) 
- [**64**星][6y] [Py] [andrew-morris/stupid_malware](https://github.com/andrew-morris/stupid_malware) 
- [**64**星][3y] [C] [coolervoid/payloadmask](https://github.com/coolervoid/payloadmask) 
- [**64**星][3m] [Py] [unkn0wnh4ckr/hackers-tool-kit](https://github.com/unkn0wnh4ckr/hackers-tool-kit) 
- [**63**星][2m] [Py] [therook/nsshell](https://github.com/therook/nsshell) 
- [**62**星][4y] [Py] [rich5/harness](https://github.com/rich5/harness) 
- [**61**星][2y] [C] [convisoappsec/firefox_tunnel](https://github.com/convisoappsec/firefox_tunnel) 使用Firefox来建立远程通信隧道, 使用cookie.sqlite/html/js实现payload上传下载
- [**59**星][2m] [JS] [atlasnx/web-cfw-loader](https://github.com/atlasnx/web-cfw-loader) 
- [**56**星][1y] [zephrfish/xsspayloads](https://github.com/zephrfish/xsspayloads) 
- [**55**星][4y] [Py] [ahhh/ntp_trojan](https://github.com/ahhh/ntp_trojan) 
- [**54**星][4y] [Go] [kevinmahaffey/tescat](https://github.com/kevinmahaffey/tescat) 
- [**49**星][2y] [PHP] [auraphp/aura.payload](https://github.com/auraphp/aura.payload) 
- [**49**星][2y] [Py] [h0nus/backtome](https://github.com/h0nus/backtome) 
- [**48**星][1y] [PowerShell] [mr-un1k0d3r/base64-obfuscator](https://github.com/mr-un1k0d3r/base64-obfuscator) 
- [**47**星][10m] [C] [imbushuo/boot-shim](https://github.com/imbushuo/boot-shim) 
- [**46**星][1y] [codworth/esp-host](https://github.com/codworth/esp-host) 
- [**46**星][7y] [Objective-C] [logicalparadox/apnagent-ios](https://github.com/logicalparadox/apnagent-ios) 
- [**45**星][2y] [PowerShell] [golem445/bunny_payloads](https://github.com/golem445/bunny_payloads) 
- [**42**星][9m] [Batchfile] [chrisad/ads-payload](https://github.com/chrisad/ads-payload) 
- [**38**星][3m] [Py] [outflanknl/redfile](https://github.com/outflanknl/redfile) 
- [**38**星][3m] [Py] [projecthorus/wenet](https://github.com/projecthorus/wenet) 
- [**35**星][3y] [Py] [huntergregal/bothunter](https://github.com/huntergregal/bothunter) 
- [**35**星][2y] [C] [xerub/ibex64](https://github.com/xerub/ibex64) 
- [**34**星][19d] [Shell] [hax4us/apkmod](https://github.com/hax4us/apkmod) 
- [**34**星][1y] [Go] [leoloobeek/keyserver](https://github.com/leoloobeek/keyserver) 
- [**30**星][2y] [deroko/payloadrestrictions](https://github.com/deroko/payloadrestrictions) EMET 集成到 Win10Insider 之后改名为 PayloadRestrictions，文章分析了 PayloadRestrictions.dll 的加载过程
- [**30**星][2y] [PHP] [jhaddix/seclists](https://github.com/jhaddix/seclists) 
- [**30**星][14d] [C] [xerpi/vita-libbaremetal](https://github.com/xerpi/vita-libbaremetal) 
- [**28**星][1y] [Py] [zhanghaoyil/hawk-i](https://github.com/zhanghaoyil/hawk-i) 
- [**24**星][8m] [C#] [nyan-x-cat/dropless-malware](https://github.com/nyan-x-cat/dropless-malware) 
- [**24**星][17d] [C] [xerpi/vita-baremetal](https://github.com/xerpi/vita-baremetal) 
- [**23**星][2y] [PHP] [blackfan/jpg_payload](https://github.com/blackfan/jpg_payload) 
- [**22**星][5m] [C] [xerpi/vita-baremetal-sample](https://github.com/xerpi/vita-baremetal-sample) 
- [**11**星][2m] [Py] [angelkitty/stegosaurus](https://github.com/angelkitty/stegosaurus) 


#### <a id="b5d99a78ddb383c208aae474fc2cb002"></a>Payload收集


- [**21409**星][14d] [PHP] [danielmiessler/seclists](https://github.com/danielmiessler/seclists) 多种类型资源收集：用户名、密码、URL、敏感数据类型、Fuzzing  Payload、WebShell等
    - 重复区段: [工具/webshell/收集](#e08366dcf7aa021c6973d9e2a8944dff) |[工具/wordlist/收集](#3202d8212db5699ea5e6021833bf3fa2) |
- [**10579**星][14d] [Py] [swisskyrepo/payloadsallthethings](https://github.com/swisskyrepo/payloadsallthethings) 
- [**1994**星][8m] [Shell] [foospidy/payloads](https://github.com/foospidy/payloads) payloads：web 攻击 Payload 集合
- [**1989**星][26d] [edoverflow/bugbounty-cheatsheet](https://github.com/edoverflow/bugbounty-cheatsheet) 
- [**1856**星][10m] [PHP] [bartblaze/php-backdoors](https://github.com/bartblaze/php-backdoors) 
- [**842**星][2y] [PowerShell] [curi0usjack/luckystrike](https://github.com/curi0usJack/luckystrike) 
- [**717**星][2m] [HTML] [ismailtasdelen/xss-payload-list](https://github.com/payloadbox/xss-payload-list) XSS 漏洞Payload列表
- [**384**星][3y] [pgaijin66/xss-payloads](https://github.com/pgaijin66/xss-payloads) 
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/XSS&&XXE/收集](#493e36d0ceda2fb286210a27d617c44d) |
- [**367**星][2m] [renwax23/xss-payloads](https://github.com/renwax23/xss-payloads) 
- [**272**星][3m] [Py] [thekingofduck/easyxsspayload](https://github.com/thekingofduck/easyxsspayload) 
- [**238**星][3m] [payloadbox/command-injection-payload-list](https://github.com/payloadbox/command-injection-payload-list) 
- [**226**星][2y] [C#] [t3ntman/social-engineering-payloads](https://github.com/t3ntman/social-engineering-payloads) 
- [**193**星][4y] [Java] [pwntester/serialkillerbypassgadgetcollection](https://github.com/pwntester/serialkillerbypassgadgetcollection) 
- [**171**星][2y] [CSS] [bhdresh/socialengineeringpayloads](https://github.com/bhdresh/socialengineeringpayloads) 
- [**148**星][3m] [HTML] [zer0yu/berserker](https://github.com/zer0yu/berserker) 
- [**141**星][2y] [Py] [vduddu/malware](https://github.com/vduddu/malware) 
    - 重复区段: [工具/webshell/收集](#e08366dcf7aa021c6973d9e2a8944dff) |
- [**81**星][6y] [Java] [schierlm/javapayload](https://github.com/schierlm/javapayload) 
- [**61**星][7y] [JS] [enablesecurity/webapp-exploit-payloads](https://github.com/EnableSecurity/Webapp-Exploit-Payloads) 
- [**36**星][4y] [7iosecurity/xss-payloads](https://github.com/7iosecurity/xss-payloads) 
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/XSS&&XXE/收集](#493e36d0ceda2fb286210a27d617c44d) |
- [**27**星][3m] [payloadbox/open-redirect-payload-list](https://github.com/payloadbox/open-redirect-payload-list) 


#### <a id="b318465d0d415e35fc0883e9894261d1"></a>远控&&RAT


- [**5045**星][3m] [Py] [n1nj4sec/pupy](https://github.com/n1nj4sec/pupy) 
- [**1696**星][6m] [Smali] [ahmyth/ahmyth-android-rat](https://github.com/ahmyth/ahmyth-android-rat) 
- [**1402**星][3y] [Py] [nathanlopez/stitch](https://github.com/nathanlopez/stitch) 
- [**1306**星][1y] [Py] [marten4n6/evilosx](https://github.com/marten4n6/evilosx) 
- [**763**星][22d] [Py] [kevthehermit/ratdecoders](https://github.com/kevthehermit/ratdecoders) 
- [**597**星][1y] [PowerShell] [fortynorthsecurity/wmimplant](https://github.com/FortyNorthSecurity/WMImplant) 
- [**477**星][5m] [Visual Basic] [nyan-x-cat/lime-rat](https://github.com/nyan-x-cat/lime-rat) 
- [**352**星][2m] [C++] [werkamsus/lilith](https://github.com/werkamsus/lilith) 
- [**325**星][3y] [Pascal] [malwares/remote-access-trojan](https://github.com/malwares/remote-access-trojan) 
- [**307**星][5m] [Py] [mvrozanti/rat-via-telegram](https://github.com/mvrozanti/rat-via-telegram) 
- [**282**星][2y] [Py] [0xislamtaha/python-rootkit](https://github.com/0xIslamTaha/Python-Rootkit) 
- [**271**星][1m] [C#] [nyan-x-cat/asyncrat-c-sharp](https://github.com/nyan-x-cat/asyncrat-c-sharp) 
- [**269**星][3m] [C++] [yuanyuanxiang/simpleremoter](https://github.com/yuanyuanxiang/simpleremoter) 
- [**256**星][7y] [C++] [sin5678/gh0st](https://github.com/sin5678/gh0st) 
- [**179**星][1m] [PHP] [0blio/caesar](https://github.com/0blio/Caesar) 
- [**177**星][1m] [Py] [pure-l0g1c/loki](https://github.com/pure-l0g1c/loki) 
- [**156**星][1y] [Py] [fireeye/geologonalyzer](https://github.com/fireeye/geologonalyzer) 
- [**154**星][2y] [C++] [hussein-aitlahcen/blackhole](https://github.com/hussein-aitlahcen/blackhole) 
- [**152**星][3y] [Visual Basic] [mwsrc/plasmarat](https://github.com/mwsrc/PlasmaRAT) 
- [**151**星][2y] [Java] [the404hacking/androrat](https://github.com/the404hacking/androrat) 
- [**127**星][3y] [Java] [mwsrc/betterandrorat](https://github.com/mwsrc/betterandrorat) 
- [**122**星][5m] [C] [abhishekkr/n00brat](https://github.com/abhishekkr/n00brat) 
- [**100**星][2y] [Py] [syss-research/outis](https://github.com/syss-research/outis) 
- [**99**星][6m] [C#] [dannythesloth/vanillarat](https://github.com/dannythesloth/vanillarat) 
- [**95**星][2y] [Pascal] [senjaxus/allakore_remote](https://github.com/senjaxus/allakore_remote) 
- [**94**星][7y] [C#] [ilikenwf/darkagent](https://github.com/ilikenwf/darkagent) 
- [**81**星][1y] [C#] [advancedhacker101/c-sharp-r.a.t-server](https://github.com/advancedhacker101/c-sharp-r.a.t-server) 
- [**80**星][3y] [Py] [lukasikic/hacoder.py](https://github.com/lukasikic/hacoder.py) 
- [**78**星][4y] [C++] [rwhitcroft/dnschan](https://github.com/rwhitcroft/dnschan) 
- [**66**星][4y] [C#] [stphivos/rat-shell](https://github.com/stphivos/rat-shell) 
- [**58**星][4m] [Visual Basic] [thesph1nx/rt-101](https://github.com/thesph1nx/rt-101) 
- [**53**星][2y] [Py] [m4sc3r4n0/spyrat](https://github.com/m4sc3r4n0/spyrat) 


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
- [**551**星][2y] [Visual Basic] [mdsecactivebreach/cactustorch](https://github.com/mdsecactivebreach/cactustorch) Payload Generation for Adversary Simulations
- [**521**星][3y] [PowerShell] [enigma0x3/generate-macro](https://github.com/enigma0x3/generate-macro) 
- [**457**星][2y] [Py] [0xdeadbeefjerky/office-dde-payloads](https://github.com/0xdeadbeefjerky/office-dde-payloads) 
- [**457**星][2y] [Go] [egebalci/hercules](https://github.com/egebalci/hercules) 
- [**397**星][28d] [Perl] [chinarulezzz/pixload](https://github.com/chinarulezzz/pixload) 
- [**377**星][2y] [Shell] [screetsec/microsploit](https://github.com/screetsec/microsploit) 
- [**299**星][1y] [Py] [stormshadow07/hacktheworld](https://github.com/stormshadow07/hacktheworld) 
- [**287**星][7m] [Py] [0xacb/viewgen](https://github.com/0xacb/viewgen) 
- [**281**星][3y] [Py] [mandatoryprogrammer/xssless](https://github.com/mandatoryprogrammer/xssless) 
- [**268**星][1y] [Shell] [abedalqaderswedan1/aswcrypter](https://github.com/abedalqaderswedan1/aswcrypter) 
- [**262**星][1y] [Java] [ewilded/shelling](https://github.com/ewilded/shelling) 
- [**222**星][1y] [Java] [ewilded/psychopath](https://github.com/ewilded/psychopath) 
- [**190**星][3y] [Ruby] [crowecybersecurity/ps1encode](https://github.com/crowecybersecurity/ps1encode) 
- [**171**星][3y] [Py] [4w4k3/insanity-framework](https://github.com/4w4k3/insanity-framework) 
- [**170**星][2y] [Py] [plazmaz/lnkup](https://github.com/plazmaz/lnkup) 
- [**153**星][1y] [voidfyoo/cve-2018-3191](https://github.com/voidfyoo/cve-2018-3191) 
- [**149**星][1y] [Py] [souhardya/zerodoor](https://github.com/souhardya/zerodoor) 
- [**142**星][3y] [Java] [secarmalabs/psychopath](https://github.com/secarmalabs/psychopath) 
- [**132**星][3y] [Shell] [pasahitz/zirikatu](https://github.com/pasahitz/zirikatu) 
- [**123**星][2y] [Go] [egebalci/arcanus](https://github.com/egebalci/arcanus) 
- [**118**星][4y] [Py] [packz/ropeme](https://github.com/packz/ropeme) 
- [**113**星][11m] [Py] [ghost123gg/wep](https://github.com/ghost123gg/wep) 
- [**107**星][2y] [Shell] [xillwillx/cactustorch_ddeauto](https://github.com/xillwillx/cactustorch_ddeauto) 
- [**104**星][1y] [Py] [redlectroid/overthruster](https://github.com/redlectroid/overthruster) 
- [**95**星][2y] [Py] [safebreach-labs/mkmalwarefrom](https://github.com/safebreach-labs/mkmalwarefrom) 
- [**86**星][1y] [Shell] [jbreed/apkwash](https://github.com/jbreed/apkwash) 
- [**85**星][3y] [Py] [vysecurity/genhta](https://github.com/vysecurity/genHTA) 
- [**80**星][2m] [Py] [huntergregal/png-idat-payload-generator](https://github.com/huntergregal/png-idat-payload-generator) 
- [**70**星][12m] [Shell] [thelinuxchoice/getwin](https://github.com/thelinuxchoice/getwin) 
- [**66**星][6m] [Shell] [violentlydave/mkhtaccess_red](https://github.com/violentlydave/mkhtaccess_red) 
- [**64**星][5m] [Java] [portswigger/command-injection-attacker](https://github.com/portswigger/command-injection-attacker) 
- [**62**星][2y] [AutoIt] [9aylas/shortcut-payload-generator](https://github.com/9aylas/shortcut-payload-generator) 
- [**60**星][1y] [Py] [darkw1z/ps1jacker](https://github.com/darkw1z/ps1jacker) 
- [**59**星][28d] [JS] [rastating/xss-chef](https://github.com/rastating/xss-chef) 
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/XSS&&XXE/未分类-XSS](#648e49b631ea4ba7c128b53764328c39) |
- [**57**星][4m] [C#] [gigajew/powerdropper](https://github.com/gigajew/powerdropper) 
- [**48**星][3y] [PHP] [incredibleindishell/ldap-credentials-collector-backdoor-generator](https://github.com/incredibleindishell/ldap-credentials-collector-backdoor-generator) 
- [**47**星][1y] [Visual Basic] [vysecurity/cactustorch](https://github.com/vysecurity/CACTUSTORCH) Payload Generation for Adversary Simulations
- [**40**星][3y] [Py] [lukasikic/kodi-backdoor-generator](https://github.com/lukasikic/kodi-backdoor-generator) 
- [**35**星][4y] [Java] [grrrdog/acedcup](https://github.com/grrrdog/acedcup) 
- [**33**星][2y] [HTML] [rh0dev/shellcode2asmjs](https://github.com/rh0dev/shellcode2asmjs) 
- [**32**星][3y] [Shell] [b3rito/trolo](https://github.com/b3rito/trolo) 
- [**29**星][3y] [Java] [yolosec/ysoserial](https://github.com/yolosec/ysoserial) 
- [**27**星][2m] [C#] [3gstudent/gadgettojscript](https://github.com/3gstudent/gadgettojscript) 
- [**24**星][1y] [Py] [fsacer/nps_payload](https://github.com/fsacer/nps_payload) 


#### <a id="c45a90ab810d536a889e4e2dd45132f8"></a>Botnet&&僵尸网络


- [**3690**星][3m] [Py] [malwaredllc/byob](https://github.com/malwaredllc/byob) 
- [**2135**星][1y] [C++] [maestron/botnets](https://github.com/maestron/botnets) 
- [**903**星][2y] [Py] [sweetsoftware/ares](https://github.com/sweetsoftware/ares) 
- [**894**星][6y] [C] [visgean/zeus](https://github.com/visgean/zeus) 
- [**413**星][3y] [C++] [malwares/botnet](https://github.com/malwares/botnet) 
- [**390**星][19d] [C++] [souhardya/uboat](https://github.com/souhardya/uboat) 
- [**319**星][5m] [Go] [saturnsvoid/gobot2](https://github.com/saturnsvoid/gobot2) 
- [**135**星][2y] [Py] [pjlantz/hale](https://github.com/pjlantz/hale) 
- [**127**星][6y] [Py] [valdikss/billgates-botnet-tracker](https://github.com/valdikss/billgates-botnet-tracker) 
- [**119**星][7m] [C] [treehacks/botnet-hackpack](https://github.com/treehacks/botnet-hackpack) 
- [**115**星][14d] [Py] [jpdias/botnet-lab](https://github.com/jpdias/botnet-lab) 
- [**90**星][12d] [Py] [blackhacker511/blacknet](https://github.com/blackhacker511/blacknet) 
- [**72**星][6m] [C++] [watersalesman/aura-botnet](https://github.com/watersalesman/aura-botnet) 
- [**71**星][6y] [Py] [mushorg/buttinsky](https://github.com/mushorg/buttinsky) 
- [**64**星][1y] [Jupyter Notebook] [hmishra2250/botnet-detection-using-machine-learning](https://github.com/hmishra2250/botnet-detection-using-machine-learning) 
- [**56**星][3y] [C#] [lontivero/vinchuca](https://github.com/lontivero/vinchuca) 
- [**56**星][10m] [Py] [pirate/mesh-botnet](https://github.com/pirate/mesh-botnet) 
- [**52**星][5y] [Py] [bwall/bamf](https://github.com/bwall/bamf) 
- [**45**星][7m] [Go] [threeaccents/botnet](https://github.com/threeaccents/botnet) 
- [**43**星][1y] [PHP] [4k-developer/4k-botnet](https://github.com/4k-developer/4k-botnet) 
- [**37**星][3y] [PowerShell] [wkleinhenz/powershell-botnet](https://github.com/wkleinhenz/powershell-botnet) 
- [**33**星][2y] [C] [soufianetahiri/mirai-botnet](https://github.com/soufianetahiri/mirai-botnet) 
- [**30**星][1y] [C#] [valsov/backnet](https://github.com/valsov/backnet) 
- [**29**星][3y] [C] [hklcf/mirai](https://github.com/hklcf/mirai) 
- [**26**星][4m] [Go] [magisterquis/dnsbotnet](https://github.com/magisterquis/dnsbotnet) 
- [**25**星][2y] [Go] [peoples-cloud/pc](https://github.com/peoples-cloud/pc) 
- [**21**星][3y] [C++] [dinamsky/malware-botnets](https://github.com/dinamsky/malware-botnets) 
- [**21**星][3y] [Jupyter Notebook] [equalitie/bothound](https://github.com/equalitie/bothound) 
- [**21**星][1y] [CSS] [tuhinshubhra/uboat-panel](https://github.com/tuhinshubhra/uboat-panel) 
- [**21**星][3y] [Py] [cylance/idpanel](https://github.com/cylance/IDPanel) 


#### <a id="b6efee85bca01cde45faa45a92ece37f"></a>后门&&添加后门


- [**2357**星][2y] [Py] [secretsquirrel/the-backdoor-factory](https://github.com/secretsquirrel/the-backdoor-factory) 为PE, ELF, Mach-O二进制文件添加Shellcode后门
- [**1278**星][4y] [Py] [elvanderb/tcp-32764](https://github.com/elvanderb/tcp-32764) 
    - 重复区段: [工具/硬件设备&&USB&树莓派/未分类-Hardware](#ff462a6d508ef20aa41052b1cc8ad044) |
- [**676**星][2y] [Py] [kkevsterrr/backdoorme](https://github.com/kkevsterrr/backdoorme) 
- [**538**星][3y] [Py] [mimoo/diffie-hellman_backdoor](https://github.com/mimoo/diffie-hellman_backdoor) 
- [**473**星][5y] [Py] [infodox/python-pty-shells](https://github.com/infodox/python-pty-shells) 
- [**405**星][2y] [Py] [operatorequals/covertutils](https://github.com/operatorequals/covertutils) Python2包，包含 N 多用于实现自定义后门的模块，从文件传输到自定义Shell，应有尽有
- [**378**星][7m] [C] [zerosum0x0/smbdoor](https://github.com/zerosum0x0/smbdoor) 
- [**364**星][2m] [Shell] [screetsec/vegile](https://github.com/screetsec/vegile) 
- [**362**星][7m] [Py] [s0md3v/cloak](https://github.com/s0md3v/Cloak) 
- [**347**星][3y] [C] [cr4sh/smmbackdoor](https://github.com/cr4sh/smmbackdoor) 
- [**341**星][11m] [Shell] [r00t-3xp10it/backdoorppt](https://github.com/r00t-3xp10it/backdoorppt) backdoorppt：将Exe格式Payload伪装成Doc（.ppt）
- [**335**星][6y] [C] [orangetw/tsh](https://github.com/orangetw/tsh) 
- [**317**星][1y] [Ruby] [carletonstuberg/browser-backdoor](https://github.com/CarletonStuberg/browser-backdoor) 
- [**287**星][3m] [C#] [mvelazc0/defcon27_csharp_workshop](https://github.com/mvelazc0/defcon27_csharp_workshop) 
- [**283**星][2y] [C] [creaktive/tsh](https://github.com/creaktive/tsh) 
- [**271**星][2y] [Py] [hadi999/nxcrypt](https://github.com/hadi999/nxcrypt) 
- [**269**星][3y] [C] [andreafabrizi/prism](https://github.com/andreafabrizi/prism) 
- [**229**星][2y] [Shell] [linuz/sticky-keys-slayer](https://github.com/linuz/sticky-keys-slayer) 
- [**220**星][4y] [PowerShell] [jseidl/babadook](https://github.com/jseidl/babadook) 
- [**204**星][3y] [Shell] [ztgrace/sticky_keys_hunter](https://github.com/ztgrace/sticky_keys_hunter) 
- [**203**星][4y] [PowerShell] [mattifestation/wmi_backdoor](https://github.com/mattifestation/wmi_backdoor) 
- [**201**星][8m] [C] [paradoxis/php-backdoor](https://github.com/Paradoxis/PHP-Backdoor) 
- [**193**星][1y] [C++] [unapibageek/cbm](https://github.com/unapibageek/cbm) 
- [**187**星][1y] [Py] [malwaredllc/bamf](https://github.com/malwaredllc/bamf) 
- [**176**星][3y] [Shell] [jivoi/openssh-backdoor-kit](https://github.com/jivoi/openssh-backdoor-kit) 
- [**171**星][1m] [C] [rokups/virtual-reality](https://github.com/rokups/virtual-reality) 
- [**143**星][7y] [Shell] [offensive-security/hid-backdoor-peensy](https://github.com/offensive-security/hid-backdoor-peensy) 
- [**141**星][1y] [Py] [checkymander/imessagesbackdoor](https://github.com/checkymander/iMessagesBackdoor) 
- [**137**星][3y] [C] [cr4sh/peibackdoor](https://github.com/cr4sh/peibackdoor) 
- [**133**星][8y] [Perl] [anestisb/webacoo](https://github.com/anestisb/webacoo) 
- [**131**星][2m] [Py] [nccgroup/thetick](https://github.com/nccgroup/thetick) 
- [**117**星][4y] [C] [shellntel/backdoors](https://github.com/shellntel/backdoors) 
- [**117**星][1y] [Shell] [tunisianeagles/winspy](https://github.com/Cyb0r9/winspy) 
- [**111**星][6y] [C] [mncoppola/rpef](https://github.com/mncoppola/rpef) 
- [**95**星][4y] [PowerShell] [enigma0x3/invoke-altdsbackdoor](https://github.com/enigma0x3/invoke-altdsbackdoor) 
- [**91**星][1y] [C] [wangyihang/apache-http-server-module-backdoor](https://github.com/wangyihang/apache-http-server-module-backdoor) 
- [**85**星][2y] [PowerShell] [re4lity/schtasks-backdoor](https://github.com/re4lity/schtasks-backdoor) 
- [**84**星][4y] [C] [gitdurandal/dbd](https://github.com/gitdurandal/dbd) 
- [**81**星][5y] [C++] [hackedteam/scout-win](https://github.com/hackedteam/scout-win) 
- [**81**星][1y] [Shell] [cyb0r9/androspy](https://github.com/Cyb0r9/Androspy) 
- [**76**星][2y] [PHP] [tuhinshubhra/shellstack](https://github.com/tuhinshubhra/shellstack) 
- [**72**星][5y] [Py] [joridos/custom-ssh-backdoor](https://github.com/joridos/custom-ssh-backdoor) 
- [**65**星][5y] [C] [akamajoris/php-extension-backdoor](https://github.com/akamajoris/php-extension-backdoor) 
- [**61**星][4y] [Py] [secretsquirrel/backdoor-pyc](https://github.com/secretsquirrel/backdoor-pyc) 
- [**58**星][7y] [C] [chokepoint/jynx2](https://github.com/chokepoint/jynx2) 
- [**55**星][2y] [abatchy17/introduction-to-manual-backdooring](https://github.com/abatchy17/introduction-to-manual-backdooring) 
- [**54**星][1m] [Py] [angus-y/pyiris-backdoor](https://github.com/angus-y/pyiris-backdoor) 
- [**54**星][4y] [Py] [az0ne/python_backdoor](https://github.com/az0ne/python_backdoor) 
- [**52**星][11m] [Shell] [damonmohammadbagher/nativepayload_image](https://github.com/damonmohammadbagher/nativepayload_image) 
- [**46**星][1y] [PHP] [mrsqar-ye/door404](https://github.com/mrsqar-ye/door404) 
- [**45**星][5y] [JS] [shd101wyy/python_reverse_tcp](https://github.com/shd101wyy/python_reverse_tcp) 
- [**44**星][6m] [Py] [tengzhangchao/pyshell](https://github.com/tengzhangchao/pyshell) 
- [**44**星][2y] [Py] [unkl4b/gitbackdorizer](https://github.com/unkl4b/gitbackdorizer) 
- [**40**星][4y] [C] [fi01/backdoor_mmap_tools](https://github.com/fi01/backdoor_mmap_tools) 
- [**38**星][3y] [C++] [k2/languagebackdoors](https://github.com/k2/languagebackdoors) 
- [**34**星][7y] [C] [chokepoint/jynxkit](https://github.com/chokepoint/jynxkit) 
- [**33**星][3y] [Py] [cys3c/backdoorman](https://github.com/cys3c/backdoorman) 
- [**33**星][1y] [C#] [damonmohammadbagher/nativepayload_arp](https://github.com/damonmohammadbagher/nativepayload_arp) 
- [**30**星][1y] [Java] [airman604/jdbc-backdoor](https://github.com/airman604/jdbc-backdoor) 
- [**30**星][3y] [matthewdunwoody/poshspy](https://github.com/matthewdunwoody/poshspy) 
- [**30**星][2y] [C] [srakai/adun](https://github.com/srakai/adun) 
- [**30**星][1y] [unapibageek/thebicho](https://github.com/unapibageek/thebicho) 
- [**27**星][10m] [Go] [razc411/gobd](https://github.com/razc411/gobd) 
- [**25**星][6m] [Py] [tarcisio-marinho/rsb-framework](https://github.com/tarcisio-marinho/rsb-framework) 
- [**25**星][4y] [C++] [vivek-ramachandran/wi-door](https://github.com/vivek-ramachandran/wi-door) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**24**星][3y] [C] [te-k/openssh-backdoor](https://github.com/te-k/openssh-backdoor) 
- [**24**星][1y] [PHP] [ismailtasdelen/shell-backdoor-list](https://github.com/backdoorhub/shell-backdoor-list) 
- [**23**星][1y] [C#] [damonmohammadbagher/nativepayload_ip6dns](https://github.com/damonmohammadbagher/nativepayload_ip6dns) 
- [**23**星][2m] [Py] [k8gege/phpstudydoor](https://github.com/k8gege/phpstudydoor) 
- [**21**星][1y] [C] [droberson/icmp-backdoor](https://github.com/droberson/icmp-backdoor) 


#### <a id="85bb0c28850ffa2b4fd44f70816db306"></a>混淆器&&Obfuscate


- [**1351**星][9m] [PowerShell] [danielbohannon/invoke-obfuscation](https://github.com/danielbohannon/invoke-obfuscation) 


#### <a id="78d0ac450a56c542e109c07a3b0225ae"></a>Payload管理


- [**930**星][1y] [JS] [netflix/sleepy-puppy](https://github.com/Netflix-Skunkworks/sleepy-puppy) 


#### <a id="d08b7bd562a4bf18275c63ffe7d8fc91"></a>勒索软件


- [**379**星][1y] [Go] [mauri870/ransomware](https://github.com/mauri870/ransomware) 
- [**313**星][13d] [Batchfile] [mitchellkrogza/ultimate.hosts.blacklist](https://github.com/mitchellkrogza/ultimate.hosts.blacklist) 
- [**247**星][2y] [Py] [deadpix3l/cryptsky](https://github.com/deadpix3l/cryptsky) 
- [**178**星][29d] [Py] [tarcisio-marinho/gonnacry](https://github.com/tarcisio-marinho/gonnacry) 
- [**156**星][3y] [Go] [wille/cry](https://github.com/wille/cry) 
- [**135**星][2y] [Py] [nullarray/cypher](https://github.com/nullarray/cypher) 
- [**105**星][2y] [Py] [sithis993/crypter](https://github.com/sithis993/crypter) 
- [**100**星][4y] [utkusen/eda2](https://github.com/utkusen/eda2) 
- [**90**星][1m] [Py] [zer0dx/cryptondie](https://github.com/zer0dx/cryptondie) 
- [**81**星][2y] [PHP] [bug7sec/ransomware](https://github.com/bug7sec/ransomware) 
- [**76**星][3y] [C] [decryptoniteteam/decryptonite](https://github.com/decryptoniteteam/decryptonite) 
- [**76**星][4y] [C] [gdbinit/gopher](https://github.com/gdbinit/gopher) 
- [**76**星][4y] [PHP] [subtlescope/bash-ransomware](https://github.com/subtlescope/bash-ransomware) 
- [**73**星][3y] [Java] [panagiotisdrakatos/javaransomware](https://github.com/panagiotisdrakatos/javaransomware) 
- [**71**星][2y] [Py] [roothaxor/ransom](https://github.com/roothaxor/ransom) 
- [**61**星][13d] [TSQL] [mitchellkrogza/the-big-list-of-hacked-malware-web-sites](https://github.com/mitchellkrogza/the-big-list-of-hacked-malware-web-sites) 
- [**56**星][3y] [hackstar7/wanacry](https://github.com/hackstar7/wanacry) 
- [**49**星][11m] [PHP] [atmoner/nodecrypto](https://github.com/atmoner/nodecrypto) 
- [**48**星][4y] [Shell] [jdsecurity/cryptotrooper](https://github.com/jdsecurity/cryptotrooper) 
- [**44**星][3y] [C#] [nccgroup/ransomware-simulator](https://github.com/nccgroup/ransomware-simulator) 
- [**42**星][4y] [C#] [alphadelta/dumb](https://github.com/alphadelta/dumb) 
- [**39**星][3y] [C#] [sneaksensed/hiddentear](https://github.com/sneaksensed/hiddentear) 
- [**36**星][4y] [C] [ofercas/ransomware_begone](https://github.com/ofercas/ransomware_begone) 
- [**34**星][5y] [C++] [adamkramer/handle_monitor](https://github.com/adamkramer/handle_monitor) 
- [**32**星][23d] [Py] [codingo/ransomware-json-dataset](https://github.com/codingo/ransomware-json-dataset) 
- [**30**星][2y] [JS] [rpgeeganage/file-less-ransomware-demo](https://github.com/rpgeeganage/file-less-ransomware-demo) 
- [**29**星][2y] [C++] [mogongtech/ransomdetection](https://github.com/mogongtech/ransomdetection) 
- [**28**星][12m] [Py] [knownsec/decrypt-ransomware](https://github.com/knownsec/decrypt-ransomware) 
- [**27**星][5y] [Go] [lucdew/goransomware](https://github.com/lucdew/goransomware) 
- [**23**星][4y] [brucecio9999/cryptowire-advanced-autoit-ransomware-project](https://github.com/brucecio9999/cryptowire-advanced-autoit-ransomware-project) 
- [**23**星][2y] [C++] [kuqadk3/winrarer-ransomware](https://github.com/kuqadk3/winrarer-ransomware) 


#### <a id="82f546c7277db7919986ecf47f3c9495"></a>键盘记录器


- [**359**星][11m] [Py] [ajinabraham/xenotix-python-keylogger](https://github.com/ajinabraham/xenotix-python-keylogger) 
- [**292**星][2y] [C++] [minhaskamal/trojancockroach](https://github.com/minhaskamal/trojancockroach) 
- [**246**星][2y] [C++] [minhaskamal/stupidkeylogger](https://github.com/minhaskamal/stupidkeylogger) 
- [**173**星][4y] [C#] [alphadelta/secure-desktop](https://github.com/alphadelta/secure-desktop) 
- [**152**星][7y] [C] [dannvix/keylogger-osx](https://github.com/dannvix/keylogger-osx) 
- [**75**星][1y] [Py] [sh4rk0-666/spykeyboard](https://github.com/sh4rk0-666/spykeyboard) 
- [**68**星][2y] [C] [akayn/kbmon](https://github.com/akayn/kbmon) 
- [**62**星][3m] [C] [dorneanu/ixkeylog](https://github.com/dorneanu/ixkeylog) 
- [**47**星][1y] [Py] [undeadsec/herakeylogger](https://github.com/undeadsec/herakeylogger) 
- [**42**星][5y] [Py] [bones-codes/the_colonel](https://github.com/bones-codes/the_colonel) 
- [**31**星][6y] [netspi/skl](https://github.com/netspi/skl) 
- [**23**星][3y] [Py] [nairuzabulhul/keyplexer](https://github.com/nairuzabulhul/keyplexer) 
- [**22**星][2m] [Py] [darksecdevelopers/absorber](https://github.com/darksecdevelopers/absorber) 
- [**22**星][2y] [Py] [invasi0nz/lo0sr](https://github.com/invasi0nz/lo0sr) 


#### <a id="8f99087478f596139922cd1ad9ec961b"></a>Meterpreter


- [**233**星][5m] [Py] [mez0cc/ms17-010-python](https://github.com/mez0cc/ms17-010-python) 
- [**220**星][4y] [C] [rapid7/meterpreter](https://github.com/rapid7/meterpreter) 
- [**156**星][6m] [C] [rapid7/mettle](https://github.com/rapid7/mettle) 
- [**147**星][10m] [Ruby] [darkoperator/meterpreter-scripts](https://github.com/darkoperator/meterpreter-scripts) 
- [**140**星][3y] [Py] [vvalien/sharpmeter](https://github.com/vvalien/sharpmeter) A Simple Way To Make Meterpreter Reverse Payloads
- [**121**星][3y] [JS] [cn33liz/jsmeter](https://github.com/cn33liz/jsmeter) 
- [**110**星][18d] [C#] [oj/clr-meterpreter](https://github.com/oj/clr-meterpreter) 
- [**99**星][3m] [C#] [damonmohammadbagher/nativepayload_reverse_tcp](https://github.com/damonmohammadbagher/nativepayload_reverse_tcp) 
- [**75**星][5y] [C++] [sherifeldeeb/inmet](https://github.com/sherifeldeeb/inmet) 
- [**73**星][3y] [Visual Basic] [cn33liz/vbsmeter](https://github.com/cn33liz/vbsmeter) 
- [**51**星][3y] [Visual Basic] [cn33liz/macrometer](https://github.com/cn33liz/macrometer) 
- [**50**星][11m] [C] [realoriginal/reflective-rewrite](https://github.com/realoriginal/reflective-rewrite) 
- [**29**星][5y] [C++] [codeliker/mymig_meterpreter](https://github.com/codeliker/mymig_meterpreter) 


#### <a id="63e0393e375e008af46651a3515072d8"></a>Payload投递


- [**323**星][3y] [Visual Basic] [khr0x40sh/macroshop](https://github.com/khr0x40sh/macroshop) 
- [**255**星][3m] [Py] [no0be/dnslivery](https://github.com/no0be/dnslivery) 
- [**98**星][1y] [Go] [0x09al/go-deliver](https://github.com/0x09al/go-deliver) 
- [**68**星][6y] [enigma0x3/powershell-payload-excel-delivery](https://github.com/enigma0x3/powershell-payload-excel-delivery) 
- [**66**星][16d] [Py] [s1egesystems/ghostdelivery](https://github.com/s1egesystems/ghostdelivery) 
- [**25**星][2y] [PowerShell] [thoughtfuldev/psimage-delivery](https://github.com/thoughtfuldev/psimage-delivery) 




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
- [**6043**星][3y] [PowerShell] [powershellmafia/powersploit](https://github.com/PowerShellMafia/PowerSploit) 
- [**3671**星][2y] [JS] [samyk/evercookie](https://github.com/samyk/evercookie) JavaScript API，在浏览器中创建超级顽固的cookie，在标准Cookie、Flask Cookie等被清除之后依然能够识别客户端
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/指纹&&Fingerprinting](#016bb6bd00f1e0f8451f779fe09766db) |
- [**3268**星][2m] [C] [screetsec/thefatrat](https://github.com/screetsec/thefatrat) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload生成](#ad92f6b801a18934f1971e2512f5ae4f) |
- [**2346**星][1m] [Shell] [rebootuser/linenum](https://github.com/rebootuser/linenum) 
- [**2136**星][14d] [Py] [commixproject/commix](https://github.com/commixproject/commix) 
- [**1380**星][3y] [PowerShell] [putterpanda/mimikittenz](https://github.com/putterpanda/mimikittenz) 
- [**1226**星][9m] [C] [a0rtega/pafish](https://github.com/a0rtega/pafish) 
- [**1191**星][1y] [C#] [cn33liz/p0wnedshell](https://github.com/cn33liz/p0wnedshell) 
- [**1158**星][2y] [C] [mubix/post-exploitation](https://github.com/mubix/post-exploitation) post-exploitation工具收集
- [**1045**星][8m] [Py] [0x00-0x00/shellpop](https://github.com/0x00-0x00/shellpop) 在渗透中生产简易的/复杂的反向/绑定Shell
- [**1029**星][28d] [Boo] [byt3bl33d3r/silenttrinity](https://github.com/byt3bl33d3r/silenttrinity) 
- [**1015**星][3m] [Py] [byt3bl33d3r/deathstar](https://github.com/byt3bl33d3r/deathstar) 在Active Directory环境中使用Empire自动获取域管理员权限
- [**754**星][4m] [Py] [lgandx/pcredz](https://github.com/lgandx/pcredz) 
- [**737**星][4m] [PowerShell] [hausec/adape-script](https://github.com/hausec/adape-script) 
- [**668**星][1m] [C#] [cobbr/sharpsploit](https://github.com/cobbr/sharpsploit) 
- [**485**星][4y] [JS] [mandatoryprogrammer/sonar.js](https://github.com/mandatoryprogrammer/sonar.js) 通过 WebRTC IP 枚举，结合 WebSockets 和外部资源指纹，来识别内网主机的漏洞并发动攻击的框架
- [**449**星][2y] [PowerShell] [spiderlabs/portia](https://github.com/spiderlabs/portia) 
- [**405**星][4m] [Shell] [thesecondsun/bashark](https://github.com/thesecondsun/bashark) 
- [**345**星][3y] [C++] [m00nrise/processhider](https://github.com/m00nrise/processhider) 
- [**341**星][4m] [Py] [adrianvollmer/powerhub](https://github.com/adrianvollmer/powerhub) 
- [**294**星][1y] [Shell] [sevagas/swap_digger](https://github.com/sevagas/swap_digger) 
    - 重复区段: [工具/事件响应&&取证&&内存取证&&数字取证/取证&&Forensics&&数字取证&&内存取证](#1fc5d3621bb13d878f337c8031396484) |
- [**282**星][1y] [JS] [chrisallenlane/novahot](https://github.com/chrisallenlane/novahot) Webshell框架，实现了基于Json的API，可与任何语言编写的后门（默认支持PHP/Ruby/Python）进行通信。
    - 重复区段: [工具/webshell/未分类-webshell](#faa91844951d2c29b7b571c6e8a3eb54) |
- [**235**星][2y] [Py] [panagiks/rspet](https://github.com/panagiks/rspet) 
- [**216**星][2y] [PowerShell] [arno0x/dbc2](https://github.com/arno0x/dbc2) 
- [**212**星][2m] [Go] [brompwnie/botb](https://github.com/brompwnie/botb) 
- [**197**星][1m] [Py] [elevenpaths/ibombshell](https://github.com/elevenpaths/ibombshell) 
- [**196**星][2y] [emilyanncr/windows-post-exploitation](https://github.com/emilyanncr/windows-post-exploitation) 
- [**174**星][4y] [C] [hvqzao/foolav](https://github.com/hvqzao/foolav) 
- [**164**星][12m] [Py] [spiderlabs/scavenger](https://github.com/spiderlabs/scavenger) is a multi-threaded post-exploitation scanning tool for scavenging systems, finding most frequently used files and folders as well as "interesting" files containing sensitive information.
- [**145**星][2y] [PowerShell] [milo2012/portia](https://github.com/milo2012/portia) portia：自动化内网渗透测试工具
- [**131**星][9m] [PowerShell] [securemode/invoke-apex](https://github.com/securemode/invoke-apex) 
- [**101**星][2y] [C] [akayn/postexploits](https://github.com/akayn/postexploits) post exploitation: Keyloggers, UacByPass etc..
- [**67**星][1y] [Py] [kdaoudieh/bella](https://github.com/kdaoudieh/bella) 
- [**58**星][2y] [Visual Basic] [mgeeky/robustpentestmacro](https://github.com/mgeeky/robustpentestmacro) 
- [**28**星][14d] [Py] [entynetproject/proton](https://github.com/entynetproject/proton) 


#### <a id="4c2095e7e192ac56f6ae17c8fc045c51"></a>提权&&PrivilegeEscalation


- [**3509**星][4m] [C] [secwiki/windows-kernel-exploits](https://github.com/secwiki/windows-kernel-exploits) 
- [**1245**星][2m] [Py] [alessandroz/beroot](https://github.com/alessandroz/beroot) 
- [**821**星][5y] [Py] [pentestmonkey/windows-privesc-check](https://github.com/pentestmonkey/windows-privesc-check) 独立工具，查找Windows系统上可导致本地提权的错误配置
- [**784**星][4y] [Assembly] [xoreaxeaxeax/sinkhole](https://github.com/xoreaxeaxeax/sinkhole) 
- [**664**星][2y] [C] [1n3/privesc](https://github.com/1n3/privesc) 
- [**583**星][11m] [C++] [ohpe/juicy-potato](https://github.com/ohpe/juicy-potato) 
- [**548**星][5y] [C] [kabot/unix-privilege-escalation-exploits-pack](https://github.com/kabot/unix-privilege-escalation-exploits-pack) 
- [**541**星][3y] [C] [ausjock/privilege-escalation](https://github.com/ausjock/privilege-escalation) 
- [**529**星][4m] [rhinosecuritylabs/aws-iam-privilege-escalation](https://github.com/rhinosecuritylabs/aws-iam-privilege-escalation) 
- [**492**星][7m] [Py] [initstring/dirty_sock](https://github.com/initstring/dirty_sock) 
- [**467**星][8m] [C] [nongiach/sudo_inject](https://github.com/nongiach/sudo_inject) 
- [**443**星][1m] [C#] [rasta-mouse/watson](https://github.com/rasta-mouse/watson) 
- [**413**星][4y] [Py] [ngalongc/autolocalprivilegeescalation](https://github.com/ngalongc/autolocalprivilegeescalation) 
- [**383**星][3m] [PowerShell] [cyberark/aclight](https://github.com/cyberark/ACLight) 
- [**376**星][4y] [Py] [sleventyeleven/linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker) Linux提权检查脚本
- [**353**星][2m] [PowerShell] [gdedrouas/exchange-ad-privesc](https://github.com/gdedrouas/exchange-ad-privesc) 
- [**337**星][20d] [Shell] [nullarray/roothelper](https://github.com/nullarray/roothelper) 辅助在被攻克系统上的提权过程：自动枚举、下载、解压并执行提权脚本
- [**330**星][2y] [C#] [foxglovesec/rottenpotato](https://github.com/foxglovesec/rottenpotato) 
- [**302**星][4m] [Batchfile] [frizb/windows-privilege-escalation](https://github.com/frizb/windows-privilege-escalation) 
- [**258**星][3m] [PHP] [lawrenceamer/0xsp-mongoose](https://github.com/lawrenceamer/0xsp-mongoose) 
- [**189**星][3y] [Shell] [b3rito/yodo](https://github.com/b3rito/yodo) 
- [**166**星][2y] [PowerShell] [absolomb/windowsenum](https://github.com/absolomb/windowsenum) 
- [**144**星][2m] [Py] [initstring/uptux](https://github.com/initstring/uptux) 
- [**140**星][3y] [Objective-C] [zhengmin1989/os-x-10.11.6-exp-via-pegasus](https://github.com/zhengmin1989/os-x-10.11.6-exp-via-pegasus) 
- [**137**星][8m] [Shell] [wazehell/pe-linux](https://github.com/wazehell/pe-linux) 
- [**134**星][4m] [Shell] [mbahadou/postenum](https://github.com/mbahadou/postenum) 
- [**132**星][9m] [Shell] [nullarray/mida-multitool](https://github.com/nullarray/mida-multitool) 
- [**122**星][4y] [Py] [raffaele-forte/climber](https://github.com/raffaele-forte/climber) 
- [**118**星][4y] [Batchfile] [brianwrf/winsystemhelper](https://github.com/brianwrf/winsystemhelper) 
- [**85**星][3y] [Objective-C] [zhengmin1989/macos-10.12.2-exp-via-mach_voucher](https://github.com/zhengmin1989/macos-10.12.2-exp-via-mach_voucher) 
- [**83**星][4y] [C#] [monoxgas/trebuchet](https://github.com/monoxgas/trebuchet) 
- [**78**星][4y] [C#] [realalexandergeorgiev/tempracer](https://github.com/realalexandergeorgiev/tempracer) 
- [**68**星][3y] [Batchfile] [azmatt/windowsenum](https://github.com/azmatt/windowsenum) 
- [**55**星][9m] [Py] [cnotin/splunkwhisperer2](https://github.com/cnotin/splunkwhisperer2) 
- [**52**星][1y] [Self] [ayoul3/privesc](https://github.com/ayoul3/privesc) 
- [**52**星][3y] [C++] [rwfpl/rewolf-msi-exploit](https://github.com/rwfpl/rewolf-msi-exploit) 
- [**47**星][5y] [C] [lukasikic/unix-privilege-escalation-exploits-pack](https://github.com/lukasikic/unix-privilege-escalation-exploits-pack) 
- [**45**星][1y] [C] [bazad/launchd-portrep](https://github.com/bazad/launchd-portrep) macOS 10.13.5 Mach端口替换漏洞, 可导致提权和SIP绕过(CVE-2018-4280)
- [**45**星][4y] [C++] [rootkitsmm/ms15-061](https://github.com/rootkitsmm/ms15-061) 
- [**45**星][3y] [C++] [notglop/sysexec](https://github.com/NotGlop/SysExec) 
- [**43**星][4y] [Shell] [brianwrf/roothelper](https://github.com/brianwrf/roothelper) 
- [**43**星][6m] [Py] [initstring/lxd_root](https://github.com/initstring/lxd_root) 
- [**40**星][3y] [C] [laginimaineb/cve-2016-2431](https://github.com/laginimaineb/cve-2016-2431) 
- [**39**星][4m] [PowerShell] [absozed/steamprivesc](https://github.com/absozed/steamprivesc) 
- [**37**星][3y] [C++] [scalys7/privilege-escalation-framework](https://github.com/scalys7/privilege-escalation-framework) 
- [**36**星][1y] [Py] [linted/linuxprivchecker](https://github.com/linted/linuxprivchecker) 
- [**34**星][1y] [C++] [tarlogicsecurity/eoploaddriver](https://github.com/tarlogicsecurity/eoploaddriver) 
- [**27**星][10m] [Batchfile] [sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop) Windows/Linux本地提权工作室
- [**26**星][3y] [C++] [rwfpl/rewolf-pcausa-exploit](https://github.com/rwfpl/rewolf-pcausa-exploit) 
- [**25**星][2y] [C] [0x00-0x00/cve-2018-1000001](https://github.com/0x00-0x00/cve-2018-1000001) 
- [**24**星][4y] [C++] [rootkitsmm/winio-vidix](https://github.com/rootkitsmm/winio-vidix) 


#### <a id="caab36bba7fa8bb931a9133e37d397f6"></a>Windows


##### <a id="7ed8ee71c4a733d5e5e5d239f0e8b9e0"></a>未分类


- [**328**星][2m] [C] [mattiwatti/efiguard](https://github.com/mattiwatti/efiguard) 
- [**209**星][1y] [C++] [tandasat/pgresarch](https://github.com/tandasat/pgresarch) 
- [**182**星][2y] [C++] [killvxk/disablewin10patchguardpoc](https://github.com/killvxk/disablewin10patchguardpoc) 
- [**153**星][1m] [C++] [can1357/byepg](https://github.com/can1357/byepg) 
- [**79**星][5y] [C++] [tandasat/findpg](https://github.com/tandasat/findpg) 


##### <a id="58f3044f11a31d0371daa91486d3694e"></a>UAC


- [**2283**星][15d] [C] [hfiref0x/uacme](https://github.com/hfiref0x/uacme) 
- [**223**星][2y] [fuzzysecurity/defcon25](https://github.com/fuzzysecurity/defcon25) 
- [**189**星][1y] [Py] [feicong/lua_re](https://github.com/feicong/lua_re) 
- [**145**星][2y] [C++] [l3cr0f/dccwbypassuac](https://github.com/l3cr0f/dccwbypassuac) 
- [**140**星][1y] [C++] [hjc4869/uacbypass](https://github.com/hjc4869/uacbypass) 
- [**118**星][8m] [C] [dimopouloselias/alpc-mmc-uac-bypass](https://github.com/dimopouloselias/alpc-mmc-uac-bypass) 
- [**103**星][3y] [C++] [cn33liz/tpminituacbypass](https://github.com/cn33liz/tpminituacbypass) 
- [**91**星][1m] [Py] [elevenpaths/uac-a-mola](https://github.com/elevenpaths/uac-a-mola) 
- [**83**星][4y] [Visual Basic] [vozzie/uacscript](https://github.com/vozzie/uacscript) 
- [**79**星][3y] [PowerShell] [winscripting/uac-bypass](https://github.com/winscripting/uac-bypass) 
- [**72**星][6y] [Shell] [mkottman/luacrypto](https://github.com/mkottman/luacrypto) 
- [**64**星][1y] [C++] [3gstudent/use-com-objects-to-bypass-uac](https://github.com/3gstudent/use-com-objects-to-bypass-uac) 
- [**60**星][7m] [Ruby] [gushmazuko/winbypass](https://github.com/gushmazuko/winbypass) 
- [**59**星][5y] [C++] [malwaretech/uacelevator](https://github.com/malwaretech/uacelevator) 
- [**52**星][12m] [C] [mikeryan/uberducky](https://github.com/mikeryan/uberducky) 将Ubertooth转换为通过BLE触发的无线USB橡皮鸭
- [**40**星][9m] [C++] [bytecode77/slui-file-handler-hijack-privilege-escalation](https://github.com/bytecode77/slui-file-handler-hijack-privilege-escalation) 利用 slui.exe 的文件 Handler 劫持漏洞实现 UAC 绕过和本地提权
- [**36**星][2y] [C++] [cedarctic/digiquack](https://github.com/cedarctic/digiquack) 
- [**36**星][3y] [C++] [cn33liz/tpminituacanniversarybypass](https://github.com/cn33liz/tpminituacanniversarybypass) 
- [**36**星][2y] [fuzzysecurity/defcon-beijing-uac](https://github.com/fuzzysecurity/defcon-beijing-uac) 


##### <a id="b84c84a853416b37582c3b7f13eabb51"></a>AppLocker


- [**162**星][2m] [Swift] [ryasnoy/applocker](https://github.com/ryasnoy/applocker) 
- [**39**星][2y] [milkdevil/ultimateapplockerbypasslist](https://github.com/milkdevil/ultimateapplockerbypasslist) 
- [**33**星][2y] [C] [demonsec666/secist_applocker](https://github.com/demonsec666/secist_applocker) 


##### <a id="e3c4c83dfed529ceee65040e565003c4"></a>ActiveDirectory


- [**1943**星][2m] [infosecn1nja/ad-attack-defense](https://github.com/infosecn1nja/ad-attack-defense) 


##### <a id="25697cca32bd8c9492b8e2c8a3a93bfe"></a>域渗透






#### <a id="2dd40db455d3c6f1f53f8a9c25bbe63e"></a>驻留&&Persistence


- [**271**星][2m] [C#] [fireeye/sharpersist](https://github.com/fireeye/sharpersist) Windows persistence toolkit 
- [**260**星][1y] [C++] [ewhitehats/invisiblepersistence](https://github.com/ewhitehats/invisiblepersistence) 
- [**119**星][9m] [PowerShell] [p0w3rsh3ll/autoruns](https://github.com/p0w3rsh3ll/autoruns) 
- [**93**星][2y] [Batchfile] [huntresslabs/evading-autoruns](https://github.com/huntresslabs/evading-autoruns) 几种用于逃避常见的驻留枚举工具的技术（Evading Autoruns，Derbycon 2017）
- [**83**星][3y] [C++] [hasherezade/persistence_demos](https://github.com/hasherezade/persistence_demos) 
- [**59**星][5y] [PowerShell] [enigma0x3/outlookpersistence](https://github.com/enigma0x3/outlookpersistence) 
- [**58**星][3y] [PowerShell] [killswitch-gui/persistence-survivability](https://github.com/killswitch-gui/persistence-survivability) 
- [**37**星][6m] [C#] [woanware/autorunner](https://github.com/woanware/autorunner) 
- [**31**星][2y] [PowerShell] [3gstudent/office-persistence](https://github.com/3gstudent/office-persistence) 




### <a id="fc8737aef0f59c3952d11749fe582dac"></a>自动化


- [**2039**星][2y] [Py] [derv82/wifite](https://github.com/derv82/wifite) 自动化无线攻击工具
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**1799**星][4m] [Shell] [arismelachroinos/lscript](https://github.com/arismelachroinos/lscript) 自动化无线渗透和Hacking 任务的脚本
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**1741**星][21d] [Shell] [leebaird/discover](https://github.com/leebaird/discover) 自定义的bash脚本, 用于自动化多个渗透测试任务, 包括: 侦查、扫描、解析、在Metasploit中创建恶意Payload和Listener
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload生成](#ad92f6b801a18934f1971e2512f5ae4f) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Metasploit/未分类-metasploit](#01be61d5bb9f6f7199208ff0fba86b5d) |
- [**1656**星][2m] [Py] [rootm0s/winpwnage](https://github.com/rootm0s/winpwnage) 


### <a id="3ae4408f4ab03f99bab9ef9ee69642a8"></a>数据渗透


- [**929**星][2y] [Py] [trycatchhcf/cloakify](https://github.com/trycatchhcf/cloakify) 
- [**453**星][3m] [Py] [viralmaniar/powershell-rat](https://github.com/viralmaniar/powershell-rat) 
- [**301**星][2y] [JS] [arno0x/dnsexfiltrator](https://github.com/arno0x/dnsexfiltrator) 
    - 重复区段: [工具/通信&&代理&&反向代理&&隧道/隧道](#e996f5ff54050629de0d9d5e68fcb630) |


### <a id="adfa06d452147ebacd35981ce56f916b"></a>横向渗透




### <a id="39e9a0fe929fffe5721f7d7bb2dae547"></a>Burp


#### <a id="6366edc293f25b57bf688570b11d6584"></a>收集


- [**1920**星][1y] [BitBake] [1n3/intruderpayloads](https://github.com/1n3/intruderpayloads) 
- [**1058**星][27d] [snoopysecurity/awesome-burp-extensions](https://github.com/snoopysecurity/awesome-burp-extensions) Burp扩展收集


#### <a id="5b761419863bc686be12c76451f49532"></a>未分类-Burp


- [**1091**星][1y] [Py] [bugcrowd/hunt](https://github.com/bugcrowd/HUNT) Burp和ZAP的扩展收集
- [**893**星][3y] [Java] [summitt/burp-non-http-extension](https://github.com/summitt/burp-non-http-extension) 
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
- [**388**星][2y] [Java] [federicodotta/java-deserialization-scanner](https://github.com/federicodotta/java-deserialization-scanner) 
- [**373**星][2y] [Py] [0x4d31/burpa](https://github.com/0x4d31/burpa) 
- [**373**星][1y] [Py] [rhinosecuritylabs/sleuthql](https://github.com/rhinosecuritylabs/sleuthql) 
- [**371**星][2m] [Java] [nccgroup/autorepeater](https://github.com/nccgroup/autorepeater) 
- [**367**星][4y] [JS] [allfro/burpkit](https://github.com/allfro/burpkit) 
- [**352**星][4m] [Java] [bit4woo/domain_hunter](https://github.com/bit4woo/domain_hunter) 
- [**340**星][2y] [Py] [pathetiq/burpsmartbuster](https://github.com/pathetiq/burpsmartbuster) 
- [**336**星][2y] [Py] [securityinnovation/authmatrix](https://github.com/securityinnovation/authmatrix) 
- [**327**星][2m] [Kotlin] [portswigger/turbo-intruder](https://github.com/portswigger/turbo-intruder) 
- [**309**星][1y] [Java] [ebryx/aes-killer](https://github.com/ebryx/aes-killer) 
- [**300**星][3m] [Java] [bit4woo/knife](https://github.com/bit4woo/knife) 
- [**300**星][7m] [Java] [ilmila/j2eescan](https://github.com/ilmila/j2eescan) 
- [**299**星][2m] [Java] [portswigger/http-request-smuggler](https://github.com/PortSwigger/http-request-smuggler) an extension for Burp Suite designed to help you launch HTTP Request Smuggling attack
- [**298**星][3y] [Java] [nvisium/xssvalidator](https://github.com/nvisium/xssvalidator) 
- [**297**星][11m] [Shell] [yw9381/burp_suite_doc_zh_cn](https://github.com/yw9381/burp_suite_doc_zh_cn) 
- [**296**星][1y] [Java] [vmware/burp-rest-api](https://github.com/vmware/burp-rest-api) 
- [**273**星][2y] [Java] [mateuszk87/badintent](https://github.com/mateuszk87/badintent) 
    - 重复区段: [工具/移动&&Mobile/Android](#fe88ee8c0df10870b44c2dedcd86d3d3) |
- [**272**星][1y] [Java] [elkokc/reflector](https://github.com/elkokc/reflector) reflector：Burp 插件，浏览网页时实时查找反射 XSS
- [**264**星][18d] [Py] [quitten/autorize](https://github.com/quitten/autorize) 
- [**254**星][3y] [Java] [codewatchorg/bypasswaf](https://github.com/codewatchorg/bypasswaf) 
- [**250**星][2m] [Py] [rhinosecuritylabs/iprotate_burp_extension](https://github.com/rhinosecuritylabs/iprotate_burp_extension) 
- [**245**星][2y] [Java] [portswigger/collaborator-everywhere](https://github.com/portswigger/collaborator-everywhere) collaborator-everywhere：Burp Suite 扩展，通过注入非侵入性 headers 来增强代理流量，通过引起 Pingback 到 Burp Collaborator 来揭露后端系统
- [**241**星][4m] [Py] [initroot/burpjslinkfinder](https://github.com/initroot/burpjslinkfinder) 
- [**235**星][1m] [Java] [samlraider/samlraider](https://github.com/samlraider/samlraider) 
- [**231**星][1y] [Java] [nccgroup/burpsuiteloggerplusplus](https://github.com/nccgroup/burpsuiteloggerplusplus) 
- [**230**星][1y] [Py] [audibleblink/doxycannon](https://github.com/audibleblink/doxycannon) DoxyCannon: 为一堆OpenVPN文件分别创建Docker容器, 每个容器开启SOCKS5代理服务器并绑定至Docker主机端口, 再结合使用Burp或ProxyChains, 构建私有的Botnet
- [**230**星][1y] [Java] [difcareer/sqlmap4burp](https://github.com/difcareer/sqlmap4burp) 
- [**222**星][6m] [Java] [c0ny1/jsencrypter](https://github.com/c0ny1/jsencrypter) 
- [**214**星][2m] [Java] [c0ny1/passive-scan-client](https://github.com/c0ny1/passive-scan-client) 
- [**205**星][2m] [Java] [h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator) 
- [**202**星][5m] [Perl] [modzero/mod0burpuploadscanner](https://github.com/modzero/mod0burpuploadscanner) 
- [**189**星][2y] [Java] [p3gleg/pwnback](https://github.com/P3GLEG/PwnBack) 
- [**178**星][8m] [Py] [teag1e/burpcollector](https://github.com/teag1e/burpcollector) 
- [**172**星][2y] [Py] [virtuesecurity/aws-extender](https://github.com/virtuesecurity/aws-extender) 
- [**169**星][1y] [Py] [codewatchorg/sqlipy](https://github.com/codewatchorg/sqlipy) sqlipy: Burp Suite 插件, 使用 SQLMap API 集成SQLMap
- [**158**星][3m] [Py] [regala/burp-scope-monitor](https://github.com/regala/burp-scope-monitor) 
- [**156**星][4m] [Java] [netspi/javaserialkiller](https://github.com/netspi/javaserialkiller) 
- [**154**星][1y] [Py] [bayotop/off-by-slash](https://github.com/bayotop/off-by-slash) off-by-slash: Bupr扩展, 检测利用Nginx错误配置导致的重名遍历(alias traversal)
- [**153**星][2m] [Py] [wish-i-was/femida](https://github.com/wish-i-was/femida) 
- [**150**星][4m] [Py] [kacperszurek/burp_wp](https://github.com/kacperszurek/burp_wp) 
- [**147**星][3y] [Java] [mwielgoszewski/jython-burp-api](https://github.com/mwielgoszewski/jython-burp-api) 
- [**144**星][4y] [trietptm/sql-injection-payloads](https://github.com/trietptm/sql-injection-payloads) 
- [**140**星][5m] [Py] [integrity-sa/burpcollaborator-docker](https://github.com/integrity-sa/burpcollaborator-docker) 
- [**140**星][12m] [Java] [tomsteele/burpbuddy](https://github.com/tomsteele/burpbuddy) 
- [**139**星][5m] [Py] [codingo/minesweeper](https://github.com/codingo/minesweeper) 
- [**139**星][3m] [Java] [netsoss/headless-burp](https://github.com/netsoss/headless-burp) 
- [**137**星][1y] [Java] [netspi/wsdler](https://github.com/netspi/wsdler) 
- [**137**星][6m] [Py] [thekingofduck/burpfakeip](https://github.com/thekingofduck/burpfakeip) 
- [**135**星][1y] [JS] [h3xstream/burp-retire-js](https://github.com/h3xstream/burp-retire-js) 
- [**130**星][6m] [Go] [empijei/wapty](https://github.com/empijei/wapty) Go语言编写的Burp的替代品。（已不再维护）
- [**127**星][2y] [Java] [yandex/burp-molly-scanner](https://github.com/yandex/burp-molly-scanner) 
- [**122**星][4y] [Py] [moloch--/csp-bypass](https://github.com/moloch--/csp-bypass) 
- [**117**星][6y] [Py] [meatballs1/burp-extensions](https://github.com/meatballs1/burp-extensions) 
- [**116**星][20d] [cujanovic/content-bruteforcing-wordlist](https://github.com/cujanovic/content-bruteforcing-wordlist) 
- [**113**星][19d] [Java] [nccgroup/decoder-improved](https://github.com/nccgroup/decoder-improved) 
- [**107**星][2y] [Java] [x-ai/burpunlimitedre](https://github.com/x-ai/burpunlimitedre) 
- [**103**星][2m] [Py] [redhuntlabs/burpsuite-asset_discover](https://github.com/redhuntlabs/burpsuite-asset_discover) 
- [**102**星][6m] [Py] [kibodwapon/noeye](https://github.com/kibodwapon/noeye) 
- [**101**星][2y] [Java] [clr2of8/gathercontacts](https://github.com/clr2of8/gathercontacts) 
- [**101**星][2y] [Java] [gosecure/csp-auditor](https://github.com/gosecure/csp-auditor) 
- [**101**星][1y] [Java] [mystech7/burp-hunter](https://github.com/mystech7/burp-hunter) 
- [**101**星][25d] [Py] [prodigysml/dr.-watson](https://github.com/prodigysml/dr.-watson) 
- [**100**星][1m] [Java] [netspi/burp-extensions](https://github.com/netspi/burp-extensions) 
- [**98**星][4y] [Java] [summitt/burp-ysoserial](https://github.com/summitt/burp-ysoserial) 
- [**97**星][2y] [Java] [spiderlabs/airachnid-burp-extension](https://github.com/spiderlabs/airachnid-burp-extension) 
- [**95**星][2y] [Java] [jgillam/burp-co2](https://github.com/jgillam/burp-co2) 
- [**93**星][2y] [Py] [debasishm89/burpy](https://github.com/debasishm89/burpy) 
- [**93**星][19d] [Java] [mvetsch/jwt4b](https://github.com/mvetsch/jwt4b) 
- [**90**星][3m] [Java] [c0ny1/sqlmap4burp-plus-plus](https://github.com/c0ny1/sqlmap4burp-plus-plus) 
- [**89**星][3y] [Java] [dobin/burpsentinel](https://github.com/dobin/burpsentinel) 
- [**88**星][1y] [Java] [federicodotta/handycollaborator](https://github.com/federicodotta/handycollaborator) 
- [**88**星][5m] [Java] [rub-nds/burpssoextension](https://github.com/rub-nds/burpssoextension) 
- [**86**星][8m] [Java] [doyensec/burpdeveltraining](https://github.com/doyensec/burpdeveltraining) 
- [**85**星][8m] [Py] [laconicwolf/burp-extensions](https://github.com/laconicwolf/burp-extensions) 
- [**85**星][1y] [Java] [silentsignal/burp-image-size](https://github.com/silentsignal/burp-image-size) 
- [**85**星][6m] [Py] [lopseg/jsdir](https://github.com/Lopseg/Jsdir) 
- [**83**星][2y] [Java] [yandex/burp-molly-pack](https://github.com/yandex/burp-molly-pack) 
- [**82**星][2m] [Java] [jgillam/burp-paramalyzer](https://github.com/jgillam/burp-paramalyzer) 
- [**80**星][6y] [Py] [mwielgoszewski/burp-protobuf-decoder](https://github.com/mwielgoszewski/burp-protobuf-decoder) 
- [**80**星][7m] [Py] [nccgroup/argumentinjectionhammer](https://github.com/nccgroup/argumentinjectionhammer) 
- [**79**星][1y] [Py] [nccgroup/blackboxprotobuf](https://github.com/nccgroup/blackboxprotobuf) 
- [**78**星][3m] [Py] [kapytein/jsonp](https://github.com/kapytein/jsonp) 
- [**76**星][5m] [Go] [root4loot/rescope](https://github.com/root4loot/rescope) 
- [**75**星][4y] [Java] [directdefense/superserial](https://github.com/directdefense/superserial) 
- [**74**星][4y] [Py] [integrissecurity/carbonator](https://github.com/integrissecurity/carbonator) 
- [**73**星][2y] [Java] [spiderlabs/burplay](https://github.com/spiderlabs/burplay) 
- [**70**星][2y] [Java] [ikkisoft/bradamsa](https://github.com/ikkisoft/bradamsa) 
- [**70**星][6y] [Java] [irsdl/burpsuitejsbeautifier](https://github.com/irsdl/burpsuitejsbeautifier) 
- [**70**星][7m] [Py] [jiangsir404/pbscan](https://github.com/jiangsir404/pbscan) 
- [**70**星][15d] [Py] [ziirish/burp-ui](https://github.com/ziirish/burp-ui) 
- [**69**星][1y] [Java] [bit4woo/u2c](https://github.com/bit4woo/u2c) 
- [**68**星][3y] [Py] [stayliv3/burpsuite-changeu](https://github.com/stayliv3/burpsuite-changeu) 
- [**66**星][2m] [Java] [netspi/burpcollaboratordnstunnel](https://github.com/netspi/burpcollaboratordnstunnel) 
- [**65**星][2y] [Py] [markclayton/bumpster](https://github.com/markclayton/bumpster) 
- [**63**星][4m] [Java] [nccgroup/berserko](https://github.com/nccgroup/berserko) 
- [**62**星][4m] [Py] [pinnace/burp-jwt-fuzzhelper-extension](https://github.com/pinnace/burp-jwt-fuzzhelper-extension) burp-jwt-fuzzhelper-extension: Burp扩展, 用于Fuzzing JWT
- [**61**星][2m] [Java] [aress31/swurg](https://github.com/aress31/swurg) 
- [**61**星][4y] [Py] [tony1016/burplogfilter](https://github.com/tony1016/burplogfilter) 
- [**60**星][1m] [Java] [static-flow/burpsuite-team-extension](https://github.com/static-flow/burpsuite-team-extension) 
- [**59**星][5y] [Ruby] [tduehr/buby](https://github.com/tduehr/buby) 
- [**58**星][10m] [Java] [portswigger/replicator](https://github.com/portswigger/replicator) 
- [**57**星][1y] [Java] [c0ny1/httpheadmodifer](https://github.com/c0ny1/httpheadmodifer) 
- [**57**星][6y] [Java] [spiderlabs/burpnotesextension](https://github.com/spiderlabs/burpnotesextension) 
- [**56**星][1y] [Py] [capt-meelo/telewreck](https://github.com/capt-meelo/telewreck) 
- [**56**星][12m] [Py] [destine21/zipfileraider](https://github.com/destine21/zipfileraider) 
- [**56**星][3y] [Java] [linkedin/sometime](https://github.com/linkedin/sometime) 
- [**54**星][3y] [Py] [mseclab/burp-pyjfuzz](https://github.com/mseclab/burp-pyjfuzz) 
- [**54**星][3y] [Java] [vulnerscom/burp-dirbuster](https://github.com/vulnerscom/burp-dirbuster) 
- [**53**星][1m] [Java] [coreyd97/stepper](https://github.com/coreyd97/stepper) 
- [**52**星][2y] [Java] [bigsizeme/burplugin-java-rce](https://github.com/bigsizeme/burplugin-java-rce) 
- [**52**星][5y] [Py] [jfoote/burp-git-bridge](https://github.com/jfoote/burp-git-bridge) 
- [**51**星][7m] [Py] [leoid/matchandreplace](https://github.com/leoid/matchandreplace) 
- [**50**星][2m] [Py] [lich4/personal_script](https://github.com/lich4/personal_script) 010Editor/BurpSuite/Frida/IDA等多个工具的多个脚本
    - [010Editor](https://github.com/lich4/personal_script/tree/master/010Editor_Script) 010Editor的多个脚本
    - [ParamChecker](https://github.com/lich4/personal_script/tree/master/BurpSuite_Script) Burp插件
    - [Frida](https://github.com/lich4/personal_script/tree/master/Frida_script) Frida多个脚本
    - [IDA](https://github.com/lich4/personal_script/tree/master/IDA_Script) IDA多个脚本
    - [IDA-read_unicode.py](https://github.com/lich4/personal_script/blob/master/IDA_Script/read_unicode.py) IDA插件，识别程序中的中文字符
    - [IDA-add_xref_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_xref_for_macho.py) 辅助识别Objective-C成员函数的caller和callee
    - [IDA-add_info_for_androidgdb](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_info_for_androidgdb.py) 使用gdbserver和IDA调试Android时，读取module列表和segment
    - [IDA-trace_instruction](https://github.com/lich4/personal_script/blob/master/IDA_Script/trace_instruction.py) 追踪指令流
    - [IDA-detect_ollvm](https://github.com/lich4/personal_script/blob/master/IDA_Script/detect_ollvm.py) 检测OLLVM，在某些情况下修复（Android/iOS）
    - [IDA-add_block_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_block_for_macho.py) 分析macho文件中的block结构
- [**49**星][2y] [Py] [mrschyte/socksmon](https://github.com/mrschyte/socksmon) socksmon：使用 BURP 或 ZAP 的 TCP 拦截代理
- [**49**星][1y] [Java] [netspi/burpextractor](https://github.com/netspi/burpextractor) 
- [**48**星][1y] [java] [anbai-inc/burpstart](https://github.com/anbai-inc/burpstart) 
- [**48**星][2y] [Java] [inode-/attackselector](https://github.com/inode-/attackselector) 
- [**48**星][2y] [Java] [righettod/virtualhost-payload-generator](https://github.com/righettod/virtualhost-payload-generator) 
- [**46**星][2m] [Java] [netspi/awssigner](https://github.com/netspi/awssigner) 
- [**44**星][1y] [Ruby] [pentestgeek/burpcommander](https://github.com/pentestgeek/burpcommander) 
- [**44**星][2y] [Java] [portswigger/httpoxy-scanner](https://github.com/portswigger/httpoxy-scanner) 
- [**43**星][5m] [Py] [bitthebyte/bitblinder](https://github.com/bitthebyte/bitblinder) 
- [**43**星][1y] [Py] [br3akp0int/gqlparser](https://github.com/br3akp0int/gqlparser) 
- [**43**星][2y] [Py] [hvqzao/report-ng](https://github.com/hvqzao/report-ng) 
- [**42**星][11m] [Py] [bayotop/sink-logger](https://github.com/bayotop/sink-logger) sink-logger: Burp扩展,无缝记录所有传递到已知JavaScript sinks的数据
- [**42**星][1y] [Py] [modzero/interestingfilescanner](https://github.com/modzero/interestingfilescanner) 
- [**41**星][10m] [Java] [secdec/attack-surface-detector-burp](https://github.com/secdec/attack-surface-detector-burp) 
- [**41**星][11m] [Py] [zynga/hiccup](https://github.com/zynga/hiccup) 
- [**40**星][10m] [Go] [joanbono/gurp](https://github.com/joanbono/gurp) 
- [**39**星][1y] [Java] [bit4woo/burp_collaborator_http_api](https://github.com/bit4woo/burp_collaborator_http_api) burp_collaborator_http_api: 基于Burp Collaborator的HTTP API
- [**39**星][3y] [Java] [directdefense/superserial-active](https://github.com/directdefense/superserial-active) 
- [**38**星][11m] [Py] [luh2/detectdynamicjs](https://github.com/luh2/detectdynamicjs) 
- [**38**星][3y] [team-firebugs/burp-lfi-tests](https://github.com/team-firebugs/burp-lfi-tests) 
- [**38**星][6y] [Java] [wuntee/burpauthzplugin](https://github.com/wuntee/burpauthzplugin) 
- [**38**星][10m] [Java] [tijme/similar-request-excluder](https://github.com/tijme/similar-request-excluder) 
- [**38**星][1m] [Java] [portswigger/stepper](https://github.com/portswigger/stepper) 
- [**37**星][7m] [Dockerfile] [marco-lancini/docker_burp](https://github.com/marco-lancini/docker_burp) 
- [**36**星][1y] [Java] [augustd/burp-suite-error-message-checks](https://github.com/augustd/burp-suite-error-message-checks) 
- [**36**星][8y] [Py] [gdssecurity/burpee](https://github.com/gdssecurity/burpee) 
- [**36**星][8y] [C#] [gdssecurity/wcf-binary-soap-plug-in](https://github.com/gdssecurity/wcf-binary-soap-plug-in) 
- [**35**星][3y] [Py] [0ang3el/unsafe-jax-rs-burp](https://github.com/0ang3el/unsafe-jax-rs-burp) 
- [**35**星][1y] [Java] [ikkisoft/blazer](https://github.com/ikkisoft/blazer) 
- [**35**星][7y] [Java] [continuumsecurity/resty-burp](https://github.com/continuumsecurity/resty-burp) 
- [**35**星][1y] [Java] [bit4woo/resign](https://github.com/bit4woo/ReSign) 
- [**34**星][2m] [Py] [arbazkiraak/burpblh](https://github.com/arbazkiraak/burpblh) BurpBLH: 使用IScannerCheck发现被劫持的损坏链接. Burp插件
- [**34**星][2y] [Py] [penafieljlm/burp-tracer](https://github.com/penafieljlm/burp-tracer) burp-tracer：BurpSuite 扩展。获取当前的站点地图，提取每个请求参数，并搜索存在请求参数值的回复（responseswhere request parameter value is present）
- [**34**星][3y] [Py] [politoinc/yara-scanner](https://github.com/politoinc/yara-scanner) 
- [**34**星][3y] [Py] [thomaspatzke/burp-sessionauthtool](https://github.com/thomaspatzke/burp-sessionauthtool) 
- [**34**星][3m] [Py] [gh0stkey/jsonandhttpp](https://github.com/gh0stkey/JSONandHTTPP) 
- [**33**星][3y] [Py] [attackercan/burp-xss-sql-plugin](https://github.com/attackercan/burp-xss-sql-plugin) 
- [**33**星][5y] [Py] [dionach/headersanalyzer](https://github.com/dionach/headersanalyzer) 
- [**33**星][1y] [Java] [dnet/burp-oauth](https://github.com/dnet/burp-oauth) 
- [**33**星][4y] [Py] [peacand/burp-pytemplate](https://github.com/peacand/burp-pytemplate) 
- [**33**星][26d] [Py] [zephrfish/burpfeed](https://github.com/zephrfish/burpfeed) 
- [**32**星][5y] [Java] [malerisch/burp-csj](https://github.com/malerisch/burp-csj) 
- [**32**星][6m] [Py] [portswigger/active-scan-plus-plus](https://github.com/portswigger/active-scan-plus-plus) 
- [**32**星][3y] [tdifg/payloads](https://github.com/tdifg/payloads) 
- [**31**星][9m] [twelvesec/bearerauthtoken](https://github.com/twelvesec/bearerauthtoken) 
- [**30**星][4y] [Py] [carstein/burp-extensions](https://github.com/carstein/burp-extensions) 
- [**30**星][6y] [Py] [meatballs1/burp_jsbeautifier](https://github.com/meatballs1/burp_jsbeautifier) 
- [**30**星][2m] [Java] [righettod/log-requests-to-sqlite](https://github.com/righettod/log-requests-to-sqlite) 
- [**30**星][3y] [Java] [silentsignal/burp-collab-gw](https://github.com/silentsignal/burp-collab-gw) 
- [**30**星][3y] [Go] [tomsteele/burpstaticscan](https://github.com/tomsteele/burpstaticscan) 
- [**29**星][2y] [Py] [aurainfosec/burp-multi-browser-highlighting](https://github.com/aurainfosec/burp-multi-browser-highlighting) 
- [**29**星][6m] [Java] [hvqzao/burp-flow](https://github.com/hvqzao/burp-flow) 
- [**28**星][1y] [Java] [bit4woo/gui_burp_extender_para_encrypter](https://github.com/bit4woo/gui_burp_extender_para_encrypter) 
- [**28**星][4y] [Java] [burp-hash/burp-hash](https://github.com/burp-hash/burp-hash) 
- [**28**星][3y] [Py] [floyd-fuh/burp-httpfuzzer](https://github.com/floyd-fuh/burp-httpfuzzer) 
- [**27**星][2y] [Java] [ibey0nd/nstproxy](https://github.com/ibey0nd/nstproxy) 
- [**27**星][2y] [JS] [psych0tr1a/elscripto](https://github.com/psych0tr1a/elscripto) 
- [**27**星][4y] [Py] [smeegesec/burp-importer](https://github.com/smeegesec/burp-importer) 
- [**26**星][2y] [Py] [mrts/burp-suite-http-proxy-history-converter](https://github.com/mrts/burp-suite-http-proxy-history-converter) 
- [**26**星][3y] [Java] [portswigger/xss-validator](https://github.com/portswigger/xss-validator) 
- [**26**星][4m] [Java] [bit4woo/burp-api-drops](https://github.com/bit4woo/burp-api-drops) 
- [**26**星][6m] [Java] [static-flow/directoryimporter](https://github.com/static-flow/directoryimporter) 
- [**25**星][3y] [Java] [pokeolaf/pokemongodecoderforburp](https://github.com/pokeolaf/pokemongodecoderforburp) 
- [**25**星][1m] [Java] [portswigger/taborator](https://github.com/portswigger/taborator) 
- [**25**星][2y] [Java] [vankyver/burp-vulners-scanner](https://github.com/vankyver/burp-vulners-scanner) 
- [**24**星][9m] [Kotlin] [gosecure/burp-ntlm-challenge-decoder](https://github.com/gosecure/burp-ntlm-challenge-decoder) 
- [**24**星][2y] [Py] [portswigger/burp-smart-buster](https://github.com/portswigger/burp-smart-buster) 
- [**24**星][1m] [Shell] [putsi/privatecollaborator](https://github.com/putsi/privatecollaborator) 
- [**24**星][3y] [Py] [silentsignal/activescan3plus](https://github.com/silentsignal/activescan3plus) 
- [**23**星][2y] [Py] [aur3lius-dev/spydir](https://github.com/aur3lius-dev/spydir) 
- [**23**星][6m] [Java] [ettic-team/endpointfinder-burp](https://github.com/ettic-team/endpointfinder-burp) 
- [**23**星][3y] [Java] [vah13/burpcrlfplugin](https://github.com/vah13/burpcrlfplugin) 
- [**23**星][2y] [Ruby] [zidekmat/graphql_beautifier](https://github.com/zidekmat/graphql_beautifier) 
- [**22**星][3m] [Py] [elespike/burp-cph](https://github.com/elespike/burp-cph) 
- [**22**星][8m] [BitBake] [ghsec/bbprofiles](https://github.com/ghsec/bbprofiles) 
- [**22**星][3y] [Swift] [melvinsh/burptoggle](https://github.com/melvinsh/burptoggle) 
- [**22**星][7y] [Py] [milo2012/burpsql](https://github.com/milo2012/burpsql) 
- [**22**星][1y] [Py] [portswigger/sqli-py](https://github.com/portswigger/sqli-py) 
- [**22**星][13d] [Java] [rub-nds/tls-attacker-burpextension](https://github.com/rub-nds/tls-attacker-burpextension) 
- [**22**星][7m] [Java] [silentsignal/burp-requests](https://github.com/silentsignal/burp-requests) 
- [**22**星][2y] [Java] [silentsignal/burp-uuid](https://github.com/silentsignal/burp-uuid) 
- [**21**星][3y] [Java] [ernw/burpsuite-extensions](https://github.com/ernw/burpsuite-extensions) 
- [**21**星][12m] [Py] [jiangsir404/xss-sql-fuzz](https://github.com/jiangsir404/xss-sql-fuzz) 
- [**21**星][2y] [Py] [unamer/ctfhelper](https://github.com/unamer/ctfhelper) 
- [**20**星][5y] [Java] [khai-tran/burpjdser](https://github.com/khai-tran/burpjdser) 
- [**20**星][3y] [Ruby] [kingsabri/burp_suite_extension_ruby](https://github.com/kingsabri/burp_suite_extension_ruby) 
- [**20**星][1m] [Java] [portswigger/json-web-tokens](https://github.com/portswigger/json-web-tokens) 
- [**20**星][3y] [Py] [securitymb/burp-exceptions](https://github.com/securitymb/burp-exceptions) 
- [**19**星][6m] [Java] [hvqzao/burp-wildcard](https://github.com/hvqzao/burp-wildcard) 
- [**19**星][4y] [Java] [lgrangeia/aesburp](https://github.com/lgrangeia/aesburp) 
- [**19**星][5y] [Java] [nccgroup/wcfdser-ngng](https://github.com/nccgroup/wcfdser-ngng) 
- [**18**星][2m] [Java] [augustd/burp-suite-software-version-checks](https://github.com/augustd/burp-suite-software-version-checks) 
- [**18**星][7y] [Java] [omercnet/burpjdser-ng](https://github.com/omercnet/burpjdser-ng) 
- [**18**星][6y] [raz0r/burp-radamsa](https://github.com/raz0r/burp-radamsa) 
- [**18**星][26d] [Java] [silentsignal/burp-json-jtree](https://github.com/silentsignal/burp-json-jtree) 
- [**17**星][2y] [HCL] [4armed/terraform-burp-collaborator](https://github.com/4armed/terraform-burp-collaborator) 
- [**17**星][3y] [codewatchorg/burp-yara-rules](https://github.com/codewatchorg/burp-yara-rules) 
- [**17**星][1y] [Py] [mgeeky/burpcontextawarefuzzer](https://github.com/mgeeky/burpcontextawarefuzzer) 
- [**17**星][11m] [Py] [portswigger/additional-scanner-checks](https://github.com/portswigger/additional-scanner-checks) 
- [**17**星][2y] [Java] [portswigger/j2ee-scan](https://github.com/portswigger/j2ee-scan) 
- [**17**星][1m] [BitBake] [sy3omda/burp-bounty](https://github.com/sy3omda/burp-bounty) 
- [**17**星][5m] [Java] [thomashartm/burp-aem-scanner](https://github.com/thomashartm/burp-aem-scanner) 
- [**17**星][26d] [Java] [phefley/burp-javascript-security-extension](https://github.com/phefley/burp-javascript-security-extension) 
- [**17**星][6m] [Py] [yeswehack/yesweburp](https://github.com/yeswehack/yesweburp) 
- [**15**星][4y] [Java] [shengqi158/rsa-crypto-burp-extention](https://github.com/shengqi158/rsa-crypto-burp-extention) 
- [**15**星][1m] [thehackingsage/burpsuite](https://github.com/thehackingsage/burpsuite) 
- [**15**星][9m] [Java] [twelvesec/jdser-dcomp](https://github.com/twelvesec/jdser-dcomp) 
- [**15**星][2m] [Java] [aress31/flarequench](https://github.com/aress31/flarequench) 
- [**14**星][10m] [Java] [portswigger/auto-repeater](https://github.com/portswigger/auto-repeater) 
- [**13**星][4m] [Java] [ankokuty/belle](https://github.com/ankokuty/belle) 
- [**13**星][2y] [Java] [netspi/jsonbeautifier](https://github.com/netspi/jsonbeautifier) 
- [**13**星][2y] [Java] [portswigger/json-beautifier](https://github.com/portswigger/json-beautifier) 
- [**13**星][11m] [Py] [thomaspatzke/burp-missingscannerchecks](https://github.com/thomaspatzke/burp-missingscannerchecks) 
- [**13**星][6m] [Py] [bellma101/sri-check](https://github.com/SolomonSklash/sri-check) 
- [**12**星][1y] [Java] [ah8r/csrf](https://github.com/ah8r/csrf) 
- [**12**星][11m] [boreas514/burp-suite-2.0-chinese-document](https://github.com/boreas514/burp-suite-2.0-chinese-document) 
- [**12**星][5y] [Py] [enablesecurity/identity-crisis](https://github.com/enablesecurity/identity-crisis) 
- [**12**星][5y] [Java] [federicodotta/burpjdser-ng-edited](https://github.com/federicodotta/burpjdser-ng-edited) 
- [**12**星][7y] [Py] [infodel/burp.extension-googlehack](https://github.com/infodel/burp.extension-googlehack) 
- [**12**星][6m] [Py] [modzero/burp-responseclusterer](https://github.com/modzero/burp-responseclusterer) 
- [**12**星][1y] [Java] [moeinfatehi/admin-panel_finder](https://github.com/moeinfatehi/admin-panel_finder) 
- [**11**星][8m] [Py] [anandtiwarics/python-burp-rest-api](https://github.com/anandtiwarics/python-burp-rest-api) 
- [**11**星][2m] [Java] [augustd/burp-suite-utils](https://github.com/augustd/burp-suite-utils) 
- [**11**星][6y] [Py] [faffi/curlit](https://github.com/faffi/curlit) 
- [**11**星][8y] [Java] [gdssecurity/deflate-burp-plugin](https://github.com/gdssecurity/deflate-burp-plugin) 
- [**11**星][2y] [Java] [gozo-mt/burplist](https://github.com/gozo-mt/burplist) 
- [**11**星][3y] [Java] [h3xstream/burp-image-metadata](https://github.com/h3xstream/burp-image-metadata) 
- [**11**星][2y] [Java] [portswigger/attack-selector](https://github.com/portswigger/attack-selector) 
- [**11**星][3y] [Java] [portswigger/bypass-waf](https://github.com/portswigger/bypass-waf) 
- [**11**星][5m] [Java] [portswigger/copy-as-python-requests](https://github.com/portswigger/copy-as-python-requests) 
- [**11**星][6y] [Py] [smeegesec/wsdlwizard](https://github.com/smeegesec/wsdlwizard) 
- [**11**星][4y] [Py] [vincd/burpproxypacextension](https://github.com/vincd/burpproxypacextension) 
- [**11**星][4y] [Java] [monikamorrow/burp-suite-extension-examples](https://github.com/monikamorrow/Burp-Suite-Extension-Examples) 
- [**10**星][2y] [HTML] [adriancitu/burp-tabnabbing-extension](https://github.com/adriancitu/burp-tabnabbing-extension) 
- [**10**星][4y] [Java] [augustd/burp-suite-token-fetcher](https://github.com/augustd/burp-suite-token-fetcher) 
- [**10**星][11m] [Py] [portswigger/detect-dynamic-js](https://github.com/portswigger/detect-dynamic-js) 
- [**10**星][2y] [Java] [securifybv/phpunserializecheck](https://github.com/securifybv/phpunserializecheck) 
- [**10**星][5m] [Java] [veggiespam/imagelocationscanner](https://github.com/veggiespam/imagelocationscanner) 
- [**10**星][6y] [Java] [xxux11/burpheartbleedextension](https://github.com/xxux11/burpheartbleedextension) 
- [**9**星][4y] [Java] [allfro/dotnetbeautifier](https://github.com/allfro/dotnetbeautifier) 
- [**9**星][4y] [Java] [augustd/burp-suite-gwt-scan](https://github.com/augustd/burp-suite-gwt-scan) 
- [**9**星][6m] [Py] [defectdojo/burp-plugin](https://github.com/defectdojo/burp-plugin) 
- [**9**星][2y] [Java] [hvqzao/burp-token-rewrite](https://github.com/hvqzao/burp-token-rewrite) 
- [**9**星][5y] [Py] [milo2012/carbonator](https://github.com/milo2012/carbonator) 
- [**9**星][3y] [Java] [ring04h/java-deserialization-scanner](https://github.com/ring04h/java-deserialization-scanner) 
- [**9**星][1y] [Java] [sampsonc/authheaderupdater](https://github.com/sampsonc/authheaderupdater) 
- [**9**星][2m] [JS] [shahidcodes/android-nougat-ssl-intercept](https://github.com/shahidcodes/android-nougat-ssl-intercept) 
- [**9**星][2y] [Java] [aoncyberlabs/fastinfoset-burp-plugin](https://github.com/AonCyberLabs/FastInfoset-Burp-Plugin) 
- [**9**星][2y] [Java] [c0ny1/burp-cookie-porter](https://github.com/c0ny1/burp-cookie-porter) 
- [**8**星][2y] [Py] [andresriancho/burp-proxy-search](https://github.com/andresriancho/burp-proxy-search) 
- [**8**星][2y] [antichown/burp-payloads](https://github.com/antichown/burp-payloads) 
- [**8**星][2y] [Py] [bao7uo/waf-cookie-fetcher](https://github.com/bao7uo/waf-cookie-fetcher) 
- [**8**星][2y] [Ruby] [crashgrindrips/burp-dump](https://github.com/crashgrindrips/burp-dump) 
- [**8**星][6y] [Java] [cyberisltd/post2json](https://github.com/cyberisltd/post2json) 
- [**8**星][3y] [Java] [eonlight/burpextenderheaderchecks](https://github.com/eonlight/burpextenderheaderchecks) 
- [**8**星][1m] [Java] [hackvertor/taborator](https://github.com/hackvertor/taborator) 
- [**8**星][1y] [Py] [portswigger/elastic-burp](https://github.com/portswigger/elastic-burp) 
- [**8**星][2y] [Java] [portswigger/java-deserialization-scanner](https://github.com/portswigger/java-deserialization-scanner) 
- [**8**星][1y] [Java] [rammarj/csrf-poc-creator](https://github.com/rammarj/csrf-poc-creator) 
- [**8**星][3y] [Java] [silentsignal/burp-cfurl-cache](https://github.com/silentsignal/burp-cfurl-cache) 
- [**8**星][29d] [Java] [tmendo/burpintruderfilepayloadgenerator](https://github.com/tmendo/burpintruderfilepayloadgenerator) 
- [**7**星][3y] [Java] [dibsy/staticanalyzer](https://github.com/dibsy/staticanalyzer) 
- [**7**星][3y] [Ruby] [dradis/burp-dradis](https://github.com/dradis/burp-dradis) 
- [**7**星][2y] [Java] [fruh/extendedmacro](https://github.com/fruh/extendedmacro) 
- [**7**星][2y] [Java] [jgillam/serphper](https://github.com/jgillam/serphper) 
- [**7**星][3y] [Py] [luh2/pdfmetadata](https://github.com/luh2/pdfmetadata) 
- [**7**星][1y] [Java] [pajswigger/add-request-to-macro](https://github.com/pajswigger/add-request-to-macro) 
- [**7**星][2y] [Py] [portswigger/auth-matrix](https://github.com/portswigger/auth-matrix) 
- [**7**星][3y] [Py] [portswigger/browser-repeater](https://github.com/portswigger/browser-repeater) 
- [**7**星][2y] [Java] [portswigger/co2](https://github.com/portswigger/co2) 
- [**7**星][2y] [Java] [portswigger/extended-macro](https://github.com/portswigger/extended-macro) 
- [**7**星][6m] [Java] [portswigger/flow](https://github.com/portswigger/flow) 
- [**7**星][2y] [Java] [portswigger/logger-plus-plus](https://github.com/portswigger/logger-plus-plus) 
- [**7**星][2y] [Py] [portswigger/office-open-xml-editor](https://github.com/portswigger/office-open-xml-editor) 
- [**7**星][2y] [Java] [yehgdotnet/burp-extention-bing-translator](https://github.com/yehgdotnet/burp-extention-bing-translator) 
- [**7**星][4m] [Py] [fsecurelabs/timeinator](https://github.com/FSecureLABS/timeinator) 
- [**6**星][1y] [Java] [aress31/googleauthenticator](https://github.com/aress31/googleauthenticator) 
- [**6**星][2m] [Java] [lorenzog/burpaddcustomheader](https://github.com/lorenzog/burpaddcustomheader) 
- [**6**星][2y] [Py] [maxence-schmitt/officeopenxmleditor](https://github.com/maxence-schmitt/officeopenxmleditor) 
- [**6**星][1y] [Java] [portswigger/handy-collaborator](https://github.com/portswigger/handy-collaborator) 
- [**6**星][12m] [Py] [portswigger/multi-browser-highlighting](https://github.com/portswigger/multi-browser-highlighting) 
- [**6**星][2y] [Java] [secureskytechnology/burpextender-proxyhistory-webui](https://github.com/secureskytechnology/burpextender-proxyhistory-webui) 
- [**6**星][1y] [Java] [silentsignal/burp-uniqueness](https://github.com/silentsignal/burp-uniqueness) 
- [**6**星][1y] [Java] [stackcrash/burpheaders](https://github.com/stackcrash/burpheaders) 
- [**6**星][9m] [raspberrypilearning/burping-jelly-baby](https://github.com/raspberrypilearning/burping-jelly-baby) 
- [**6**星][4m] [Java] [augustd/burp-suite-jsonpath](https://github.com/augustd/burp-suite-jsonpath) 
- [**6**星][9m] [chef-koch/windows-redstone-4-1803-data-analysis](https://github.com/chef-koch/windows-redstone-4-1803-data-analysis) 
- [**5**星][4y] [Java] [antoinet/burp-decompressor](https://github.com/antoinet/burp-decompressor) 
- [**5**星][2m] [Java] [aress31/copy-as-powershell-requests](https://github.com/aress31/copy-as-powershell-requests) 
- [**5**星][4y] [Py] [cyberdefenseinstitute/burp-msgpack](https://github.com/cyberdefenseinstitute/burp-msgpack) 
- [**5**星][6y] [Java] [eganist/burp-issue-poster](https://github.com/eganist/burp-issue-poster) 
- [**5**星][3y] [Py] [floyd-fuh/burp-collect500](https://github.com/floyd-fuh/burp-collect500) 
- [**5**星][7m] [Java] [logicaltrust/burphttpmock](https://github.com/logicaltrust/burphttpmock) 
- [**5**星][3y] [Java] [mrts/burp-suite-http-proxy-history-viewer](https://github.com/mrts/burp-suite-http-proxy-history-viewer) 
- [**5**星][7y] [Py] [mwielgoszewski/jython-burp-extensions](https://github.com/mwielgoszewski/jython-burp-extensions) 
- [**5**星][3y] [Java] [netspi/jsws](https://github.com/netspi/jsws) 
- [**5**星][1y] [Java] [portswigger/headless-burp](https://github.com/portswigger/headless-burp) 
- [**5**星][3y] [Py] [portswigger/json-decoder](https://github.com/portswigger/json-decoder) 
- [**5**星][2y] [Java] [portswigger/proxy-auto-config](https://github.com/portswigger/proxy-auto-config) 




### <a id="8e7a6a74ff322cbf2bad59092598de77"></a>Metasploit


#### <a id="01be61d5bb9f6f7199208ff0fba86b5d"></a>未分类-metasploit


- [**18724**星][14d] [Ruby] [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework) 
- [**1872**星][3y] [Py] [aoncyberlabs/windows-exploit-suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) 
- [**1741**星][21d] [Shell] [leebaird/discover](https://github.com/leebaird/discover) 自定义的bash脚本, 用于自动化多个渗透测试任务, 包括: 侦查、扫描、解析、在Metasploit中创建恶意Payload和Listener
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/自动化](#fc8737aef0f59c3952d11749fe582dac) |[工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload生成](#ad92f6b801a18934f1971e2512f5ae4f) |
- [**1284**星][1y] [Shell] [dana-at-cp/backdoor-apk](https://github.com/dana-at-cp/backdoor-apk) 
- [**806**星][2y] [Ruby] [elevenpaths/eternalblue-doublepulsar-metasploit](https://github.com/elevenpaths/eternalblue-doublepulsar-metasploit) 
- [**709**星][2m] [C] [rapid7/metasploit-payloads](https://github.com/rapid7/metasploit-payloads) 
- [**683**星][2m] [Java] [isafeblue/trackray](https://github.com/isafeblue/trackray) 
- [**491**星][2y] [Shell] [r00t-3xp10it/venom](https://github.com/r00t-3xp10it/venom) 
- [**445**星][4m] [Py] [cchio/deep-pwning](https://github.com/cchio/deep-pwning) 
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |
- [**389**星][5m] [Ruby] [praetorian-code/purple-team-attack-automation](https://github.com/praetorian-code/purple-team-attack-automation) 
- [**387**星][2y] [Perl] [rapid7/metasploit-vulnerability-emulator](https://github.com/rapid7/metasploit-vulnerability-emulator) 
- [**309**星][10m] [Ruby] [darkoperator/metasploit-plugins](https://github.com/darkoperator/metasploit-plugins) 
- [**298**星][2m] [Ruby] [fozavci/viproy-voipkit](https://github.com/fozavci/viproy-voipkit) VoIP渗透测试工具和 Metasploit 框架
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |
- [**296**星][1m] [Py] [3ndg4me/autoblue-ms17-010](https://github.com/3ndg4me/autoblue-ms17-010) 
- [**265**星][3m] [Vue] [zerx0r/kage](https://github.com/Zerx0r/Kage) 
- [**228**星][4y] [Shell] [nccgroup/metasploitavevasion](https://github.com/nccgroup/metasploitavevasion) 
- [**225**星][5y] [Ruby] [pwnwiki/q](https://github.com/pwnwiki/q) 
- [**222**星][4y] [Py] [allfro/pymetasploit](https://github.com/allfro/pymetasploit) 
- [**203**星][4y] [Shell] [rand0m1ze/ezsploit](https://github.com/rand0m1ze/ezsploit) 
- [**187**星][3m] [Py] [milo2012/metasploithelper](https://github.com/milo2012/metasploithelper) 
- [**176**星][3y] [Ruby] [espreto/wpsploit](https://github.com/espreto/wpsploit) 
- [**172**星][15d] [Shell] [kalilinuxtricksyt/easysploit](https://github.com/kalilinuxtricksyt/easysploit) 
- [**163**星][6m] [Ruby] [r00t-3xp10it/msf-auxiliarys](https://github.com/r00t-3xp10it/msf-auxiliarys) 
- [**148**星][1y] [PowerShell] [airbus-seclab/powersap](https://github.com/airbus-seclab/powersap) powersap：PowershellSAP 评估工具。所有公开且流行/有效的工具的PowerShell 重制版，例如 Bizploit、Metasploitauxiliary 模块、网络收集的 Python 脚本。
- [**144**星][7y] [C] [rsmudge/metasploit-loader](https://github.com/rsmudge/metasploit-loader) 
- [**134**星][1y] [Py] [mohamednourtn/terminator](https://github.com/mohamednourtn/terminator) 
- [**110**星][3m] [PowerShell] [danmcinerney/pymetasploit3](https://github.com/danmcinerney/pymetasploit3) 
- [**109**星][2m] [C++] [b4rtik/metasploit-execute-assembly](https://github.com/b4rtik/metasploit-execute-assembly) 
- [**106**星][2m] [Py] [cyb0r9/ispy](https://github.com/cyb0r9/ispy) 
- [**106**星][2m] [Ruby] [rapid7/metasploit-omnibus](https://github.com/rapid7/metasploit-omnibus) 
- [**105**星][1y] [Py] [shizzz477/msploitego](https://github.com/shizzz477/msploitego) 将Metasploit数据库导入到数据挖掘工具Maltego并进行分析的框架
- [**94**星][8m] [Py] [rvn0xsy/cooolis-ms](https://github.com/rvn0xsy/cooolis-ms) 
- [**93**星][2y] [Ruby] [carnal0wnage/metasploit-code](https://github.com/carnal0wnage/metasploit-code) 
- [**92**星][1m] [Ruby] [hahwul/mad-metasploit](https://github.com/hahwul/mad-metasploit) 
- [**92**星][7y] [Ruby] [openwiresec/metasploit](https://github.com/openwiresec/metasploit) 
- [**90**星][10m] [Ruby] [hdm/metasploit-framework](https://github.com/hdm/metasploit-framework) 
- [**88**星][2y] [Ruby] [0x09al/cve-2017-11882-metasploit](https://github.com/0x09al/cve-2017-11882-metasploit) 
- [**86**星][2y] [Ruby] [hanshaze/ms17-010-eternalblue-winxp-win10](https://github.com/hanshaze/ms17-010-eternalblue-winxp-win10) 
- [**85**星][1y] [Shell] [rpranshu/autopwn](https://github.com/rpranshu/autopwn) 
- [**85**星][1y] [Py] [wez3/msfenum](https://github.com/wez3/msfenum) 在特定目标集上自动运行多个 Metasploit auxiliary 模块
- [**84**星][1y] [security-cheatsheet/metasploit-cheat-sheet](https://github.com/security-cheatsheet/metasploit-cheat-sheet) 
- [**81**星][7y] [Ruby] [dirtyfilthy/metassh](https://github.com/dirtyfilthy/metassh) 
- [**80**星][8y] [spiderlabs/msfrpc](https://github.com/spiderlabs/msfrpc) 
- [**75**星][2y] [Ruby] [xc0d3rz/metasploit-apk-embed-payload](https://github.com/xc0d3rz/metasploit-apk-embed-payload) 
- [**74**星][1y] [Ruby] [hahwul/metasploit-autopwn](https://github.com/hahwul/metasploit-autopwn) 
- [**71**星][3y] [PowerShell] [jaredhaight/invoke-metasploitpayload](https://github.com/jaredhaight/invoke-metasploitpayload) 
- [**71**星][1y] [Py] [yoda66/androidembedit](https://github.com/yoda66/androidembedit) 
- [**65**星][4m] [Py] [k8gege/scrun](https://github.com/k8gege/scrun) 
- [**64**星][1y] [Py] [wazehell/metateta](https://github.com/wazehell/metateta) 
- [**63**星][1y] [Ruby] [fbkcs/msf-elf-in-memory-execution](https://github.com/fbkcs/msf-elf-in-memory-execution) msf-elf-in-memory-execution: Metasploit模块, 用于在内存中执行ELF文件
- [**62**星][12m] [Ruby] [kingsabri/cve-in-ruby](https://github.com/kingsabri/cve-in-ruby) 
- [**61**星][2y] [blue-bird1/metasploit-cn-wiki](https://github.com/blue-bird1/metasploit-cn-wiki) 
- [**55**星][3y] [Java] [scriptjunkie/msfgui](https://github.com/scriptjunkie/msfgui) 
- [**53**星][4y] [PHP] [kulisu/metasploit-pro-trial-grabber](https://github.com/kulisu/metasploit-pro-trial-grabber) 
- [**51**星][6y] [Ruby] [depthsecurity/dahua_dvr_auth_bypass](https://github.com/depthsecurity/dahua_dvr_auth_bypass) 
- [**49**星][2y] [bluscreenofjeff/metasploit-resource-scripts](https://github.com/bluscreenofjeff/metasploit-resource-scripts) 
- [**48**星][4y] [Java] [rapid7/metasploit-javapayload](https://github.com/rapid7/metasploit-javapayload) 
- [**46**星][1y] [Py] [luis-hebendanz/msf-remote-console](https://github.com/luis-hebendanz/msf-remote-console) 
- [**45**星][2y] [Py] [hansesecure/metasploit-modules](https://github.com/hansesecure/metasploit-modules) 
- [**45**星][2y] [Ruby] [rapid7/metasploit-aggregator](https://github.com/rapid7/metasploit-aggregator) 
- [**44**星][2y] [Ruby] [j-0-t/staekka](https://github.com/j-0-t/staekka) 
- [**44**星][4m] [Ruby] [rootup/autosploit](https://github.com/rootup/autosploit) 
- [**43**星][2y] [C] [shipcod3/irc-bot-hunters](https://github.com/shipcod3/irc-bot-hunters) 
- [**43**星][3m] [HTML] [unk9vvn/andtroj](https://github.com/unk9vvn/andtroj) 
- [**41**星][2y] [Go] [empty-nest/emptynest](https://github.com/empty-nest/emptynest) emptynest：基于插件的 C2 服务器框架。其目标不是取代某些强大的工具（例如 Empire、Metasploit、CobaltStrike），而是创建一个支持框架，以便为自定义 agents 快速创建小型、专用的 handlers
- [**40**星][6y] [Ruby] [pwnieexpress/metasploit-framework](https://github.com/pwnieexpress/metasploit-framework) 
- [**39**星][2y] [Py] [h0nus/spynoteshell](https://github.com/h0nus/spynoteshell) 
- [**38**星][4m] [Py] [lorentzenman/payday](https://github.com/lorentzenman/payday) 
- [**36**星][3y] [Ruby] [neinwechter/metasploit-framework](https://github.com/neinwechter/metasploit-framework) 
- [**35**星][3y] [Ruby] [nopernik/msfvenom-bc-generator](https://github.com/nopernik/msfvenom-bc-generator) 
- [**34**星][3y] [Ruby] [dmchell/metasploit-framework](https://github.com/dmchell/metasploit-framework) 
- [**34**星][3y] [Ruby] [khr0x40sh/metasploit-modules](https://github.com/khr0x40sh/metasploit-modules) 
- [**33**星][2y] [16667/metasploitable-3-ctf](https://github.com/16667/metasploitable-3-ctf) 
- [**33**星][7m] [Ruby] [rapid7/metasploit_data_models](https://github.com/rapid7/metasploit_data_models) 
- [**32**星][3m] [C] [defcon-russia/metasploit-payloads](https://github.com/defcon-russia/metasploit-payloads) 
- [**30**星][3y] [Ruby] [skulltech/apk-payload-injector](https://github.com/skulltech/apk-payload-injector) 
- [**28**星][3y] [Ruby] [fozavci/metasploit-framework-with-viproy](https://github.com/fozavci/metasploit-framework-with-viproy) 
- [**28**星][6y] [C#] [rvazarkar/antipwny](https://github.com/rvazarkar/antipwny) 
- [**27**星][2y] [Ruby] [godinezj/metasploit-framework](https://github.com/godinezj/metasploit-framework) 
- [**27**星][4y] [Py] [ickerwx/pattern](https://github.com/ickerwx/pattern) 
- [**26**星][3m] [Shell] [gushmazuko/metasploit_in_termux](https://github.com/gushmazuko/metasploit_in_termux) 
- [**25**星][3y] [Ruby] [eik00d/reverse_dns_shellcode](https://github.com/eik00d/reverse_dns_shellcode) 
- [**25**星][2y] [Ruby] [kacperszurek/pentest_teamcity](https://github.com/kacperszurek/pentest_teamcity) 
- [**25**星][7y] [Perl] [kost/vulnscan-pwcrack](https://github.com/kost/vulnscan-pwcrack) 
- [**25**星][10m] [Dockerfile] [opsxcq/docker-metasploit](https://github.com/opsxcq/docker-metasploit) 
- [**23**星][1y] [Ruby] [defcon-russia/metasploit-framework](https://github.com/defcon-russia/metasploit-framework) 
- [**23**星][5m] [Ruby] [risksense-ops/metasploit-framework](https://github.com/risksense-ops/metasploit-framework) 
- [**22**星][5y] [Shell] [find-evil/msf-install-script-os-x-lion-mountain-lion](https://github.com/find-evil/msf-install-script-os-x-lion-mountain-lion) 
- [**22**星][4y] [Ruby] [martinvigo/metasploit-framework](https://github.com/martinvigo/metasploit-framework) 
- [**21**星][2y] [Ruby] [rapid7/msfrpc-client](https://github.com/rapid7/msfrpc-client) 
- [**20**星][7y] [Ruby] [darkoperator/nessus-bridge-for-metasploit](https://github.com/darkoperator/nessus-bridge-for-metasploit) 
- [**20**星][6y] [Ruby] [staaldraad/metasploit](https://github.com/staaldraad/metasploit) 
- [**20**星][4y] [Ruby] [vallejocc/hacking-busybox-control](https://github.com/vallejocc/Hacking-Busybox-Control) 
- [**19**星][3m] [Py] [rapid7/metasploit-baseline-builder](https://github.com/rapid7/metasploit-baseline-builder) 
- [**19**星][10m] [Ruby] [rapid7/metasploit-credential](https://github.com/rapid7/metasploit-credential) 
- [**18**星][3y] [C] [exploit-install/thefatrat](https://github.com/exploit-install/thefatrat) 
- [**18**星][3y] [C#] [volatilemindsllc/metasploit-sharp](https://github.com/VolatileMindsLLC/metasploit-sharp) 
- [**16**星][4y] [metasploit/resource-portal-data](https://github.com/metasploit/resource-portal-data) 
- [**16**星][7y] [Ruby] [sempervictus/xssf](https://github.com/sempervictus/xssf) 
- [**15**星][2y] [Java] [jlxip/mermaid](https://github.com/jlxip/mermaid) 
- [**14**星][3y] [Shell] [freelancepentester/backdoor-apk](https://github.com/freelancepentester/backdoor-apk) 
- [**14**星][5y] [Ruby] [rapid7/fastlib](https://github.com/rapid7/fastlib) 
- [**14**星][3y] [Ruby] [t-s-a/minion](https://github.com/t-s-a/minion) 
- [**13**星][2y] [bcoles/metasploit-logos](https://github.com/bcoles/metasploit-logos) 
- [**13**星][3y] [Ruby] [devsecops/firebolt](https://github.com/devsecops/firebolt) 
- [**13**星][2y] [Ruby] [rithchard/drupalgeddon3](https://github.com/rithchard/drupalgeddon3) 
- [**13**星][3y] [Ruby] [samvartaka/exploits](https://github.com/samvartaka/exploits) 
- [**13**星][2y] [Shell] [sathish09/zsh_plugins](https://github.com/sathish09/zsh_plugins) 
- [**13**星][13d] [Py] [vainlystrain/vaile](https://github.com/vainlystrain/vaile) 
- [**12**星][3y] [Py] [tanc7/easypeasey](https://github.com/tanc7/easypeasey) 
- [**12**星][12m] [Ruby] [timwr/metasploit-framework](https://github.com/timwr/metasploit-framework) 
- [**11**星][2y] [Shell] [anorebel/metasploit-termux](https://github.com/anorebel/metasploit-termux) 
- [**11**星][4y] [Ruby] [nullbind/metasploit-modules](https://github.com/nullbind/metasploit-modules) 
- [**11**星][2y] [JS] [tomasgvivo/node-msfrpc](https://github.com/tomasgvivo/node-msfrpc) 
- [**11**星][7m] [voidsec/cve-2019-5624](https://github.com/voidsec/cve-2019-5624) 
- [**11**星][2y] [Java] [xiaohuanshu/persistent-androidpayload](https://github.com/xiaohuanshu/persistent-androidpayload) 
- [**11**星][8y] [Ruby] [xntrik/beefmetasploitplugin](https://github.com/xntrik/beefmetasploitplugin) 
- [**10**星][3y] [Ruby] [leonjza/metasploit-modules](https://github.com/leonjza/metasploit-modules) 
- [**10**星][3y] [PowerShell] [pentest-academy/windows-privilege-escalation](https://github.com/pentest-academy/windows-privilege-escalation) 
- [**10**星][7m] [Shell] [sabri-zaki/metasploit](https://github.com/sabri-zaki/metasploit) 
- [**10**星][7y] [sensepost/metasploit](https://github.com/sensepost/metasploit) 
- [**9**星][2y] [HTML] [mister2tone/metasploit-webapp](https://github.com/mister2tone/metasploit-webapp) 
- [**9**星][2y] [Ruby] [nipunjaswal/mastering-metasploit](https://github.com/nipunjaswal/mastering-metasploit) 
- [**9**星][3y] [Java] [ridergoster/sms-hacker](https://github.com/ridergoster/sms-hacker) 
- [**9**星][7y] [Ruby] [v10l3nt/metasploit-framework](https://github.com/v10l3nt/metasploit-framework) 
- [**9**星][28d] [C#] [kres0345/metasploit-gui-for-windows](https://github.com/kres0345/Metasploit-GUI-for-Windows) 
- [**8**星][3y] [C++] [christian-roggia/metin2-akira-metasploit](https://github.com/christian-roggia/metin2-akira-metasploit) 




### <a id="b1161d6c4cb520d0cd574347cd18342e"></a>免杀&&躲避AV检测


- [**1009**星][4m] [C] [govolution/avet](https://github.com/govolution/avet) avet：免杀工具
- [**698**星][9m] [Py] [mr-un1k0d3r/dkmc](https://github.com/mr-un1k0d3r/dkmc) 
- [**620**星][6m] [Py] [paranoidninja/carboncopy](https://github.com/paranoidninja/carboncopy) 
- [**461**星][1y] [Go] [arvanaghi/checkplease](https://github.com/arvanaghi/checkplease) 
- [**299**星][1y] [Py] [two06/inception](https://github.com/two06/inception) 
- [**293**星][2y] [Py] [trustedsec/nps_payload](https://github.com/trustedsec/nps_payload) nps_payload：Python 脚本，生成能够绕过基础入侵检测的 payload
- [**280**星][1m] [C#] [ch0pin/aviator](https://github.com/ch0pin/aviator) 
- [**259**星][2y] [Py] [cryptolok/morphaes](https://github.com/cryptolok/morphaes) 
- [**252**星][1m] [C#] [hackplayers/salsa-tools](https://github.com/hackplayers/salsa-tools) 
- [**180**星][2y] [Visual Basic] [joesecurity/pafishmacro](https://github.com/joesecurity/pafishmacro) 
- [**175**星][2y] [C#] [bhdresh/lazykatz](https://github.com/bhdresh/lazykatz) 
- [**157**星][4y] [Go] [vyrus001/go-mimikatz](https://github.com/vyrus001/go-mimikatz) 
- [**144**星][5m] [C++] [checkpointsw/invizzzible](https://github.com/checkpointsw/invizzzible) 
- [**109**星][2y] [C++] [codewatchorg/sidestep](https://github.com/codewatchorg/sidestep) 
- [**103**星][3y] [C#] [p0cl4bs/hanzoinjection](https://github.com/p0cl4bs/hanzoinjection) 
- [**97**星][1m] [C++] [google/vxsig](https://github.com/google/vxsig) 
- [**97**星][1y] [Ruby] [green-m/green-hat-suite](https://github.com/green-m/green-hat-suite) 
- [**91**星][7m] [C++] [ajayrandhawa/keylogger](https://github.com/ajayrandhawa/Keylogger) 
- [**81**星][3y] [HTML] [vah13/avdetection](https://github.com/vah13/avdetection) 
- [**75**星][2y] [Py] [safebreach-labs/spacebin](https://github.com/safebreach-labs/spacebin) 
- [**65**星][10m] [Py] [necst/crave](https://github.com/necst/crave) crave: 自动测试和探索通用AV引擎功能的框架
- [**54**星][2y] [C++] [huoji120/av-killer](https://github.com/huoji120/av-killer) 
- [**45**星][1m] [PHP] [marcocesarato/php-antimalware-scanner](https://github.com/marcocesarato/php-antimalware-scanner) 
- [**26**星][6m] [C] [souhailhammou/panda-antivirus-lpe](https://github.com/souhailhammou/panda-antivirus-lpe) 
- [**23**星][3y] [Py] [d4vinci/anti_killer](https://github.com/d4vinci/anti_killer) 


### <a id="98a851c8e6744850efcb27b8e93dff73"></a>C&C


- [**2387**星][3m] [Go] [ne0nd0g/merlin](https://github.com/ne0nd0g/merlin) 
- [**1104**星][1y] [Py] [byt3bl33d3r/gcat](https://github.com/byt3bl33d3r/gcat) 
- [**917**星][19d] [C#] [cobbr/covenant](https://github.com/cobbr/covenant) 
- [**640**星][4y] [Py] [paulsec/twittor](https://github.com/paulsec/twittor) 
- [**632**星][10m] [Py] [mehulj94/braindamage](https://github.com/mehulj94/braindamage) 
- [**412**星][2y] [rsmudge/malleable-c2-profiles](https://github.com/rsmudge/malleable-c2-profiles) 
- [**343**星][2y] [Py] [maldevel/gdog](https://github.com/maldevel/gdog) gdog：Python 编写的后门，使用 Gmail 做 C&C
- [**314**星][1y] [C#] [spiderlabs/dohc2](https://github.com/spiderlabs/dohc2) 
- [**240**星][14d] [PowerShell] [nettitude/poshc2](https://github.com/nettitude/poshc2) 
- [**240**星][14d] [PowerShell] [nettitude/poshc2](https://github.com/nettitude/PoshC2) 
- [**235**星][2y] [Py] [arno0x/wsc2](https://github.com/arno0x/wsc2) 
- [**181**星][2y] [Go] [petercunha/goat](https://github.com/petercunha/goat) a trojan created in Go, using Twitter as a the C&C server
- [**177**星][2y] [Py] [maldevel/canisrufus](https://github.com/maldevel/canisrufus) canisrufus：Python 编写的后门，使用 Github 做 C&C
- [**173**星][2y] [Py] [woj-ciech/daily-dose-of-malware](https://github.com/woj-ciech/daily-dose-of-malware) 
- [**157**星][3y] [Py] [blazeinfosec/bt2](https://github.com/blazeinfosec/bt2) 电报后门，使用电报做C&C 服务器
- [**96**星][1m] [Py] [nccgroup/gitpwnd](https://github.com/nccgroup/gitpwnd) gitpwnd：网络渗透测试工具，可使攻击者向被攻击机器发送命令，并使用 git repo 作为 C&C 传输层接收结果
- [**93**星][2y] [Py] [arno0x/webdavc2](https://github.com/arno0x/webdavc2) 
- [**65**星][3m] [HTML] [project-prismatica/prismatica](https://github.com/project-prismatica/prismatica) 
- [**37**星][7m] [JS] [shadow-workers/shadow-workers](https://github.com/shadow-workers/shadow-workers) 
- [**34**星][3m] [Py] [geek-repo/c2-blockchain](https://github.com/geek-repo/c2-blockchain) 
- [**33**星][3m] [C#] [sf197/telegra_csharp_c2](https://github.com/sf197/telegra_csharp_c2) 
- [**27**星][1y] [Py] [ajinabraham/xenotix-xbot](https://github.com/ajinabraham/xenotix-xbot) 
- [**23**星][1y] [PowerShell] [netspi/sqlc2](https://github.com/netspi/sqlc2) 


### <a id="a0897294e74a0863ea8b83d11994fad6"></a>DDOS


- [**2443**星][17d] [C++] [pavel-odintsov/fastnetmon](https://github.com/pavel-odintsov/fastnetmon) 快速 DDoS 检测/分析工具，支持 sflow/netflow/mirror
- [**1174**星][29d] [Shell] [mitchellkrogza/nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) 
- [**831**星][2m] [Py] [649/memcrashed-ddos-exploit](https://github.com/649/memcrashed-ddos-exploit) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/Shodan](#18c7c1df2e6ae5e9135dfa2e4eb1d4db) |
- [**457**星][6m] [Shell] [jgmdev/ddos-deflate](https://github.com/jgmdev/ddos-deflate) 
- [**451**星][2m] [JS] [codemanki/cloudscraper](https://github.com/codemanki/cloudscraper) 
- [**374**星][12m] [C] [markus-go/bonesi](https://github.com/markus-go/bonesi) 
- [**293**星][3m] [Shell] [anti-ddos/anti-ddos](https://github.com/anti-ddos/Anti-DDOS) 
- [**257**星][2y] [TypeScript] [srar/memcachedos](https://github.com/srar/memcachedos) 
- [**243**星][12m] [Py] [wenfengshi/ddos-dos-tools](https://github.com/wenfengshi/ddos-dos-tools) 
- [**202**星][4y] [Py] [m57/ardt](https://github.com/m57/ardt) 
- [**191**星][9m] [JS] [rook2pawn/node-ddos](https://github.com/rook2pawn/node-ddos) 
- [**179**星][1y] [Py] [ha3mrx/ddos-attack](https://github.com/ha3mrx/ddos-attack) 
- [**158**星][13d] [C] [altramayor/gatekeeper](https://github.com/altramayor/gatekeeper) 
- [**146**星][8y] [dotfighter/torshammer](https://github.com/dotfighter/torshammer) 
- [**142**星][2y] [PHP] [drego85/ddos-php-script](https://github.com/drego85/ddos-php-script) 
- [**122**星][4y] [Py] [equalitie/learn2ban](https://github.com/equalitie/learn2ban) 
- [**112**星][1y] [Py] [jamesjgoodwin/wreckuests](https://github.com/jamesjgoodwin/wreckuests) 
- [**106**星][3y] [C++] [timeweb/ddosdetector](https://github.com/timeweb/ddosdetector) 
- [**103**星][11m] [Perl] [mustlive/davoset](https://github.com/mustlive/davoset) 
- [**87**星][9m] [PHP] [sanix-darker/antiddos-system](https://github.com/sanix-darker/antiddos-system) 
- [**81**星][4y] [Roff] [ddos-defense/bohatei](https://github.com/ddos-defense/bohatei) 
- [**76**星][4y] [Py] [dantangfan/ddos](https://github.com/dantangfan/ddos) 
- [**70**星][3y] [Shell] [ppabc/cc_iptables](https://github.com/ppabc/cc_iptables) 
- [**57**星][11m] [C] [qssec/hades-lite](https://github.com/qssec/hades-lite) 
- [**56**星][4y] [Ruby] [zenvdeluca/net_healer](https://github.com/zenvdeluca/net_healer) 
- [**51**星][7y] [Ruby] [medelibero/ddos-tools](https://github.com/medelibero/ddos-tools) 
- [**48**星][5m] [C] [praneethkarnena/ddos-scripts](https://github.com/praneethkarnena/ddos-scripts) 
- [**46**星][3y] [C++] [drizzlerisk/ntpdoser](https://github.com/drizzlerisk/ntpdoser) 
- [**43**星][9m] [Go] [konstantin8105/ddos](https://github.com/konstantin8105/ddos) 
- [**42**星][1m] [Py] [ritvikb99/dark-fantasy-hack-tool](https://github.com/ritvikb99/dark-fantasy-hack-tool) 
- [**41**星][6y] [Py] [vpnguy-zz/snmpdos](https://github.com/vpnguy-zz/snmpdos) 
- [**40**星][1y] [Py] [t7hm1/pyddos](https://github.com/t7hm1/pyddos) 
- [**39**星][2m] [Py] [0x01h/pyddoz](https://github.com/0x01h/pyddoz) 
- [**37**星][3y] [Py] [wal99d/slowloris](https://github.com/wal99d/slowloris) 
- [**35**星][5m] [Py] [ruped24/tor_ip_switcher](https://github.com/ruped24/tor_ip_switcher) 
- [**33**星][2y] [PHP] [karek314/ddos-deflate-nginx-cloudflare](https://github.com/karek314/ddos-deflate-nginx-cloudflare) 
- [**33**星][6m] [C] [ns1/xdp-workshop](https://github.com/ns1/xdp-workshop) 
- [**31**星][12d] [Lua] [c0nw0nk/nginx-lua-anti-ddos](https://github.com/c0nw0nk/nginx-lua-anti-ddos) 
- [**24**星][13d] [HTML] [equalitie/banjax](https://github.com/equalitie/banjax) 
- [**24**星][27d] [Shell] [lockedbyte/ddos2track](https://github.com/lockedbyte/ddos2track) 
- [**23**星][12m] [0xkiewicz/pwk-oscp](https://github.com/0xkiewicz/pwk-oscp) 
- [**22**星][2y] [Py] [merkjinx/saddam-plus-plus](https://github.com/merkjinx/saddam-plus-plus) 
- [**21**星][9y] [Shell] [jfernandez/ddos-deflate](https://github.com/jfernandez/ddos-deflate) 


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
- [**483**星][2y] [Py] [zdresearch/owasp-zsc](https://github.com/zdresearch/OWASP-ZSC) Shellcode/Obfuscate Code Generator
- [**480**星][17d] [owasp/wstg](https://github.com/OWASP/wstg) 
- [**480**星][17d] [owasp/wstg](https://github.com/owasp/wstg) 
- [**461**星][7m] [Java] [owasp/owasp-webscarab](https://github.com/owasp/owasp-webscarab) 
- [**402**星][5m] [Py] [stanislav-web/opendoor](https://github.com/stanislav-web/opendoor) 
- [**360**星][1m] [Java] [zaproxy/zap-extensions](https://github.com/zaproxy/zap-extensions) 
- [**354**星][5y] [Py] [ebranca/owasp-pysec](https://github.com/ebranca/owasp-pysec) 
- [**341**星][1m] [Java] [esapi/esapi-java-legacy](https://github.com/esapi/esapi-java-legacy) 
- [**292**星][5m] [0xradi/owasp-web-checklist](https://github.com/0xradi/owasp-web-checklist) 
- [**271**星][5m] [JS] [mike-goodwin/owasp-threat-dragon](https://github.com/mike-goodwin/owasp-threat-dragon) 
- [**269**星][4m] [tanprathan/owasp-testing-checklist](https://github.com/tanprathan/owasp-testing-checklist) 
- [**248**星][11m] [Java] [owasp/owasp-java-encoder](https://github.com/owasp/owasp-java-encoder) 
- [**225**星][1m] [owasp/api-security](https://github.com/owasp/api-security) 
- [**196**星][13d] [Java] [owasp/benchmark](https://github.com/owasp/benchmark) 
- [**192**星][7y] [Java] [nvisium-jack-mannino/owasp-goatdroid-project](https://github.com/nvisium-jack-mannino/OWASP-GoatDroid-Project) 
- [**173**星][7y] [Py] [gdssecurity/gwt-penetration-testing-toolset](https://github.com/gdssecurity/gwt-penetration-testing-toolset) 辅助渗透测试GWT程序的3个工具
- [**171**星][1m] [HTML] [zaproxy/zap-core-help](https://github.com/zaproxy/zap-core-help) 
- [**130**星][4m] [JS] [owasp/passfault](https://github.com/owasp/passfault) 
- [**130**星][28d] [Java] [zaproxy/zap-hud](https://github.com/zaproxy/zap-hud) 看ZAP如何解决安全工具的UX特别难用的问题
- [**122**星][12m] [Gherkin] [owasp-cloud-security/owasp-cloud-security](https://github.com/owasp-cloud-security/owasp-cloud-security) 
- [**117**星][6m] [Py] [owasp/serverless-goat](https://github.com/owasp/serverless-goat) a serverless application demonstrating common serverless security flaws
- [**115**星][6y] [C#] [jerryhoff/webgoat.net](https://github.com/jerryhoff/webgoat.net) 
- [**111**星][1m] [C#] [gaprogman/owaspheaders.core](https://github.com/gaprogman/owaspheaders.core) 
- [**111**星][11m] [Py] [grunny/zap-cli](https://github.com/grunny/zap-cli) 
- [**97**星][2y] [CSS] [owasp/owasp-summit-2017](https://github.com/OWASP/owasp-summit-2017) 
- [**93**星][23d] [JS] [securityrat/securityrat](https://github.com/securityrat/securityrat) 
- [**88**星][1m] [bkimminich/pwning-juice-shop](https://github.com/bkimminich/pwning-juice-shop) 
- [**67**星][4m] [Py] [zaproxy/zap-api-python](https://github.com/zaproxy/zap-api-python) 
- [**66**星][9m] [Java] [javabeanz/owasp-security-logging](https://github.com/javabeanz/owasp-security-logging) 
- [**66**星][10m] [HTML] [mtesauro/owasp-wte](https://github.com/mtesauro/owasp-wte) 
- [**57**星][2y] [Java] [nikolamilosevic86/owasp-seraphimdroid](https://github.com/nikolamilosevic86/owasp-seraphimdroid) 
- [**52**星][4y] [HTML] [hakanson/ng-owasp](https://github.com/hakanson/ng-owasp) OWASP Top 10 for AngularJS Applications
- [**51**星][7y] [C#] [owasp/webgoat.net](https://github.com/owasp/webgoat.net) 
- [**45**星][7m] [Java] [jenkinsci/zap-plugin](https://github.com/jenkinsci/zap-plugin) 
- [**25**星][5y] [Py] [noobiedog/dir-xcan](https://github.com/noobiedog/dir-xcan) 


### <a id="7667f6a0381b6cded2014a0d279b5722"></a>Kali


- [**2522**星][7m] [offensive-security/kali-nethunter](https://github.com/offensive-security/kali-nethunter) 
- [**2332**星][7m] [Py] [lionsec/katoolin](https://github.com/lionsec/katoolin) 
- [**1690**星][2m] [PHP] [xtr4nge/fruitywifi](https://github.com/xtr4nge/fruitywifi) 
- [**1416**星][3y] [tiancode/learn-hacking](https://github.com/tiancode/learn-hacking) 
- [**1404**星][3y] [tiancode/learn-hacking](https://github.com/tiancode/learn-hacking) 
- [**849**星][10m] [Shell] [esc0rtd3w/wifi-hacker](https://github.com/esc0rtd3w/wifi-hacker) 
- [**752**星][2y] [HTML] [wi-fi-analyzer/fluxion](https://github.com/wi-fi-analyzer/fluxion) fluxion：linset 的重制版，兼容最新版 Kali
- [**714**星][3m] [Py] [rajkumrdusad/tool-x](https://github.com/rajkumrdusad/tool-x) 
- [**667**星][7m] [offensive-security/kali-arm-build-scripts](https://github.com/offensive-security/kali-arm-build-scripts) 
- [**542**星][1m] [Shell] [offensive-security/kali-linux-docker](https://github.com/offensive-security/kali-linux-docker) 
- [**385**星][2y] [Py] [frizb/vanquish](https://github.com/frizb/vanquish) 
- [**385**星][3m] [jack-liang/kalitools](https://github.com/jack-liang/kalitools) 
- [**377**星][2y] [Shell] [und3rf10w/kali-anonsurf](https://github.com/und3rf10w/kali-anonsurf) 
- [**347**星][2y] [Shell] [koenbuyens/kalirouter](https://github.com/koenbuyens/kalirouter) kalirouter：将 KaliLinux 主机转变为路由器，使用 Wireshark 记录所有的网络流量，同时将 HTTP/HTTPS 流量发送到其他主机的拦截代理（例如 BurpSuite）
- [**328**星][7m] [offensive-security/kali-linux-recipes](https://github.com/offensive-security/kali-linux-recipes) 
- [**297**星][2y] [Shell] [0x90/kali-scripts](https://github.com/0x90/kali-scripts) 
- [**271**星][6y] [C++] [steve-m/kalibrate-rtl](https://github.com/steve-m/kalibrate-rtl) 
- [**253**星][4y] [Py] [danmcinerney/fakeap](https://github.com/danmcinerney/fakeap) 
- [**244**星][2y] [Shell] [freelancepentester/ddos-script](https://github.com/freelancepentester/ddos-script) 
- [**199**星][4m] [jiansiting/kali-windows](https://github.com/jiansiting/kali-windows) 
- [**196**星][2y] [Java] [abstractj/kalium](https://github.com/abstractj/kalium) 
- [**177**星][2m] [noorqureshi/kali-linux-cheatsheet](https://github.com/noorqureshi/kali-linux-cheatsheet) 
- [**174**星][3y] [CSS] [kali-docs-cn/kali-linux-cookbook-zh](https://github.com/kali-docs-cn/kali-linux-cookbook-zh) 
- [**150**星][3y] [C++] [scateu/kalibrate-hackrf](https://github.com/scateu/kalibrate-hackrf) 
- [**146**星][5y] [HTML] [pwnwiki/kaliwiki](https://github.com/pwnwiki/kaliwiki) 
- [**146**星][10m] [CSS] [kali-docs-cn/kali-linux-web-pentest-cookbook-zh](https://github.com/kali-docs-cn/kali-linux-web-pentest-cookbook-zh) 
- [**119**星][9m] [byt3bl33d3r/ansibleplaybooks](https://github.com/byt3bl33d3r/ansibleplaybooks) 
- [**118**星][3y] [HTML] [louchaooo/kali-tools-zh](https://github.com/louchaooo/kali-tools-zh) 
- [**104**星][11m] [Py] [re4son/kali-pi](https://github.com/re4son/kali-pi) 
- [**99**星][2y] [Py] [wetw0rk/malicious-wordpress-plugin](https://github.com/wetw0rk/malicious-wordpress-plugin) malicious-wordpress-plugin：生成带反向 Shell 的 wordpress 插件
- [**91**星][18d] [Py] [raikia/kali-setup](https://github.com/raikia/kali-setup) 
- [**83**星][7m] [offensive-security/kali-cloud-build](https://github.com/offensive-security/kali-cloud-build) 
- [**81**星][2y] [Shell] [offxec/pavelow](https://github.com/OffXec/PAVELOW) 
- [**75**星][1y] [Shell] [re4son/wsl-kali-x](https://github.com/re4son/wsl-kali-x) 
- [**73**星][1y] [ckjbug/kali-linux-learning](https://github.com/ckjbug/kali-linux-learning) 
- [**69**星][2y] [Shell] [snubbegbg/install_raspi-config](https://github.com/snubbegbg/install_raspi-config) 
- [**60**星][5y] [Py] [byt3bl33d3r/duckhunter](https://github.com/byt3bl33d3r/duckhunter) 
- [**60**星][4m] [Shell] [developerkunal/converto](https://github.com/developerkunal/converto) 
- [**59**星][2y] [Py] [lbarman/kali-tools](https://github.com/lbarman/kali-tools) 
- [**58**星][1y] [HTML] [aglcaicai/kalitoolsmanual](https://github.com/aglcaicai/kalitoolsmanual) 
- [**57**星][4y] [Shell] [wh1t3rh1n0/ssh-phone-home](https://github.com/wh1t3rh1n0/ssh-phone-home) 
- [**54**星][3y] [Shell] [docker-linux/kali-metasploit](https://github.com/docker-linux/kali-metasploit) 
- [**50**星][7m] [offensive-security/nethunter-utils](https://github.com/offensive-security/nethunter-utils) 
- [**48**星][1y] [Py] [pentestpartners/mykali](https://github.com/pentestpartners/mykali) 
- [**44**星][13d] [Shell] [pierregode/linux-active-directory-join-script](https://github.com/pierregode/linux-active-directory-join-script) 
- [**41**星][6y] [Shell] [masterbutcher/kali-cleaner](https://github.com/masterbutcher/kali-cleaner) 
- [**40**星][1y] [Shell] [nick-the-greek/aerial](https://github.com/nick-the-greek/aerial) 
- [**36**星][2y] [Shell] [re4son/pocket-kali-live-build](https://github.com/Re4son/Pocket-Kali-live-build) 
- [**35**星][2y] [Shell] [ac-mercury/mercuryiss-kali](https://github.com/ac-mercury/mercuryiss-kali) 部署KaliLinux Docker容器的Bash脚本
- [**35**星][5m] [Shell] [kawaxi/kali-setup](https://github.com/kawaxi/kali-setup) 
- [**35**星][7m] [offensive-security/kali-wsl-chroot](https://github.com/offensive-security/kali-wsl-chroot) 
- [**34**星][10m] [Shell] [keeganjk/kali-anonymous](https://github.com/keeganjk/kali-anonymous) 
- [**34**星][6m] [Py] [rikonaka/katoolin4china](https://github.com/rikonaka/katoolin4china) 
- [**33**星][3y] [Perl] [interference-security/kali-windows-binaries](https://github.com/interference-security/kali-windows-binaries) 
- [**31**星][27d] [Shell] [taylanbildik/linux_dersleri](https://github.com/taylanbildik/linux_dersleri) 
- [**30**星][3y] [Shell] [jlevitsk/lazykali](https://github.com/jlevitsk/lazykali) 
- [**30**星][1y] [Shell] [xxh3x/nethunter_universal](https://github.com/XXH3X/Nethunter_Universal) 
- [**29**星][2y] [Shell] [cyb3r3x3r/kalilinuxnethunter-termux](https://github.com/cyb3r3x3r/kalilinuxnethunter-termux) 
- [**27**星][4y] [Py] [misteriouser/nextkey](https://github.com/misteriouser/nextkey) 
- [**26**星][5m] [PHP] [lucasfrag/kali-linux-tools-interface](https://github.com/lucasfrag/kali-linux-tools-interface) 
- [**26**星][2y] [Shell] [owtf/owtf-docker](https://github.com/owtf/owtf-docker) 
- [**26**星][2y] [sunnyelf/kalitools](https://github.com/shmilylty/kalitools) 
- [**25**星][1m] [Py] [initstring/pentest-tools](https://github.com/initstring/pentest-tools) 
    - 重复区段: [工具/破解&&Crack&&爆破&&BruteForce](#de81f9dd79c219c876c1313cd97852ce) |[工具/密码&&凭证/密码](#86dc226ae8a71db10e4136f4b82ccd06) |
- [**24**星][2y] [packtpublishing/digital-forensics-with-kali-linux](https://github.com/packtpublishing/digital-forensics-with-kali-linux) 
    - 重复区段: [工具/事件响应&&取证&&内存取证&&数字取证/取证&&Forensics&&数字取证&&内存取证](#1fc5d3621bb13d878f337c8031396484) |
- [**20**星][4y] [Shell] [psrcek/kali-mitm-evil-twin](https://github.com/psrcek/kali-mitm-evil-twin) 
- [**20**星][3y] [CSS] [wizardforcel/kali-linux-cookbook-zh](https://github.com/wizardforcel/kali-linux-cookbook-zh) 
- [**19**星][2m] [Shell] [noob-hackers/kalimux](https://github.com/noob-hackers/kalimux) 
- [**17**星][8m] [Dockerfile] [xavitorello/kali-full-docker](https://github.com/xavitorello/kali-full-docker) 
- [**16**星][1m] [Shell] [brimstone/docker-kali](https://github.com/brimstone/docker-kali) 
- [**16**星][4m] [Shell] [dchhv/kali-live-build-config](https://github.com/dchhv/kali-live-build-config) 
- [**15**星][11m] [educationhacker/installkalilinux](https://github.com/educationhacker/installkalilinux) 
- [**15**星][1y] [Py] [kaushalag29/kali-linux-tools-with-python](https://github.com/kaushalag29/kali-linux-tools-with-python) 
- [**15**星][2m] [yeahhub/kali-linux-ebooks](https://github.com/yeahhub/kali-linux-ebooks) 
- [**14**星][2m] [Vim script] [brainfucksec/kali-dotfiles](https://github.com/brainfucksec/kali-dotfiles) 
- [**14**星][5m] [Shell] [elreydetoda/packer-kali_linux](https://github.com/elreydetoda/packer-kali_linux) 
- [**14**星][1y] [Makefile] [lukaszlach/kali-desktop](https://github.com/lukaszlach/kali-desktop) 
- [**14**星][3y] [mehedishakeel/hack-with-kali-linux-2017.2-unofficial-documentation](https://github.com/mehedishakeel/hack-with-kali-linux-2017.2-unofficial-documentation) 
- [**12**星][2y] [Shell] [adityadrs/kali-scripts](https://github.com/adityadrs/kali-scripts) 
- [**12**星][4m] [Shell] [prateepb/kali-live-build](https://github.com/prateepb/kali-live-build) 
- [**12**星][9m] [Shell] [thehackingsage/kali-wsl](https://github.com/thehackingsage/kali-wsl) 
- [**11**星][2y] [HTML] [packtpublishing/web-penetration-testing-with-kali-linux-third-edition](https://github.com/packtpublishing/web-penetration-testing-with-kali-linux-third-edition) 
- [**11**星][3y] [CSS] [wizardforcel/kali-linux-web-pentest-cookbook-zh](https://github.com/wizardforcel/kali-linux-web-pentest-cookbook-zh) 
- [**11**星][6m] [Py] [len0/mirrorscript](https://github.com/jayantamadhav/mirrorscript) 
- [**10**星][2y] [C] [ryansisco/keygrab](https://github.com/ryansisco/keygrab) 
- [**10**星][4y] [C] [smoz1986/what-pro](https://github.com/smoz1986/what-pro) 
- [**9**星][4y] [Shell] [hackgnar/kali_intel_edison](https://github.com/hackgnar/kali_intel_edison) 
- [**9**星][3y] [C] [semsevens/nethunter_kernel_jfltexx](https://github.com/semsevens/nethunter_kernel_jfltexx) 
- [**9**星][4y] [Py] [phr34k0/wirelessjammer](https://github.com/phr34k0/wirelessjammer) 
- [**8**星][4m] [Shell] [platypew/dotfiles-kali](https://github.com/platypew/dotfiles-kali) 
- [**8**星][2y] [Shell] [redtf/kali-script](https://github.com/redtf/kali-script) 
- [**8**星][3y] [Shell] [st0ner1995/live-build-config](https://github.com/st0ner1995/live-build-config) 
- [**8**星][8m] [tothi/kali-rpi-luks-crypt](https://github.com/tothi/kali-rpi-luks-crypt) 
- [**7**星][2y] [dictionaryhouse/the-security-handbook-kali-linux](https://github.com/dictionaryhouse/the-security-handbook-kali-linux) 
- [**7**星][5y] [forjok/kali-scripts-1](https://github.com/forjok/kali-scripts-1) 
- [**7**星][1y] [Py] [skull00/fuck_society](https://github.com/skull00/fuck_society) 
- [**7**星][1y] [Ruby] [sliim-cookbooks/kali](https://github.com/sliim-cookbooks/kali) 
- [**6**星][5m] [Shell] [belouve/discover](https://github.com/belouve/discover) 
- [**5**星][3y] [Shell] [tomekceszke/offensive-security](https://github.com/tomekceszke/offensive-security) 
- [**5**星][5y] [nathanakalish/duckyhid](https://github.com/nathanakalish/DuckyHID) 
- [**4**星][3y] [Shell] [prabinzz/powerpack](https://github.com/prabinzz/powerpack) 
- [**4**星][1y] [schenlong/porunga](https://github.com/schenlong/porunga) 
- [**4**星][3y] [CSS] [yammgao/kali-linux-web-pentest-cookbook-zh](https://github.com/yammgao/kali-linux-web-pentest-cookbook-zh) 
- [**4**星][3y] [Shell] [zecopro/fix-vpn-kali-linux](https://github.com/zecopro/fix-vpn-kali-linux) 
- [**3**星][2y] [Shell] [libyanhackers/kalifixall](https://github.com/libyanhackers/kalifixall) 
- [**3**星][6y] [molotof/kali-pwnpad-apps](https://github.com/molotof/kali-pwnpad-apps) 
- [**3**星][2y] [Shell] [mr-xn/kali-install-docker](https://github.com/mr-xn/kali-install-docker) 
- [**3**星][Shell] [oda-alexandre/kali_build](https://github.com/oda-alexandre/kali_build) 
- [**2**星][3y] [Lua] [freelancepentester/kali-nethunter](https://github.com/freelancepentester/kali-nethunter) 
- [**2**星][2m] [Shell] [gnarlyhaze/kali-update-script](https://github.com/gnarlyhaze/kali-update-script) 
- [**2**星][6m] [HTML] [packtpublishing/improving-your-penetration-testing-skills](https://github.com/packtpublishing/improving-your-penetration-testing-skills) 
- [**2**星][9m] [Py] [remonhummar/essentials-projects](https://github.com/remonhummar/essentials-projects) 
- [**2**星][QML] [wuseman/kali_splash](https://github.com/wuseman/kali_splash) 
- [**2**星][12m] [Py] [ariesduanmu/kali-mix](https://github.com/ariesduanmu/Kali-mix) 
- [**1**星][8m] [Shell] [dude0413/setup-kali-tools](https://github.com/dude0413/setup-kali-tools) 
- [**1**星][1y] [Shell] [feifeixj/docker-kali-xrdp](https://github.com/feifeixj/docker-kali-xrdp) 
- [**1**星][3y] [lxkxc/kalitools](https://github.com/lxkxc/kalitools) 
- [**1**星][3y] [Shell] [nethunteros/kali-arm-build-scripts](https://github.com/nethunteros/kali-arm-build-scripts) 
- [**1**星][2y] [onedr/kali-web-hacks](https://github.com/onedr/kali-web-hacks) 
- [**1**星][1y] [Shell] [unsubtleguy/kali-packer](https://github.com/unsubtleguy/kali-packer) 
- [**1**星][4y] [Py] [siriuxy/wifi_based_population_estimator](https://github.com/siriuxy/wifi_based_population_estimator) raspberry pi 2 b+, kali linux, airodump-ng, tp-link wireless adapter, python, mysql.
- [**0**星][2y] [aiyouwolegequ/kali-docker](https://github.com/aiyouwolegequ/kali-docker) 
- [**0**星][2y] [alphasocket/docker-kali](https://github.com/alphasocket/docker-kali) 
- [**0**星][2y] [Shell] [danilabs/kali-script](https://github.com/danilabs/kali-script) 
- [**0**星][2y] [legendsec/cve-2017-11882-for-kali](https://github.com/legendsec/cve-2017-11882-for-kali) 
- [**0**星][2y] [Py] [m4l1c3/kali-setup](https://github.com/m4l1c3/kali-setup) 
- [**0**星][2y] [Shell] [mike-lesniak/kali-linux-docker](https://github.com/mike-lesniak/kali-linux-docker) 
- [**0**星][6y] [molotof/kali-pwnpad-scripts](https://github.com/molotof/kali-pwnpad-scripts) 
- [**0**星][1y] [Shell] [pentestprime/kali-custom](https://github.com/pentestprime/kali-custom) 
- [**0**星][1y] [roomtemperatureiq/obsidiantuxedo](https://github.com/roomtemperatureiq/obsidiantuxedo) 


### <a id="0b8e79b79094082d0906153445d6ef9a"></a>CobaltStrike


- [**389**星][1y] [Shell] [killswitch-gui/cobaltstrike-toolkit](https://github.com/killswitch-gui/cobaltstrike-toolkit) 
- [**365**星][2y] [Py] [vysec/morphhta](https://github.com/vysecurity/morphHTA) 
- [**344**星][4y] [Java] [rsmudge/cortana-scripts](https://github.com/rsmudge/cortana-scripts) 
- [**205**星][2y] [Py] [bluscreenofjeff/malleable-c2-randomizer](https://github.com/bluscreenofjeff/malleable-c2-randomizer) 
- [**203**星][1y] [C#] [spiderlabs/sharpcompile](https://github.com/spiderlabs/sharpcompile) 
- [**193**星][8m] [PowerShell] [outflanknl/excel4-dcom](https://github.com/outflanknl/excel4-dcom) 
- [**190**星][2y] [PowerShell] [vysecurity/angrypuppy](https://github.com/vysecurity/ANGRYPUPPY) 
- [**180**星][7m] [C#] [marx-yu/wopihost](https://github.com/marx-yu/wopihost) 
- [**179**星][2y] [C#] [ryhanson/externalc2](https://github.com/ryhanson/externalc2) 
- [**171**星][10m] [PowerShell] [qax-a-team/cobaltstrike-toolset](https://github.com/QAX-A-Team/CobaltStrike-Toolset) 
- [**149**星][3m] [threatexpress/malleable-c2](https://github.com/threatexpress/malleable-c2) 
- [**137**星][1y] [Py] [und3rf10w/external_c2_framework](https://github.com/und3rf10w/external_c2_framework) 
- [**132**星][9m] [JS] [crowdstrike/falcon-orchestrator](https://github.com/crowdstrike/falcon-orchestrator) 
- [**117**星][4m] [C++] [xorrior/raven](https://github.com/xorrior/raven) 
- [**115**星][1y] [Py] [verctor/cs_xor64](https://github.com/verctor/cs_xor64) 
- [**110**星][1y] [ridter/cs_chinese_support](https://github.com/ridter/cs_chinese_support) 
- [**100**星][7m] [fox-it/cobaltstrike-extraneous-space](https://github.com/fox-it/cobaltstrike-extraneous-space) 
- [**95**星][3m] [xx0hcd/malleable-c2-profiles](https://github.com/xx0hcd/malleable-c2-profiles) 
- [**91**星][1y] [001spartan/aggressor_scripts](https://github.com/001spartan/aggressor_scripts) 
- [**86**星][5m] [C#] [jnqpblc/sharpspray](https://github.com/jnqpblc/sharpspray) 
- [**82**星][1y] [java] [anbai-inc/cobaltstrike_hanization](https://github.com/anbai-inc/cobaltstrike_hanization) 
- [**81**星][7m] [Py] [dcsync/pycobalt](https://github.com/dcsync/pycobalt) Cobalt Strike API, Python版本
- [**61**星][2y] [Py] [ryanohoro/csbruter](https://github.com/ryanohoro/csbruter) 
- [**61**星][1y] [tevora-threat/powerview3-aggressor](https://github.com/tevora-threat/powerview3-aggressor) 
- [**57**星][2y] [C] [outflanknl/external_c2](https://github.com/outflanknl/external_c2) 
- [**53**星][3y] [C++] [aixxe/chameleon](https://github.com/aixxe/chameleon) 
- [**51**星][2y] [p292/ddeautocs](https://github.com/p292/ddeautocs) 
- [**51**星][1y] [Py] [truneski/external_c2_framework](https://github.com/truneski/external_c2_framework) 
- [**44**星][2y] [001spartan/csfm](https://github.com/001spartan/csfm) 
- [**44**星][5m] [C#] [jnqpblc/sharptask](https://github.com/jnqpblc/sharptask) 
- [**39**星][4m] [1135/1135-cobaltstrike-toolkit](https://github.com/1135/1135-cobaltstrike-toolkit) 
- [**38**星][3y] [bluscreenofjeff/malleablec2profiles](https://github.com/bluscreenofjeff/malleablec2profiles) 
- [**38**星][1y] [vysecurity/cobaltsplunk](https://github.com/vysecurity/CobaltSplunk) 
- [**37**星][2y] [tevora-threat/aggressor-powerview](https://github.com/tevora-threat/aggressor-powerview) 
- [**34**星][3y] [tom4t0/cobalt-strike-persistence](https://github.com/tom4t0/cobalt-strike-persistence) 
- [**28**星][1y] [redteamwing/cobaltstrike_wiki](https://github.com/redteamwing/cobaltstrike_wiki) 
- [**24**星][4y] [Py] [legbacore/t2e_integrity_check](https://github.com/legbacore/t2e_integrity_check) 
- [**24**星][10m] [C++] [sonicrules11/barbossa](https://github.com/sonicrules11/barbossa) 
- [**23**星][3m] [C#] [rciworks/rci.tutorials.csgo.cheat.external](https://github.com/rciworks/rci.tutorials.csgo.cheat.external) 
- [**21**星][8m] [HTML] [ridter/cs_custom_404](https://github.com/ridter/cs_custom_404) 




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
- [**2580**星][3y] [Ruby] [arachni/arachni](https://github.com/arachni/arachni) 
- [**2261**星][3m] [JS] [retirejs/retire.js](https://github.com/retirejs/retire.js) 
- [**2027**星][2m] [Ruby] [urbanadventurer/whatweb](https://github.com/urbanadventurer/whatweb) 
- [**2023**星][2m] [Py] [nabla-c0d3/sslyze](https://github.com/nabla-c0d3/sslyze) SSL/TLS服务器扫描
- [**1983**星][4y] [Go] [yahoo/gryffin](https://github.com/yahoo/gryffin) 
- [**1692**星][3y] [Go] [s-rah/onionscan](https://github.com/s-rah/onionscan) 
- [**1630**星][1m] [NSIS] [angryip/ipscan](https://github.com/angryip/ipscan) 
- [**1530**星][7m] [Py] [m4ll0k/wascan](https://github.com/m4ll0k/WAScan) 
- [**1494**星][4m] [Py] [hannob/snallygaster](https://github.com/hannob/snallygaster) Python脚本, 扫描HTTP服务器"秘密文件"
- [**1131**星][2y] [Py] [out0fmemory/goagent-always-available](https://github.com/out0fmemory/goagent-always-available) 
- [**1060**星][2m] [PHP] [tuhinshubhra/red_hawk](https://github.com/tuhinshubhra/red_hawk) 信息收集、漏洞扫描、爬虫多合一
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |
- [**1054**星][3m] [Py] [gerbenjavado/linkfinder](https://github.com/gerbenjavado/linkfinder) 
- [**1037**星][7m] [Py] [lucifer1993/struts-scan](https://github.com/lucifer1993/struts-scan) struts2漏洞全版本检测和利用工具
- [**985**星][3m] [Py] [h4ckforjob/dirmap](https://github.com/h4ckforjob/dirmap) 一个高级web目录、文件扫描工具，功能将会强于DirBuster、Dirsearch、cansina、御剑。
- [**937**星][3y] [Py] [countercept/doublepulsar-detection-script](https://github.com/countercept/doublepulsar-detection-script) python脚本，用于扫描网络中感染DOUBLEPULSAR的操作系统。
- [**905**星][2m] [Py] [tuhinshubhra/cmseek](https://github.com/tuhinshubhra/cmseek) 
- [**880**星][5m] [PHP] [tidesec/wdscanner](https://github.com/tidesec/wdscanner) 分布式web漏洞扫描、客户管理、漏洞定期扫描、子域名枚举、端口扫描、网站爬虫、暗链检测、坏链检测、网站指纹搜集、专项漏洞检测、代理搜集及部署等功能。
- [**862**星][1m] [Py] [ajinabraham/nodejsscan](https://github.com/ajinabraham/nodejsscan) 
- [**820**星][3y] [Py] [ring04h/weakfilescan](https://github.com/ring04h/weakfilescan) 
- [**759**星][17d] [Py] [vesche/scanless](https://github.com/vesche/scanless) scanless：端口扫描器
- [**741**星][19d] [Py] [nekmo/dirhunt](https://github.com/nekmo/dirhunt) Web爬虫, 针对搜索和分析路径做了优化
    - 重复区段: [工具/爬虫](#785ad72c95e857273dce41842f5e8873) |
- [**740**星][3y] [PHP] [googleinurl/scanner-inurlbr](https://github.com/googleinurl/scanner-inurlbr) 
- [**739**星][2y] [Py] [d35m0nd142/lfisuite](https://github.com/d35m0nd142/lfisuite) 
- [**722**星][6m] [Py] [ztgrace/changeme](https://github.com/ztgrace/changeme) 默认证书扫描器
- [**694**星][4m] [CSS] [ajinabraham/cmsscan](https://github.com/ajinabraham/cmsscan) Scan Wordpress, Drupal, Joomla, vBulletin websites for Security issues
- [**690**星][2m] [CSS] [boy-hack/w12scan](https://github.com/w-digital-scanner/w12scan) a network asset discovery engine that can automatically aggregate related assets for analysis and use
- [**681**星][28d] [C] [scanmem/scanmem](https://github.com/scanmem/scanmem) 
- [**671**星][1m] [Ruby] [mozilla/ssh_scan](https://github.com/mozilla/ssh_scan) 
- [**657**星][7m] [Py] [m4ll0k/wpseku](https://github.com/m4ll0k/wpseku) 
- [**656**星][2m] [Py] [kevthehermit/pastehunter](https://github.com/kevthehermit/pastehunter) 
- [**655**星][2y] [Py] [ysrc/gourdscanv2](https://github.com/ysrc/gourdscanv2) 
- [**654**星][2y] [Py] [lijiejie/htpwdscan](https://github.com/lijiejie/htpwdscan) 
- [**649**星][5m] [Py] [droope/droopescan](https://github.com/droope/droopescan) 
- [**636**星][1y] [Py] [lmco/laikaboss](https://github.com/lmco/laikaboss) 
- [**613**星][5m] [Py] [rabbitmask/weblogicscan](https://github.com/rabbitmask/weblogicscan) 
- [**612**星][12m] [Ruby] [thesp0nge/dawnscanner](https://github.com/thesp0nge/dawnscanner) 
- [**604**星][4m] [Py] [faizann24/xsspy](https://github.com/faizann24/xsspy) Web Application XSS Scanner
- [**590**星][2y] [Go] [timest/goscan](https://github.com/timest/goscan) 
- [**585**星][3y] [Perl 6] [rapid7/iotseeker](https://github.com/rapid7/iotseeker)  scan a network for specific types of IoT devices to detect if they are using the default, factory set credentials.
- [**569**星][2m] [HTML] [gwillem/magento-malware-scanner](https://github.com/gwillem/magento-malware-scanner) 用于检测 Magento 恶意软件的规则/样本集合
- [**564**星][2m] [Perl] [alisamtechnology/atscan](https://github.com/alisamtechnology/atscan) 
- [**555**星][5m] [Py] [codingo/vhostscan](https://github.com/codingo/vhostscan) 
- [**542**星][7m] [Go] [marco-lancini/goscan](https://github.com/marco-lancini/goscan) 
- [**536**星][4m] [Py] [dhs-ncats/pshtt](https://github.com/cisagov/pshtt) 
- [**526**星][6m] [Py] [grayddq/gscan](https://github.com/grayddq/gscan) 
- [**481**星][1m] [Py] [fcavallarin/htcap](https://github.com/fcavallarin/htcap) 
- [**475**星][1y] [C] [nanshihui/scan-t](https://github.com/nanshihui/scan-t) 
- [**439**星][4y] [Py] [nimia/public_drown_scanner](https://github.com/nimia/public_drown_scanner) 
- [**415**星][7y] [C] [spinkham/skipfish](https://github.com/spinkham/skipfish) 
- [**399**星][2m] [Py] [boy-hack/w13scan](https://github.com/w-digital-scanner/w13scan) 
- [**397**星][10m] [JS] [eviltik/evilscan](https://github.com/eviltik/evilscan) evilscan：大规模 IP/端口扫描器，Node.js 编写
- [**390**星][10m] [Py] [mitre/multiscanner](https://github.com/mitre/multiscanner) 
- [**386**星][1y] [Py] [grayddq/publicmonitors](https://github.com/grayddq/publicmonitors) 
- [**385**星][1m] [C] [hasherezade/hollows_hunter](https://github.com/hasherezade/hollows_hunter) 
- [**380**星][2y] [Java] [irsdl/iis-shortname-scanner](https://github.com/irsdl/iis-shortname-scanner) 
- [**379**星][13d] [Py] [stamparm/dsss](https://github.com/stamparm/dsss) 
- [**340**星][4m] [Py] [swisskyrepo/wordpresscan](https://github.com/swisskyrepo/wordpresscan) 
- [**339**星][12m] [Py] [skavngr/rapidscan](https://github.com/skavngr/rapidscan) 
- [**338**星][1m] [Py] [fgeek/pyfiscan](https://github.com/fgeek/pyfiscan) pyfiscan：Web App 漏洞及版本扫描
- [**337**星][2y] [Py] [bugscanteam/githack](https://github.com/bugscanteam/githack) 
- [**335**星][3m] [Java] [portswigger/backslash-powered-scanner](https://github.com/portswigger/backslash-powered-scanner) 
- [**330**星][1y] [Py] [flipkart-incubator/rta](https://github.com/flipkart-incubator/rta) 
- [**316**星][2m] [HTML] [coinbase/salus](https://github.com/coinbase/salus) 
- [**315**星][15d] [C] [royhills/arp-scan](https://github.com/royhills/arp-scan) 
- [**301**星][10m] [PHP] [steverobbins/magescan](https://github.com/steverobbins/magescan) 
- [**299**星][1m] [PowerShell] [canix1/adaclscanner](https://github.com/canix1/adaclscanner) 
- [**297**星][3y] [Py] [ring04h/wyportmap](https://github.com/ring04h/wyportmap) 
- [**294**星][1y] [Shell] [cryptolok/ghostinthenet](https://github.com/cryptolok/ghostinthenet) 
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**294**星][2m] [Ruby] [m0nad/hellraiser](https://github.com/m0nad/hellraiser) 
- [**294**星][1m] [Shell] [mitchellkrogza/apache-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/apache-ultimate-bad-bot-blocker) 
- [**294**星][4y] [Py] [zer0h/httpscan](https://github.com/zer0h/httpscan) 
- [**286**星][4m] [enkomio/taipan](https://github.com/enkomio/Taipan) 
- [**285**星][2y] [Py] [xdavidhu/portspider](https://github.com/xdavidhu/portspider) A lightning fast multithreaded network scanner framework with modules.
- [**284**星][1y] [Py] [code-scan/dzscan](https://github.com/code-scan/dzscan) 
- [**280**星][8m] [Py] [boy-hack/w8fuckcdn](https://github.com/boy-hack/w8fuckcdn) 通过扫描全网绕过CDN获取网站IP地址
- [**278**星][3m] [Py] [shenril/sitadel](https://github.com/shenril/sitadel) 
- [**277**星][2y] [JS] [dpnishant/raptor](https://github.com/dpnishant/raptor) 
- [**276**星][2m] [Py] [target/strelka](https://github.com/target/strelka) 
- [**273**星][2y] [Go] [kisesy/gscan_quic](https://github.com/kisesy/gscan_quic) 
- [**269**星][2y] [Py] [toyakula/luna](https://github.com/toyakula/luna) 
- [**268**星][3y] [Py] [joxeankoret/multiav](https://github.com/joxeankoret/multiav) 
- [**268**星][1y] [PHP] [psecio/parse](https://github.com/psecio/parse) 
- [**267**星][1y] [Py] [rassec/pentester-fully-automatic-scanner](https://github.com/rassec/pentester-fully-automatic-scanner) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |
- [**262**星][5m] [Py] [abhisharma404/vault_scanner](https://github.com/abhisharma404/vault) 
- [**254**星][3m] [Py] [m4ll0k/konan](https://github.com/m4ll0k/Konan) 
- [**253**星][9m] [jeffzh3ng/insectsawake](https://github.com/jeffzh3ng/insectsawake) 
- [**252**星][2y] [Py] [chrizator/netattack2](https://github.com/chrizator/netattack2) netattack2：网络扫描和攻击脚本
- [**251**星][2y] [Py] [0x4d31/salt-scanner](https://github.com/0x4d31/salt-scanner) 
- [**249**星][4y] [Py] [wooyun/tangscan](https://github.com/wooyun/tangscan) 企业在线安全平台
- [**246**星][1m] [Py] [gildasio/h2t](https://github.com/gildasio/h2t) 
- [**245**星][2m] [Go] [zmap/zgrab2](https://github.com/zmap/zgrab2) 
- [**242**星][3y] [Swift] [netyouli/whc_scan](https://github.com/netyouli/whc_scan) 
- [**242**星][2y] [Py] [xyuanmu/checkiptools](https://github.com/xyuanmu/checkiptools) 
- [**238**星][1y] [Ruby] [rastating/joomlavs](https://github.com/rastating/joomlavs) 
- [**237**星][3y] [Py] [lijiejie/iis_shortname_scanner](https://github.com/lijiejie/iis_shortname_scanner) 
- [**235**星][3m] [PHP] [psecio/versionscan](https://github.com/psecio/versionscan) 
- [**233**星][7m] [Go] [gocaio/goca](https://github.com/gocaio/goca) 
- [**230**星][6y] [Py] [zigoo0/webpwn3r](https://github.com/zigoo0/webpwn3r) 
- [**227**星][1y] [C++] [nickcano/xenoscan](https://github.com/nickcano/xenoscan) 
- [**225**星][3y] [Perl] [davidpepper/fierce-domain-scanner](https://github.com/davidpepper/fierce-domain-scanner) 
- [**217**星][5m] [JS] [pavanw3b/sh00t](https://github.com/pavanw3b/sh00t) 
- [**213**星][4y] [Py] [mitsuhiko/python-regex-scanner](https://github.com/mitsuhiko/python-regex-scanner) 
- [**211**星][3y] [Py] [scu-igroup/telnet-scanner](https://github.com/NewBee119/telnet-scanner) 
- [**209**星][3m] [Py] [iojw/socialscan](https://github.com/iojw/socialscan) 
- [**207**星][9m] [Py] [nullarray/dorknet](https://github.com/nullarray/dorknet) 
- [**203**星][2y] [C] [royhills/ike-scan](https://github.com/royhills/ike-scan) 
- [**202**星][1y] [Py] [dionach/cmsmap](https://github.com/dionach/cmsmap) 
- [**201**星][12m] [PowerShell] [sud0woodo/dcomrade](https://github.com/sud0woodo/dcomrade) 
- [**199**星][5m] [Py] [rub-nds/corstest](https://github.com/rub-nds/corstest) 
- [**194**星][3m] [Ruby] [delvelabs/vane](https://github.com/delvelabs/vane) 
- [**194**星][3y] [Py] [tuuunya/webdirscan](https://github.com/TuuuNya/webdirscan) 
- [**189**星][10m] [Py] [emersonelectricco/fsf](https://github.com/emersonelectricco/fsf) 
- [**185**星][9m] [Batchfile] [tai7sy/fuckcdn](https://github.com/tai7sy/fuckcdn) 
- [**184**星][3y] [pwnsdx/badcode](https://github.com/pwnsdx/badcode) 
- [**184**星][2m] [Py] [swisskyrepo/damnwebscanner](https://github.com/swisskyrepo/damnwebscanner) 
- [**182**星][3y] [Py] [misterch0c/firminator_backend](https://github.com/misterch0c/firminator_backend) 
- [**179**星][6m] [JS] [antoinevastel/fpscanner](https://github.com/antoinevastel/fpscanner) 
- [**179**星][3y] [Py] [redteamsecurity/autonessus](https://github.com/redteamsecurity/autonessus) 
- [**179**星][10m] [Py] [welchbj/bscan](https://github.com/welchbj/bscan) 
- [**176**星][3y] [Py] [videns/vulners-scanner](https://github.com/videns/vulners-scanner) 
- [**175**星][1y] [Py] [0xbug/biu-framework](https://github.com/0xbug/biu-framework) Security Scan Framework For Enterprise Intranet Based Services 
- [**169**星][2m] [C#] [rasta-mouse/amsiscanbufferbypass](https://github.com/rasta-mouse/amsiscanbufferbypass) 
- [**167**星][1y] [PHP] [robocoder/rips-scanner](https://github.com/robocoder/rips-scanner) 
- [**166**星][2m] [Shell] [1n3/massbleed](https://github.com/1n3/massbleed) 
- [**165**星][5m] [Go] [liamg/furious](https://github.com/liamg/furious) 
- [**165**星][3y] [Py] [sowish/lnscan](https://github.com/sowish/lnscan) 
- [**164**星][1m] [Py] [natlas/natlas](https://github.com/natlas/natlas) 
- [**164**星][10m] [Py] [tijme/angularjs-csti-scanner](https://github.com/tijme/angularjs-csti-scanner) 
- [**162**星][4m] [PHP] [scr34m/php-malware-scanner](https://github.com/scr34m/php-malware-scanner) 
- [**160**星][11m] [Py] [mosuan/filescan](https://github.com/mosuan/filescan) 敏感文件扫描 / 二次判断降低误报率 / 扫描内容规则化 / 多目录扫描
- [**159**星][3y] [Ruby] [kost/dockscan](https://github.com/kost/dockscan) dockscan：docker安全漏洞扫描和审计工具。
- [**159**星][4y] [Py] [plaguescanner/plaguescanner](https://github.com/plaguescanner/plaguescanner) 
- [**158**星][2m] [Java] [eth-sri/securify](https://github.com/eth-sri/securify) 
- [**158**星][1m] [Py] [mykings/python-masscan](https://github.com/mykings/python-masscan) 
- [**152**星][10m] [Go] [botherder/kraken](https://github.com/botherder/kraken) 
- [**147**星][2y] [Py] [aipengjie/sensitivefilescan](https://github.com/aipengjie/sensitivefilescan) 
- [**147**星][2m] [HTML] [neal1991/gshark](https://github.com/neal1991/gshark) 
- [**143**星][4y] [C++] [lcatro/network_backdoor_scanner](https://github.com/lcatro/network_backdoor_scanner) 
- [**141**星][5y] [PHP] [veerupandey/penetration-testing-toolkit](https://github.com/veerupandey/penetration-testing-toolkit) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |
- [**140**星][1y] [Py] [madengr/ham2mon](https://github.com/madengr/ham2mon) 
- [**139**星][8m] [C] [trailofbits/onesixtyone](https://github.com/trailofbits/onesixtyone) 
- [**138**星][1y] [Py] [ultimatelabs/zoom](https://github.com/ultimatelabs/zoom) 
- [**137**星][9m] [Py] [johndekroon/serializekiller](https://github.com/johndekroon/serializekiller) 
- [**137**星][4y] [Py] [puniaze/portdog](https://github.com/puniaze/portdog)  network anomaly detector aimed to detect port scanning techniques
- [**135**星][1y] [Shell] [peterjaric/archaeologit](https://github.com/peterjaric/archaeologit) 扫描GitHub repo的历史, 按指定模式查找敏感信息, 例如用户名密码
- [**134**星][1y] [Py] [dionach/reposcanner](https://github.com/dionach/reposcanner) 
- [**132**星][4y] [HTML] [code-scan/brodomain](https://github.com/code-scan/brodomain) 
- [**132**星][6y] [Java] [sectooladdict/wavsep](https://github.com/sectooladdict/wavsep) 
- [**128**星][8m] [Ruby] [firefart/wordpresspingbackportscanner](https://github.com/firefart/wordpresspingbackportscanner) 
- [**128**星][3y] [HTML] [skylined/localnetworkscanner](https://github.com/skylined/localnetworkscanner) 
- [**127**星][4y] [PHP] [ramadhanamizudin/wordpress-scanner](https://github.com/ramadhanamizudin/wordpress-scanner) 
- [**125**星][4y] [C++] [slauc91/anticheat](https://github.com/slauc91/anticheat) 
- [**124**星][28d] [C++] [omenscan/achoir](https://github.com/omenscan/achoir) 
- [**122**星][2y] [PowerShell] [borntoberoot/powershell_ipv4networkscanner](https://github.com/borntoberoot/powershell_ipv4networkscanner) 
- [**122**星][4y] [PHP] [dermotblair/webvulscan](https://github.com/dermotblair/webvulscan) 
- [**121**星][2y] [PHP] [jamalc0m/wphunter](https://github.com/jamalc0m/wphunter) 
- [**121**星][3y] [Ruby] [melvinsh/vcsmap](https://github.com/melvinsh/vcsmap) 
- [**120**星][2y] [Shell] [scu-igroup/ssh-scanner](https://github.com/NewBee119/ssh-scanner) 
- [**119**星][4y] [Ruby] [yangbh/hammer](https://github.com/yangbh/hammer) 
- [**117**星][3y] [Py] [neuroo/grabber](https://github.com/neuroo/grabber) 
- [**113**星][5m] [Py] [drego85/joomlascan](https://github.com/drego85/joomlascan) 
- [**113**星][9m] [C] [tylabs/quicksand_lite](https://github.com/tylabs/quicksand_lite) quicksand_lite：命令行工具，扫描 Office 文档 stream
- [**108**星][27d] [Py] [baidu-security/openrasp-iast](https://github.com/baidu-security/openrasp-iast) 
- [**107**星][11m] [JS] [cloudtracer/paskto](https://github.com/cloudtracer/paskto) 
- [**107**星][2y] [C] [gvb84/pbscan](https://github.com/gvb84/pbscan) 
- [**98**星][2y] [C++] [atxsinn3r/amsiscanner](https://github.com/atxsinn3r/amsiscanner) 
- [**97**星][6m] [Py] [w-digital-scanner/w12scan-client](https://github.com/w-digital-scanner/w12scan-client) 
- [**93**星][2y] [Py] [blackye/webdirdig](https://github.com/blackye/webdirdig) 
- [**93**星][2y] [Java] [oliverklee/pixy](https://github.com/oliverklee/pixy) 
- [**93**星][22d] [C#] [retirenet/dotnet-retire](https://github.com/retirenet/dotnet-retire) 
- [**93**星][8m] [PowerShell] [vletoux/smbscanner](https://github.com/vletoux/smbscanner) 
- [**91**星][4m] [Py] [aedoo/allscanner](https://github.com/aedoo/allscanner) 
- [**91**星][7m] [Py] [jerrychan807/wspih](https://github.com/jerrychan807/wspih) 
- [**90**星][7m] [Go] [covenantsql/cookiescanner](https://github.com/covenantsql/cookiescanner) 
- [**89**星][2y] [C] [codecat/clawsearch](https://github.com/codecat/clawsearch) 
- [**88**星][2m] [C] [sfan5/fi6s](https://github.com/sfan5/fi6s) IPV6扫描器
- [**87**星][6m] [Go] [nearform/gammaray](https://github.com/nearform/gammaray) 
- [**87**星][4m] [Py] [rassec/yandi-scanner](https://github.com/rassec/yandi-scanner) 
- [**87**星][2y] [Py] [se55i0n/awvs_nessus_scanner_api](https://github.com/se55i0n/awvs_nessus_scanner_api) 
- [**87**星][1y] [PowerShell] [vletoux/spoolerscanner](https://github.com/vletoux/spoolerscanner) 
- [**86**星][2y] [Java] [blackarbiter/android_code_arbiter](https://github.com/blackarbiter/android_code_arbiter) 
- [**86**星][2y] [PowerShell] [borntoberoot/powershell_ipv4portscanner](https://github.com/borntoberoot/powershell_ipv4portscanner) 
- [**85**星][3y] [Py] [magicming200/tomcat-weak-password-scanner](https://github.com/magicming200/tomcat-weak-password-scanner) 
- [**85**星][8y] [poerschke/uniscan](https://github.com/poerschke/uniscan) 
- [**84**星][3y] [Py] [5up3rc/nagascan](https://github.com/5up3rc/nagascan) 
- [**84**星][4y] [Py] [blackye/bkscanner](https://github.com/blackye/bkscanner) 
- [**83**星][5y] [Py] [ifghou/wapiti](https://github.com/ifghou/wapiti) 
- [**83**星][5m] [Shell] [zerobyte-id-bak/bashter](https://github.com/zerobyte-id-bak/Bashter) 
- [**82**星][1y] [Py] [m4ll0k/wpsploit](https://github.com/m4ll0k/wpsploit) Wordpress主题/插件代码扫描
- [**82**星][2y] [Go] [random-robbie/aws-scanner](https://github.com/random-robbie/aws-scanner) 
- [**82**星][10m] [Py] [tlkh/prowler](https://github.com/tlkh/prowler) 
- [**81**星][1y] [Py] [oalabs/findyara](https://github.com/oalabs/findyara) 使用Yara规则扫描二进制文件
- [**81**星][4y] [Py] [shengqi158/svn_git_scanner](https://github.com/shengqi158/svn_git_scanner) 
- [**79**星][10m] [paralax/awesome-internet-scanning](https://github.com/paralax/awesome-internet-scanning) 
- [**78**星][3y] [HTML] [malqr/malqr.github.io](https://github.com/malqr/malqr.github.io) 
- [**77**星][4m] [Py] [palkeo/pakala](https://github.com/palkeo/pakala) 
- [**77**星][2y] [Py] [se55i0n/portscanner](https://github.com/se55i0n/portscanner) 
- [**76**星][2y] [dictionaryhouse/dirpath_list](https://github.com/dictionaryhouse/dirpath_list) 
- [**75**星][2y] [Py] [imiyoo2010/teye_scanner_for_book](https://github.com/imiyoo2010/teye_scanner_for_book) 
- [**73**星][Py] [minisafe/microscan](https://github.com/minisafe/microscan) 
- [**73**星][3y] [Py] [zhanghangorg/sqlinj-ant](https://github.com/zhanghangorg/sqlinj-ant) 
- [**72**星][3y] [Py] [lorexxar/bscanner](https://github.com/lorexxar/bscanner) 
- [**69**星][1m] [C] [getdrive/lazy-rdp](https://github.com/getdrive/lazy-rdp) 
- [**69**星][5m] [Objective-C] [google/gscxscanner](https://github.com/google/gscxscanner) 
- [**68**星][4y] [C] [microwave89/rtsectiontest](https://github.com/microwave89/rtsectiontest) 
- [**68**星][3m] [Go] [nray-scanner/nray](https://github.com/nray-scanner/nray) 
- [**68**星][1y] [C] [ptrrkssn/pnscan](https://github.com/ptrrkssn/pnscan) 
- [**68**星][6y] [Py] [secfree/bcrpscan](https://github.com/secfree/bcrpscan) 
- [**67**星][2y] [Py] [azizaltuntas/pymap-scanner](https://github.com/azizaltuntas/pymap-scanner) 
- [**66**星][3y] [Py] [claudioviviani/ms17-010-m4ss-sc4nn3r](https://github.com/claudioviviani/ms17-010-m4ss-sc4nn3r) 
- [**66**星][2y] [Objective-C] [iscanner/iscanner_ios](https://github.com/iscanner/iscanner_ios) 
- [**66**星][2y] [Py] [planet-work/php-malware-scanner](https://github.com/planet-work/php-malware-scanner) 
- [**65**星][5m] [Batchfile] [cornerpirate/reportcompiler](https://github.com/cornerpirate/reportcompiler) 
- [**65**星][3m] [C] [neural75/gqrx-scanner](https://github.com/neural75/gqrx-scanner) 
- [**64**星][4y] [PHP] [googleinurl/routerhunterbr](https://github.com/googleinurl/routerhunterbr) 
- [**64**星][3m] [JS] [sergejmueller/wpcheck](https://github.com/sergejmueller/wpcheck) 
- [**63**星][12m] [Shell] [floyd-fuh/crass](https://github.com/floyd-fuh/crass) 
- [**63**星][1m] [Ruby] [mephux/ruby-nessus](https://github.com/mephux/ruby-nessus) 
- [**63**星][5y] [Py] [paulsec/spipscan](https://github.com/paulsec/spipscan) 
- [**61**星][2y] [Py] [lijiejie/struts2_045_scan](https://github.com/lijiejie/struts2_045_scan) 
- [**61**星][2y] [PowerShell] [tenable/posh-nessus](https://github.com/tenable/posh-nessus) 
- [**61**星][2y] [Py] [yassergersy/sub6](https://github.com/yassergersy/sub6) 
- [**61**星][11m] [imfht/scansql](https://github.com/imfht/ScanSql) 
- [**60**星][5y] [PHP] [smaash/fuckshitup](https://github.com/smaash/fuckshitup) 
- [**59**星][2y] [Go] [tengzhangchao/portscan](https://github.com/tengzhangchao/portscan) 
- [**58**星][6m] [Vue] [nao-sec/tknk_scanner](https://github.com/nao-sec/tknk_scanner) 基于社区的集成恶意软件识别系统
- [**58**星][26d] [she11c0der/scanners-box](https://github.com/she11c0der/scanners-box) 
- [**57**星][8m] [YARA] [sfaci/masc](https://github.com/sfaci/masc) 扫描网站中的恶意软件, 以及其他一些网站维护功能
- [**56**星][7m] [Shell] [malscan/malscan](https://github.com/malscan/malscan) 
- [**55**星][1y] [Py] [programa-stic/marvin-static-analyzer](https://github.com/programa-stic/marvin-static-analyzer) 
- [**55**星][2y] [PowerShell] [vletoux/ms17-010-scanner](https://github.com/vletoux/ms17-010-scanner) 
- [**54**星][8m] [Py] [attackanddefencesecuritylab/ad_webscanner](https://github.com/attackanddefencesecuritylab/ad_webscanner) 
- [**53**星][4y] [JS] [az0ne/simple_zoomeye](https://github.com/az0ne/simple_zoomeye) 
- [**53**星][1y] [Py] [vulnerscom/vulners-scanner](https://github.com/vulnerscom/vulners-scanner) 
- [**52**星][2y] [Py] [apkjet/trustlookwannacrytoolkit](https://github.com/apkjet/trustlookwannacrytoolkit) 
- [**51**星][5y] [C] [dgoulet/kjackal](https://github.com/dgoulet/kjackal) 
- [**51**星][5m] [C++] [jesseemond/cheat-and-gin](https://github.com/jesseemond/cheat-and-gin) 
- [**51**星][11m] [Py] [klsecservices/s7scan](https://github.com/klsecservices/s7scan) 
- [**50**星][3y] [Py] [kovige/netscan](https://github.com/kovige/netscan) 
- [**47**星][13d] [Java] [rub-nds/tls-scanner](https://github.com/rub-nds/tls-scanner) 
- [**46**星][4y] [securitytube/wifiscanvisualizer](https://github.com/securitytube/wifiscanvisualizer) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**46**星][6m] [Py] [k8gege/k8portscan](https://github.com/k8gege/k8portscan) 
- [**45**星][2y] [Py] [tr3jer/incextensivelist](https://github.com/tr3jer/incextensivelist) 
- [**44**星][3y] [Py] [ramadhanamizudin/python-icap-yara](https://github.com/ramadhanamizudin/python-icap-yara) 
- [**43**星][2y] [Py] [grayddq/passiveseccheck](https://github.com/grayddq/passiveseccheck) 
- [**43**星][3y] [yeahwu/google-ip-range](https://github.com/yeahwu/google-ip-range) 
- [**43**星][3y] [JS] [yinzhixin/scanner](https://github.com/yinzhixin/scanner) 
- [**42**星][2y] [Py] [imp0wd3r/scanner](https://github.com/imp0wd3r/scanner) 
- [**40**星][2y] [Py] [se55i0n/cwebscanner](https://github.com/se55i0n/cwebscanner) 
- [**39**星][2y] [Java] [aninstein/network-security-situation-awareness-system](https://github.com/aninstein/network-security-situation-awareness-system) 
- [**39**星][2y] [Roff] [apxar/xlog](https://github.com/apxar/xlog) 
- [**39**星][9m] [lj147/awesome-wechat](https://github.com/lj147/awesome-wechat) 
- [**36**星][3y] [Py] [villanch/pr0xy](https://github.com/villanch/pr0xy) 
- [**36**星][3m] [Py] [lengjibo/dedecmscan](https://github.com/lengjibo/dedecmscan) 
- [**35**星][6m] [Py] [tidesec/tdscanner](https://github.com/tidesec/tdscanner) 
- [**35**星][3y] [Py] [lightless233/pansidong](https://github.com/lightless233/Pansidong) 
- [**34**星][3y] [Go] [jmpews/goscan](https://github.com/jmpews/goscan) 
- [**31**星][2y] [Py] [sigploiter/m3uascan](https://github.com/sigploiter/m3uascan) 
- [**31**星][2y] [Py] [sewellding/sitepathscan](https://github.com/SewellDinG/SitePathScan) 
- [**30**星][1y] [Py] [dd4rk/ctfwebscan](https://github.com/dd4rk/ctfwebscan) 
- [**29**星][1y] [Py] [he1m4n6a/dcweb](https://github.com/he1m4n6a/dcweb) 
- [**29**星][7m] [Go] [jimyj/scanproxy](https://github.com/jimyj/scanproxy) 
- [**28**星][12m] [Py] [98587329/web-scan](https://github.com/98587329/web-scan) 
- [**27**星][4y] [C] [hxp2k6/smart7ec-scan-console](https://github.com/hxp2k6/smart7ec-scan-console) 
- [**26**星][2y] [Py] [bipabo1l/ssrf_scan](https://github.com/bipabo1l/ssrf_scan) 
- [**25**星][4m] [Py] [spuerbread/kun](https://github.com/spuerbread/kun) 
- [**25**星][6y] [waytai/cloudsafe](https://github.com/waytai/cloudsafe) 
- [**24**星][3y] [Py] [topranks/ms17-010_subnet](https://github.com/topranks/ms17-010_subnet) 
- [**23**星][2y] [Py] [grayddq/passivedatasorting](https://github.com/grayddq/passivedatasorting) 
- [**22**星][2y] [C++] [d35m0nd142/kadabra](https://github.com/d35m0nd142/kadabra) 
- [**22**星][1y] [Go] [lakevilladom/goskylar](https://github.com/lakevilladom/goskylar) 
- [**22**星][2m] [C#] [shack2/swebscan](https://github.com/shack2/swebscan) 
- [**21**星][6m] [Py] [duchengyao/hkdvr_login](https://github.com/duchengyao/hkdvr_login) 


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
- [**191**星][3m] [cryptoseb/cryptopaper](https://github.com/cryptoseb/cryptopaper) 
- [**165**星][5y] [CSS] [nknetobserver/nknetobserver.github.io](https://github.com/nknetobserver/nknetobserver.github.io) 
- [**140**星][5m] [Py] [macr0phag3/githubmonitor](https://github.com/macr0phag3/githubmonitor) 
- [**118**星][18d] [chef-koch/online-privacy-test-resource-list](https://github.com/chef-koch/online-privacy-test-resource-list) 
- [**83**星][1y] [github-classroom-cybros/ethical-hacking](https://github.com/github-classroom-cybros/ethical-hacking) 
- [**70**星][6m] [HTML] [securityautomation/dumpthegit](https://github.com/securityautomation/dumpthegit) 
- [**60**星][13d] [Py] [deepdivesec/gitmad](https://github.com/deepdivesec/gitmad) 
- [**32**星][2y] [Shell] [deepwn/gitpagehijack](https://github.com/deepwn/gitpagehijack) 


### <a id="1927ed0a77ff4f176b0b7f7abc551e4a"></a>隐私存储


#### <a id="1af1c4f9dba1db2a4137be9c441778b8"></a>未分类


- [**5029**星][2m] [Shell] [stackexchange/blackbox](https://github.com/stackexchange/blackbox) 文件使用PGP加密后隐藏在Git/Mercurial/Subversion


#### <a id="362dfd9c1f530dd20f922fd4e0faf0e3"></a>隐写


- [**569**星][1m] [Go] [dimitarpetrov/stegify](https://github.com/dimitarpetrov/stegify) 
- [**501**星][2y] [Py] [robindavid/lsb-steganography](https://github.com/robindavid/lsb-steganography) 
- [**466**星][6y] [Ruby] [zed-0xff/zsteg](https://github.com/zed-0xff/zsteg) 
- [**465**星][6y] [Py] [bramcohen/dissidentx](https://github.com/bramcohen/dissidentx) 
- [**344**星][6m] [Go] [lukechampine/jsteg](https://github.com/lukechampine/jsteg) 
- [**342**星][5m] [Java] [syvaidya/openstego](https://github.com/syvaidya/openstego) 
- [**337**星][5y] [JS] [yndi/darkjpeg](https://github.com/yndi/darkjpeg) 
- [**274**星][1y] [C] [abeluck/stegdetect](https://github.com/abeluck/stegdetect) 
- [**256**星][26d] [Py] [cedricbonhomme/stegano](https://github.com/cedricbonhomme/stegano) 
- [**243**星][2y] [Py] [livz/cloacked-pixel](https://github.com/livz/cloacked-pixel) 
- [**144**星][5m] [Py] [ragibson/steganography](https://github.com/ragibson/steganography) 
- [**120**星][1y] [Java] [b3dk7/stegexpose](https://github.com/b3dk7/stegexpose) 
- [**105**星][1y] [JS] [offdev/zwsp-steg-js](https://github.com/offdev/zwsp-steg-js) 零宽度空间隐写术, 将隐藏的消息编码/解码为不可打印/可读的字符
- [**96**星][12m] [JS] [desudesutalk/desudesutalk](https://github.com/desudesutalk/desudesutalk) 
- [**79**星][6m] [MATLAB] [ktekeli/audio-steganography-algorithms](https://github.com/ktekeli/audio-steganography-algorithms) 
- [**76**星][14d] [Crystal] [maxfierke/fincher](https://github.com/maxfierke/fincher) 
- [**55**星][7m] [JS] [jes/chess-steg](https://github.com/jes/chess-steg) 
- [**40**星][2y] [Py] [aqcurate/lsb-steganography](https://github.com/aqcurate/lsb-steganography) 
- [**36**星][2y] [C++] [hitanshu-dhawan/imagesteganography](https://github.com/hitanshu-dhawan/imagesteganography) 
- [**35**星][4m] [Rust] [teovoinea/steganography](https://github.com/teovoinea/steganography) 
- [**27**星][5m] [PowerShell] [johnaho/cloakify-powershell](https://github.com/johnaho/cloakify-powershell) 
- [**22**星][2y] [HTML] [beardog108/snow10](https://github.com/beardog108/snow10) 
- [**22**星][2y] [C] [h3xx/jphs](https://github.com/h3xx/jphs) 






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
- [**1501**星][2y] [Py] [eldraco/domain_analyzer](https://github.com/eldraco/domain_analyzer) 通过查找所有能够查找的信息，来分析任意域名的安全性
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
- [**857**星][3y] [bastilleresearch/mousejack](https://github.com/bastilleresearch/mousejack) 
- [**851**星][7m] [Py] [s0md3v/recondog](https://github.com/s0md3v/ReconDog) 
- [**818**星][6y] [Py] [ilektrojohn/creepy](https://github.com/ilektrojohn/creepy) 
- [**781**星][2y] [Shell] [screetsec/dracnmap](https://github.com/screetsec/dracnmap) 
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
- [**461**星][2y] [Py] [dchrastil/scrapedin](https://github.com/dchrastil/scrapedin) 
- [**453**星][5y] [pyrotek3/powershell-ad-recon](https://github.com/pyrotek3/powershell-ad-recon) 
- [**417**星][2m] [Py] [superhedgy/attacksurfacemapper](https://github.com/superhedgy/attacksurfacemapper) 
- [**404**星][4m] [Shell] [d4rk007/redghost](https://github.com/d4rk007/redghost) 
- [**393**星][6y] [Py] [milo2012/osintstalker](https://github.com/milo2012/osintstalker) 
- [**388**星][3m] [Go] [graniet/operative-framework](https://github.com/graniet/operative-framework) 
- [**387**星][12m] [Py] [chrismaddalena/odin](https://github.com/chrismaddalena/odin) 
- [**378**星][2m] [ph055a/osint-collection](https://github.com/ph055a/osint-collection) 
- [**370**星][2y] [PowerShell] [xorrior/remoterecon](https://github.com/xorrior/remoterecon) 
- [**362**星][1m] [Py] [dedsecinside/torbot](https://github.com/dedsecinside/torbot) 
- [**350**星][11m] [Py] [aancw/belati](https://github.com/aancw/belati) 
- [**350**星][18d] [Py] [depthsecurity/armory](https://github.com/depthsecurity/armory) 
- [**335**星][1m] [Py] [darryllane/bluto](https://github.com/darryllane/bluto) 
- [**332**星][2y] [Ruby] [jobertabma/virtual-host-discovery](https://github.com/jobertabma/virtual-host-discovery) virtual-host-discovery：枚举服务器上的虚拟主机（Ruby脚本）
- [**329**星][11m] [Py] [mdsecactivebreach/linkedint](https://github.com/mdsecactivebreach/linkedint) A LinkedIn scraper for reconnaissance during adversary simulation
- [**320**星][5m] [Go] [nhoya/gosint](https://github.com/nhoya/gosint) 
- [**304**星][4m] [Py] [initstring/linkedin2username](https://github.com/initstring/linkedin2username) Generate username lists for companies on LinkedIn
- [**303**星][3y] [Ruby] [michenriksen/birdwatcher](https://github.com/michenriksen/birdwatcher) 
- [**302**星][1y] [Py] [sharadkumar97/osint-spy](https://github.com/sharadkumar97/osint-spy) 
- [**299**星][1y] [Py] [twelvesec/gasmask](https://github.com/twelvesec/gasmask) 
- [**296**星][11m] [Py] [r3vn/badkarma](https://github.com/r3vn/badkarma) 
- [**289**星][6m] [Shell] [eschultze/urlextractor](https://github.com/eschultze/urlextractor) 
- [**284**星][2m] [JS] [pownjs/pown-recon](https://github.com/pownjs/pown-recon) 
- [**279**星][1y] [Shell] [ha71/namechk](https://github.com/ha71/namechk) 
- [**278**星][2y] [Shell] [jobertabma/recon.sh](https://github.com/jobertabma/recon.sh) 跟踪,识别和存储侦查(reconnaissance)工具的输出
- [**268**星][1y] [Go] [tomsteele/blacksheepwall](https://github.com/tomsteele/blacksheepwall) 
- [**267**星][2y] [ivmachiavelli/osint_team_links](https://github.com/ivmachiavelli/osint_team_links) 
- [**267**星][1y] [Py] [rassec/pentester-fully-automatic-scanner](https://github.com/rassec/pentester-fully-automatic-scanner) 
    - 重复区段: [工具/扫描器&&安全扫描&&App扫描&&漏洞扫描/未分类-Scanner](#de63a029bda6a7e429af272f291bb769) |
- [**264**星][2m] [Py] [ekultek/whatbreach](https://github.com/ekultek/whatbreach) 
- [**253**星][2y] [Py] [rolisoft/reconscan](https://github.com/rolisoft/reconscan) 
- [**253**星][4y] [Py] [smaash/snitch](https://github.com/smaash/snitch) 
- [**242**星][2m] [Shell] [solomonsklash/chomp-scan](https://github.com/solomonsklash/chomp-scan) 
- [**238**星][2y] [PowerShell] [dafthack/hostrecon](https://github.com/dafthack/hostrecon) 
- [**236**星][13d] [Py] [zephrfish/googd0rker](https://github.com/zephrfish/googd0rker) 
- [**229**星][7m] [JS] [cliqz-oss/local-sheriff](https://github.com/cliqz-oss/local-sheriff) 
- [**229**星][1m] [Propeller Spin] [grandideastudio/jtagulator](https://github.com/grandideastudio/jtagulator) Assisted discovery of on-chip debug interfaces
- [**227**星][1m] [Py] [sc1341/instagramosint](https://github.com/sc1341/instagramosint) 
- [**225**星][1m] [Py] [anon-exploiter/sitebroker](https://github.com/anon-exploiter/sitebroker) 
- [**224**星][3y] [Py] [az0ne/github_nuggests](https://github.com/az0ne/github_nuggests) 
- [**223**星][2y] [Py] [automatingosint/osint_public](https://github.com/automatingosint/osint_public) 
- [**220**星][3m] [Py] [thewhiteh4t/finalrecon](https://github.com/thewhiteh4t/finalrecon) 
- [**220**星][13d] [PowerShell] [tonyphipps/meerkat](https://github.com/tonyphipps/meerkat) 
- [**219**星][3m] [Py] [eth0izzle/the-endorser](https://github.com/eth0izzle/the-endorser) 
- [**218**星][1y] [Shell] [edoverflow/megplus](https://github.com/edoverflow/megplus) 
- [**217**星][1y] [Py] [003random/003recon](https://github.com/003random/003recon) 
- [**214**星][3y] [Py] [darryllane/bluto-old](https://github.com/darryllane/bluto-old) 
- [**212**星][2y] [Py] [famavott/osint-scraper](https://github.com/famavott/osint-scraper) 输入人名或邮箱地址, 自动从互联网爬取关于此人的信息
- [**210**星][4m] [Py] [spiderlabs/hosthunter](https://github.com/spiderlabs/hosthunter) 
- [**191**星][19d] [Shell] [x1mdev/reconpi](https://github.com/x1mdev/reconpi) 
- [**188**星][2m] [Py] [alainiamburg/sniffrom](https://github.com/alainiamburg/sniffrom) 
- [**186**星][9m] [hannoch/scaner](https://github.com/hannoch/scaner) 开源扫描器的集合，包括子域枚举、数据库漏洞扫描器、弱密码或信息泄漏扫描器、端口扫描器、指纹扫描器以及其他大规模扫描仪、模块扫描器等。对于其他著名的扫描工具，如：awvs、nmap，w3af将不包含在集合范围内。
- [**185**星][2y] [Go] [woj-ciech/osint](https://github.com/woj-ciech/osint) 
- [**185**星][3y] [Py] [xyntax/filesensor](https://github.com/xyntax/filesensor) 基于爬虫的动态敏感文件探测工具
- [**182**星][3m] [Py] [j3ssie/iposint](https://github.com/j3ssie/iposint) 
- [**182**星][28d] [TypeScript] [ninoseki/mitaka](https://github.com/ninoseki/mitaka) 
- [**179**星][4m] [Py] [abdulgaphy/r3con1z3r](https://github.com/abdulgaphy/r3con1z3r) 
- [**179**星][1y] [C] [ehsahil/recon-my-way](https://github.com/ehsahil/recon-my-way) 
- [**179**星][6m] [Py] [lijiejie/idea_exploit](https://github.com/lijiejie/idea_exploit) 
- [**179**星][4m] [Py] [sham00n/buster](https://github.com/sham00n/buster) 
- [**178**星][6m] [C++] [arsenalrecon/arsenal-image-mounter](https://github.com/arsenalrecon/arsenal-image-mounter) 
- [**176**星][4y] [Go] [jrozner/sonar](https://github.com/jrozner/sonar) 
- [**176**星][4m] [Py] [s0md3v/orbit](https://github.com/s0md3v/orbit) 
- [**175**星][2m] [Py] [mschwager/gitem](https://github.com/mschwager/gitem) 
- [**173**星][2y] [PowerShell] [fsecurelabs/azurite](https://github.com/FSecureLABS/Azurite) 
    - 重复区段: [工具/特定目标/Azure](#786201db0bcc40fdf486cee406fdad31) |
- [**172**星][5m] [Shell] [silverpoision/rock-on](https://github.com/silverpoision/rock-on) 
- [**170**星][1y] [Py] [vergl4s/instarecon](https://github.com/vergl4s/instarecon) 
- [**169**星][19d] [Shell] [edoverflow/contact.sh](https://github.com/edoverflow/contact.sh) 
- [**168**星][4m] [Shell] [ginjachris/pentmenu](https://github.com/ginjachris/pentmenu) 
- [**166**星][6m] [Py] [yassineaboukir/asnlookup](https://github.com/yassineaboukir/asnlookup) 
- [**163**星][8m] [Py] [githacktools/billcipher](https://github.com/githacktools/billcipher) 
- [**162**星][3y] [Standard ML] [gamelinux/prads](https://github.com/gamelinux/prads) 
- [**160**星][2m] [Py] [martinvigo/email2phonenumber](https://github.com/martinvigo/email2phonenumber) 
- [**157**星][9m] [Shell] [nullarray/intrec-pack](https://github.com/nullarray/intrec-pack) 
- [**156**星][2y] [Py] [galkan/flashlight](https://github.com/galkan/flashlight) 
- [**156**星][4m] [Py] [itsmehacker/darkscrape](https://github.com/itsmehacker/darkscrape) 
- [**151**星][8m] [Shell] [viralmaniar/i-see-you](https://github.com/viralmaniar/i-see-you) 
- [**150**星][5m] [Py] [leunammejii/osweep](https://github.com/ecstatic-nobel/OSweep) 
- [**141**星][5y] [PHP] [veerupandey/penetration-testing-toolkit](https://github.com/veerupandey/penetration-testing-toolkit) 
    - 重复区段: [工具/扫描器&&安全扫描&&App扫描&&漏洞扫描/未分类-Scanner](#de63a029bda6a7e429af272f291bb769) |
- [**137**星][6y] [Py] [jezdez/django-discover-runner](https://github.com/jezdez/django-discover-runner) 
- [**135**星][7m] [Py] [dvopsway/datasploit](https://github.com/dvopsway/datasploit) 
- [**132**星][10m] [Ruby] [bahaabdelwahed/killshot](https://github.com/bahaabdelwahed/killshot) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |[工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞扫描&&挖掘&&发现/漏洞扫描/未分类](#0ed7e90d216a8a5be1dafebaf9eaeb5d) |
- [**131**星][2y] [Py] [bharshbarger/autosint](https://github.com/bharshbarger/autosint) 
- [**125**星][2m] [Py] [batuhaniskr/twitter-intelligence](https://github.com/batuhaniskr/twitter-intelligence) 
- [**120**星][25d] [Py] [initstring/cloud_enum](https://github.com/initstring/cloud_enum) 
- [**115**星][2y] [Py] [penafieljlm/inquisitor](https://github.com/penafieljlm/inquisitor) 
- [**113**星][12m] [Py] [realsanjay/domainrecon](https://github.com/realsanjay/DomainRecon) 
- [**108**星][3y] [Py] [jmortega/osint_tools_security_auditing](https://github.com/jmortega/osint_tools_security_auditing) 
- [**106**星][2y] [Shell] [b3rito/yotter](https://github.com/b3rito/yotter) Bash 脚本, 执行侦察，然后使用 dirb 发现可能导致信息泄露的目录
- [**105**星][3m] [PHP] [radenvodka/recsech](https://github.com/radenvodka/recsech) 
- [**105**星][1m] [C++] [outflanknl/recon-ad](https://github.com/outflanknl/recon-ad) 
- [**104**星][8m] [webbreacher/orcs](https://github.com/webbreacher/orcs) 
- [**103**星][4y] [Py] [tripwire/tardis](https://github.com/tripwire/tardis) 
    - 重复区段: [工具/威胁情报/未分类-ThreatIntelligence](#8fd1f0cfde78168c88fc448af9c6f20f) |
- [**102**星][3m] [Go] [twistlock/cloud-discovery](https://github.com/twistlock/cloud-discovery) 
- [**98**星][4y] [C] [ionescu007/hookingnirvana](https://github.com/ionescu007/hookingnirvana) 
- [**95**星][27d] [Py] [sandialabs/dr_robot](https://github.com/sandialabs/dr_robot) 
- [**93**星][1y] [Shell] [cyb0r9/quasar](https://github.com/Cyb0r9/quasar) An Information Gathering Framework For Lazy Penetration Testers
- [**92**星][12m] [reconjson/reconjson](https://github.com/reconjson/reconjson) 
- [**89**星][4m] [Py] [itsmehacker/cardpwn](https://github.com/itsmehacker/cardpwn) 
- [**88**星][1m] [Shell] [greycatz/cloudunflare](https://github.com/greycatz/cloudunflare) 
- [**84**星][4y] [Py] [danmcinerney/fast-recon](https://github.com/danmcinerney/fast-recon) 
- [**83**星][2y] [Py] [sensepost/birp](https://github.com/sensepost/birp) 
- [**83**星][1y] [Py] [viralmaniar/smwyg-show-me-what-you-got](https://github.com/viralmaniar/smwyg-show-me-what-you-got) 
- [**80**星][3m] [CSS] [pielco11/doge](https://github.com/pielco11/doge) 
- [**79**星][9m] [Shell] [naltun/eyes.sh](https://github.com/naltun/eyes.sh) 
- [**77**星][10m] [Py] [nullarray/mimir](https://github.com/nullarray/mimir) 
- [**76**星][2m] [Ruby] [r00t-3xp10it/resource_files](https://github.com/r00t-3xp10it/resource_files) 
- [**74**星][5m] [Py] [netevert/pockint](https://github.com/netevert/pockint) 
- [**74**星][1y] [Py] [pielco11/dot](https://github.com/pielco11/dot) 
- [**66**星][8m] [Visual Basic] [visualbasic6/chatter](https://github.com/visualbasic6/chatter) 
- [**62**星][2y] [Py] [vysecurity/maiint](https://github.com/vysecurity/MaiInt) 
- [**58**星][2y] [Shell] [offxec/samurai](https://github.com/OffXec/Samurai) 
- [**53**星][28d] [Py] [highmeh/lure](https://github.com/highmeh/lure) 
- [**52**星][5m] [Shell] [cignoraptor-ita/cignotrack](https://github.com/cignoraptor-ita/cignotrack) 
- [**52**星][2y] [Py] [shaanen/osint-combiner](https://github.com/shaanen/osint-combiner) 
- [**48**星][2m] [netstalking-core/netstalking-osint](https://github.com/netstalking-core/netstalking-osint) 
- [**48**星][10m] [sourcingdenis/free-online-competitive-intelligence](https://github.com/sourcingdenis/free-online-competitive-intelligence) 
- [**47**星][8m] [CSS] [appsecco/using-docker-kubernetes-for-automating-appsec-and-osint-workflows](https://github.com/appsecco/using-docker-kubernetes-for-automating-appsec-and-osint-workflows) 
- [**47**星][5m] [sekhan/nightpi](https://github.com/sekhan/nightpi) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |
- [**43**星][8m] [Py] [chriswmorris/metaforge](https://github.com/chriswmorris/metaforge) 
- [**43**星][3y] [Py] [xyntax/drystan](https://github.com/xyntax/drystan) 
- [**41**星][14d] [Py] [entynetproject/geospy](https://github.com/entynetproject/geospy) 
- [**41**星][2y] [Py] [ntddk/virustream](https://github.com/ntddk/virustream) 
- [**40**星][2y] [C] [gamelinux/cxtracker](https://github.com/gamelinux/cxtracker) 
- [**36**星][15d] [Py] [agrawalsmart7/autorecon](https://github.com/agrawalsmart7/autorecon) 自动化渗透初期的一些手动工作，是我们可专注于主要目标
- [**33**星][4m] [HTML] [adulau/misp-osint-collection](https://github.com/adulau/misp-osint-collection) 
- [**32**星][10m] [CSS] [appsecco/practical-recon-levelup0x02](https://github.com/appsecco/practical-recon-levelup0x02) 
- [**32**星][1y] [C] [dlrobertson/sylkie](https://github.com/dlrobertson/sylkie) sylkie：利用 NeighborDiscovery Protocol 实现的 IPv6 地址欺骗工具
- [**31**星][1y] [Py] [003random/icu](https://github.com/003random/icu) 
- [**30**星][3y] [Py] [emersonelectricco/boomerang](https://github.com/emersonelectricco/boomerang) 
- [**30**星][1y] [HTML] [p3t3rp4rk3r/my_dirty_scripts](https://github.com/p3t3rp4rk3r/my_dirty_scripts) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |
- [**28**星][3y] [Py] [baltimorechad/pyonionscan](https://github.com/baltimorechad/pyonionscan) 
- [**28**星][5m] [oldbonhart/osint-resources](https://github.com/oldbonhart/osint-resources) 
- [**27**星][2y] [JS] [anandtiwarics/datasploit](https://github.com/anandtiwarics/datasploit) 
- [**27**星][2y] [Ruby] [stebbins/strigil](https://github.com/stebbins/strigil) 
- [**22**星][29d] [TypeScript] [kennbroorg/iky](https://github.com/kennbroorg/iky) 
- [**21**星][2y] [ivmachiavelli/osint_opendata](https://github.com/ivmachiavelli/osint_opendata) 
- [**21**星][24d] [Py] [saeeddhqan/maryam](https://github.com/saeeddhqan/maryam) Open-source Intelligence(OSINT) Framework
- [**13**星][4m] [JS] [david3107/squatm3gator](https://github.com/david3107/squatm3gator) 


### <a id="e945721056c78a53003e01c3d2f3b8fe"></a>子域名枚举&&爆破


- [**4008**星][1m] [Py] [aboul3la/sublist3r](https://github.com/aboul3la/sublist3r) 
- [**3147**星][15d] [Py] [laramies/theharvester](https://github.com/laramies/theharvester) 
- [**2981**星][6m] [Go] [michenriksen/aquatone](https://github.com/michenriksen/aquatone) 子域名枚举工具。除了经典的爆破枚举之外，还利用多种开源工具和在线服务大幅度增加发现子域名的数量。
- [**2246**星][3y] [Py] [therook/subbrute](https://github.com/therook/subbrute) 
- [**1750**星][6m] [Py] [lijiejie/subdomainsbrute](https://github.com/lijiejie/subdomainsbrute) 子域名爆破
- [**1686**星][1m] [Go] [subfinder/subfinder](https://github.com/subfinder/subfinder) 使用Passive Sources, Search Engines, Pastebins, Internet Archives等查找子域名
- [**1668**星][7m] [Py] [guelfoweb/knock](https://github.com/guelfoweb/knock) 使用 Wordlist 枚举子域名
    - 重复区段: [工具/wordlist/未分类-wordlist](#af1d71122d601229dc4aa9d08f4e3e15) |
- [**1555**星][14d] [Go] [caffix/amass](https://github.com/caffix/amass) 子域名枚举, 搜索互联网数据源, 使用机器学习猜测子域名. Go语言
- [**1087**星][1m] [Py] [john-kurkowski/tldextract](https://github.com/john-kurkowski/tldextract) 
- [**1071**星][2y] [Py] [ring04h/wydomain](https://github.com/ring04h/wydomain) 
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
- [**184**星][1y] [Py] [ak1t4/open-redirect-scanner](https://github.com/ak1t4/open-redirect-scanner) open-redirect-scanner：open redirect subdomains scanner
- [**182**星][8m] [Py] [m4ll0k/takeover](https://github.com/m4ll0k/takeover) 子域名漏洞扫描器
- [**156**星][2m] [Py] [gnebbia/pdlist](https://github.com/gnebbia/pdlist) 
- [**151**星][2m] [Go] [lukasikic/subzy](https://github.com/lukasikic/subzy) 
- [**144**星][5m] [Py] [nashcontrol/bounty-monitor](https://github.com/nashcontrol/bounty-monitor) 
- [**139**星][2m] [Py] [antichown/subdomain-takeover](https://github.com/antichown/subdomain-takeover) 
- [**139**星][2y] [Py] [we5ter/gsdf](https://github.com/We5ter/GSDF) 基于谷歌SSL透明证书的子域名查询工具
- [**134**星][28d] [Py] [m8r0wn/subscraper](https://github.com/m8r0wn/subscraper) 
- [**122**星][2y] [CSS] [0xbug/orangescan](https://github.com/0xbug/orangescan) 
- [**111**星][10m] [Py] [plazmaz/sublist3r](https://github.com/plazmaz/sublist3r) 
- [**104**星][2y] [Go] [mhmdiaa/second-order](https://github.com/mhmdiaa/second-order) 爬取web app, 收集 URL, 扫描second-order 子域名接管
- [**100**星][6m] [Py] [janniskirschner/horn3t](https://github.com/janniskirschner/horn3t) 
- [**94**星][5y] [Py] [le4f/dnsmaper](https://github.com/le4f/dnsmaper) 
- [**94**星][7y] [C] [m0nad/dns-discovery](https://github.com/m0nad/dns-discovery) 
- [**88**星][2m] [Py] [si9int/acamar](https://github.com/si9int/acamar) 
- [**84**星][11m] [Py] [0xbharath/censys-enumeration](https://github.com/0xbharath/censys-enumeration) 
- [**81**星][2m] [Py] [fleetcaptain/turbolist3r](https://github.com/fleetcaptain/turbolist3r) 
- [**80**星][2y] [Py] [coco413/discoversubdomain](https://github.com/coco413/discoversubdomain) 
- [**78**星][1y] [Py] [sawzeeyy/sanitiz3r](https://github.com/sawzeeyy/sanitiz3r) 
- [**74**星][4y] [Shell] [rossmairm/pentools](https://github.com/rossmairm/pentools) 
- [**70**星][2y] [Py] [nmalcolm/inventus](https://github.com/nmalcolm/inventus) 
- [**69**星][5y] [Py] [el3ct71k/subdomain-analyzer](https://github.com/el3ct71k/subdomain-analyzer) 
- [**69**星][10m] [Py] [viperbluff/portwitness](https://github.com/viperbluff/portwitness) 
- [**63**星][1y] [Shell] [samhaxr/takeover-v1](https://github.com/samhaxr/takeover-v1) 
- [**63**星][1y] [Py] [avicoder/spoodle](https://github.com/avicoder/spoodle) spoodle：大规模子域名及 poodle漏洞扫描器
- [**58**星][3m] [Py] [simplysecurity/simplydomain](https://github.com/simplysecurity/simplydomain) 
- [**56**星][2y] [Py] [bonkc/bugbountysubdomains](https://github.com/bonkc/bugbountysubdomains) 
- [**56**星][9m] [Py] [leoid/b1tmass](https://github.com/leoid/b1tmass) 
- [**54**星][1y] [cujanovic/subdomain-bruteforce-list](https://github.com/cujanovic/subdomain-bruteforce-list) 
- [**51**星][1m] [Shell] [cihanmehmet/sub.sh](https://github.com/cihanmehmet/sub.sh) 
- [**45**星][2y] [Py] [n4xh4ck5/n4xd0rk](https://github.com/n4xh4ck5/n4xd0rk) 
- [**44**星][2y] [PHP] [nkkollaw/reserved-subdomains](https://github.com/nkkollaw/reserved-subdomains) 
- [**39**星][3y] [Py] [xiphosresearch/dnsbrute](https://github.com/xiphosresearch/dnsbrute) 
- [**38**星][1y] [Py] [tanc7/arms-commander](https://github.com/tanc7/arms-commander) 
- [**35**星][8m] [Go] [netevert/delator](https://github.com/netevert/delator) 
- [**35**星][8m] [Visual Basic] [visualbasic6/subdomain-bruteforce](https://github.com/visualbasic6/subdomain-bruteforce) 
- [**28**星][5y] [Py] [zombiesam/wikigen](https://github.com/zombiesam/wikigen) 
- [**27**星][4m] [Py] [n4xh4ck5/v1d0m](https://github.com/n4xh4ck5/v1d0m) 
- [**26**星][27d] [Py] [starnightcyber/findsubdomains](https://github.com/starnightcyber/findsubdomains) 
- [**25**星][4m] [Py] [initroot/fransrecon](https://github.com/initroot/fransrecon) 
- [**24**星][1y] [Py] [si9int/screenshooter](https://github.com/si9int/screenshooter) 
- [**22**星][1y] [Py] [buckhacker/subdomaintakeovertools](https://github.com/buckhacker/subdomaintakeovertools) 
- [**22**星][4y] [Py] [cleveridge/cleveridge-subdomain-scanner](https://github.com/cleveridge/cleveridge-subdomain-scanner) 
- [**22**星][25d] [Go] [hahwul/ras-fuzzer](https://github.com/hahwul/ras-fuzzer) 


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
- [**1098**星][3y] [C] [xroche/httrack](https://github.com/xroche/httrack) download a World Wide website from the Internet to a local directory, building recursively all directories, getting html, images, and other files from the server to your computer.
- [**659**星][2y] [Py] [jhaddix/domain](https://github.com/jhaddix/domain) 
- [**619**星][29d] [Py] [tib3rius/autorecon](https://github.com/tib3rius/autorecon) 
- [**510**星][9m] [Py] [fortynorthsecurity/just-metadata](https://github.com/FortyNorthSecurity/Just-Metadata) 
- [**453**星][19d] [Py] [yassineaboukir/sublert](https://github.com/yassineaboukir/sublert) 
- [**388**星][10m] [Swift] [ibm/mac-ibm-enrollment-app](https://github.com/ibm/mac-ibm-enrollment-app) 
- [**349**星][4m] [C++] [wbenny/pdbex](https://github.com/wbenny/pdbex) 
- [**343**星][27d] [Py] [lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng) 
- [**283**星][2m] [Py] [govanguard/legion](https://github.com/govanguard/legion) 
- [**269**星][10m] [Py] [LaNMaSteR53/recon-ng](https://bitbucket.org/lanmaster53/recon-ng) 
- [**185**星][3m] [Py] [ex0dus-0x/doxbox](https://github.com/ex0dus-0x/doxbox) 
- [**184**星][3y] [PowerShell] [sekirkity/browsergather](https://github.com/sekirkity/browsergather) 
- [**167**星][2y] [HTML] [ihebski/angryfuzzer](https://github.com/ihebski/angryfuzzer) 
- [**152**星][1y] [Py] [ultrasecurity/webkiller](https://github.com/ultrasecurity/webkiller) 多功能渗透测试辅助脚本
- [**150**星][1m] [Py] [richiercyrus/venator](https://github.com/richiercyrus/venator) 
- [**143**星][1y] [Py] [viralmaniar/remote-desktop-caching-](https://github.com/viralmaniar/remote-desktop-caching-) 
- [**137**星][7m] [Py] [giovanifss/gitmails](https://github.com/giovanifss/gitmails) 
- [**125**星][2y] [Py] [opensourcesec/forager](https://github.com/opensourcesec/Forager) 
- [**121**星][2m] [Py] [decoxviii/userrecon-py](https://github.com/decoxviii/userrecon-py) 
- [**120**星][6m] [PowerShell] [nyxgeek/o365recon](https://github.com/nyxgeek/o365recon) o365recon：PowerShell脚本，使用单个 cred 来转储完整的 o365 用户列表，组列表和组成员
- [**114**星][9m] [Shell] [capt-meelo/lazyrecon](https://github.com/capt-meelo/lazyrecon) 
- [**114**星][2y] [Py] [williballenthin/process-forest](https://github.com/williballenthin/process-forest) 
- [**111**星][2y] [Perl] [raikia/smbcrunch](https://github.com/raikia/smbcrunch) 
- [**107**星][7m] [Shell] [rpranshu/eternalview](https://github.com/rpranshu/eternalview) 
- [**102**星][2y] [Py] [blindfuzzy/lhf](https://github.com/blindfuzzy/lhf) 
- [**100**星][3y] [C] [jndok/iokit-dumper-arm64](https://github.com/jndok/iokit-dumper-arm64) 
- [**92**星][10m] [Py] [tijme/not-your-average-web-crawler](https://github.com/tijme/not-your-average-web-crawler) 
- [**89**星][5m] [Go] [devanshbatham/gorecon](https://github.com/devanshbatham/gorecon) 
- [**87**星][19d] [Py] [0xprateek/stardox](https://github.com/0xprateek/stardox) 
- [**85**星][1y] [Shell] [thelinuxchoice/infog](https://github.com/thelinuxchoice/infog) 
- [**83**星][5y] [Py] [bwall/ircsnapshot](https://github.com/bwall/ircsnapshot) 
- [**75**星][6m] [Py] [abaykan/53r3n17y](https://github.com/abaykan/53r3n17y) 
- [**73**星][5y] [C] [cooloppo/reclass](https://github.com/cooloppo/reclass) 
- [**72**星][4m] [Py] [clirimemini/keye](https://github.com/clirimemini/keye) 
- [**62**星][25d] [Shell] [joshuamart/autorecon](https://github.com/joshuamart/autorecon) 
- [**56**星][4y] [Py] [rehints/blackhat_2015](https://github.com/rehints/blackhat_2015) 
- [**54**星][3y] [Py] [chadillac/mdns_recon](https://github.com/chadillac/mdns_recon) 
- [**54**星][4y] [Py] [nnewsom/webbies](https://github.com/nnewsom/webbies) 
- [**54**星][5m] [PowerShell] [tasox/logrm](https://github.com/tasox/logrm) 
- [**48**星][3y] [Shell] [danielmiessler/honeycrediptracker](https://github.com/danielmiessler/honeycrediptracker) 
- [**48**星][7m] [JS] [tuhinshubhra/wpintel](https://github.com/tuhinshubhra/wpintel) 
- [**46**星][1y] [C] [jthuraisamy/dirt](https://github.com/jthuraisamy/dirt) 
- [**46**星][6m] [jaxbcd/recscansec](https://github.com/jaxBCD/RecScanSec) 
- [**44**星][5m] [HTML] [adrecon/adrecon](https://github.com/adrecon/adrecon) 
- [**43**星][2m] [Py] [cleanunicorn/theo](https://github.com/cleanunicorn/theo) 
- [**43**星][3y] [Py] [hewlettpackard/reconbf](https://github.com/hewlettpackard/reconbf) 
- [**39**星][2y] [Py] [danmcinerney/smb-reverse-brute](https://github.com/danmcinerney/smb-reverse-brute) 
- [**38**星][1m] [Dockerfile] [crytic/eth-security-toolbox](https://github.com/crytic/eth-security-toolbox) 
- [**37**星][3y] [HTML] [mortenschenk/rtlcapturecontext-cfg-bypass](https://github.com/mortenschenk/rtlcapturecontext-cfg-bypass) 
- [**37**星][4m] [Shell] [plenumlab/lazyrecon](https://github.com/plenumlab/lazyrecon) 
- [**33**星][5y] [PHP] [smaash/kunai](https://github.com/smaash/kunai) 
- [**31**星][1y] [Py] [righettod/owasp-cs-book](https://github.com/righettod/owasp-cs-book) 
- [**30**星][3y] [Py] [tengzhangchao/information](https://github.com/tengzhangchao/information) 
- [**28**星][2y] [Shell] [0utrider/malrecon](https://github.com/0utrider/malrecon) malrecon：基本的恶意代码检测和分析工具，Shell 编写
- [**28**星][3y] [Py] [deadbits/arcreactor](https://github.com/deadbits/arcreactor) 
- [**28**星][8m] [Batchfile] [vanhauser-thc/audit_scripts](https://github.com/vanhauser-thc/audit_scripts) 
- [**27**星][2y] [Py] [netspi/jig](https://github.com/netspi/jig) 
- [**23**星][1y] [ActionScript] [ga1ois/recon-2018-montreal](https://github.com/ga1ois/recon-2018-montreal) 
- [**23**星][3y] [Py] [german-namestnikov/unhidens](https://github.com/german-namestnikov/unhidens) 
- [**23**星][21d] [Py] [thehairyj/scout](https://github.com/thehairyj/scout) 
- [**21**星][6m] [Py] [joda32/certcrunchy](https://github.com/joda32/certcrunchy) 


### <a id="016bb6bd00f1e0f8451f779fe09766db"></a>指纹&&Fingerprinting


- [**8843**星][13d] [JS] [valve/fingerprintjs2](https://github.com/valve/fingerprintjs2) 
- [**3671**星][2y] [JS] [samyk/evercookie](https://github.com/samyk/evercookie) JavaScript API，在浏览器中创建超级顽固的cookie，在标准Cookie、Flask Cookie等被清除之后依然能够识别客户端
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/后渗透/未分类-post-exp](#12abc279c69d1fcf10692b9cb89bcdf7) |
- [**3230**星][2y] [CSS] [jbtronics/crookedstylesheets](https://github.com/jbtronics/crookedstylesheets) 使用纯CSS收集网页/用户信息
- [**3029**星][1m] [JS] [valve/fingerprintjs](https://github.com/valve/fingerprintjs) 
- [**1595**星][14d] [JS] [ghacksuserjs/ghacks-user.js](https://github.com/ghacksuserjs/ghacks-user.js) 
- [**1595**星][9m] [C] [nmikhailov/validity90](https://github.com/nmikhailov/validity90) 
- [**1153**星][6y] [PHP] [lucb1e/cookielesscookies](https://github.com/lucb1e/cookielesscookies) 
- [**1011**星][2y] [JS] [umpox/zero-width-detection](https://github.com/umpox/zero-width-detection) Fingerprinting小技巧
- [**918**星][7m] [JS] [song-li/cross_browser](https://github.com/song-li/cross_browser) 
- [**783**星][1m] [Py] [salesforce/ja3](https://github.com/salesforce/ja3) SSL/TLS 客户端指纹，用于恶意代码检测
- [**456**星][4y] [JS] [ghostwords/chameleon](https://github.com/ghostwords/chameleon) 
- [**393**星][2y] [JS] [chpmrc/zero-width-chrome-extension](https://github.com/chpmrc/zero-width-chrome-extension) Chrome扩展, 将网页中可用于Fingerprinting的"零长度"字符替换为搞笑的表情
- [**372**星][21d] [Py] [0x4d31/fatt](https://github.com/0x4d31/fatt) 
- [**309**星][2m] [Py] [dpwe/audfprint](https://github.com/dpwe/audfprint) 
- [**305**星][3m] [Py] [salesforce/hassh](https://github.com/salesforce/hassh) 
- [**268**星][1y] [CSS] [w-digital-scanner/w11scan](https://github.com/w-digital-scanner/w11scan) 
- [**240**星][2m] [C] [leebrotherston/tls-fingerprinting](https://github.com/leebrotherston/tls-fingerprinting) 
- [**224**星][2m] [GLSL] [westpointltd/tls_prober](https://github.com/westpointltd/tls_prober) 
- [**223**星][2y] [Go] [vedhavyas/zwfp](https://github.com/vedhavyas/zwfp) 
- [**212**星][1y] [Py] [sensepost/spartan](https://github.com/sensepost/spartan) 
- [**200**星][1y] [Erlang] [kudelskisecurity/scannerl](https://github.com/kudelskisecurity/scannerl) scannerl：模块化、分布式指纹识别引擎，在单个主机运行即可扫描数千目标，也可轻松的部署到多台主机
- [**185**星][19d] [Ruby] [erwanlr/fingerprinter](https://github.com/erwanlr/fingerprinter) 
- [**178**星][7m] [lucifer1993/cmsprint](https://github.com/lucifer1993/cmsprint) 
- [**172**星][2y] [Java] [ms0x0/dayu](https://github.com/ms0x0/dayu) 
- [**142**星][4y] [JS] [ben174/hsts-cookie](https://github.com/ben174/hsts-cookie) 
- [**139**星][5y] [PHP] [btoplak/joomla-anti-malware-scan-script--jamss-](https://github.com/btoplak/joomla-anti-malware-scan-script--jamss-) 
- [**124**星][7m] [Go] [l3m0n/whatweb](https://github.com/l3m0n/whatweb) 
- [**123**星][1y] [JS] [jonaslejon/tor-fingerprint](https://github.com/jonaslejon/tor-fingerprint) 
- [**97**星][2m] [TypeScript] [eddyverbruggen/nativescript-fingerprint-auth](https://github.com/eddyverbruggen/nativescript-fingerprint-auth) 
- [**88**星][2y] [Objective-C] [bahome/batouchid](https://github.com/bahome/batouchid) 
- [**83**星][5y] [JS] [kmowery/canvas-fingerprinting](https://github.com/kmowery/canvas-fingerprinting) 
- [**72**星][3y] [Perl] [tanjiti/fingerprint](https://github.com/tanjiti/fingerprint) 
- [**64**星][5y] [Py] [falcon-lnhg/mwebfp](https://github.com/falcon-lnhg/mwebfp) 
- [**57**星][4y] [Ruby] [zombiecraig/c0f](https://github.com/zombiecraig/c0f) 
- [**56**星][11m] [JS] [antoinevastel/fp-collect](https://github.com/antoinevastel/fp-collect) 
- [**46**星][10m] [Py] [engelsjo/raspireader](https://github.com/engelsjo/raspireader) 
- [**46**星][28d] [Py] [cisco/mercury](https://github.com/cisco/mercury) network fingerprinting and packet metadata capture
- [**41**星][3y] [Perl] [wireghoul/lbmap](https://github.com/wireghoul/lbmap) 
- [**38**星][1y] [Py] [csecgroup/wafid](https://github.com/csecgroup/wafid) 
- [**38**星][2m] [Java] [x41sec/beanstack](https://github.com/x41sec/beanstack) 
- [**35**星][5m] [Py] [trylinux/lift](https://github.com/trylinux/lift) 
- [**30**星][2y] [HTML] [plaperdr/fprandom](https://github.com/plaperdr/fprandom) 
- [**26**星][7m] [Py] [plaperdr/blink-docker](https://github.com/plaperdr/blink-docker) 


### <a id="6ea9006a5325dd21d246359329a3ede2"></a>收集


- [**3674**星][15d] [jivoi/awesome-osint](https://github.com/jivoi/awesome-osint) OSINT资源收集


### <a id="dc74ad2dd53aa8c8bf3a3097ad1f12b7"></a>社交网络


#### <a id="de93515e77c0ca100bbf92c83f82dc2a"></a>Twitter


- [**2797**星][21d] [Py] [twintproject/twint](https://github.com/twintproject/twint) 
- [**1242**星][2y] [Py] [vaguileradiaz/tinfoleak](https://github.com/vaguileradiaz/tinfoleak) Twitter 智能分析工具


#### <a id="8d1ae776898748b8249132e822f6c919"></a>Github


- [**4155**星][1y] [Go] [michenriksen/gitrob](https://github.com/michenriksen/gitrob) 查找push到公开的Github repo中的敏感信息
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
- [**1389**星][2y] [JS] [sqren/fb-sleep-stats](https://github.com/sqren/fb-sleep-stats) 使用Facebook追踪用户的睡觉习惯
- [**653**星][1y] [Go] [0x09al/raven](https://github.com/0x09al/raven) 




### <a id="a695111d8e30d645354c414cb27b7843"></a>DNS


- [**3203**星][4y] [C] [shadowsocks/chinadns](https://github.com/shadowsocks/chinadns) 
- [**2421**星][4m] [Go] [oj/gobuster](https://github.com/oj/gobuster) 
- [**2278**星][30d] [Py] [ab77/netflix-proxy](https://github.com/ab77/netflix-proxy) 
- [**2081**星][19d] [Py] [elceef/dnstwist](https://github.com/elceef/dnstwist) 域名置换引擎，用于检测打字错误，网络钓鱼和企业间谍活动
- [**1885**星][27d] [C++] [powerdns/pdns](https://github.com/powerdns/pdns) 
- [**1669**星][3m] [Py] [lgandx/responder](https://github.com/lgandx/responder) 
- [**1117**星][7m] [Py] [darkoperator/dnsrecon](https://github.com/darkoperator/dnsrecon) DNS 枚举脚本
- [**1046**星][3y] [Perl] [samyk/usbdriveby](https://github.com/samyk/usbdriveby) 
- [**1044**星][2m] [Py] [infosec-au/altdns](https://github.com/infosec-au/altdns) 
- [**1039**星][1m] [Go] [nadoo/glider](https://github.com/nadoo/glider) 正向代理，支持若干协议
- [**969**星][6m] [Py] [m57/dnsteal](https://github.com/m57/dnsteal) 
- [**891**星][18d] [Py] [mschwager/fierce](https://github.com/mschwager/fierce) 
- [**877**星][5m] [Py] [m0rtem/cloudfail](https://github.com/m0rtem/cloudfail) 通过错误配置的DNS和老数据库，发现CloudFlare网络后面的隐藏IP
- [**787**星][2y] [Go] [evilsocket/dnssearch](https://github.com/evilsocket/dnssearch) 
- [**743**星][2y] [Go] [pforemski/dingo](https://github.com/pforemski/dingo) 
- [**681**星][1y] [Py] [bugscanteam/dnslog](https://github.com/bugscanteam/dnslog) 监控 DNS 解析记录和 HTTP 访问记录
- [**594**星][7m] [Shell] [cokebar/gfwlist2dnsmasq](https://github.com/cokebar/gfwlist2dnsmasq) 
- [**558**星][6m] [C] [getdnsapi/stubby](https://github.com/getdnsapi/stubby) 
- [**457**星][8m] [C] [cofyc/dnscrypt-wrapper](https://github.com/cofyc/dnscrypt-wrapper) 
- [**429**星][1y] [JS] [brannondorsey/whonow](https://github.com/brannondorsey/whonow) 恶意DNS服务器, 可动态执行DNS重绑定攻击
- [**390**星][3y] [JS] [mandatoryprogrammer/judasdns](https://github.com/mandatoryprogrammer/judasdns) 
- [**360**星][1y] [JS] [brannondorsey/dns-rebind-toolkit](https://github.com/brannondorsey/dns-rebind-toolkit) 
- [**359**星][3m] [JS] [nccgroup/singularity](https://github.com/nccgroup/singularity) 
- [**296**星][5y] [Perl] [fwaeytens/dnsenum](https://github.com/fwaeytens/dnsenum) 
- [**287**星][6y] [Py] [xiaomi-sa/smartdns](https://github.com/xiaomi-sa/smartdns) 
- [**268**星][2y] [C] [taviso/rbndr](https://github.com/taviso/rbndr) 
- [**259**星][11m] [Py] [trycatchhcf/packetwhisper](https://github.com/trycatchhcf/packetwhisper) Stealthily exfiltrate data and defeat attribution using DNS queries and text-based steganography. Avoid the problems associated with typical DNS exfiltration methods. Transfer data between systems without the communicating devices directly connecting to each other or to a common endpoint. No need to control a DNS Name Server.
- [**258**星][2m] [Go] [zmap/zdns](https://github.com/zmap/zdns) 快速DNS查找, 命令行工具
- [**249**星][3m] [C#] [kevin-robertson/inveighzero](https://github.com/kevin-robertson/inveighzero) 
- [**243**星][9m] [Go] [erbbysam/dnsgrep](https://github.com/erbbysam/dnsgrep) 
- [**237**星][25d] [Py] [mandatoryprogrammer/trusttrees](https://github.com/mandatoryprogrammer/trusttrees) a script to recursively follow all the possible delegation paths for a target domain and graph the relationships between various nameservers along the way.
- [**230**星][1m] [Go] [sensepost/godoh](https://github.com/sensepost/godoh)  A DNS-over-HTTPS Command & Control Proof of Concept 
- [**213**星][1y] [PowerShell] [lukebaggett/dnscat2-powershell](https://github.com/lukebaggett/dnscat2-powershell) 
- [**211**星][2y] [Shell] [jakewmeyer/geo](https://github.com/jakewmeyer/geo) A Bash utility for easy wan, lan, router, dns, mac address, and geolocation output,
- [**182**星][4y] [Py] [breenmachine/dnsftp](https://github.com/breenmachine/dnsftp) 
- [**167**星][1y] [JS] [brannondorsey/host-validation](https://github.com/brannondorsey/host-validation) 
- [**167**星][20d] [C] [curl/doh](https://github.com/curl/doh) 
- [**162**星][2y] [Py] [manisso/crips](https://github.com/manisso/crips) 
- [**162**星][5y] [Roff] [opendns/security_ninjas_appsec_training](https://github.com/opendns/security_ninjas_appsec_training) 
- [**151**星][1y] [Ruby] [chrislee35/passivedns-client](https://github.com/chrislee35/passivedns-client) 
- [**145**星][3y] [HTML] [luxiaok/dnsmasqweb](https://github.com/luxiaok/dnsmasqweb) 
- [**144**星][2y] [Py] [mdsecactivebreach/powerdns](https://github.com/mdsecactivebreach/powerdns) Powershell DNS Delivery
- [**142**星][11m] [Go] [justinazoff/bro-pdns](https://github.com/justinazoff/bro-pdns) 
- [**129**星][3m] [Py] [daeken/httprebind](https://github.com/daeken/httprebind) 
- [**79**星][6y] [Py] [corelan/dnshjmon](https://github.com/corelan/dnshjmon) 
- [**78**星][8m] [Go] [subfinder/goaltdns](https://github.com/subfinder/goaltdns) 
- [**70**星][2y] [C] [makefu/dnsmap](https://github.com/makefu/dnsmap) 
- [**57**星][2y] [Go] [linkedin/jaqen](https://github.com/linkedin/jaqen) Simple DNS rebinding
- [**37**星][2m] [C] [dnsdb/dnsdbq](https://github.com/dnsdb/dnsdbq) 
- [**37**星][1y] [Py] [weebsec/weebdns](https://github.com/weebsec/weebdns) 
- [**31**星][3m] [C] [aa65535/chinadns](https://github.com/aa65535/chinadns) 
- [**28**星][1y] [Shell] [themiddleblue/dnsenum](https://github.com/themiddleblue/dnsenum) 
- [**28**星][4y] [Ruby] [praetorian-code/dert](https://github.com/praetorian-code/dert) 
- [**22**星][2y] [Py] [leonardonve/dns2proxy_hsts](https://github.com/leonardonve/dns2proxy_hsts) 
- [**11**星][6m] [Py] [diogo-fernan/domfind](https://github.com/diogo-fernan/domfind) 


### <a id="18c7c1df2e6ae5e9135dfa2e4eb1d4db"></a>Shodan


- [**1082**星][2m] [Py] [achillean/shodan-python](https://github.com/achillean/shodan-python) 
- [**954**星][4m] [Py] [woj-ciech/kamerka](https://github.com/woj-ciech/kamerka) 利用Shodan构建交互式摄像头地图
- [**831**星][2m] [Py] [649/memcrashed-ddos-exploit](https://github.com/649/memcrashed-ddos-exploit) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/DDOS](#a0897294e74a0863ea8b83d11994fad6) |
- [**669**星][2m] [jakejarvis/awesome-shodan-queries](https://github.com/jakejarvis/awesome-shodan-queries) 
- [**353**星][1m] [Py] [pielco11/fav-up](https://github.com/pielco11/fav-up) 
- [**337**星][2m] [Py] [random-robbie/my-shodan-scripts](https://github.com/random-robbie/my-shodan-scripts) 
- [**233**星][10m] [Py] [nethunteros/punter](https://github.com/nethunteros/punter) punter：使用 DNSDumpster, WHOIS, Reverse WHOIS 挖掘域名
- [**195**星][2m] [Py] [shodansploit/shodansploit](https://github.com/shodansploit/shodansploit) 
- [**181**星][3y] [Py] [hatbashbr/shodanhat](https://github.com/hatbashbr/shodanhat) 
- [**161**星][2y] [Py] [6ix7ine/shodanwave](https://github.com/6ix7ine/shodanwave) 
- [**161**星][2y] [Py] [hackatnow/shodanwave](https://github.com/hackatnow/shodanwave) 
- [**140**星][2y] [javierolmedo/shodan-filters](https://github.com/javierolmedo/shodan-filters) 
- [**132**星][1m] [JS] [jesusprubio/shodan-client.js](https://github.com/jesusprubio/shodan-client) 
- [**131**星][2y] [Py] [jlospinoso/memcachedump](https://github.com/jlospinoso/memcachedump) 
- [**117**星][2m] [Go] [ns3777k/go-shodan](https://github.com/ns3777k/go-shodan) 
- [**115**星][6m] [Py] [danmcinerney/device-pharmer](https://github.com/danmcinerney/device-pharmer) 
- [**109**星][2m] [Py] [bullseye0/shodan-eye](https://github.com/bullseye0/shodan-eye) 
- [**88**星][9m] [Py] [0x27/ssh_keyscanner](https://github.com/0x27/ssh_keyscanner) 
- [**69**星][2y] [PHP] [joesmithjaffa/jenkins-shell](https://github.com/joesmithjaffa/jenkins-shell) 
- [**53**星][4y] [Py] [juliocesarfort/netscreen-shodan-scanner](https://github.com/juliocesarfort/netscreen-shodan-scanner) 
- [**47**星][6m] [Ruby] [picatz/shodanz](https://github.com/picatz/shodanz) 
- [**41**星][4m] [Py] [laincode/shodan-seeker](https://github.com/laincode/shodan-seeker) 
- [**41**星][11m] [Py] [zev3n/shodan_so](https://github.com/zev3n/shodan_so) 
- [**40**星][2y] [Java] [fooock/jshodan](https://github.com/fooock/jshodan) 
- [**40**星][12m] [Shell] [mavrepis/shodanvulncheck](https://github.com/mavrepis/shodanvulncheck) 
- [**37**星][4y] [Java] [xyntax/jboss-exp](https://github.com/xyntax/jboss-exp) 
- [**35**星][10m] [Go] [yvesago/shodan-cli](https://github.com/yvesago/shodan-cli) 
- [**32**星][1y] [Ruby] [thesubtlety/shocens](https://github.com/thesubtlety/shocens) 
- [**29**星][8m] [Py] [inishantgrover/shodmon](https://github.com/inishantgrover/shodmon) 
- [**25**星][6y] [C] [kylekirkby/python-exploit-search-tool](https://github.com/kylekirkby/python-exploit-search-tool) 
- [**24**星][1y] [Py] [nullarray/shogun](https://github.com/nullarray/shogun) 
- [**24**星][11m] [Py] [thom-s/shodan-cli](https://github.com/thom-s/shodan-cli) 
- [**22**星][2y] [Py] [adanvillarreal/spydan](https://github.com/adanvillarreal/spydan) 


### <a id="94c01f488096fafc194b9a07f065594c"></a>nmap


- [**3492**星][16d] [C] [nmap/nmap](https://github.com/nmap/nmap) Nmap
- [**2099**星][6m] [Py] [calebmadrigal/trackerjacker](https://github.com/calebmadrigal/trackerjacker) 映射你没连接到的Wifi网络, 类似于NMap, 另外可以追踪设备
- [**1666**星][3m] [Lua] [vulnerscom/nmap-vulners](https://github.com/vulnerscom/nmap-vulners) 
- [**1497**星][2m] [C] [nmap/npcap](https://github.com/nmap/npcap) 
- [**1237**星][2m] [Lua] [scipag/vulscan](https://github.com/scipag/vulscan) vulscan：Nmap 模块，将 Nmap 转化为高级漏洞扫描器
- [**972**星][2y] [Py] [moosedojo/apt2](https://github.com/moosedojo/apt2) 自动化渗透测试工具包。执行NMap扫描, 或者导入Nexpose, Nessus, NMap扫描结果
- [**936**星][4m] [Shell] [trimstray/sandmap](https://github.com/trimstray/sandmap) 使用NMap引擎, 辅助网络和系统侦查(reconnaissance)
- [**887**星][11m] [Py] [rev3rsesecurity/webmap](https://github.com/rev3rsesecurity/webmap) 
- [**822**星][2m] [Py] [x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) brutespray：获取 nmapGNMAP 输出，自动调用 Medusa 使用默认证书爆破服务（brute-forces services）
- [**728**星][4m] [Lua] [cldrn/nmap-nse-scripts](https://github.com/cldrn/nmap-nse-scripts) 
- [**658**星][4m] [Py] [iceyhexman/onlinetools](https://github.com/iceyhexman/onlinetools) 
- [**504**星][1y] [Shell] [superkojiman/onetwopunch](https://github.com/superkojiman/onetwopunch) 
- [**481**星][1y] [XSLT] [honze-net/nmap-bootstrap-xsl](https://github.com/honze-net/nmap-bootstrap-xsl) 
- [**391**星][7m] [Py] [savon-noir/python-libnmap](https://github.com/savon-noir/python-libnmap) 
- [**325**星][9m] [Py] [samhaxr/hackbox](https://github.com/samhaxr/hackbox) 集合了某些Hacking工具和技巧的攻击工具
- [**308**星][2y] [Shell] [milesrichardson/docker-onion-nmap](https://github.com/milesrichardson/docker-onion-nmap) docker-onion-nmap：使用 nmap 扫描 Tor 隐藏网络的Docker 镜像。基于 alpine，使用proxychains 做 nmap 的包装
- [**307**星][1y] [Java] [s4n7h0/halcyon](https://github.com/s4n7h0/halcyon) 
- [**282**星][1y] [Ruby] [danmcinerney/pentest-machine](https://github.com/danmcinerney/pentest-machine) 
- [**267**星][1y] [Py] [rassec/pentester_fully-automatic-scanner](https://github.com/RASSec/RASrecon) 
- [**257**星][1y] [Java] [danicuestasuarez/nmapgui](https://github.com/danicuestasuarez/nmapgui) 
- [**247**星][1y] [Shell] [m4ll0k/autonse](https://github.com/m4ll0k/autonse) 
- [**230**星][7m] [Lua] [rvn0xsy/nse_vuln](https://github.com/rvn0xsy/nse_vuln) 
- [**228**星][5m] [Py] [maaaaz/nmaptocsv](https://github.com/maaaaz/nmaptocsv) 
- [**220**星][2y] [Ruby] [sophsec/ruby-nmap](https://github.com/sophsec/ruby-nmap) 
- [**206**星][2y] [Shell] [johnnyxmas/scancannon](https://github.com/johnnyxmas/scancannon) 
- [**203**星][6y] [Lua] [spiderlabs/nmap-tools](https://github.com/spiderlabs/nmap-tools) 
- [**197**星][1y] [C++] [quarkslab/binmap](https://github.com/quarkslab/binmap) 
- [**188**星][5m] [Py] [hellogoldsnakeman/masnmapscan-v1.0](https://github.com/hellogoldsnakeman/masnmapscan-v1.0) 
- [**184**星][1m] [Py] [rackerlabs/scantron](https://github.com/rackerlabs/scantron) 
- [**182**星][3y] [Py] [cldrn/rainmap-lite](https://github.com/cldrn/rainmap-lite) Web界面,从浏览器中启动Nmap扫描. 界面是响应式, 可在手机/平板/PC浏览器中使用
- [**176**星][4m] [XSLT] [ernw/nmap-parse-output](https://github.com/ernw/nmap-parse-output) 
- [**171**星][1m] [Py] [mrschyte/nmap-converter](https://github.com/mrschyte/nmap-converter) 
- [**168**星][3m] [Lua] [ocsaf/freevulnsearch](https://github.com/ocsaf/freevulnsearch) 
- [**166**星][2y] [Py] [northernsec/cve-scan](https://github.com/northernsec/cve-scan) 
- [**162**星][3y] [Makefile] [kost/nmap-android](https://github.com/kost/nmap-android) 
- [**146**星][3y] [leonjza/awesome-nmap-grep](https://github.com/leonjza/awesome-nmap-grep) 
- [**143**星][6m] [Shell] [petermosmans/security-scripts](https://github.com/petermosmans/security-scripts) 
- [**140**星][1m] [Go] [ullaakut/nmap](https://github.com/ullaakut/nmap) 
- [**133**星][4y] [Shell] [commonexploits/port-scan-automation](https://github.com/commonexploits/port-scan-automation) 
- [**133**星][2m] [Lua] [nnposter/nndefaccts](https://github.com/nnposter/nndefaccts) 
- [**131**星][4y] [Lua] [glennzw/shodan-hq-nse](https://github.com/glennzw/shodan-hq-nse) 
- [**130**星][6m] [TypeScript] [phiresky/nmap-log-parse](https://github.com/phiresky/nmap-log-parse) 
- [**113**星][12m] [Shell] [peterpt/eternal_check](https://github.com/peterpt/eternal_check) 检查指定IP是否有某些SMB漏洞, 比如永恒之蓝. 基于nmap
- [**110**星][6m] [Shell] [leviathan36/trigmap](https://github.com/leviathan36/trigmap) 
- [**99**星][9m] [Py] [attactics/nmapgrapher](https://github.com/attactics/nmapgrapher) 
- [**93**星][6y] [Shell] [nccgroup/port-scan-automation](https://github.com/nccgroup/port-scan-automation) 
- [**86**星][1y] [Py] [sigploiter/gtscan](https://github.com/sigploiter/gtscan) 
- [**84**星][4y] [shodan-labs/iotdb](https://github.com/shodan-labs/iotdb) 
- [**79**星][1y] [Py] [billyv4/id-entify](https://github.com/billyv4/id-entify) 
- [**77**星][7m] [Py] [gelim/nmap-erpscan](https://github.com/gelim/nmap-erpscan) 
- [**76**星][10m] [Py] [laconicwolf/nmap-scan-to-csv](https://github.com/laconicwolf/nmap-scan-to-csv) 
- [**76**星][6y] [Lua] [jpalanco/nmap-scada](https://github.com/jpalanco/nmap-scada) 
- [**71**星][7y] [PHP] [geekchannel/webmap](https://github.com/geekchannel/webmap) 
- [**71**星][9m] [Shell] [xvass/vscan](https://github.com/xvass/vscan) 
- [**66**星][2y] [Lua] [s4n7h0/nse](https://github.com/s4n7h0/nse) 
- [**65**星][1y] [Go] [lair-framework/go-nmap](https://github.com/lair-framework/go-nmap) 
- [**62**星][2y] [Lua] [scipag/httprecon-nse](https://github.com/scipag/httprecon-nse) 
- [**58**星][2y] [Lua] [tkcert/winnti-nmap-script](https://github.com/tkcert/winnti-nmap-script) 
- [**57**星][8m] [Shell] [ernw/static-toolbox](https://github.com/ernw/static-toolbox) 
- [**57**星][2m] [Go] [rickgray/vscan-go](https://github.com/rickgray/vscan-go) 
- [**56**星][4m] [al0ne/nmap_bypass_ids](https://github.com/al0ne/nmap_bypass_ids) 
- [**52**星][10m] [JS] [krudex/lan-monitor](https://github.com/kruegerrobotics/lan-monitor) 
- [**51**星][2y] [Lua] [christophetd/nmap-nse-info](https://github.com/christophetd/nmap-nse-info) nmap-nse-info：浏览、搜索Nmap 的 NSE 脚本
- [**51**星][2y] [HTML] [jgamblin/nmaptable](https://github.com/jgamblin/nmaptable) nmaptable：将 Nmap 扫描结果转变为 D3.js HTML 表格
- [**50**星][2y] [JS] [johnhhorton/node-nmap](https://github.com/johnhhorton/node-nmap) 
- [**48**星][2y] [Py] [nixawk/nmap_vscan](https://github.com/nixawk/nmap_vscan) 
- [**44**星][2y] [Py] [coolervoid/vision2](https://github.com/coolervoid/vision2) 
- [**44**星][2y] [Py] [milo2012/nmap2nessus](https://github.com/milo2012/nmap2nessus) 
- [**43**星][1y] [Java] [narkisr/nmap4j](https://github.com/narkisr/nmap4j) 
- [**43**星][3y] [shmilylty/nmap-reference-guide](https://github.com/shmilylty/Nmap-Reference-Guide) 
- [**40**星][3y] [Lua] [z-0ne/scans2-045-nmap](https://github.com/z-0ne/scans2-045-nmap) 
- [**40**星][4y] [Lua] [aoncyberlabs/nmap-scripts](https://github.com/AonCyberLabs/Nmap-Scripts) 
- [**39**星][2y] [Go] [averagesecurityguy/searchscan](https://github.com/averagesecurityguy/searchscan) 
- [**39**星][6m] [Rust] [dentrax/netlyser](https://github.com/dentrax/netlyser) 
- [**39**星][4y] [Shell] [jivoi/ansible-pentest-with-tor](https://github.com/jivoi/ansible-pentest-with-tor) 
    - 重复区段: [工具/通信&&代理&&反向代理&&隧道/匿名网络/Tor&&&Onion&&洋葱](#e99ba5f3de02f68412b13ca718a0afb6) |
- [**36**星][1m] [JS] [cxueqin/falcon](https://github.com/cxueqin/falcon) 
- [**36**星][1m] [Lua] [r00t-3xp10it/nmap-nse-modules](https://github.com/r00t-3xp10it/nmap-nse-modules) 
- [**35**星][4m] [Py] [m57/piescan](https://github.com/m57/piescan) 
- [**34**星][5y] [Lua] [peter-hackertarget/nmap-nse-scripts](https://github.com/peter-hackertarget/nmap-nse-scripts) 
- [**33**星][8m] [JS] [cylance/nmap-cluster](https://github.com/cylance/NMAP-Cluster) 
- [**33**星][1y] [jasonniebauer/nmap-cheatsheet](https://github.com/jasonniebauer/nmap-cheatsheet) 
- [**32**星][3y] [C] [mehdilauters/esp8266-wifiscanmap](https://github.com/mehdilauters/esp8266-wifiscanmap) 
- [**31**星][4y] [Lua] [kost/nmap-nse](https://github.com/kost/nmap-nse) 
- [**29**星][8m] [C++] [isoadam/gina_public](https://github.com/isoadam/gina_public) 
- [**29**星][6y] [CSS] [savon-noir/nmap-webgui](https://github.com/savon-noir/nmap-webgui) 
- [**28**星][6y] [Ruby] [andrewsmhay/brisket](https://github.com/andrewsmhay/brisket) 
- [**28**星][3y] [Shell] [superkojiman/scanreport](https://github.com/superkojiman/scanreport) 
- [**26**星][5y] [Py] [alfarom/nmap](https://github.com/alfarom/nmap) 
- [**26**星][10m] [Perl] [modernistik/nmap-parser](https://github.com/modernistik/nmap-parser) 
- [**25**星][5y] [Py] [danmcinerney/nmap-parser](https://github.com/danmcinerney/nmap-parser) 
- [**24**星][2m] [Lua] [0x4d31/hassh-utils](https://github.com/0x4d31/hassh-utils) Nmap NSE Script and Docker image for HASSH - the SSH client/server fingerprinting method (
- [**24**星][3y] [Py] [felmoltor/keepnote_import_nmap](https://github.com/felmoltor/keepnote_import_nmap) 
- [**23**星][4y] [PHP] [jgamblin/nmap-for-slack](https://github.com/jgamblin/nmap-for-slack) 
- [**20**星][9m] [XSLT] [capt-meelo/massmap](https://github.com/capt-meelo/massmap) 
- [**20**星][1y] [Py] [the-c0d3r/pynmap](https://github.com/the-c0d3r/pynmap) 
- [**20**星][3y] [Lua] [takeshixx/nmap-scripts](https://github.com/takeshixx/nmap-scripts) 
- [**19**星][2y] [C#] [thomdixon/saltwatertaffy](https://github.com/thomdixon/saltwatertaffy) 
- [**18**星][2y] [Go] [malfunkt/iprange](https://github.com/malfunkt/iprange) 
- [**18**星][4y] [Lua] [raikia/nmap-scripts](https://github.com/raikia/nmap-scripts) 
- [**17**星][6m] [Lua] [b4ldr/nse-scripts](https://github.com/b4ldr/nse-scripts) 
- [**17**星][7y] [Lua] [michenriksen/nmap-scripts](https://github.com/michenriksen/nmap-scripts) 
- [**17**星][1m] [Py] [scivision/findssh](https://github.com/scivision/findssh) 
- [**16**星][1y] [Go] [anshumanbh/merge-nmap-masscan](https://github.com/anshumanbh/merge-nmap-masscan) 
- [**16**星][6y] [Lua] [c-x/nmap-webshot](https://github.com/c-x/nmap-webshot) 
- [**16**星][2y] [Lua] [hkm/nmap-nse-scripts](https://github.com/hkm/nmap-nse-scripts) 
- [**16**星][2y] [Py] [sergiodmn/cherrymap](https://github.com/sergiodmn/cherrymap) 
- [**15**星][8m] [Lua] [aerissecure/nse](https://github.com/aerissecure/nse) 
- [**15**星][3y] [Lua] [chaitanyaharitash/nmapii](https://github.com/chaitanyaharitash/nmapii) 
- [**15**星][3y] [Py] [cornerpirate/nmap-summariser](https://github.com/cornerpirate/nmap-summariser) 
- [**15**星][11m] [XSLT] [sapran/nmap-xsl](https://github.com/sapran/nmap-xsl) 
- [**14**星][7m] [Py] [anouarbensaad/nmapvision](https://github.com/anouarbensaad/nmapvision) 
- [**14**星][5y] [Lua] [bojanisc/nmap-scripts](https://github.com/bojanisc/nmap-scripts) 
- [**14**星][8y] [Py] [d1b/python-nmap-xml-output-parser](https://github.com/d1b/python-nmap-xml-output-parser) 
- [**14**星][8m] [Go] [t94j0/nmap](https://github.com/t94j0/nmap) 
- [**13**星][2m] [Py] [7dog7/masscan_to_nmap](https://github.com/7dog7/masscan_to_nmap) 
- [**13**星][11m] [Py] [abhaybhargav/robonmap](https://github.com/abhaybhargav/robonmap) 
- [**13**星][4y] [Lua] [esentire/nmap-esentire](https://github.com/esentire/nmap-esentire) 
- [**12**星][9y] [Lua] [nosteve/vnc-auth](https://github.com/nosteve/vnc-auth) 
- [**12**星][4m] [wuseman/wnmap](https://github.com/wuseman/wnmap) 




***


## <a id="969212c047f97652ceb9c789e4d8dae5"></a>数据库&&SQL攻击&&SQL注入


### <a id="e8d5cfc417b84fa90eff2e02c3231ed1"></a>未分类-Database


- [**950**星][18d] [PowerShell] [netspi/powerupsql](https://github.com/netspi/powerupsql) 攻击SQL服务器的PowerShell工具箱
- [**661**星][3m] [Py] [v3n0m-scanner/v3n0m-scanner](https://github.com/v3n0m-scanner/v3n0m-scanner) 
- [**638**星][2m] [Py] [quentinhardy/odat](https://github.com/quentinhardy/odat) Oracle Database Attacking Tool
- [**526**星][4m] [Py] [quentinhardy/msdat](https://github.com/quentinhardy/msdat) Microsoft SQL Database Attacking Tool
- [**134**星][2y] [JS] [usscltd/dorks](https://github.com/usscltd/dorks) 


### <a id="3157bf5ee97c32454d99fd4a9fa3f04a"></a>SQL


#### <a id="1cfe1b2a2c88cd92a414f81605c8d8e7"></a>未分类-SQL


- [**2883**星][1m] [Go] [cookiey/yearning](https://github.com/cookiey/yearning) 
- [**712**星][1y] [Py] [the-robot/sqliv](https://github.com/the-robot/sqliv) 
- [**553**星][1m] [HTML] [netspi/sqlinjectionwiki](https://github.com/netspi/sqlinjectionwiki) 
- [**533**星][2y] [Py] [torque59/nosql-exploitation-framework](https://github.com/torque59/nosql-exploitation-framework) 
- [**444**星][9m] [Go] [netxfly/x-crack](https://github.com/netxfly/x-crack) Weak password scanner, Support: FTP/SSH/SNMP/MSSQL/MYSQL/PostGreSQL/REDIS/ElasticSearch/MONGODB
- [**439**星][3m] [Go] [stripe/safesql](https://github.com/stripe/safesql) 
- [**437**星][3y] [Py] [ring04h/wyproxy](https://github.com/ring04h/wyproxy) 
- [**395**星][3m] [C#] [shack2/supersqlinjectionv1](https://github.com/shack2/supersqlinjectionv1) 
- [**393**星][4y] [PHP] [breakthenet/hackme-sql-injection-challenges](https://github.com/breakthenet/hackme-sql-injection-challenges) 
- [**295**星][8m] [JS] [ning1022/sqlinjectionwiki](https://github.com/ning1022/SQLInjectionWiki) 
- [**255**星][7m] [Py] [s0md3v/sqlmate](https://github.com/s0md3v/sqlmate) 
- [**226**星][3y] [chaitin/sqlchop](https://github.com/chaitin/sqlchop) 
- [**169**星][3y] [C] [cyrus-and/mysql-unsha1](https://github.com/cyrus-and/mysql-unsha1) 无需明文密码，认证MySQL服务器
- [**163**星][4y] [C] [uptimejp/sql_firewall](https://github.com/uptimejp/sql_firewall) 
    - 重复区段: [工具/防护&&Defense/防火墙&&FireWall](#ce6532938f729d4c9d66a5c75d1676d3) |
- [**140**星][3y] [PHP] [laurent22/so-sql-injections](https://github.com/laurent22/so-sql-injections) 
- [**133**星][6m] [C] [hc0d3r/mysql-magic](https://github.com/hc0d3r/mysql-magic) 
- [**124**星][7y] [Py] [sysdream/pysqli](https://github.com/sysdream/pysqli) 
- [**113**星][6y] [spiderlabs/sqlol](https://github.com/spiderlabs/sqlol) 
- [**112**星][1y] [Py] [blueudp/dorkme](https://github.com/blueudp/dorkme) 
- [**97**星][3y] [lorexxar/feigong](https://github.com/lorexxar/feigong) 
- [**92**星][2y] [Shell] [offxec/thedoc](https://github.com/OffXec/TheDoc) 
- [**86**星][6y] [Py] [uber/py-find-injection](https://github.com/uber/py-find-injection) 
- [**84**星][3y] [Py] [3xp10it/mytoolkit](https://github.com/3xp10it/mytoolkit) 
- [**80**星][3y] [Py] [z00nx/reversemap](https://github.com/z00nx/reversemap) 
- [**65**星][2y] [lcamry/sqli-labs](https://github.com/lcamry/sqli-labs) 
- [**56**星][9y] [Py] [gdssecurity/sqlbrute](https://github.com/gdssecurity/sqlbrute) 
- [**50**星][2y] [Py] [awnumar/blind-sql-bitshifting](https://github.com/awnumar/blind-sql-bitshifting) 
- [**49**星][4y] [Py] [silentsignal/duncan](https://github.com/silentsignal/duncan) 
- [**42**星][2y] [Py] [miss-d/blindy](https://github.com/miss-d/blindy) 
- [**41**星][3y] [Py] [muodov/sqlmapchik](https://github.com/muodov/sqlmapchik) 
- [**38**星][3y] [PHP] [incredibleindishell/local-file-disclosure-sql-injection-lab](https://github.com/incredibleindishell/local-file-disclosure-sql-injection-lab) 
- [**35**星][10m] [Py] [alessiovierti/blindpie](https://github.com/alessiovierti/blindpie) 
- [**35**星][2y] [JS] [kingsabri/sqlmap-tamper-api](https://github.com/kingsabri/sqlmap-tamper-api) 
- [**27**星][4y] [Py] [nbshelton/bitdump](https://github.com/nbshelton/bitdump) 
- [**26**星][3y] [Py] [tiankonguse/themole](https://github.com/tiankonguse/themole) 
- [**26**星][3y] [Py] [toxic-ig/sql-xss](https://github.com/toxic-ig/sql-xss) 
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/XSS&&XXE/未分类-XSS](#648e49b631ea4ba7c128b53764328c39) |
- [**23**星][7y] [Ruby] [nuke99/sqlnuke](https://github.com/nuke99/sqlnuke) 
- [**23**星][1y] [Go] [releasel0ck/blind-sql-injector](https://github.com/releasel0ck/blind-sql-injector) 
- [**23**星][2y] [PHP] [riyazwalikar/sql-injection-training-app](https://github.com/riyazwalikar/sql-injection-training-app) 
- [**23**星][2m] [itechub/sqlmap-wiki-zhcn](https://github.com/itechub/sqlmap-wiki-zhcn) 
- [**21**星][3y] [PHP] [emanuil/php-reaper](https://github.com/emanuil/php-reaper) 


#### <a id="0519846509746aa50a04abd3ccf2f1d5"></a>SQL注入


- [**15554**星][16d] [Py] [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) 
- [**665**星][2y] [Java] [ron190/jsql-injection](https://github.com/ron190/jsql-injection) Java编写的自动化 SQL 注入工具，跨平台
- [**619**星][2y] [Py] [0xbug/sqliscanner](https://github.com/0xbug/sqliscanner) 
- [**592**星][6m] [aleenzz/mysql_sql_bypass_wiki](https://github.com/aleenzz/mysql_sql_bypass_wiki) 
- [**342**星][3y] [Py] [fengxuangit/fox-scan](https://github.com/fengxuangit/fox-scan) 
- [**69**星][3y] [JS] [himadriganguly/sqlilabs](https://github.com/himadriganguly/sqlilabs) 


#### <a id="5a7451cdff13bc6709da7c943dda967f"></a>SQL漏洞


- [**896**星][2y] [Ruby] [whitewidowscanner/whitewidow](https://github.com/whitewidowscanner/whitewidow) 
- [**49**星][4m] [Py] [bambish/scanqli](https://github.com/bambish/scanqli) 




### <a id="ca6f4bd198f3712db7f24383e8544dfd"></a>NoSQL


#### <a id="af0aaaf233cdff3a88d04556dc5871e0"></a>未分类-NoSQL


- [**1180**星][15d] [Py] [codingo/nosqlmap](https://github.com/codingo/NoSQLMap) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |[工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞利用/漏洞利用](#c83f77f27ccf5f26c8b596979d7151c3) |
- [**275**星][1y] [Java] [florent37/android-nosql](https://github.com/florent37/android-nosql) 


#### <a id="54d36c89712652a7064db6179faa7e8c"></a>MongoDB


- [**1069**星][2m] [Py] [stampery/mongoaudit](https://github.com/stampery/mongoaudit) 
- [**385**星][2y] [Py] [se55i0n/dbscanner](https://github.com/se55i0n/dbscanner) 
- [**308**星][2y] [Py] [sebdah/scrapy-mongodb](https://github.com/sebdah/scrapy-mongodb) 
- [**230**星][3y] [HTML] [mongodb-labs/disasm](https://github.com/mongodb-labs/disasm) 
- [**194**星][9y] [Ruby] [sfeley/candy](https://github.com/sfeley/candy) 
- [**104**星][3y] [Py] [noplay/scrapy-mongodb](https://github.com/noplay/scrapy-mongodb) 
- [**98**星][1y] [Go] [netxfly/crack_ssh](https://github.com/netxfly/crack_ssh) 
- [**75**星][3m] [Go] [yashpl/mongobuster](https://github.com/yashpl/mongobuster) 
- [**48**星][2y] [Py] [qianniaoge/f-scrack](https://github.com/qianniaoge/f-scrack) 
- [**24**星][4y] [Py] [tampe125/mongodb-scraper](https://github.com/tampe125/mongodb-scraper) 
- [**22**星][1y] [HTML] [websecurify/acme-no-login-ng](https://github.com/websecurify/acme-no-login-ng) 






***


## <a id="df8a5514775570707cce56bb36ca32c8"></a>审计&&安全审计&&代码审计


### <a id="6a5e7dd060e57d9fdb3fed8635d61bc7"></a>未分类-Audit


- [**6407**星][1m] [Shell] [cisofy/lynis](https://github.com/cisofy/lynis) Security auditing tool for Linux, macOS, and UNIX-based systems. Assists with compliance testing (HIPAA/ISO27001/PCI DSS) and system hardening. Agentless, and installation optional.
- [**2390**星][3y] [Py] [arthepsy/ssh-audit](https://github.com/arthepsy/ssh-audit) 
- [**1465**星][27d] [Shell] [mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester) 
- [**967**星][2m] [Py] [nccgroup/scoutsuite](https://github.com/nccgroup/scoutsuite) 
- [**604**星][6m] [JS] [vincentcox/stacoan](https://github.com/vincentcox/stacoan) 
    - 重复区段: [工具/移动&&Mobile/未分类-Mobile](#4a64f5e8fdbd531a8c95d94b28c6c2c1) |
- [**271**星][17d] [Py] [lorexxar/cobra-w](https://github.com/lorexxar/cobra-w) 
- [**185**星][1y] [PHP] [smarttang/w3a_soc](https://github.com/smarttang/w3a_soc) 
- [**172**星][2m] [Py] [thekingofduck/filemonitor](https://github.com/thekingofduck/filemonitor) 
- [**136**星][2y] [guanchao/androidchecklist](https://github.com/guanchao/androidchecklist) 
- [**127**星][4m] [Py] [alpha1e0/kiwi](https://github.com/alpha1e0/kiwi) 
- [**51**星][1y] [Py] [5alt/vulhint](https://github.com/5alt/vulhint) 
- [**41**星][30d] [Py] [patois/mrspicky](https://github.com/patois/mrspicky) IDA反编译器脚本，辅助审计对于memcpy() 和memmove()函数的调用
- [**33**星][3y] [HTML] [tennc/1000php](https://github.com/tennc/1000php) 
- [**29**星][1y] [PHP] [yaofeifly/php_code_challenge](https://github.com/yaofeifly/php_code_challenge) 
- [**25**星][4y] [Py] [xfkxfk/pyvulhunter](https://github.com/xfkxfk/pyvulhunter) 


### <a id="34569a6fdce10845eae5fbb029cd8dfa"></a>代码审计


- [**2041**星][3m] [Py] [whaleshark-team/cobra](https://github.com/WhaleShark-Team/cobra) 
- [**807**星][1y] [Py] [utkusen/leviathan](https://github.com/utkusen/leviathan) 
- [**646**星][1y] [chybeta/code-audit-challenges](https://github.com/chybeta/code-audit-challenges) 
- [**626**星][8m] [Py] [klen/pylama](https://github.com/klen/pylama) 
- [**399**星][4m] [C] [anssi-fr/ad-control-paths](https://github.com/anssi-fr/ad-control-paths) 
- [**355**星][11m] [Py] [enablesecurity/sipvicious](https://github.com/enablesecurity/sipvicious) 
- [**293**星][2m] [C#] [ossindex/devaudit](https://github.com/ossindex/devaudit) 
- [**269**星][5y] [Scala] [fix-macosx/net-monitor](https://github.com/fix-macosx/net-monitor) 
- [**263**星][14d] [Py] [exodus-privacy/exodus](https://github.com/exodus-privacy/exodus) 
- [**254**星][1m] [Py] [hubblestack/hubble](https://github.com/hubblestack/hubble) 
- [**240**星][4m] [PowerShell] [nccgroup/azucar](https://github.com/nccgroup/azucar) Azure环境安全审计工具
- [**222**星][2y] [Py] [alibaba/iossecaudit](https://github.com/alibaba/iossecaudit) 
- [**215**星][1y] [C] [meliot/filewatcher](https://github.com/meliot/filewatcher) 
- [**189**星][26d] [Go] [google/certificate-transparency-go](https://github.com/google/certificate-transparency-go) 
- [**168**星][2m] [C#] [dionach/ntdsaudit](https://github.com/dionach/ntdsaudit) 
- [**153**星][4m] [PowerShell] [phillips321/adaudit](https://github.com/phillips321/adaudit) 自动域名审计
- [**152**星][2y] [JS] [snooze6/fios](https://github.com/snooze6/fios) 
- [**149**星][1m] [Shell] [0xmachos/mosl](https://github.com/0xmachos/mosl) 
- [**138**星][2m] [Py] [nuid/nebulousad](https://github.com/nuid/nebulousad) 
- [**138**星][4y] [Py] [shengqi158/pyvulhunter](https://github.com/shengqi158/pyvulhunter) 
- [**126**星][6m] [Py] [ex0dus-0x/dedsploit](https://github.com/ex0dus-0x/dedsploit) 
- [**126**星][1y] [Py] [spotify/gcp-audit](https://github.com/spotify/gcp-audit) 
- [**122**星][2y] [PHP] [anssi-fr/ad-permissions](https://github.com/anssi-fr/ad-permissions) 
- [**113**星][3y] [Java] [nil1666/auditdroid](https://github.com/nil1666/auditdroid) 
- [**112**星][7m] [Py] [tkisason/unhash](https://github.com/tkisason/unhash) 
- [**110**星][1m] [PowerShell] [jrentenaar/office-365-extractor](https://github.com/jrentenaar/office-365-extractor) 
- [**110**星][2y] [Py] [lcatro/php_source_audit_tools](https://github.com/lcatro/php_source_audit_tools) 
- [**109**星][5y] [Py] [behindthefirewalls/parsero](https://github.com/behindthefirewalls/parsero) 
- [**106**星][3y] [Py] [aeondave/doork](https://github.com/aeondave/doork) 
- [**105**星][2y] [Ruby] [chrisallenlane/watchtower](https://github.com/chrisallenlane/watchtower) 
- [**102**星][1y] [Py] [preos-security/fwaudit](https://github.com/preos-security/fwaudit) 
- [**101**星][1y] [Py] [apg-intel/ipv6tools](https://github.com/apg-intel/ipv6tools) 
- [**97**星][2y] [HTML] [chrisallenlane/drek](https://github.com/chrisallenlane/drek) drek：静态代码分析工具，用于执行以安全性为主的代码审计
- [**87**星][2m] [JS] [ossindex/auditjs](https://github.com/ossindex/auditjs) 
- [**86**星][4y] [Py] [airbus-seclab/bta](https://github.com/airbus-seclab/bta) 
- [**86**星][2y] [Ruby] [eurialo/vsaudit](https://github.com/eurialo/vsaudit) 
- [**85**星][2m] [Py] [eth0izzle/cracke-dit](https://github.com/eth0izzle/cracke-dit) 
- [**81**星][6y] [C] [chokepoint/beleth](https://github.com/chokepoint/beleth) 
- [**77**星][2y] [iamhdt/ecommerce-website-security-checklist](https://github.com/iamhdt/ecommerce-website-security-checklist) 
- [**75**星][4y] [hardhatdigital/rails-security-audit](https://github.com/hardhatdigital/rails-security-audit) 
- [**74**星][7m] [PowerShell] [cottinghamd/hardeningauditor](https://github.com/cottinghamd/hardeningauditor) 
- [**71**星][6y] [Py] [0xdevalias/sparty](https://github.com/0xdevalias/sparty) 
- [**71**星][5y] [80vul/pasc2at](https://github.com/80vul/pasc2at) 
- [**67**星][8m] [Go] [mozilla/audit-go](https://github.com/mozilla/audit-go) 
- [**66**星][1m] [Py] [skelsec/msldap](https://github.com/skelsec/msldap) 从Active Directory中获取用户对象, 并将重要内容存储在一个大型电子表格中. 用于渗透期间快速识别易受攻击的用户设置
- [**66**星][1y] [Py] [takeshixx/knxmap](https://github.com/takeshixx/knxmap) 
- [**60**星][4y] [MATLAB] [konstantinberlin/malware-windows-audit-log-detection](https://github.com/konstantinberlin/malware-windows-audit-log-detection) 
- [**58**星][8y] [Ruby] [wuntee/androidaudittools](https://github.com/wuntee/androidaudittools) 
- [**56**星][10m] [Go] [appliscale/cloud-security-audit](https://github.com/appliscale/cloud-security-audit) 
- [**55**星][7y] [Py] [antitree/manitree](https://github.com/antitree/manitree) 
- [**54**星][3m] [Py] [giantbranch/mipsaudit](https://github.com/giantbranch/mipsaudit) 
- [**52**星][9m] [sukaralin/php_code_audit_project](https://github.com/sukaralin/php_code_audit_project) 
- [**52**星][8m] [Shell] [xalfie/nix-auditor](https://github.com/xalfie/nix-auditor) 




***


## <a id="546f4fe70faa2236c0fbc2d486a83391"></a>社工(SET)&&钓鱼&&鱼叉攻击


### <a id="ce734598055ad3885d45d0b35d2bf0d7"></a>未分类-SET


- [**1301**星][26d] [CSS] [undeadsec/socialfish](https://github.com/undeadsec/socialfish) 网络钓鱼培训与信息收集
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |
- [**742**星][3m] [Py] [threatexpress/domainhunter](https://github.com/threatexpress/domainhunter) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |
- [**556**星][2m] [Py] [thewhiteh4t/seeker](https://github.com/thewhiteh4t/seeker) 
- [**305**星][1m] [Py] [raikia/uhoh365](https://github.com/raikia/uhoh365) 
- [**171**星][2y] [Ruby] [section9labs/cartero](https://github.com/section9labs/cartero) 
- [**166**星][1y] [Py] [azizaltuntas/camelishing](https://github.com/azizaltuntas/camelishing) 
- [**110**星][5m] [Vue] [tevora-threat/dragnet](https://github.com/tevora-threat/dragnet) 
- [**81**星][4y] [Py] [pinperepette/geotweet_gui](https://github.com/pinperepette/geotweet_gui) 
- [**27**星][3y] [Py] [jofpin/sack](https://github.com/jofpin/sack) 
- [**25**星][4y] [Py] [milo2012/social-engineering-toys](https://github.com/milo2012/social-engineering-toys) 
- [**22**星][3y] [JS] [gregkcarson/googleappscriptse](https://github.com/gregkcarson/googleappscriptse) 


### <a id="f30507893511f89b19934e082a54023e"></a>社工


- [**4854**星][2m] [Py] [trustedsec/social-engineer-toolkit](https://github.com/trustedsec/social-engineer-toolkit) 
- [**70**星][1y] [Batchfile] [0xcoto/evilusb](https://github.com/0xcoto/evilusb) 
    - 重复区段: [工具/硬件设备&&USB&树莓派/USB](#48c53d1304b1335d9addf45b959b7d8a) |


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
- [**789**星][3y] [Go] [ryhanson/phishery](https://github.com/ryhanson/phishery) phishery：启用 SSL 的 HTTP 服务器，首要目的是通过基本身份认证进行网络钓鱼，以获取凭证。自带将钓鱼url 注入 .docx Word 文档的功能，用户打开Word 文档时会向钓鱼 url 发送请求，并自动弹出认证对话框。
- [**578**星][2y] [PHP] [pentestgeek/phishing-frenzy](https://github.com/pentestgeek/phishing-frenzy) phishing-frenzy：Rubyon Rails 钓鱼框架
- [**524**星][26d] [Py] [shellphish/driller](https://github.com/shellphish/driller) augmenting AFL with symbolic execution!
- [**472**星][2y] [Ruby] [ring0lab/catphish](https://github.com/ring0lab/catphish) 用于网络钓鱼及企业间谍活动。Ruby编写
- [**380**星][2y] [Py] [fireeye/reelphish](https://github.com/fireeye/reelphish) 
- [**348**星][4m] [Py] [tatanus/spf](https://github.com/tatanus/spf) 
- [**336**星][4y] [HTML] [cxxr/lostpass](https://github.com/cxxr/lostpass) 
- [**328**星][3y] [Ruby] [antisnatchor/phishlulz](https://github.com/antisnatchor/phishlulz) 
- [**303**星][2y] [C++] [exploitagency/esploitv2](https://github.com/exploitagency/esploitv2) 
- [**297**星][10m] [Py] [mr-un1k0d3r/catmyphish](https://github.com/Mr-Un1k0d3r/CatMyPhish) 
- [**293**星][2y] [swiftonsecurity/swiftfilter](https://github.com/swiftonsecurity/swiftfilter) 
- [**265**星][3m] [Go] [muraenateam/muraena](https://github.com/muraenateam/muraena) 
- [**240**星][2m] [Py] [atexio/mercure](https://github.com/atexio/mercure) 对员工进行网络钓鱼的培训
- [**233**星][2y] [JS] [google/password-alert](https://github.com/google/password-alert) 
- [**228**星][1y] [Jupyter Notebook] [wesleyraptor/streamingphish](https://github.com/wesleyraptor/streamingphish) 使用受监督的机器学习, 从证书透明度(Certificate Transparency)日志中检测钓鱼域名
- [**226**星][2y] [Py] [evait-security/weeman](https://github.com/evait-security/weeman) 
- [**220**星][3m] [Py] [duo-labs/isthislegit](https://github.com/duo-labs/isthislegit) isthislegit：收集、分析和回复网络钓鱼邮件的框架
- [**200**星][1y] [Py] [omergunal/pot](https://github.com/omergunal/pot) 
- [**193**星][3y] [mechaphish/mecha-docs](https://github.com/mechaphish/mecha-docs) 
- [**189**星][2m] [Py] [dionach/phemail](https://github.com/dionach/phemail) 
- [**182**星][2y] [Py] [savio-code/ghost-phisher](https://github.com/savio-code/ghost-phisher) 带 GUI的钓鱼工具
- [**170**星][2y] [Py] [cldrn/macphish](https://github.com/cldrn/macphish) macphish：Office 宏 Payload 生成器（Mac 版）
- [**158**星][2y] [Py] [phishai/phish-ai-api](https://github.com/phishai/phish-ai-api) phish.ai 公开和私有的API接口, Python编写
- [**155**星][7m] [dsignr/disallowed-usernames](https://github.com/dsignr/disallowed-usernames) 
- [**153**星][6m] [C] [angr/patcherex](https://github.com/angr/patcherex) 
- [**153**星][4y] [Py] [samyoyo/weeman](https://github.com/samyoyo/weeman) 
- [**143**星][9m] [JS] [certsocietegenerale/swordphish-awareness](https://github.com/certsocietegenerale/swordphish-awareness) 
- [**143**星][4m] [HTML] [l4bf0x/phishingpretexts](https://github.com/l4bf0x/phishingpretexts) 
- [**142**星][5y] [PHP] [pentestgeek/phishing-frenzy-templates](https://github.com/pentestgeek/phishing-frenzy-templates) 
- [**139**星][10m] [Py] [t4d/phishingkithunter](https://github.com/t4d/phishingkithunter) 
- [**136**星][3y] [Py] [hasameli/foghorn](https://github.com/hasameli/foghorn) 
- [**125**星][1y] [JS] [danielstjules/blankshield](https://github.com/danielstjules/blankshield) 
- [**119**星][1y] [HTML] [xhak9x/socialphish](https://github.com/xhak9x/socialphish) 
- [**118**星][2y] [JS] [duo-labs/phinn](https://github.com/duo-labs/phinn) phinn：生成脱机 Chrome 扩展，使用 bespoke convolutional 神经网络来检测网络钓鱼攻击
- [**116**星][13d] [Py] [t4d/stalkphish](https://github.com/t4d/stalkphish) 
- [**115**星][11m] [PowerShell] [fox-it/invoke-credentialphisher](https://github.com/fox-it/invoke-credentialphisher) 
- [**114**星][11m] [HTML] [wifiphisher/extra-phishing-pages](https://github.com/wifiphisher/extra-phishing-pages) 
- [**112**星][2y] [Py] [simplysecurity/simplytemplate](https://github.com/SimplySecurity/SimplyTemplate) 
- [**108**星][9m] [HTML] [m4cs/blackeye-python](https://github.com/m4cs/blackeye-python) 
- [**104**星][1y] [JS] [phishai/phish-protect](https://github.com/phishai/phish-protect) 警报并可能阻止IDN/Unicode域名的网站
- [**100**星][9m] [Shell] [vishnudxb/docker-blackeye](https://github.com/vishnudxb/docker-blackeye) 
- [**95**星][7y] [JS] [feross/fullscreen-api-attack](https://github.com/feross/fullscreen-api-attack) 
- [**90**星][3y] [swiftonsecurity/phishingregex](https://github.com/swiftonsecurity/phishingregex) 
- [**88**星][2y] [C#] [schillings/swordphish](https://github.com/schillings/swordphish) 
- [**84**星][3m] [Py] [duo-labs/phish-collect](https://github.com/duo-labs/phish-collect) 
- [**81**星][6m] [Py] [initstring/evil-ssdp](https://github.com/initstring/evil-ssdp) 
- [**80**星][3m] [JS] [securestate/king-phisher-templates](https://github.com/securestate/king-phisher-templates) 
- [**79**星][12d] [Shell] [mitchellkrogza/phishing.database](https://github.com/mitchellkrogza/phishing.database) 
- [**77**星][2m] [HTML] [jenyraval/phishing-simulation](https://github.com/jenyraval/phishing-simulation) 
- [**75**星][1y] [Py] [hadojae/data](https://github.com/hadojae/data) 
- [**71**星][4m] [Shell] [chunkingz/linsetmv1-2](https://github.com/chunkingz/linsetmv1-2) 
- [**70**星][12m] [JS] [hackatnow/certstreamcatcher](https://github.com/hackatnow/certstreamcatcher) 
- [**62**星][4m] [Py] [greenwolf/social_attacker](https://github.com/greenwolf/social_attacker) 
- [**62**星][2m] [Ruby] [ninoseki/miteru](https://github.com/ninoseki/miteru) 
- [**59**星][5m] [Py] [neonprimetime/phishingkittracker](https://github.com/neonprimetime/phishingkittracker) 
- [**59**星][10m] [Py] [thom-s/httphish](https://github.com/thom-s/httphish) 
- [**58**星][2y] [JS] [monkeym4ster/domainfuzz](https://github.com/monkeym4ster/domainfuzz) 
- [**57**星][2y] [PowerShell] [obscuritylabs/infophish](https://github.com/obscuritylabs/InfoPhish) 
- [**56**星][4m] [Py] [chrismaddalena/goreport](https://github.com/chrismaddalena/goreport) 
- [**53**星][4m] [Py] [sneakerhax/pyphisher](https://github.com/sneakerhax/pyphisher) 
- [**53**星][4y] [PowerShell] [xorrior/emailraider](https://github.com/xorrior/emailraider) 
- [**51**星][1y] [HTML] [an0nud4y/blackeye](https://github.com/an0nud4y/blackeye) 
- [**51**星][5y] [Py] [fuzzynop/fiveonceinyourlife](https://github.com/fuzzynop/fiveonceinyourlife) 
- [**49**星][2y] [Ruby] [mrbrutti/cartero](https://github.com/mrbrutti/Cartero) 
- [**48**星][1m] [YARA] [hestat/lw-yara](https://github.com/hestat/lw-yara) 
- [**44**星][25d] [C++] [adam24exe/esp8266_wifi_captive_portal](https://github.com/adam24exe/ESP8266_WiFi_Captive_Portal) 
- [**41**星][1y] [HTML] [an0nud4y/socialfish](https://github.com/an0nud4y/socialfish) 
- [**41**星][2m] [Py] [securestate/king-phisher-plugins](https://github.com/securestate/king-phisher-plugins) 
- [**40**星][3y] [Shell] [jbreed/apkinjector](https://github.com/jbreed/apkinjector) 
- [**40**星][10m] [Py] [jh00nbr/phishruffus](https://github.com/jh00nbr/phishruffus) 
- [**40**星][4m] [Py] [philomathic-guy/malicious-web-content-detection-using-machine-learning](https://github.com/philomathic-guy/Malicious-Web-Content-Detection-Using-Machine-Learning) 
- [**39**星][2y] [Py] [mthbernardes/houseproxy](https://github.com/mthbernardes/houseproxy) 
- [**39**星][2y] [PowerShell] [msadministrator/pprt](https://github.com/MSAdministrator/PPRT) 
- [**34**星][1y] [Py] [pure-l0g1c/spectre](https://github.com/pure-l0g1c/spectre) 
- [**31**星][2y] [Py] [medhini/malicious_website_detection](https://github.com/medhini/malicious_website_detection) 
- [**31**星][3y] [Py] [ytisf/hemingway](https://github.com/ytisf/hemingway) 
- [**30**星][12m] [Java] [harryfrey/fakegumtree](https://github.com/harryfrey/fakegumtree) 
- [**30**星][29d] [JS] [m1nl/pompa](https://github.com/m1nl/pompa) 
- [**27**星][8y] [PHP] [koto/squid-imposter](https://github.com/koto/squid-imposter) 
- [**27**星][1y] [Py] [sweetsoftware/artemis](https://github.com/sweetsoftware/artemis) 
- [**26**星][2y] [Py] [xiphosresearch/smsisher](https://github.com/xiphosresearch/smsisher) 
- [**23**星][1y] [Go] [olihough86/stinkyphish](https://github.com/olihough86/stinkyphish) 
- [**23**星][2y] [Ruby] [trailofbits/trailofphish](https://github.com/trailofbits/trailofphish) 
- [**22**星][7m] [Py] [horusteknoloji/tr-phishinglist](https://github.com/horusteknoloji/tr-phishinglist) 
- [**22**星][4m] [Py] [steved3/kit_hunter](https://github.com/steved3/kit_hunter) 
- [**22**星][2y] [PHP] [vysecurity/basicauth](https://github.com/vysecurity/basicAuth) 
- [**20**星][1y] [Py] [gosecure/gophish-cli](https://github.com/gosecure/gophish-cli) 
- [**20**星][3y] [CSS] [xeushack/fake-login-page](https://github.com/xeushack/fake-login-page) 
- [**19**星][9m] [Swift] [alexruperez/safebrowsing](https://github.com/alexruperez/safebrowsing) 
- [**19**星][2y] [PHP] [mgeeky/phishingpost](https://github.com/mgeeky/phishingpost) 
- [**19**星][4y] [Py] [milo2012/phishing-frenzy-template-cloner](https://github.com/milo2012/phishing-frenzy-template-cloner) 
- [**18**星][1y] [Py] [iosiro/blockphish](https://github.com/iosiro/blockphish) 
- [**15**星][2y] [matteoggl/docker-gophish](https://github.com/matteoggl/docker-gophish) 
- [**14**星][2y] [HTML] [kdhacker1995/social-fish-v2.0](https://github.com/kdhacker1995/social-fish-v2.0) 
- [**13**星][1y] [HTML] [p1r06u3/phishing](https://github.com/p1r06u3/phishing) 
- [**13**星][3y] [C++] [taner1/esp8266_deauther](https://github.com/taner1/esp8266_deauther) 
- [**11**星][12m] [Go] [darkanhell/fastphish](https://github.com/darkanhell/fastphish) 
- [**11**星][10m] [Shell] [vincenzogianfelice/rogueportal](https://github.com/vincenzogianfelice/rogueportal) 
- [**10**星][2y] [Ruby] [trailofbits/tacklebox](https://github.com/trailofbits/tacklebox) 
- [**9**星][1y] [Py] [decidedlygray/mfa_slipstream_poc](https://github.com/decidedlygray/mfa_slipstream_poc) 
- [**9**星][3y] [JS] [sfi0zy/blank-protector](https://github.com/sfi0zy/blank-protector) 
- [**8**星][2y] [Py] [dpmforensics/pst-go-phish](https://github.com/dpmforensics/pst-go-phish) 
- [**7**星][11m] [Py] [fox-it/signed-phishing-email](https://github.com/fox-it/signed-phishing-email) 
- [**6**星][1y] [HTML] [pipioli/social-pay](https://github.com/pipioli/social-pay) 
- [**5**星][1y] [Py] [blackhatmonkey/robophisher](https://github.com/blackhatmonkey/robophisher) 
- [**5**星][2y] [PHP] [fogsec/fiercephish](https://github.com/fogsec/fiercephish) 
- [**4**星][1y] [html] [flagellantx/gophish](https://github.com/flagellantx/gophish) 
- [**4**星][1y] [Py] [serdarhaliloglu/phishing-email-analyzer](https://github.com/serdarhaliloglu/phishing-email-analyzer) 
- [**4**星][3m] [Rust] [wisespace-io/nettfiske](https://github.com/wisespace-io/nettfiske) 
- [**3**星][1y] [php] [galkan/sees](https://github.com/galkan/sees) 
- [**3**星][13d] [Shell] [mitchellkrogza/phishing-url-testing-database-of-link-statuses](https://github.com/mitchellkrogza/phishing-url-testing-database-of-link-statuses) 
- [**2**星][2y] [Py] [dgolak/phishing-tracker](https://github.com/dgolak/phishing-tracker) 
- [**2**星][4y] [HTML] [joshingeneral/feelingphishy](https://github.com/joshingeneral/feelingphishy) 
- [**1**星][2y] [Py] [abreksa4/phishing_catcher](https://github.com/abreksa4/phishing_catcher) 
- [**1**星][11m] [Py] [adrinavaas/staff-tester](https://github.com/adrinavaas/staff-tester) 
- [**1**星][10y] [Ruby] [cedric/safe_browsing](https://github.com/cedric/safe_browsing) 
- [**1**星][2y] [ics/domainfuzzer](https://github.com/ics/domainfuzzer) 
- [**1**星][2y] [Shell] [op7ic/rt-officebeaconbox](https://github.com/op7ic/rt-officebeaconbox) 
- [**1**星][3y] [C++] [prettyneet/proof-of-concept-host-hijack](https://github.com/prettyneet/proof-of-concept-host-hijack) 
- [**1**星][2y] [Py] [samyoyo/evilurl](https://github.com/samyoyo/evilurl) 
- [**0**星][3y] [c4ndym4n/pyphish](https://github.com/c4ndym4n/pyphish) 
- [**0**星][1y] [Py] [flagellantx/spf](https://github.com/flagellantx/spf) 
- [**0**星][1y] [Py] [flagellantx/weeman](https://github.com/flagellantx/weeman) 
- [**0**星][4y] [JS] [gskouroupathis/tabnabtor](https://github.com/gskouroupathis/tabnabtor) 
- [**0**星][2y] [CSS] [h-a-t/sectf](https://github.com/h-a-t/sectf) 
- [**0**星][2y] [PHP] [r3dfruitrollup/fiercephish](https://github.com/r3dfruitrollup/fiercephish) 


### <a id="ab3e6e6526d058e35c7091d8801ebf3a"></a>鱼叉攻击






***


## <a id="04102345243a4bcaec83f703afff6cb3"></a>硬件设备&&USB&树莓派


### <a id="ff462a6d508ef20aa41052b1cc8ad044"></a>未分类-Hardware


- [**2696**星][3y] [Eagle] [samyk/magspoof](https://github.com/samyk/magspoof) 信用卡/磁条欺骗
- [**2190**星][18d] [Shell] [eliaskotlyar/xiaomi-dafang-hacks](https://github.com/eliaskotlyar/xiaomi-dafang-hacks) 
- [**2009**星][1y] [C] [xoreaxeaxeax/rosenbridge](https://github.com/xoreaxeaxeax/rosenbridge) 
- [**1932**星][13d] [Go] [ullaakut/cameradar](https://github.com/Ullaakut/cameradar) 
- [**1327**星][1y] [Py] [carmaa/inception](https://github.com/carmaa/inception) 利用基于PCI的DMA实现物理内存的操纵与Hacking，可以攻击FireWire，Thunderbolt，ExpressCard，PC Card和任何其他PCI / PCIe硬件接口
- [**1278**星][4y] [Py] [elvanderb/tcp-32764](https://github.com/elvanderb/tcp-32764) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/后门&&添加后门](#b6efee85bca01cde45faa45a92ece37f) |
- [**1117**星][10m] [JS] [mame82/p4wnp1_aloa](https://github.com/mame82/p4wnp1_aloa) 将 Rapsberry Pi Zero W 转变成灵活的渗透平台
    - 重复区段: [工具/环境配置&&分析系统/未分类-Env](#f5a7a43f964b2c50825f3e2fee5078c8) |
- [**962**星][2m] [C] [olimex/olinuxino](https://github.com/olimex/olinuxino) 
- [**905**星][5y] [Py] [pwnieexpress/raspberry_pwn](https://github.com/pwnieexpress/raspberry_pwn) 树莓派渗透测试套件
    - 重复区段: [工具/硬件设备&&USB&树莓派/树莓派&&RaspberryPi](#77c39a0ad266ad42ab8157ba4b3d874a) |
- [**516**星][3m] [Java] [1998lixin/hardwarecode](https://github.com/1998lixin/hardwarecode) 
- [**85**星][1y] [sectool/redteam-hardware-toolkit](https://github.com/sectool/redteam-hardware-toolkit) 
- [**31**星][4y] [Eagle] [thedarknet/hhvkit](https://github.com/thedarknet/hhvkit) 


### <a id="48c53d1304b1335d9addf45b959b7d8a"></a>USB


- [**3811**星][17d] [drduh/yubikey-guide](https://github.com/drduh/yubikey-guide) 
- [**3607**星][5y] [C#] [brandonlw/psychson](https://github.com/brandonlw/Psychson) 
- [**3457**星][3y] [C] [hak5darren/usb-rubber-ducky](https://github.com/hak5darren/usb-rubber-ducky) 
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
- [**277**星][1y] [C++] [ondrejbudai/hidviz](https://github.com/ondrejbudai/hidviz) hidviz：深入分析 USB HID设备通信的工具
- [**255**星][3y] [Py] [mame82/duck2spark](https://github.com/mame82/duck2spark) 
- [**224**星][5y] [Py] [nccgroup/umap](https://github.com/nccgroup/umap) 
- [**224**星][3y] [PowerShell] [xyntax/badusb-code](https://github.com/xyntax/badusb-code) 
- [**221**星][5m] [ANTLR] [myriadrf/limesdr-usb](https://github.com/myriadrf/limesdr-usb) 
- [**157**星][1m] [C#] [jlospinoso/beamgun](https://github.com/jlospinoso/beamgun) 
- [**154**星][2y] [C++] [mharjac/bad_ducky](https://github.com/mharjac/bad_ducky) 
- [**151**星][3m] [AGS Script] [tinyfpga/tinyfpga-bootloader](https://github.com/tinyfpga/tinyfpga-bootloader) 
- [**149**星][2m] [C] [libimobiledevice/libirecovery](https://github.com/libimobiledevice/libirecovery) 
- [**139**星][3m] [Py] [nccgroup/umap2](https://github.com/nccgroup/umap2) 
- [**137**星][3y] [C] [ebursztein/malusb](https://github.com/ebursztein/malusb) 
- [**131**星][3y] [Py] [schumilo/vusbf](https://github.com/schumilo/vusbf) 
- [**125**星][8m] [Shell] [tenable/router_badusb](https://github.com/tenable/router_badusb) 
- [**118**星][2y] [Shell] [shipcod3/mazda_getinfo](https://github.com/shipcod3/mazda_getinfo) 
- [**97**星][9m] [C] [nowrep/vita-shellbat](https://github.com/nowrep/vita-shellbat) 
- [**92**星][5y] [Shell] [ckuethe/usbarmory](https://github.com/ckuethe/usbarmory) 
- [**86**星][1y] [Shell] [ossiozac/raspberry-pi-zero-rubber-ducky-duckberry-pi](https://github.com/ossiozac/raspberry-pi-zero-rubber-ducky-duckberry-pi) 
- [**80**星][2y] [C] [dword1511/onewire-over-uart](https://github.com/dword1511/onewire-over-uart) 
- [**77**星][1m] [Py] [fgsect/scat](https://github.com/fgsect/scat) 通过USB解析Qualcomm和Samsung基带的诊断消息，并生成包含蜂窝控制平面消息的GSMTAP数据包流
- [**74**星][29d] [Batchfile] [tresacton/passwordstealer](https://github.com/tresacton/passwordstealer) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/未分类-payload](#6602e118e0245c83b13ff0db872c3723) |
- [**70**星][1y] [Batchfile] [0xcoto/evilusb](https://github.com/0xcoto/evilusb) 
    - 重复区段: [工具/社工(SET)&&钓鱼&&鱼叉攻击/社工](#f30507893511f89b19934e082a54023e) |
- [**62**星][29d] [C++] [changeofpace/mouclassinputinjection](https://github.com/changeofpace/mouclassinputinjection) 
- [**57**星][3m] [C++] [changeofpace/mouhidinputhook](https://github.com/changeofpace/mouhidinputhook) 
- [**56**星][2y] [Py] [rafiot/kittengroomer](https://github.com/rafiot/kittengroomer) 
- [**52**星][6m] [C#] [nyan-x-cat/limeusb-csharp](https://github.com/nyan-x-cat/limeusb-csharp) 
- [**47**星][4y] [Shell] [adafruit/adafruit-pi-externalroot-helper](https://github.com/adafruit/adafruit-pi-externalroot-helper) 
- [**47**星][1y] [C] [kkamagui/iron-hid](https://github.com/kkamagui/iron-hid) Create Your Own Bad USB Device (Presented at HITBSecConf 2016)
- [**44**星][6y] [nccgroup/frisbeelite](https://github.com/nccgroup/frisbeelite) 
- [**43**星][4m] [Java] [maxieds/chameleonminilivedebugger](https://github.com/maxieds/chameleonminilivedebugger) 
- [**42**星][3y] [Py] [uber/usb2fac](https://github.com/uber/usb2fac) 
- [**39**星][1m] [C#] [mashed-potatoes/usbtrojan](https://github.com/mashed-potatoes/usbtrojan) 
- [**34**星][2y] [Py] [ernw/dizzy-legacy](https://github.com/ernw/dizzy-legacy) 
- [**32**星][1y] [Py] [ernw/dizzy](https://github.com/ernw/dizzy) 
- [**31**星][2y] [C] [zwclose/hidusb2](https://github.com/zwclose/hidusb2) hidusb2：Win10hidusb.sys 源代码
- [**30**星][2y] [C] [simoninns/smallymouse2](https://github.com/simoninns/smallymouse2) 
- [**27**星][2y] [C] [daveti/usbfilter](https://github.com/daveti/usbfilter) 
- [**27**星][3y] [Visual Basic] [phreak87/espeensy-and-peensy-payload-generator-esp8266-teensy-3.5-](https://github.com/phreak87/espeensy-and-peensy-payload-generator-esp8266-teensy-3.5-) 
- [**27**星][2m] [C] [surajfale/passthrough-minifilter-driver](https://github.com/surajfale/passthrough-minifilter-driver) 
- [**24**星][9m] [C] [stooged/apptousb-50x](https://github.com/stooged/apptousb-50x) 
- [**23**星][2y] [PowerShell] [elevenpaths/usbhiddennetworks](https://github.com/elevenpaths/usbhiddennetworks) 
- [**22**星][2y] [C] [celesteblue-dev/ps4-pkg2usb](https://github.com/celesteblue-dev/ps4-pkg2usb) 


### <a id="77c39a0ad266ad42ab8157ba4b3d874a"></a>树莓派&&RaspberryPi


- [**2643**星][12m] [Py] [mame82/p4wnp1](https://github.com/mame82/p4wnp1) 基于Raspberry Pi Zero 或 Raspberry Pi Zero W 的USB攻击平台, 高度的可定制性
    - 重复区段: [工具/硬件设备&&USB&树莓派/USB](#48c53d1304b1335d9addf45b959b7d8a) |
- [**1658**星][7m] [Makefile] [raspberrypi/noobs](https://github.com/raspberrypi/noobs) 
- [**1510**星][1m] [C] [raspberrypi/userland](https://github.com/raspberrypi/userland) 
- [**905**星][5y] [Py] [pwnieexpress/raspberry_pwn](https://github.com/pwnieexpress/raspberry_pwn) 树莓派渗透测试套件
    - 重复区段: [工具/硬件设备&&USB&树莓派/未分类-Hardware](#ff462a6d508ef20aa41052b1cc8ad044) |
- [**881**星][2y] [Py] [nsacyber/gosecure](https://github.com/nsacyber/goSecure) 
- [**653**星][2y] [Py] [travisfsmith/sweetsecurity](https://github.com/travisfsmith/sweetsecurity) 
- [**296**星][6m] [C++] [cyphunk/jtagenum](https://github.com/cyphunk/jtagenum) 
- [**258**星][5m] [Py] [mbro95/portablecellnetwork](https://github.com/mbro95/portablecellnetwork) 
- [**246**星][4m] [Py] [tipam/pi3d](https://github.com/tipam/pi3d) 
- [**218**星][2y] [C++] [ha7ilm/qtcsdr](https://github.com/ha7ilm/qtcsdr) 
- [**181**星][3y] [Shell] [wismna/hackpi](https://github.com/wismna/hackpi) 
- [**177**星][2y] [Py] [tenrec-builders/pi-scan](https://github.com/tenrec-builders/pi-scan) 
- [**157**星][1y] [Py] [musicmancorley/briarids](https://github.com/musicmancorley/briarids) 
- [**154**星][12d] [Shell] [dshield-isc/dshield](https://github.com/dshield-isc/dshield) 
- [**142**星][28d] [Py] [futuresharks/rpi-security](https://github.com/futuresharks/rpi-security) 
- [**140**星][2y] [Py] [sarah314/spypi](https://github.com/sarah314/spypi) 
- [**135**星][1m] [C++] [raspberrypi/piserver](https://github.com/raspberrypi/piserver) 
- [**116**星][2y] [Py] [willphillipscvdemo/raspberry-pi-camera-motion-detection.](https://github.com/willphillipscvdemo/raspberry-pi-camera-motion-detection.) 
- [**92**星][2y] [Shell] [henryho2006/rpiproxy](https://github.com/henryho2006/rpiproxy) 
- [**87**星][5y] [Py] [adafruit/freqshow](https://github.com/adafruit/freqshow) 
- [**79**星][1y] [Py] [brandonasuncion/reverse-engineering-bluetooth-protocols](https://github.com/brandonasuncion/reverse-engineering-bluetooth-protocols) 
- [**78**星][6y] [Shell] [breadtk/onion_pi](https://github.com/breadtk/onion_pi) 
- [**70**星][7m] [Py] [busescanfly/rpi-hunter](https://github.com/busescanfly/rpi-hunter) 
- [**69**星][6y] [intrepidusgroup/rpi-atv](https://github.com/intrepidusgroup/rpi-atv) 
- [**68**星][2y] [Py] [dekunukem/facepunch](https://github.com/dekunukem/facepunch) 
- [**66**星][4y] [C] [0xabu/qemu](https://github.com/0xabu/qemu) 
- [**63**星][1y] [Py] [crescentvenus/walb](https://github.com/crescentvenus/walb) 
- [**59**星][6m] [Shell] [vs4vijay/swissarmypi](https://github.com/vs4vijay/swissarmypi) 
- [**57**星][8m] [Shell] [vay3t/hax0rpi](https://github.com/vay3t/hax0rpi) 
- [**55**星][2y] [Py] [elevenpaths/dirtytooth-raspberrypi](https://github.com/elevenpaths/dirtytooth-raspberrypi) 
- [**51**星][4y] [Py] [sensepost/wifi-rifle](https://github.com/sensepost/wifi-rifle) 
- [**41**星][3y] [KiCad Layout] [salmg/magspoofpi](https://github.com/salmg/magspoofpi) 
- [**37**星][12m] [Shell] [adityashrm21/raspberrypi-packet-sniffer](https://github.com/adityashrm21/raspberrypi-packet-sniffer) 
- [**37**星][10m] [M4] [raspberrypi/usbbootgui](https://github.com/raspberrypi/usbbootgui) 
- [**30**星][1y] [HTML] [evilbotnet/openpimap](https://github.com/evilbotnet/openpimap) 
- [**26**星][8m] [Shell] [shverni/raspberry-pi-vpn-gateway](https://github.com/shverni/raspberry-pi-vpn-gateway) 
- [**23**星][2y] [PHP] [graniet/physics-command](https://github.com/graniet/physics-command) 硬件系统分析平台(例如:树莓派3B)
- [**22**星][1y] [Py] [somu1795/shodan_raspi](https://github.com/somu1795/shodan_raspi) 
- [**22**星][6y] [Py] [zachhuff386/dashcam](https://github.com/zachhuff386/dashcam) 
- [**21**星][2m] [xxpe3/clash_raspberrypi](https://github.com/xxpe3/clash_raspberrypi) 
- [**19**星][3y] [Py] [salmg/tokenget](https://github.com/salmg/tokenget) 
- [**17**星][2y] [Shell] [cmar0ck/raspoc](https://github.com/cmar0ck/raspoc) 
- [**17**星][2y] [Shell] [hugsy/raspi-fuzz-cluster](https://github.com/hugsy/raspi-fuzz-cluster) 
- [**16**星][2y] [Py] [banjopkr/wq7tpanadapter](https://github.com/banjopkr/wq7tpanadapter) 
- [**15**星][2y] [Py] [davikawasaki/iot-security-vulnerability](https://github.com/davikawasaki/iot-security-vulnerability) 
- [**15**星][2y] [Py] [seytonic/p4wnp1](https://github.com/seytonic/p4wnp1) 
- [**14**星][6y] [Py] [learningequality/ka-lite-config-pi](https://github.com/learningequality/ka-lite-config-pi) 
- [**13**星][17d] [Py] [ekiojp/circo](https://github.com/ekiojp/circo) 
- [**12**星][1y] [Py] [niraspberryjam/raspberry-jam-resources](https://github.com/niraspberryjam/raspberry-jam-resources) 
- [**9**星][1y] [Py] [cjcase/rpi3-hackrf](https://github.com/cjcase/rpi3-hackrf) 
- [**8**星][2y] [JS] [deadpackets/hackpi](https://github.com/deadpackets/hackpi) 
- [**7**星][2y] [JS] [mohitrajain/raswall](https://github.com/mohitrajain/raswall) 
- [**6**星][2y] [Py] [mubix/p4wnp1](https://github.com/mubix/p4wnp1) 
- [**6**星][2y] [Jupyter Notebook] [yangchuan80/katyobd](https://github.com/yangchuan80/katyobd) 
- [**5**星][2y] [Shell] [wuusn/ss-redir-on-raspberry-script](https://github.com/wuusn/ss-redir-on-raspberry-script) 
- [**4**星][2y] [Py] [nethunteros/p4wnp1](https://github.com/nethunteros/p4wnp1) 
- [**3**星][2y] [Shell] [altiplanogao/raspbian-ss](https://github.com/altiplanogao/raspbian-ss) 
- [**2**星][4y] [Py] [waps101/pisquare](https://github.com/waps101/pisquare) 
- [**2**星][5y] [Py] [dhnishi/wifitracker](https://github.com/dhnishi/wifitracker) 
- [**1**星][1y] [Py] [xxxtheinternxxx/dangerouspi](https://github.com/xxxtheinternxxx/dangerouspi) 
- [**1**星][4y] [Py] [bliz937/wipy](https://github.com/bliz937/wipy) 
- [**0**星][3y] [Shell] [coffeehb/hax0rpi](https://github.com/coffeehb/hax0rpi) 


### <a id="da75af123f2f0f85a4c8ecc08a8aa848"></a>车&&汽车&&Vehicle


- [**1305**星][1m] [jaredthecoder/awesome-vehicle-security](https://github.com/jaredthecoder/awesome-vehicle-security) 
- [**768**星][1y] [C++] [polysync/oscc](https://github.com/polysync/oscc) 
- [**513**星][7m] [Py] [schutzwerk/canalyzat0r](https://github.com/schutzwerk/canalyzat0r) 
- [**261**星][1y] [Shell] [jgamblin/carhackingtools](https://github.com/jgamblin/carhackingtools) 
- [**216**星][2m] [Py] [caringcaribou/caringcaribou](https://github.com/caringcaribou/caringcaribou) 
- [**177**星][2y] [C] [mcarpenter/afl](https://github.com/mcarpenter/afl) 
- [**126**星][3y] [C] [adamcaudill/ccsrch](https://github.com/adamcaudill/ccsrch) 
- [**68**星][3y] [PowerShell] [1ricardotavares/offensive-powershell](https://github.com/1ricardotavares/offensive-powershell) 
- [**41**星][2y] [oscarakaelvis/game-of-thrones-hacking-ctf](https://github.com/oscarakaelvis/game-of-thrones-hacking-ctf) 
- [**32**星][2y] [Py] [rudsarkar/crlf-injector](https://github.com/rudsarkar/crlf-injector) 
- [**28**星][1m] [Py] [carlospolop/legion](https://github.com/carlospolop/legion) 




***


## <a id="dc89c90b80529c1f62f413288bca89c4"></a>环境配置&&分析系统


### <a id="f5a7a43f964b2c50825f3e2fee5078c8"></a>未分类-Env


- [**1571**星][13d] [HTML] [clong/detectionlab](https://github.com/clong/detectionlab) 
- [**1371**星][16d] [Go] [crazy-max/windowsspyblocker](https://github.com/crazy-max/windowsspyblocker) 
- [**1294**星][2m] [C] [cisco-talos/pyrebox](https://github.com/cisco-talos/pyrebox) 逆向沙箱，基于QEMU，Python Scriptable
- [**1117**星][10m] [JS] [mame82/p4wnp1_aloa](https://github.com/mame82/p4wnp1_aloa) 将 Rapsberry Pi Zero W 转变成灵活的渗透平台
    - 重复区段: [工具/硬件设备&&USB&树莓派/未分类-Hardware](#ff462a6d508ef20aa41052b1cc8ad044) |
- [**1022**星][1y] [Batchfile] [nextronsystems/aptsimulator](https://github.com/NextronSystems/APTSimulator) 
- [**799**星][3m] [redhuntlabs/redhunt-os](https://github.com/redhuntlabs/redhunt-os) 
- [**781**星][2m] [sh4hin/androl4b](https://github.com/sh4hin/androl4b) 用于评估Android应用程序，逆向工程和恶意软件分析的虚拟机
    - 重复区段: [工具/移动&&Mobile/Android](#fe88ee8c0df10870b44c2dedcd86d3d3) |
- [**560**星][5m] [Ruby] [sliim/pentest-env](https://github.com/sliim/pentest-env) 
- [**309**星][3y] [Shell] [screetsec/lalin](https://github.com/screetsec/lalin) 
- [**210**星][11m] [Shell] [proxycannon/proxycannon-ng](https://github.com/proxycannon/proxycannon-ng) 使用多个云环境构建私人僵尸网络, 用于渗透测试和RedTeaming


### <a id="cf07b04dd2db1deedcf9ea18c05c83e0"></a>Linux-Distro


- [**2830**星][1m] [Py] [trustedsec/ptf](https://github.com/trustedsec/ptf) 创建基于Debian/Ubuntu/ArchLinux的渗透测试环境
- [**2310**星][1m] [security-onion-solutions/security-onion](https://github.com/security-onion-solutions/security-onion) 
- [**1459**星][13d] [Shell] [blackarch/blackarch](https://github.com/blackarch/blackarch) 
- [**342**星][13d] [Shell] [archstrike/archstrike](https://github.com/archstrike/archstrike) 
- [**76**星][4y] [oguzhantopgul/vezir-project](https://github.com/oguzhantopgul/vezir-project) 


### <a id="4709b10a8bb691204c0564a3067a0004"></a>环境自动配置&&自动安装


- [**3058**星][2m] [PowerShell] [fireeye/commando-vm](https://github.com/fireeye/commando-vm) 
- [**1686**星][18d] [PowerShell] [fireeye/flare-vm](https://github.com/fireeye/flare-vm) 火眼发布用于 Windows 恶意代码分析的虚拟机：FLARE VM
- [**74**星][9m] [Py] [inquest/python-sandboxapi](https://github.com/inquest/python-sandboxapi) 




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
- [**418**星][4y] [HTML] [praetorian-code/dvrf](https://github.com/praetorian-code/DVRF) 
- [**311**星][28d] [Py] [owasp/owasp-vwad](https://github.com/owasp/owasp-vwad) 
- [**308**星][3y] [PHP] [snoopysecurity/dvws](https://github.com/snoopysecurity/dvws) 
- [**262**星][1y] [PHP] [sqlmapproject/testenv](https://github.com/sqlmapproject/testenv) 
- [**254**星][1y] [PHP] [interference-security/dvws](https://github.com/interference-security/dvws) 
- [**252**星][2m] [PHP] [incredibleindishell/ssrf_vulnerable_lab](https://github.com/incredibleindishell/ssrf_vulnerable_lab) 
- [**250**星][2y] [Ruby] [bcoles/ssrf_proxy](https://github.com/bcoles/ssrf_proxy) 
- [**237**星][2m] [JS] [owasp/dvsa](https://github.com/owasp/dvsa) 
- [**218**星][11m] [C] [stephenbradshaw/vulnserver](https://github.com/stephenbradshaw/vulnserver) 
- [**217**星][1y] [dustyfresh/php-vulnerability-audit-cheatsheet](https://github.com/dustyfresh/php-vulnerability-audit-cheatsheet) 
- [**177**星][7m] [C] [owasp/igoat-swift](https://github.com/owasp/igoat-swift) 
- [**169**星][4y] [PHP] [chuckfw/owaspbwa](https://github.com/chuckfw/owaspbwa) 
- [**162**星][3y] [JS] [nvisium/django.nv](https://github.com/nvisium/django.nv) 
- [**156**星][4m] [Py] [certcc/trommel](https://github.com/certcc/trommel) Sift Through Embedded Device Files to Identify Potential Vulnerable Indicators
- [**155**星][1y] [JS] [logicalhacking/dvhma](https://github.com/logicalhacking/dvhma) 
- [**153**星][2y] [HTML] [mpirnat/lets-be-bad-guys](https://github.com/mpirnat/lets-be-bad-guys) 
- [**149**星][2y] [Java] [psiinon/bodgeit](https://github.com/psiinon/bodgeit) 
- [**144**星][2y] [Py] [appsecco/vulnerable-apps](https://github.com/appsecco/vulnerable-apps) 
- [**141**星][3m] [PHP] [incredibleindishell/cors-vulnerable-lab](https://github.com/incredibleindishell/cors-vulnerable-lab) 
- [**135**星][1y] [PowerShell] [gpoguy/getvulnerablegpo](https://github.com/gpoguy/getvulnerablegpo) 
- [**134**星][2y] [Py] [gradiusx/hevd-python-solutions](https://github.com/gradiusx/hevd-python-solutions) 
- [**120**星][7m] [Perl] [davisjam/vuln-regex-detector](https://github.com/davisjam/vuln-regex-detector) 
- [**117**星][5y] [Py] [gdssecurity/jetleak-testing-script](https://github.com/gdssecurity/jetleak-testing-script) 
- [**106**星][2y] [geosn0w/myriam](https://github.com/geosn0w/myriam) 
- [**105**星][2m] [Java] [dogangcr/vulnerable-sso](https://github.com/dogangcr/vulnerable-sso) 
- [**104**星][3y] [Py] [3gstudent/smbtouch-scanner](https://github.com/3gstudent/smbtouch-scanner) 
- [**101**星][3y] [JS] [jkingsman/bishop](https://github.com/jkingsman/bishop) 
- [**100**星][3y] [Go] [zaf/sipshock](https://github.com/zaf/sipshock) 
- [**95**星][1m] [PHP] [commixproject/commix-testbed](https://github.com/commixproject/commix-testbed) 
- [**94**星][26d] [CMake] [abhi-r3v0/evabs](https://github.com/abhi-r3v0/evabs) 
- [**94**星][2m] [geeksonsecurity/vuln-web-apps](https://github.com/geeksonsecurity/vuln-web-apps) 
- [**93**星][10m] [Java] [cspf-founder/javavulnerablelab](https://github.com/cspf-founder/javavulnerablelab) 
- [**90**星][3y] [PowerShell] [secvulture/dvta](https://github.com/secvulture/dvta) 
- [**85**星][2y] [vegabird/xvna](https://github.com/vegabird/xvna) 带漏洞的Node App
- [**82**星][5y] [Shell] [anexia-it/winshock-test](https://github.com/anexia-it/winshock-test) 
- [**78**星][7y] [C#] [g0tmi1k/vulninjector](https://github.com/g0tmi1k/vulninjector) 
- [**70**星][1y] [PHP] [opsxcq/docker-vulnerable-dvwa](https://github.com/opsxcq/docker-vulnerable-dvwa) 
- [**67**星][3y] [HTML] [davevs/dvxte](https://github.com/davevs/dvxte) 
- [**64**星][5m] [PHP] [owasp/owaspwebgoatphp](https://github.com/owasp/owaspwebgoatphp) 
- [**64**星][10m] [Py] [we45/dvfaas-damn-vulnerable-functions-as-a-service](https://github.com/we45/dvfaas-damn-vulnerable-functions-as-a-service) 
- [**63**星][5y] [CSS] [opensecurityresearch/fsexploitme](https://github.com/opensecurityresearch/fsexploitme) 
- [**62**星][11m] [Ruby] [livingsocial/bundler-patch](https://github.com/livingsocial/bundler-patch) 
- [**58**星][5m] [Py] [b-mueller/scrooge-mcetherface](https://github.com/b-mueller/scrooge-mcetherface) 
- [**57**星][2y] [C] [jas502n/ubuntu-0day](https://github.com/jas502n/ubuntu-0day) 
- [**56**星][28d] [Java] [appsecco/vyapi](https://github.com/appsecco/vyapi) 
- [**56**星][2m] [Go] [wickett/lambhack](https://github.com/wickett/lambhack) 
- [**52**星][2y] [C] [cn33liz/hsevd-stackoverflowx64](https://github.com/cn33liz/hsevd-stackoverflowx64) 
- [**50**星][2y] [Py] [jflyup/goms17-010](https://github.com/jflyup/goms17-010) 
- [**48**星][4y] [Py] [breakingmalware/avulnerabilitychecker](https://github.com/breakingmalware/avulnerabilitychecker) 
- [**45**星][9m] [Java] [veracode-research/actuator-testbed](https://github.com/veracode-research/actuator-testbed) 
- [**45**星][5y] [Java] [ikkisoft/parrotng](https://github.com/ikkisoft/parrotng) 
- [**44**星][2y] [Py] [649/memfixed-mitigation-tool](https://github.com/649/memfixed-mitigation-tool) 
- [**44**星][3y] [Shell] [shotokanzh/pa-th-zuzu](https://github.com/shotokanzh/pa-th-zuzu) 
- [**43**星][1y] [Py] [649/apache-struts-shodan-exploit](https://github.com/649/apache-struts-shodan-exploit) 
- [**43**星][3y] [C#] [jacobmisirian/dbltekgoippwn](https://github.com/jacobmisirian/dbltekgoippwn) 
- [**43**星][5y] [JS] [rapid7/dllhijackauditkit](https://github.com/rapid7/dllhijackauditkit) 
- [**43**星][4y] [JS] [nvisium/grails-nv](https://github.com/nVisium/grails-nV) 
- [**42**星][2y] [C] [invictus-0x90/vulnerable_linux_driver](https://github.com/invictus-0x90/vulnerable_linux_driver) 
- [**42**星][14d] [C++] [tihmstar/ra1nsn0w](https://github.com/tihmstar/ra1nsn0w) 
- [**41**星][2y] [PHP] [mddanish/vulnerable-otp-application](https://github.com/mddanish/vulnerable-otp-application) 
- [**41**星][2y] [JS] [opsxcq/exploit-cve-2016-6515](https://github.com/opsxcq/exploit-cve-2016-6515) 
- [**41**星][3y] [Py] [t0kx/exploit-cve-2015-3306](https://github.com/t0kx/exploit-cve-2015-3306) 
- [**39**星][3y] [C] [cn33liz/hsevd-arbitraryoverwritegdi](https://github.com/cn33liz/hsevd-arbitraryoverwritegdi) 
- [**39**星][2m] [Ruby] [mrackwitz/jeroboam](https://github.com/mrackwitz/jeroboam) 
- [**39**星][5y] [Shell] [tjluoma/bash-fix](https://github.com/tjluoma/bash-fix) 
- [**39**星][4m] [Java] [scalesec/vulnado](https://github.com/scalesec/vulnado) 
- [**38**星][3m] [Java] [voorivex/andrill](https://github.com/voorivex/andrill) 
- [**36**星][3y] [Py] [the-c0d3r/sqli-scanner](https://github.com/the-c0d3r/sqli-scanner) 
- [**35**星][2y] [PHP] [havysec/vulnerable-scene](https://github.com/havysec/vulnerable-scene) 
- [**35**星][3m] [Go] [jakejarvis/subtake](https://github.com/jakejarvis/subtake) 
- [**34**星][30d] [C] [alxbrn/gdrv-loader](https://github.com/alxbrn/gdrv-loader) 
- [**33**星][2y] [Py] [d3vilbug/brutal_ssh](https://github.com/d3vilbug/brutal_ssh) SSH Login brute force, scan for vulnerable version and 0 day exploit (under development)
- [**31**星][2y] [C++] [mgeeky/hevd_kernel_exploit](https://github.com/mgeeky/hevd_kernel_exploit) 
- [**31**星][2y] [HTML] [mthbernardes/heimdall_webserver](https://github.com/mthbernardes/heimdall_webserver) heimdall_webserver：在 *inux 服务器上集中管理有漏洞的包（vulnerables packages）
- [**30**星][2y] [Java] [htbridge/pivaa](https://github.com/htbridge/pivaa) 
- [**30**星][1y] [CSS] [m6a-uds/dvca](https://github.com/m6a-uds/dvca) 
- [**30**星][7m] [HTML] [skepticfx/damnvulnerable.me](https://github.com/skepticfx/damnvulnerable.me) 
- [**30**星][5y] [Py] [tripwire/openssl-ccs-inject-test](https://github.com/tripwire/openssl-ccs-inject-test) 
- [**30**星][1y] [PowerShell] [nsacyber/detect-cve-2017-15361-tpm](https://github.com/nsacyber/Detect-CVE-2017-15361-TPM) 
- [**29**星][2y] [misterch0c/solidlity-vulnerable](https://github.com/misterch0c/solidlity-vulnerable) 
- [**28**星][1y] [C++] [abatchy17/hevd-exploits](https://github.com/abatchy17/hevd-exploits) 
- [**28**星][4y] [Java] [nvisium/moneyx](https://github.com/nvisium/moneyx) 
- [**27**星][10m] [JS] [chainsecurity/constantinople-reentrancy](https://github.com/chainsecurity/constantinople-reentrancy) 
- [**27**星][3y] [C] [cn33liz/hsevd-stackoverflow](https://github.com/cn33liz/hsevd-stackoverflow) 
- [**27**星][3y] [Py] [d4vinci/clickjacking-tester](https://github.com/d4vinci/clickjacking-tester) 
- [**27**星][26d] [Py] [kudelskisecurity/fumblechain](https://github.com/kudelskisecurity/fumblechain) 
- [**27**星][2y] [PHP] [securelayer7/csv-injection-vulnerable-php-script-](https://github.com/securelayer7/csv-injection-vulnerable-php-script-) 
- [**27**星][2y] [HTML] [torque59/aws-vulnerable-lambda](https://github.com/torque59/aws-vulnerable-lambda) 
- [**26**星][2y] [Py] [danmcinerney/smb-autopwn](https://github.com/danmcinerney/smb-autopwn) 
- [**25**星][3y] [JS] [sethsec/nodejs-ssrf-app](https://github.com/sethsec/nodejs-ssrf-app) 
- [**25**星][3y] [C++] [vix597/vulny](https://github.com/vix597/vulny) 
- [**24**星][2y] [Groovy] [continuumsecurity/ropeytasks](https://github.com/continuumsecurity/ropeytasks) 
- [**24**星][3y] [Py] [sizzop/hevd-exploits](https://github.com/sizzop/hevd-exploits) 
- [**23**星][3y] [C] [cn33liz/hsevd-arbitraryoverwrite](https://github.com/cn33liz/hsevd-arbitraryoverwrite) 
- [**22**星][3y] [Py] [t0kx/exploit-cve-2016-9920](https://github.com/t0kx/exploit-cve-2016-9920) 


### <a id="a6a2bb02c730fc1e1f88129d4c2b3d2e"></a>WebApp


- [**2902**星][13d] [JS] [webgoat/webgoat](https://github.com/webgoat/webgoat) 带漏洞WebApp
- [**2556**星][15d] [JS] [bkimminich/juice-shop](https://github.com/bkimminich/juice-shop) 
- [**698**星][2y] [HTML] [rapid7/hackazon](https://github.com/rapid7/hackazon) 
- [**459**星][14d] [Py] [stamparm/dsvw](https://github.com/stamparm/dsvw) 
- [**427**星][3m] [Py] [payatu/tiredful-api](https://github.com/payatu/tiredful-api) 
- [**289**星][1y] [CSS] [appsecco/dvna](https://github.com/appsecco/dvna) 
- [**226**星][2y] [PHP] [adamdoupe/wackopicko](https://github.com/adamdoupe/wackopicko) 
- [**218**星][5m] [JS] [cr0hn/vulnerable-node](https://github.com/cr0hn/vulnerable-node) 
- [**68**星][2y] [Py] [qazbnm456/vwgen](https://github.com/qazbnm456/vwgen) 
    - 重复区段: [工具/靶机&&漏洞环境&&漏洞App/靶机生成](#60b4d03a0cff6efc4b9b998a4a1a79d6) |
- [**57**星][3y] [PHP] [cspf-founder/btslab](https://github.com/cspf-founder/btslab) 
- [**49**星][2y] [JS] [secureskytechnology/badlibrary](https://github.com/secureskytechnology/badlibrary) 
- [**46**星][4m] [PHP] [owasp/vulnerable-web-application](https://github.com/owasp/vulnerable-web-application) 


### <a id="60b4d03a0cff6efc4b9b998a4a1a79d6"></a>靶机生成


- [**1699**星][13d] [Ruby] [cliffe/secgen](https://github.com/cliffe/secgen) 
- [**1408**星][5m] [PHP] [s4n7h0/xvwa](https://github.com/s4n7h0/xvwa) 
- [**305**星][7m] [Ruby] [secgen/secgen](https://github.com/secgen/secgen) 
- [**68**星][2y] [Py] [qazbnm456/vwgen](https://github.com/qazbnm456/vwgen) 
    - 重复区段: [工具/靶机&&漏洞环境&&漏洞App/WebApp](#a6a2bb02c730fc1e1f88129d4c2b3d2e) |


### <a id="383ad9174d3f7399660d36cd6e0b2c00"></a>收集


- [**735**星][4y] [fabiobaroni/awesome-exploit-development](https://github.com/fabiobaroni/awesome-exploit-development) 
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/资源收集](#750f4c05b5ab059ce4405f450b56d720) |
- [**358**星][4m] [xtiankisutsa/awesome-mobile-ctf](https://github.com/xtiankisutsa/awesome-mobile-ctf) 
    - 重复区段: [工具/CTF&&HTB/收集](#30c4df38bcd1abaaaac13ffda7d206c6) |


### <a id="aa60e957e4da03301643a7abe4c1938a"></a>MobileApp


- [**645**星][4m] [Java] [dineshshetty/android-insecurebankv2](https://github.com/dineshshetty/android-insecurebankv2) 
- [**433**星][4y] [Java] [payatu/diva-android](https://github.com/payatu/diva-android) 
- [**358**星][5y] [Objective-C] [prateek147/dvia](https://github.com/prateek147/dvia) 
- [**252**星][2y] [Swift] [prateek147/dvia-v2](https://github.com/prateek147/dvia-v2) 
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
- [**2523**星][2y] [Py] [google/nogotofail](https://github.com/google/nogotofail) 网络安全测试, 辅助定位和修复弱TLS/SSL连接和敏感明文流量
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
- [**928**星][2y] [Py] [tomchop/malcom](https://github.com/tomchop/malcom) 
- [**920**星][2y] [JS] [diracdeltas/sniffly](https://github.com/diracdeltas/sniffly) 
- [**916**星][3y] [Eagle] [samyk/keysweeper](https://github.com/samyk/keysweeper) 
- [**853**星][3m] [C] [cisco/joy](https://github.com/cisco/joy) 捕获和分析网络流数据和intraflow数据，用于网络研究、取证和安全监视
- [**820**星][6m] [Go] [40t/go-sniffer](https://github.com/40t/go-sniffer) 
- [**817**星][29d] [C] [zerbea/hcxtools](https://github.com/zerbea/hcxtools) 
- [**800**星][2m] [C] [emmericp/ixy](https://github.com/emmericp/ixy) 
- [**790**星][7m] [Py] [phaethon/kamene](https://github.com/phaethon/kamene) 
- [**779**星][2m] [C] [netsniff-ng/netsniff-ng](https://github.com/netsniff-ng/netsniff-ng) 
- [**714**星][2y] [Py] [madeye/sssniff](https://github.com/madeye/sssniff) sssniff：ShadowSocks流量嗅探
- [**713**星][2m] [Py] [cloudflare/bpftools](https://github.com/cloudflare/bpftools) 
- [**707**星][2y] [Py] [google/ssl_logger](https://github.com/google/ssl_logger) 解密并记录进程的SSL 流程
- [**652**星][1m] [Py] [kbandla/dpkt](https://github.com/kbandla/dpkt) 
- [**645**星][1m] [C] [zerbea/hcxdumptool](https://github.com/zerbea/hcxdumptool) 
- [**636**星][1y] [Go] [ga0/netgraph](https://github.com/ga0/netgraph) 
- [**633**星][1y] [Py] [mschwager/dhcpwn](https://github.com/mschwager/dhcpwn)  testing DHCP IP exhaustion attacks， sniff local DHCP traffic
- [**597**星][3y] [Py] [omriher/captipper](https://github.com/omriher/captipper) 
- [**509**星][9m] [Perl] [mrash/fwknop](https://github.com/mrash/fwknop) 
- [**505**星][7m] [C++] [kohler/click](https://github.com/kohler/click) 
- [**499**星][1m] [C] [sam-github/libnet](https://github.com/libnet/libnet) 
- [**489**星][2y] [Py] [sjvasquez/web-traffic-forecasting](https://github.com/sjvasquez/web-traffic-forecasting) 
- [**458**星][1m] [Py] [netzob/netzob](https://github.com/netzob/netzob)  Protocol Reverse Engineering, Modeling and Fuzzing
- [**453**星][3y] [C] [haka-security/haka](https://github.com/haka-security/haka) a collection of tools that allows capturing TCP/IP packets and filtering them based on Lua policy files.
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
- [**359**星][3y] [C] [rafael-santiago/pig](https://github.com/rafael-santiago/pig) 
- [**330**星][12m] [Ruby] [packetfu/packetfu](https://github.com/packetfu/packetfu) 数据包篡改工具。Ruby语言编写。
- [**326**星][14d] [TypeScript] [shroudedcode/apk-mitm](https://github.com/shroudedcode/apk-mitm) 
    - 重复区段: [工具/移动&&Mobile/Android](#fe88ee8c0df10870b44c2dedcd86d3d3) |[工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**315**星][5y] [C] [seastorm/puttyrider](https://github.com/seastorm/puttyrider) 
- [**304**星][2y] [JS] [kristian-lange/net-glimpse](https://github.com/kristian-lange/net-glimpse) 
- [**303**星][1y] [Py] [tintinweb/scapy-ssl_tls](https://github.com/tintinweb/scapy-ssl_tls) 
- [**292**星][4m] [C] [pulkin/esp8266-injection-example](https://github.com/pulkin/esp8266-injection-example) 
- [**278**星][23d] [C] [troglobit/nemesis](https://github.com/troglobit/nemesis) 网络数据包构造和注入的命令行工具
- [**273**星][9m] [C] [jiaoxianjun/btle](https://github.com/jiaoxianjun/btle) 
- [**258**星][2y] [Py] [xdavidhu/probesniffer](https://github.com/xdavidhu/probesniffer) 
- [**254**星][2m] [Go] [sachaos/tcpterm](https://github.com/sachaos/tcpterm) 
- [**243**星][7m] [Py] [needmorecowbell/sniff-paste](https://github.com/needmorecowbell/sniff-paste) 
- [**241**星][2m] [C] [nccgroup/sniffle](https://github.com/nccgroup/sniffle) 
- [**233**星][2y] [C++] [pellegre/libcrafter](https://github.com/pellegre/libcrafter) libcrafter：C++ 编写的网络数据包嗅探和解码库
- [**228**星][3y] [C] [omriiluz/nrf24-btle-decoder](https://github.com/omriiluz/nrf24-btle-decoder) 
- [**218**星][18d] [Py] [ghostop14/sparrow-wifi](https://github.com/ghostop14/sparrow-wifi) 
    - 重复区段: [工具/蓝牙&&Bluetooth](#ceb90405292daed9bb32ac20836c219a) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**213**星][2m] [C] [dns-oarc/dnscap](https://github.com/dns-oarc/dnscap) 
- [**206**星][3y] [Py] [countercept/doublepulsar-c2-traffic-decryptor](https://github.com/countercept/doublepulsar-c2-traffic-decryptor) 
- [**196**星][3y] [Py] [isofew/sssniff](https://github.com/isofew/sssniff) 
- [**194**星][5m] [Go] [cuishark/cuishark](https://github.com/cuishark/cuishark) 
- [**172**星][2m] [Py] [openvizsla/ov_ftdi](https://github.com/openvizsla/ov_ftdi) 
- [**172**星][6y] [Py] [syworks/wireless-ids](https://github.com/syworks/wireless-ids) 
- [**168**星][1y] [Shell] [brannondorsey/sniff-probes](https://github.com/brannondorsey/sniff-probes) 
- [**165**星][4y] [Perl] [xme/hoover](https://github.com/xme/hoover) 
- [**149**星][11m] [Py] [shirosaidev/sharesniffer](https://github.com/shirosaidev/sharesniffer) 远程文件系统自动嗅探、挂载和爬取
- [**142**星][11m] [C] [caesar0301/http-sniffer](https://github.com/caesar0301/http-sniffer) 
- [**140**星][1y] [Py] [secureworks/flowsynth](https://github.com/secureworks/flowsynth) 
- [**135**星][2y] [Objective-C] [objective-see/sniffmk](https://github.com/objective-see/sniffmk) 
- [**135**星][7y] [C] [t57root/pwnginx](https://github.com/t57root/pwnginx) 
- [**132**星][9m] [C] [yadutaf/tracepkt](https://github.com/yadutaf/tracepkt) 跟踪 Linux 系统 PING 数据包跨网络接口和命名空间的路线，支持 IPv4 及 IPv6
- [**114**星][1y] [C] [nospaceships/raw-socket-sniffer](https://github.com/nospaceships/raw-socket-sniffer) 
- [**101**星][1y] [Py] [macr0phag3/sniffer](https://github.com/macr0phag3/sniffer) 
- [**94**星][1y] [HTML] [frizb/sourcecodesniffer](https://github.com/frizb/sourcecodesniffer) 
- [**75**星][2m] [Py] [r00ts3c/ddos-rootsec](https://github.com/r00ts3c/ddos-rootsec) 
- [**75**星][5y] [C++] [yveaux/nrf24_sniffer](https://github.com/yveaux/nrf24_sniffer) 
- [**73**星][9m] [Verilog] [denandz/lpc_sniffer_tpm](https://github.com/denandz/lpc_sniffer_tpm) 
- [**73**星][2y] [C++] [vecna/sniffjoke](https://github.com/vecna/sniffjoke) 
- [**65**星][1y] [Py] [ch3k1/squidmagic](https://github.com/ch3k1/squidmagic) 
- [**65**星][5y] [Py] [aperturelabsltd/hdmi-sniff](https://github.com/AdamLaurie/hdmi-sniff) 
- [**64**星][3y] [Py] [milesrichardson/docker-nfqueue-scapy](https://github.com/milesrichardson/docker-nfqueue-scapy) Docker容器，使用python脚本在netfilter队列中监听数据包，并使用scapy操作数据包。
- [**64**星][3y] [Py] [scipag/btle-sniffer](https://github.com/scipag/btle-sniffer) 
- [**61**星][7y] [C++] [hurley25/sniffer](https://github.com/hurley25/sniffer) 
- [**56**星][4y] [Go] [zond/qisniff](https://github.com/zond/qisniff) 
- [**53**星][4y] [Py] [geovation/wifispy](https://github.com/geovation/wifispy) 
- [**50**星][9m] [Java] [ruedigergad/clj-net-pcap](https://github.com/ruedigergad/clj-net-pcap) 
- [**50**星][1y] [Py] [zhovner/airport-sniffer](https://github.com/zhovner/airport-sniffer) 
- [**49**星][3m] [Java] [p1sec/sigfw](https://github.com/p1sec/sigfw) 
- [**47**星][7y] [C++] [1184893257/simplesniffer](https://github.com/1184893257/simplesniffer) 
- [**47**星][3y] [C] [rodrigoalvesvieira/soundkeylogger](https://github.com/rodrigoalvesvieira/soundkeylogger) 
- [**47**星][1y] [Go] [zredshift/mimemagic](https://github.com/zredshift/mimemagic) 
- [**44**星][8m] [C++] [ncatlin/exilesniffer](https://github.com/ncatlin/exilesniffer) 
- [**44**星][1y] [C] [petabi/sniffles](https://github.com/petabi/sniffles) Packet Capture Generator for IDS and Regular Expression Evaluation
- [**43**星][5y] [IDL] [riverloopsec/apimote](https://github.com/riverloopsec/apimote) 
- [**39**星][3y] [Py] [tengzhangchao/websniff](https://github.com/tengzhangchao/websniff) 
- [**39**星][5y] [Py] [flankerhqd/wifimonster](https://github.com/flankerhqd/wifimonster) 
- [**38**星][7y] [Py] [mainframed/mfsniffer](https://github.com/mainframed/mfsniffer) 
- [**38**星][15d] [Go] [x-way/iptables-tracer](https://github.com/x-way/iptables-tracer) 
- [**34**星][12m] [Py] [activecm/passer](https://github.com/activecm/passer) 
- [**32**星][1y] [Py] [oros42/dns_sniffer](https://github.com/oros42/dns_sniffer) 
- [**29**星][6y] [Py] [catalyst256/sniffmypackets](https://github.com/catalyst256/sniffmypackets) 
- [**25**星][4m] [Py] [mechpen/sockdump](https://github.com/mechpen/sockdump) 
- [**24**星][6m] [Py] [antisomnus/sniffer](https://github.com/antisomnus/sniffer) 
- [**21**星][9y] [C] [zapotek/cdpsnarf](https://github.com/zapotek/cdpsnarf) 
- [**20**星][3y] [C] [a232319779/phantom-3-standard](https://github.com/a232319779/phantom-3-standard) 
- [**19**星][7y] [C++] [6e726d/native-wifi-api-beacon-sniffer](https://github.com/6e726d/native-wifi-api-beacon-sniffer) 
- [**18**星][6y] [Py] [eldraco/darm](https://github.com/eldraco/darm) 
- [**18**星][5y] [C++] [halfdanj/ofxsniffer](https://github.com/halfdanj/ofxsniffer) 
- [**17**星][3y] [JS] [bugscanteam/bugrequest](https://github.com/bugscanteam/bugrequest) 
- [**14**星][2y] [C] [julioreynaga/sniffer](https://github.com/julioreynaga/sniffer) 
- [**12**星][4y] [PowerShell] [harmj0y/netripper](https://github.com/harmj0y/netripper) 
- [**10**星][29d] [Py] [gisdev01/security-ssid-abi](https://github.com/gisdev01/security-ssid-abi) 
- [**10**星][4y] [C] [wifimon/wifimon](https://github.com/wifimon/wifimon) 
- [**8**星][8m] [Py] [ajackal/cherrywasp](https://github.com/ajackal/cherrywasp) 
- [**6**星][1y] [Py] [crcarlo/arp-spoofing-python](https://github.com/crcarlo/arp-spoofing-python) 
- [**6**星][21d] [Py] [programmingathlete/brutesniffing_fisher](https://github.com/programmingathlete/brutesniffing_fisher) 
- [**4**星][7y] [Shell] [dc414/fakeap_pwnage](https://github.com/dc414/fakeap_pwnage) 
- [**4**星][4y] [Visual Basic] [pyblendnet-js/realtermbuspiratesniff](https://github.com/pyblendnet-js/realtermbuspiratesniff) 
- [**4**星][2y] [Py] [wangjksjtu/jksniffer](https://github.com/wangjksjtu/jksniffer) 
- [**4**星][6m] [JS] [sipcapture/hepjack.js](https://github.com/sipcapture/hepjack.js) 
- [**3**星][2y] [Py] [orf53975/malware](https://github.com/orf53975/malware) 
- [**3**星][5y] [C++] [simonberson/chromeurlsniffer](https://github.com/simonberson/chromeurlsniffer) 
- [**3**星][4y] [Py] [wirelesshack/desniffer](https://github.com/wirelesshack/desniffer) 
- [**3**星][4y] [C] [bwoolf1122/tcp-seqnum](https://github.com/bwoolf1122/tcp-seqnum) 
- [**3**星][7y] [Py] [0x0d/wallofshame](https://github.com/0x0d/wallofshame) 
- [**2**星][9m] [Shell] [b3n-j4m1n/flood-kick-sniff](https://github.com/b3n-j4m1n/flood-kick-sniff) 
- [**2**星][1y] [Go] [progtramder/webproxy](https://github.com/progtramder/webproxy) 
- [**2**星][5y] [Py] [depthdeluxe/dot11sniffer](https://github.com/depthdeluxe/dot11sniffer) 
- [**2**星][2y] [C] [samclarke2012/ssidentity](https://github.com/samclarke2012/ssidentity) 
- [**2**星][9y] [de-ibh/mupe](https://github.com/de-ibh/mupe) 
- [**1**星][3y] [Py] [wouterbudding/scapygelftograylog2](https://github.com/wouterbudding/scapygelftograylog2) 
- [**1**星][4y] [Py] [dcrisan/wifi-802.11-demo-sniffer](https://github.com/dcrisan/wifi-802.11-demo-sniffer) 
- [**1**星][5y] [C] [gauravpatwardhan/wireless-sniffer](https://github.com/gauravpatwardhan/wireless-sniffer) 
- [**1**星][6y] [C] [saintkepha/airtraf](https://github.com/saintkepha/airtraf) 
- [**0**星][11y] [C] [jackiexie168/como](https://github.com/jackiexie168/como) 
- [**0**星][7y] [Py] [dappiu/rifsniff](https://github.com/dappiu/rifsniff) 


### <a id="11c73d3e2f71f3914a3bca35ba90de36"></a>中间人&&MITM


- [**16743**星][18d] [Py] [mitmproxy/mitmproxy](https://github.com/mitmproxy/mitmproxy) 
    - 重复区段: [工具/通信&&代理&&反向代理&&隧道/未分类-Proxy](#56acb7c49c828d4715dce57410d490d1) |
- [**6294**星][12d] [Go] [bettercap/bettercap](https://github.com/bettercap/bettercap) 新版的bettercap, Go 编写. bettercap 是强大的、模块化、可移植且易于扩展的 MITM 框架, 旧版用 Ruby 编写
- [**2886**星][1y] [Py] [byt3bl33d3r/mitmf](https://github.com/byt3bl33d3r/mitmf) 
- [**2721**星][1m] [Go] [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2) 独立的MITM攻击工具，用于登录凭证钓鱼，可绕过双因素认证
    - 重复区段: [工具/社工(SET)&&钓鱼&&鱼叉攻击/钓鱼&&Phish](#290e9ae48108d21d6d8b9ea9e74d077d) |
- [**2555**星][2y] [evilsocket/bettercap](https://github.com/evilsocket/bettercap) 中间人攻击框架，功能完整，模块化设计，轻便且易于扩展。
- [**2480**星][15d] [Py] [evilsocket/pwnagotchi](https://github.com/evilsocket/pwnagotchi) 
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**1405**星][2y] [Py] [xdavidhu/mitmap](https://github.com/xdavidhu/mitmap) 
- [**1288**星][2y] [Go] [malfunkt/hyperfox](https://github.com/malfunkt/hyperfox) hyperfox: 在局域网上代理和记录 HTTP 和 HTTPs 通信
- [**1258**星][2m] [Go] [unrolled/secure](https://github.com/unrolled/secure) 
- [**1199**星][3m] [C] [droe/sslsplit](https://github.com/droe/sslsplit) 透明SSL/TLS拦截
- [**1184**星][2m] [Py] [jtesta/ssh-mitm](https://github.com/jtesta/ssh-mitm) ssh-mitm：SSH 中间人攻击工具
- [**1085**星][7m] [Ruby] [lionsec/xerosploit](https://github.com/lionsec/xerosploit) 
- [**1017**星][3m] [PowerShell] [kevin-robertson/inveigh](https://github.com/kevin-robertson/inveigh) 
- [**999**星][7m] [Go] [justinas/nosurf](https://github.com/justinas/nosurf) 
- [**983**星][1y] [HTML] [sensepost/mana](https://github.com/sensepost/mana) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**977**星][30d] [Py] [syss-research/seth](https://github.com/syss-research/seth) 
- [**945**星][2y] [Py] [arnaucube/coffeeminer](https://github.com/arnaucube/coffeeMiner) 
- [**778**星][2y] [Py] [secretsquirrel/bdfproxy](https://github.com/secretsquirrel/bdfproxy) 
- [**568**星][11m] [HTML] [r00t-3xp10it/morpheus](https://github.com/r00t-3xp10it/morpheus) 
- [**551**星][8m] [Py] [fox-it/mitm6](https://github.com/fox-it/mitm6) mitm6: 攻击代码
- [**541**星][2y] [TypeScript] [samdenty99/injectify](https://github.com/samdenty/injectify) injectify: 对网站实行中间人攻击的框架
- [**521**星][4y] [C] [jondonym/peinjector](https://github.com/jondonym/peinjector) 
- [**509**星][5m] [JS] [moll/node-mitm](https://github.com/moll/node-mitm) 
- [**474**星][3y] [CoffeeScript] [rastapasta/pokemon-go-mitm](https://github.com/rastapasta/pokemon-go-mitm) 
- [**432**星][1y] [JS] [digitalsecurity/btlejuice](https://github.com/digitalsecurity/btlejuice) 
- [**426**星][8y] [C++] [moxie0/sslsniff](https://github.com/moxie0/sslsniff) 
- [**393**星][3m] [Go] [cloudflare/mitmengine](https://github.com/cloudflare/mitmengine) 
- [**390**星][2y] [Py] [conorpp/btproxy](https://github.com/conorpp/btproxy) 
- [**382**星][3m] [JS] [joeferner/node-http-mitm-proxy](https://github.com/joeferner/node-http-mitm-proxy) 
- [**380**星][5y] [Py] [meeee/pushproxy](https://github.com/mfrister/pushproxy) 
- [**379**星][1y] [JS] [securing/gattacker](https://github.com/securing/gattacker) 
- [**366**星][3y] [Java] [ssun125/lanmitm](https://github.com/ssun125/lanmitm) 
- [**365**星][10m] [Py] [crypt0s/fakedns](https://github.com/crypt0s/fakedns) 
- [**347**星][17d] [Py] [gosecure/pyrdp](https://github.com/gosecure/pyrdp) 
- [**347**星][1y] [Py] [quickbreach/smbetray](https://github.com/quickbreach/smbetray) 
- [**339**星][2y] [Shell] [brannondorsey/mitm-router](https://github.com/brannondorsey/mitm-router) mitm-router：将任何一台Linux 计算机转变成公开的 Wi-Fi 网络，并且默认Man-in-the-middle 所有 http 流量
- [**326**星][14d] [TypeScript] [shroudedcode/apk-mitm](https://github.com/shroudedcode/apk-mitm) 
    - 重复区段: [工具/移动&&Mobile/Android](#fe88ee8c0df10870b44c2dedcd86d3d3) |[工具/浏览嗅探&&流量拦截&&流量分析&&中间人/未分类-Network](#99398a5a8aaf99228829dadff48fb6a7) |
- [**294**星][1y] [Shell] [cryptolok/ghostinthenet](https://github.com/cryptolok/ghostinthenet) 
    - 重复区段: [工具/扫描器&&安全扫描&&App扫描&&漏洞扫描/未分类-Scanner](#de63a029bda6a7e429af272f291bb769) |
- [**280**星][2y] [Py] [websploit/websploit](https://github.com/websploit/websploit) 
- [**267**星][3y] [JS] [wuchangming/https-mitm-proxy-handbook](https://github.com/wuchangming/https-mitm-proxy-handbook) 
- [**236**星][3y] [Py] [intrepidusgroup/mallory](https://github.com/intrepidusgroup/mallory) 
- [**233**星][3y] [Py] [withdk/badusb2-mitm-poc](https://github.com/withdk/badusb2-mitm-poc) 
- [**225**星][8m] [Py] [ivanvza/arpy](https://github.com/ivanvza/arpy) 
- [**205**星][3m] [sab0tag3d/mitm-cheatsheet](https://github.com/sab0tag3d/mitm-cheatsheet) 
- [**186**星][2m] [Py] [internetarchive/warcprox](https://github.com/internetarchive/warcprox) 
- [**176**星][3y] [Py] [ctxis/wsuspect-proxy](https://github.com/ctxis/wsuspect-proxy) 
- [**176**星][4y] [Shell] [floyd-fuh/tiny-mitm-proxy](https://github.com/floyd-fuh/tiny-mitm-proxy) 
- [**174**星][3y] [Shell] [praetorian-inc/mitm-vm](https://github.com/praetorian-code/mitm-vm) 
- [**164**星][2m] [JS] [wuchangming/node-mitmproxy](https://github.com/wuchangming/node-mitmproxy) 
- [**159**星][3y] [Py] [pentesteres/delorean](https://github.com/pentesteres/delorean) 
- [**148**星][5y] [Py] [mveytsman/dilettante](https://github.com/mveytsman/dilettante) 
- [**144**星][2y] [Go] [magisterquis/sshhipot](https://github.com/magisterquis/sshhipot) 
    - 重复区段: [工具/密罐&&Honeypot/SSH&&Telnet](#c8f749888134d57b5fb32382c78ef2d1) |
- [**143**星][2y] [chan9390/awesome-mitm](https://github.com/chan9390/awesome-mitm) 
- [**134**星][28d] [Py] [certcc/tapioca](https://github.com/certcc/tapioca) 
- [**129**星][3m] [Shell] [rebe11ion/tornado](https://github.com/reb311ion/tornado) 
- [**128**星][4y] [Py] [andrewhilts/snifflab](https://github.com/andrewhilts/snifflab) 
- [**117**星][1y] [Py] [amossys/memitm](https://github.com/amossys/memitm) 
- [**111**星][3y] [Py] [codepr/creak](https://github.com/codepr/creak) 
- [**108**星][2y] [Shell] [pimps/wsuxploit](https://github.com/pimps/wsuxploit) wsuxploit：MiTM 漏洞利用脚本，用于将“假冒”更新注入到非 SSL WSUS 流量中
- [**96**星][2y] [Py] [jjf012/passivescanner](https://github.com/jjf012/passivescanner) 
- [**93**星][3y] [JS] [compewter/copycat](https://github.com/compewter/copycat) 
- [**85**星][4y] [Py] [liuhui0613/thewind](https://github.com/liuhui0613/thewind) 
- [**79**星][5m] [Ruby] [argos83/ritm](https://github.com/argos83/ritm) 
- [**76**星][6y] [Shell] [neohapsis/suddensix](https://github.com/neohapsis/suddensix) 
- [**76**星][4y] [CoffeeScript] [olegberman/mitm-omegle](https://github.com/olegberman/mitm-omegle) 
- [**66**星][4y] [JS] [etherdream/mitm-http-cache-poisoning](https://github.com/etherdream/mitm-http-cache-poisoning) 
- [**59**星][1y] [Py] [cortesi/mitmproxy](https://github.com/cortesi/mitmproxy) 
- [**55**星][2y] [C++] [caseysmithrc/memmitm](https://github.com/caseysmithrc/memmitm) 
- [**51**星][1y] [Go] [mrexodia/haxxmap](https://github.com/mrexodia/haxxmap) 
- [**51**星][3y] [Py] [cylance/mitmcanary](https://github.com/cylance/mitmcanary) 
- [**47**星][2y] [PowerShell] [clr2of8/detect-sslmitm](https://github.com/clr2of8/detect-sslmitm) 
- [**47**星][4y] [C++] [mozmark/ringleader](https://github.com/mozmark/ringleader) 
- [**46**星][9m] [Py] [lorenzb/libsubmarine](https://github.com/lorenzb/libsubmarine) 
- [**42**星][5y] [Py] [husam212/mitmer](https://github.com/husam212/mitmer) 
- [**40**星][6y] [Py] [ipopov/starttls-mitm](https://github.com/ipopov/starttls-mitm) 
- [**40**星][1y] [C#] [advancedhacker101/c-sharp-proxy-server](https://github.com/advancedhacker101/c-sharp-proxy-server) 
- [**37**星][6m] [Java] [hsiafan/monkey-proxy](https://github.com/hsiafan/cute-proxy) 
- [**35**星][3y] [JS] [jackgu1988/dsploit-scripts](https://github.com/jackgu1988/dsploit-scripts) 
- [**32**星][5y] [Ruby] [jduck/addjsif](https://github.com/jduck/addjsif) 
- [**32**星][5y] [Perl] [linvex/mitm-squid](https://github.com/linvex/mitm-squid) 
- [**31**星][18d] [Ruby] [gplcc/gplcc](https://github.com/gplcc/gplcc) 
- [**31**星][3y] [Py] [syss-research/dns-mitm](https://github.com/syss-research/dns-mitm) 
- [**31**星][1y] [Py] [thusoy/postgres-mitm](https://github.com/thusoy/postgres-mitm) 
- [**28**星][5y] [C] [conorpp/mitm-http-proxy](https://github.com/conorpp/mitm-http-proxy) 
- [**28**星][3y] [Java] [elynx/pokemon-go-xposed-mitm](https://github.com/elynx/pokemon-go-xposed-mitm) 
- [**27**星][2m] [JS] [dangkyokhoang/man-in-the-middle](https://github.com/dangkyokhoang/man-in-the-middle) 
- [**26**星][3m] [Py] [kevcui/mitm-scripts](https://github.com/kevcui/mitm-scripts) 
- [**26**星][3y] [Py] [mvondracek/wifimitm](https://github.com/mvondracek/wifimitm) Automation of MitM Attack on Wi-Fi Networks
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**25**星][4y] [C] [gregwar/mitm](https://github.com/gregwar/mitm) 
- [**24**星][7y] [Java] [akdeniz/mitmsocks4j](https://github.com/akdeniz/mitmsocks4j) 
    - 重复区段: [工具/通信&&代理&&反向代理&&隧道/代理](#21cbd08576a3ead42f60963cdbfb8599) |
- [**23**星][10m] [Nim] [imgp3dev/drmitm](https://github.com/imgp3dev/drmitm) 
- [**21**星][1m] [Py] [lockgit/py](https://github.com/lockgit/py) 
- [**21**星][2y] [Py] [the404hacking/websploit](https://github.com/the404hacking/websploit) 
- [**20**星][1m] [TypeScript] [dialogs/electron-ssl-pinning](https://github.com/dialogs/electron-ssl-pinning) 
- [**19**星][1y] [Py] [jakev/mitm-helper-wifi](https://github.com/jakev/mitm-helper-wifi) 
- [**17**星][2y] [Py] [shramos/winregmitm](https://github.com/shramos/winregmitm) 
- [**16**星][6m] [Java] [aquazus/d1proxy](https://github.com/aquazus/d1proxy) 
- [**15**星][6y] [Ruby] [yakindanegitim/mbfuzzer](https://github.com/yakindanegitim/mbfuzzer) 
- [**12**星][1y] [Go] [syncsynchalt/dime-a-tap](https://github.com/syncsynchalt/dime-a-tap) 
- [**12**星][2y] [C++] [wakbox/wakxy](https://github.com/wakbox/wakxy) 
- [**11**星][11m] [JS] [xtr4nge/fruityproxy](https://github.com/xtr4nge/fruityproxy) 
- [**10**星][5m] [Rust] [nlevitt/mitmprox](https://github.com/nlevitt/monie) 
- [**9**星][6m] [HTML] [chinarulezzz/refluxion](https://github.com/chinarulezzz/refluxion) 
- [**9**星][10m] [Py] [daniel4x/mitm-python](https://github.com/daniel4x/mitm-python) 
- [**8**星][4m] [Py] [skyplabs/scapy-mitm](https://github.com/skyplabs/scapy-mitm) 
- [**8**星][4y] [atiqazafar/vpn-security-analysis](https://github.com/8tiqa/vpn-security-analysis) 
- [**7**星][1y] [Py] [mathewmarcus/stoptls](https://github.com/mathewmarcus/stoptls) 
- [**7**星][2y] [C++] [pfussell/pivotal](https://github.com/pfussell/pivotal) 
- [**7**星][1y] [socprime/muddywater-apt](https://github.com/socprime/muddywater-apt) 
- [**7**星][5m] [Py] [th3hurrican3/mitm](https://github.com/th3hurrican3/mitm) 
- [**6**星][2y] [Java] [arvahedi/gl4dius](https://github.com/arvahedi/gl4dius) 
- [**6**星][9m] [JS] [cutenode/mitm.cool](https://github.com/cutenode/mitm.cool) 
- [**6**星][12m] [Py] [kr1tzb1tz/mitmproxy_pwnage](https://github.com/kr1tzb1tz/mitmproxy_pwnage) 
- [**5**星][4y] [Py] [0x8008135/pymitm6](https://github.com/0x8008135/pymitm6) 
- [**5**星][9m] [JS] [hotstu/open-slim-mock](https://github.com/hotstu/open-slim-mock) 
- [**5**星][1y] [TypeScript] [pogosandbox/node-pogo-mitm](https://github.com/pogosandbox/node-pogo-mitm) 
- [**5**星][2y] [C++] [xiaxiaoyu1988/smitm](https://github.com/xiaxiaoyu1988/smitm) 
- [**5**星][5y] [Shell] [mrmugiwara/airbase-ng-sslstrip-airstrip-](https://github.com/mrmugiwara/airbase-ng-sslstrip-airstrip-) 
- [**4**星][2y] [Py] [gteissier/cve-2016-6271](https://github.com/gteissier/cve-2016-6271) 
- [**4**星][2y] [C++] [robertblackwell/marvincpp](https://github.com/robertblackwell/marvincpp) 
- [**4**星][6y] [wshen0123/mitm-rogue-wifi-ap](https://github.com/wshen0123/mitm-rogue-wifi-ap) 
- [**3**星][5y] [Perl] [em616/juli](https://github.com/em616/juli) 
- [**3**星][1y] [Py] [tanc7/facerider](https://github.com/tanc7/facerider) 
- [**2**星][2y] [Py] [alvarogzp/man-in-the-middle](https://github.com/alvarogzp/man-in-the-middle) 
- [**2**星][3y] [Go] [andream16/gocrackerino](https://github.com/andream16/gocrackerino) 
- [**2**星][12m] [Shell] [apacketofsweets/buttertrace](https://github.com/apacketofsweets/buttertrace) 
- [**2**星][1m] [Py] [danngalann/arpdos](https://github.com/danngalann/arpdos) 
- [**2**星][4y] [C#] [hotallday/xat-mitm](https://github.com/hotallday/xat-mitm) 
- [**2**星][6y] [Py] [koto/exceed-mitm](https://github.com/koto/exceed-mitm) 
- [**2**星][10m] [Py] [nametoolong/mesona](https://github.com/nametoolong/mesona) 
- [**2**星][2y] [Swift] [windblaze/aegis](https://github.com/windblaze/aegis) 
- [**1**星][6y] [kenjoe41/mitmproxy](https://github.com/kenjoe41/mitmproxy) 
- [**1**星][2y] [Ruby] [samyoyo/bettercap](https://github.com/samyoyo/bettercap) 
- [**0**星][6y] [Shell] [ekultek/suddensix](https://github.com/ekultek/suddensix) 
- [**0**星][3y] [C#] [klemenb/fiddly](https://github.com/klemenb/fiddly) 


### <a id="c09843b4d4190dea0bf9773f8114300a"></a>流量嗅探&&监控


- [**3480**星][7m] [Go] [fanpei91/torsniff](https://github.com/fanpei91/torsniff) 从BitTorrent网络嗅探种子
- [**2950**星][14d] [Lua] [ntop/ntopng](https://github.com/ntop/ntopng) 基于Web的流量监控工具
- [**1328**星][1y] [C] [gamelinux/passivedns](https://github.com/gamelinux/passivedns) 
- [**912**星][2y] [HTML] [snorby/snorby](https://github.com/snorby/snorby) 
- [**849**星][3y] [Py] [hubert3/isniff-gps](https://github.com/hubert3/isniff-gps) 
    - 重复区段: [工具/移动&&Mobile/iOS&&MacOS&&iPhone&&iPad&&iWatch](#dbde77352aac39ee710d3150a921bcad) |
- [**313**星][2y] [Py] [tnich/honssh](https://github.com/tnich/honssh) honssh: 记录客户端和服务器之间的所有 SSH 通信
- [**286**星][1m] [Shell] [tehw0lf/airbash](https://github.com/tehw0lf/airbash) airbash: 全自动的WPAPSK握手包捕获脚本, 用于渗透测试


### <a id="dde87061175108fc66b00ef665b1e7d0"></a>pcap数据包


- [**820**星][13d] [C++] [seladb/pcapplusplus](https://github.com/seladb/pcapplusplus) 
- [**780**星][3m] [Py] [srinivas11789/pcapxray](https://github.com/srinivas11789/pcapxray) A Network Forensics Tool
- [**459**星][30d] [C#] [chmorgan/sharppcap](https://github.com/chmorgan/sharppcap) 
- [**234**星][4y] [C] [softethervpn/win10pcap](https://github.com/softethervpn/win10pcap) WinPcap for Windows 10 (NDIS 6.x driver model)
- [**210**星][12m] [Py] [mateuszk87/pcapviz](https://github.com/mateuszk87/pcapviz) 
- [**209**星][7m] [JS] [dirtbags/pcapdb](https://github.com/dirtbags/pcapdb) 分布式、搜索优化的网络数据包捕获系统
- [**206**星][4m] [Py] [pynetwork/pypcap](https://github.com/pynetwork/pypcap) python libpcap module, forked from code.google.com/p/pypcap, now actively maintained
- [**190**星][6y] [Py] [andrewf/pcap2har](https://github.com/andrewf/pcap2har) 
- [**188**星][4y] [Java] [ripe-ncc/hadoop-pcap](https://github.com/ripe-ncc/hadoop-pcap) 


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
- [**645**星][2y] [C++] [nathancastle/bootshellcredentialprovider](https://github.com/nathancastle/bootshellcredentialprovider) 
- [**601**星][2y] [PowerShell] [peewpw/invoke-wcmdump](https://github.com/peewpw/invoke-wcmdump) 
- [**514**星][2m] [Py] [unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) 
- [**492**星][2m] [Py] [byt3bl33d3r/sprayingtoolkit](https://github.com/byt3bl33d3r/sprayingtoolkit) 
- [**483**星][1y] [JS] [emilbayes/secure-password](https://github.com/emilbayes/secure-password) 
- [**481**星][2y] [C] [realjtg/meltdown](https://github.com/realjtg/meltdown) 
- [**442**星][1y] [Go] [ncsa/ssh-auditor](https://github.com/ncsa/ssh-auditor) 扫描网络中的弱SSH密码
- [**396**星][3y] [Scala] [philwantsfish/shard](https://github.com/philwantsfish/shard) 
- [**385**星][11m] [Shell] [mthbernardes/sshlooter](https://github.com/mthbernardes/sshlooter) 
- [**347**星][3m] [Py] [davidtavarez/pwndb](https://github.com/davidtavarez/pwndb) 
- [**295**星][5m] [C#] [raikia/credninja](https://github.com/raikia/credninja) 
- [**284**星][6m] [Shell] [greenwolf/spray](https://github.com/Greenwolf/Spray) 
- [**272**星][2m] [JS] [kspearrin/ff-password-exporter](https://github.com/kspearrin/ff-password-exporter) 
- [**267**星][1m] [Py] [xfreed0m/rdpassspray](https://github.com/xfreed0m/rdpassspray) 
- [**257**星][7y] [C] [quarkslab/quarkspwdump](https://github.com/quarkslab/quarkspwdump) 
- [**255**星][5m] [C] [rub-syssec/omen](https://github.com/rub-syssec/omen) Ordered Markov ENumerator - Password Guesser
- [**224**星][6y] [Shell] [brav0hax/easy-creds](https://github.com/brav0hax/easy-creds) leverages tools for stealing credentials during a pen test
- [**210**星][3m] [Ruby] [bdmac/strong_password](https://github.com/bdmac/strong_password) 
- [**198**星][2y] [Go] [magoo/authtables](https://github.com/magoo/authtables) 
- [**191**星][2y] [PowerShell] [gimini/mimidbg](https://github.com/gimini/mimidbg) 
- [**186**星][7m] [PowerShell] [hansesecure/credgrap_ie_edge](https://github.com/hansesecure/credgrap_ie_edge) 
- [**178**星][10m] [Shell] [drduh/purse](https://github.com/drduh/purse) 
- [**177**星][10m] [Py] [acceis/leakscraper](https://github.com/acceis/leakscraper) 
- [**170**星][4y] [JS] [fnando/password_strength](https://github.com/fnando/password_strength) 
- [**164**星][7m] [PowerShell] [dviros/credsleaker](https://github.com/dviros/credsleaker) 
- [**160**星][2y] [TypeScript] [cupslab/password_meter](https://github.com/cupslab/password_meter) 数据驱动的密码测量仪表，可对密码进行强度和可用性检测
- [**153**星][3y] [Py] [inquisb/keimpx](https://github.com/inquisb/keimpx) 
- [**152**星][2m] [Py] [rndinfosecguy/scavenger](https://github.com/rndinfosecguy/scavenger) 
- [**149**星][7m] [Py] [fox-it/adconnectdump](https://github.com/fox-it/adconnectdump) 
- [**149**星][8m] [Py] [githacktools/leaked](https://github.com/githacktools/leaked) 
- [**145**星][20d] [C#] [mihaifm/hibpofflinecheck](https://github.com/mihaifm/hibpofflinecheck) 
- [**139**星][2y] [Ruby] [michenriksen/searchpass](https://github.com/michenriksen/searchpass) searchpass：离线搜索网络设备、Web应用程序等的默认凭据
- [**136**星][26d] [Py] [darkarp/chromepass](https://github.com/darkarp/chromepass) 
- [**123**星][7y] [Ruby] [livingsocial/keyspace](https://github.com/livingsocial/keyspace) 
- [**107**星][2y] [Go] [jthomas/serverless-pwned-passwords](https://github.com/jthomas/serverless-pwned-passwords) serverless-pwned-passwords：提供了1个API，用于从各种数据泄漏的巨大密码库中检查潜在密码
- [**73**星][12m] [C] [securifera/servicefu](https://github.com/securifera/servicefu) 
- [**73**星][6m] [Py] [shashank-in/travisleaks](https://github.com/shashank-in/travisleaks) 
- [**43**星][2y] [CSS] [pure-l0g1c/apex](https://github.com/pure-l0g1c/apex) 
- [**38**星][7m] [Py] [llt4l/iculeak.py](https://github.com/llt4l/iculeak.py) 
- [**31**星][2y] [C#] [nccgroup/scomdecrypt](https://github.com/nccgroup/scomdecrypt) 
- [**27**星][7m] [Go] [ahhh/goredshell](https://github.com/ahhh/goredshell) 
- [**24**星][8m] [gitguardian/getting-started-with-the-individual-app](https://github.com/gitguardian/getting-started-with-the-individual-app) 
- [**21**星][9m] [Ruby] [audibleblink/doubletap](https://github.com/audibleblink/doubletap) 


### <a id="86dc226ae8a71db10e4136f4b82ccd06"></a>密码


- [**10647**星][2y] [CoffeeScript] [dropbox/zxcvbn](https://github.com/dropbox/zxcvbn) 
- [**6832**星][17d] [C] [hashcat/hashcat](https://github.com/hashcat/hashcat) 世界上最快最先进的密码恢复工具
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/后渗透/未分类-post-exp](#12abc279c69d1fcf10692b9cb89bcdf7) |
- [**5149**星][12m] [JS] [samyk/poisontap](https://github.com/samyk/poisontap) 
- [**3083**星][13d] [C] [magnumripper/johntheripper](https://github.com/magnumripper/johntheripper) 
- [**2536**星][1m] [C] [huntergregal/mimipenguin](https://github.com/huntergregal/mimipenguin) dump 当前Linux用户的登录密码
- [**2110**星][4y] [C] [hashcat/hashcat-legacy](https://github.com/hashcat/hashcat-legacy) 
- [**1280**星][3y] [Py] [ddevault/evilpass](https://github.com/ddevault/evilpass) 
- [**1124**星][7m] [Py] [mebus/cupp](https://github.com/mebus/cupp) 
- [**859**星][4m] [Go] [fireeye/gocrack](https://github.com/fireeye/gocrack) 火眼开源的密码破解工具，可以跨多个 GPU 服务器执行任务
- [**843**星][2m] [Go] [ukhomeoffice/repo-security-scanner](https://github.com/ukhomeoffice/repo-security-scanner) 
- [**773**星][4y] [C++] [denandz/keefarce](https://github.com/denandz/keefarce) 
- [**770**星][2y] [Py] [viralmaniar/passhunt](https://github.com/viralmaniar/passhunt) 
- [**663**星][4y] [praetorian-code/hob0rules](https://github.com/praetorian-code/Hob0Rules) 
- [**628**星][1y] [Java] [faizann24/wifi-bruteforcer-fsecurify](https://github.com/faizann24/wifi-bruteforcer-fsecurify) Android app，无需 Root 即可爆破 Wifi 密码
- [**585**星][1y] [Py] [brannondorsey/passgan](https://github.com/brannondorsey/passgan) 
- [**578**星][6m] [C] [hashcat/hashcat-utils](https://github.com/hashcat/hashcat-utils) 
- [**574**星][3m] [Py] [thewhiteh4t/pwnedornot](https://github.com/thewhiteh4t/pwnedornot) 
- [**482**星][1y] [PowerShell] [dafthack/domainpasswordspray](https://github.com/dafthack/domainpasswordspray) 
- [**404**星][1y] [C++] [vah13/extracttvpasswords](https://github.com/vah13/extracttvpasswords) 
- [**369**星][2y] [Py] [lightos/credmap](https://github.com/lightos/credmap) credmap：在若干已知网站测试用户提供的认证信息，检查是否有密码重复使用
- [**344**星][7m] [Py] [iphelix/pack](https://github.com/iphelix/pack) 
- [**318**星][2m] [JS] [auth0/repo-supervisor](https://github.com/auth0/repo-supervisor) Serverless工具，在pull请求中扫描源码，搜索密码及其他秘密
- [**318**星][1m] [CSS] [guyoung/captfencoder](https://github.com/guyoung/captfencoder) 
- [**234**星][2y] [C#] [jephthai/openpasswordfilter](https://github.com/jephthai/openpasswordfilter) 
- [**218**星][4y] [lavalamp-/password-lists](https://github.com/lavalamp-/password-lists) 
- [**189**星][2y] [Py] [mxdg/passbytcp](https://github.com/mxdg/passbytcp) 内网 tcp 穿透
- [**176**星][6y] [C] [gat3way/hashkill](https://github.com/gat3way/hashkill) 
- [**158**星][2y] [netbiosx/default-credentials](https://github.com/netbiosx/default-credentials) 
- [**134**星][5m] [tarraschk/richelieu](https://github.com/tarraschk/richelieu) 
    - 重复区段: [工具/wordlist/未分类-wordlist](#af1d71122d601229dc4aa9d08f4e3e15) |
- [**102**星][3y] [JS] [trustedsec/ships](https://github.com/trustedsec/ships) 
- [**88**星][5y] [Py] [cheetz/brutescrape](https://github.com/cheetz/brutescrape) 
- [**80**星][6m] [Py] [localh0t/m4ngl3m3](https://github.com/localh0t/m4ngl3m3) m4ngl3m3: 使用字符串列表的通用密码模式生成器
- [**77**星][6y] [Py] [t-s-a/smbspider](https://github.com/t-s-a/smbspider) 
- [**63**星][3y] [Py] [xorond/sudo-snooper](https://github.com/xorond/sudo-snooper) 
- [**49**星][6y] [CSS] [mubix/whitechapel](https://github.com/mubix/whitechapel) 
- [**44**星][2y] [C#] [amarkulo/openpasswordfilter](https://github.com/amarkulo/openpasswordfilter) 
- [**36**星][3m] [Py] [initstring/lyricpass](https://github.com/initstring/lyricpass) 
- [**36**星][4m] [PHP] [xchwarze/cain](https://github.com/xchwarze/cain) 
- [**27**星][1y] [Shell] [mikhbur/conformer](https://github.com/mikhbur/conformer) 
- [**25**星][1m] [Py] [initstring/pentest-tools](https://github.com/initstring/pentest-tools) 
    - 重复区段: [工具/破解&&Crack&&爆破&&BruteForce](#de81f9dd79c219c876c1313cd97852ce) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Kali](#7667f6a0381b6cded2014a0d279b5722) |
- [**25**星][4m] [Py] [michaeldim02/hvazard](https://github.com/michaeldim02/hvazard) 
- [**24**星][4y] [Py] [karblue/pppoe-hijack](https://github.com/karblue/pppoe-hijack) 
- [**21**星][1y] [Py] [ins1gn1a/pwdlyser](https://github.com/ins1gn1a/pwdlyser) pwdlyser：密码分析工具，Python编写




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
- [**141**星][2y] [Py] [vduddu/malware](https://github.com/vduddu/malware) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload收集](#b5d99a78ddb383c208aae474fc2cb002) |
- [**30**星][3m] [PHP] [x-o-r-r-o/php-webshells-collection](https://github.com/x-o-r-r-o/php-webshells-collection) 


### <a id="faa91844951d2c29b7b571c6e8a3eb54"></a>未分类-webshell


- [**1746**星][1y] [CSS] [b374k/b374k](https://github.com/b374k/b374k) 
- [**1739**星][2m] [Py] [epinna/weevely3](https://github.com/epinna/weevely3) 
- [**1376**星][4y] [PHP] [johntroony/php-webshells](https://github.com/johntroony/php-webshells) 
- [**956**星][1m] [Py] [yzddmr6/webshell-venom](https://github.com/yzddmr6/webshell-venom) 
- [**669**星][3y] [PHP] [xl7dev/webshell](https://github.com/xl7dev/webshell) 
- [**474**星][7m] [ASP] [landgrey/webshell-detect-bypass](https://github.com/landgrey/webshell-detect-bypass) 
- [**440**星][4y] [C#] [keepwn/altman](https://github.com/keepwn/altman) 
- [**421**星][1y] [Py] [shmilylty/cheetah](https://github.com/shmilylty/cheetah) 
- [**411**星][1y] [PHP] [ysrc/webshell-sample](https://github.com/ysrc/webshell-sample) 
- [**366**星][5m] [PHP] [blackarch/webshells](https://github.com/blackarch/webshells) 
- [**351**星][7m] [PHP] [s0md3v/nano](https://github.com/s0md3v/nano) PHP Webshell家族
- [**321**星][2y] [PHP] [tanjiti/webshellsample](https://github.com/tanjiti/webshellsample) 
- [**305**星][8m] [Py] [wangyihang/webshell-sniper](https://github.com/wangyihang/webshell-sniper) webshell管理器，命令行工具
- [**294**星][4y] [Py] [emposha/shell-detector](https://github.com/emposha/shell-detector) 
- [**282**星][1y] [JS] [chrisallenlane/novahot](https://github.com/chrisallenlane/novahot) Webshell框架，实现了基于Json的API，可与任何语言编写的后门（默认支持PHP/Ruby/Python）进行通信。
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/后渗透/未分类-post-exp](#12abc279c69d1fcf10692b9cb89bcdf7) |
- [**243**星][8m] [Py] [antoniococo/sharpyshell](https://github.com/antoniococo/sharpyshell) ASP.NET webshell，小型，混淆，针对C# Web App
- [**241**星][3y] [PHP] [tdifg/webshell](https://github.com/tdifg/webshell) 
- [**231**星][5y] [PHP] [smaash/quasibot](https://github.com/smaash/quasibot) 
- [**207**星][6m] [PHP] [samdark/yii2-webshell](https://github.com/samdark/yii2-webshell) 
- [**189**星][5m] [Py] [ares-x/awd-predator-framework](https://github.com/ares-x/awd-predator-framework) 
- [**185**星][1y] [Py] [he1m4n6a/findwebshell](https://github.com/he1m4n6a/findwebshell) 
- [**183**星][1y] [Java] [rebeyond/memshell](https://github.com/rebeyond/memshell) 
- [**168**星][10m] [Java] [joychou93/webshell](https://github.com/joychou93/webshell) 
- [**166**星][7y] [PHP] [secrule/falcon](https://github.com/secrule/falcon) 
- [**145**星][2y] [ASP] [testsecer/webshell](https://github.com/testsecer/webshell) 
- [**144**星][3y] [PHP] [webshellpub/awsome-webshell](https://github.com/webshellpub/awsome-webshell) 
- [**131**星][8m] [PHP] [k4mpr3t/b4tm4n](https://github.com/k4mpr3t/b4tm4n) b4tm4n: Php webshell
- [**122**星][8y] [evilcos/python-webshell](https://github.com/evilcos/python-webshell) 
- [**120**星][3y] [malwares/webshell](https://github.com/malwares/webshell) 
- [**106**星][3y] [Py] [lingerhk/fshell](https://github.com/lingerhk/fshell) 
- [**99**星][3y] [Py] [ym2011/scanbackdoor](https://github.com/ym2011/scanbackdoor) 
- [**96**星][2y] [Java] [tengzhangchao/pycmd](https://github.com/tengzhangchao/pycmd) 
- [**92**星][2y] [Py] [lcatro/webshell-detect-by-machine-learning](https://github.com/lcatro/webshell-detect-by-machine-learning) 
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |
- [**92**星][2y] [Java] [securityriskadvisors/cmd.jsp](https://github.com/securityriskadvisors/cmd.jsp) 
- [**83**星][5y] [Py] [xypiie/webshell](https://github.com/xypiie/webshell) 
- [**82**星][2y] [Py] [hi-wenr0/mlcheckwebshell](https://github.com/hi-wenr0/mlcheckwebshell) 
- [**77**星][2y] [Py] [wofeiwo/webshell-find-tools](https://github.com/wofeiwo/webshell-find-tools) 
- [**74**星][3y] [PHP] [secwiki/webshell-2](https://github.com/secwiki/webshell-2) 
- [**73**星][4y] [PHP] [phith0n/b374k](https://github.com/phith0n/b374k) 
- [**69**星][2y] [Py] [3xp10it/xdump](https://github.com/3xp10it/xdump) 
- [**59**星][7m] [PHP] [michyamrane/wso-webshell](https://github.com/mIcHyAmRaNe/wso-webshell) 
- [**46**星][2y] [Py] [erevus-cn/scan_webshell](https://github.com/erevus-cn/scan_webshell) 
- [**45**星][3y] [Py] [threatexpress/subshell](https://github.com/threatexpress/subshell) 
- [**42**星][4y] [Py] [secwiki/scaing-backdoor](https://github.com/secwiki/scaing-backdoor) 
- [**41**星][2y] [PHP] [backlion/webshell](https://github.com/backlion/webshell) 
- [**40**星][5y] [evi1m0/webshell](https://github.com/evi1m0/webshell) 
- [**40**星][3y] [PHP] [wso-shell/wso](https://github.com/wso-shell/wso) 
- [**39**星][5y] [PHP] [ridter/webshell](https://github.com/ridter/webshell) 
- [**38**星][2y] [PHP] [whitewinterwolf/wwwolf-php-webshell](https://github.com/whitewinterwolf/wwwolf-php-webshell) 
- [**36**星][2m] [C#] [guillac/wsmanager](https://github.com/guillac/wsmanager) 
- [**34**星][8m] [PHP] [linuxsec/indoxploit-shell](https://github.com/linuxsec/indoxploit-shell) 
- [**33**星][2m] [JS] [medicean/superterm](https://github.com/medicean/superterm) 
- [**32**星][3y] [Py] [jkkj93/mint-webshell-defender](https://github.com/jkkj93/mint-webshell-defender) 
- [**32**星][4y] [PHP] [wstart/webshell](https://github.com/wstart/webshell) 
- [**31**星][2y] [Py] [bwsw/webshell](https://github.com/bwsw/webshell) 
- [**31**星][5y] [Py] [jofpin/fuckshell](https://github.com/jofpin/fuckshell) 
- [**31**星][2y] [Java] [mindawei/aliyun-safe-match](https://github.com/mindawei/aliyun-safe-match) 
- [**30**星][8m] [Py] [3xp10it/xupload](https://github.com/3xp10it/xupload) 
- [**30**星][4y] [PHP] [fuzzdb-project/webshell](https://github.com/fuzzdb-project/webshell) 
- [**30**星][2y] [ysrc/shelldaddy](https://github.com/ysrc/shelldaddy) 
- [**29**星][5y] [jgor/php-jpeg-shell](https://github.com/jgor/php-jpeg-shell) 
- [**26**星][9m] [JS] [onrik/django-webshell](https://github.com/onrik/django-webshell) 
- [**24**星][3y] [PHP] [3xp10it/xwebshell](https://github.com/3xp10it/xwebshell) 
- [**23**星][2y] [PHP] [xiaoxiaoleo/xiao-webshell](https://github.com/xiaoxiaoleo/xiao-webshell) 
- [**22**星][4m] [Py] [manhnho/shellsum](https://github.com/manhnho/shellsum) 




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
- [**103**星][1y] [Swift] [ehrishirajsharma/swiftness](https://github.com/ehrishirajsharma/swiftness) 
- [**46**星][2y] [Pascal] [felipedaragon/huntpad](https://github.com/felipedaragon/huntpad) huntpad: 开源的Notepad,有很多有助于渗透测试的特性


### <a id="86d5daccb4ed597e85a0ec9c87f3c66f"></a>TLS&&SSL&&HTTPS


- [**4292**星][5m] [Py] [diafygi/acme-tiny](https://github.com/diafygi/acme-tiny) 
- [**1663**星][2m] [HTML] [chromium/badssl.com](https://github.com/chromium/badssl.com) 
- [**1177**星][2m] [Go] [jsha/minica](https://github.com/jsha/minica) 
- [**1126**星][19d] [Go] [smallstep/certificates](https://github.com/smallstep/certificates) 私有的证书颁发机构（X.509和SSH）和ACME服务器，用于安全的自动证书管理，因此您可以在SSH和SSO处使用TLS
- [**507**星][14d] [Java] [rub-nds/tls-attacker](https://github.com/rub-nds/tls-attacker) 




***


## <a id="e1fc1d87056438f82268742dc2ba08f5"></a>事件响应&&取证&&内存取证&&数字取证


### <a id="65f1e9dc3e08dff9fcda9d2ee245764e"></a>未分类-Forensics


- [**196**星][10m] [Py] [medbenali/cyberscan](https://github.com/medbenali/cyberscan) 
- [**143**星][2y] [Py] [davidpany/wmi_forensics](https://github.com/davidpany/wmi_forensics) 
- [**70**星][2y] [C++] [kasperskylab/forensicstools](https://github.com/kasperskylab/forensicstools) 
- [**38**星][2y] [Py] [ytisf/muninn](https://github.com/ytisf/muninn) 


### <a id="d0f59814394c5823210aa04a8fcd1220"></a>事件响应&&IncidentResponse


- [**3054**星][14d] [meirwah/awesome-incident-response](https://github.com/meirwah/awesome-incident-response) 
- [**1801**星][4m] [bypass007/emergency-response-notes](https://github.com/bypass007/emergency-response-notes) 
- [**1310**星][3m] [HTML] [thehive-project/thehive](https://github.com/thehive-project/thehive) 
- [**1132**星][10m] [Py] [certsocietegenerale/fir](https://github.com/certsocietegenerale/fir) 
- [**988**星][9m] [Go] [gencebay/httplive](https://github.com/gencebay/httplive) 
- [**965**星][1m] [JS] [monzo/response](https://github.com/monzo/response) 
- [**800**星][3y] [C#] [netflix/fido](https://github.com/netflix/fido) an orchestration layer used to automate the incident response process by evaluating, assessing and responding to malware
- [**764**星][16d] [microsoft/msrc-security-research](https://github.com/microsoft/msrc-security-research) 
- [**744**星][10m] [PowerShell] [davehull/kansa](https://github.com/davehull/kansa) 
- [**715**星][2y] [kristate/krackinfo](https://github.com/kristate/krackinfo) 
- [**710**星][2m] [HTML] [pagerduty/incident-response-docs](https://github.com/pagerduty/incident-response-docs) 
- [**634**星][9m] [Roff] [palantir/windows-event-forwarding](https://github.com/palantir/windows-event-forwarding) 使用 Windows 事件转发实现网络事件监测和防御
- [**627**星][21d] [Kotlin] [chuckerteam/chucker](https://github.com/chuckerteam/chucker) simplifies the inspection of HTTP(S) requests/responses, and Throwables fired by your Android App
- [**579**星][9m] [Go] [nytimes/gziphandler](https://github.com/nytimes/gziphandler) 
- [**572**星][4y] [certsocietegenerale/irm](https://github.com/certsocietegenerale/irm) 
- [**535**星][5m] [Py] [owasp/qrljacking](https://github.com/owasp/qrljacking) 一个简单的能够进行会话劫持的社会工程攻击向量，影响所有使用“使用 QR 码登录”作为安全登录方式的应用程序。（ Quick Response CodeLogin Jacking）
- [**489**星][2y] [PowerShell] [powershellmafia/cimsweep](https://github.com/powershellmafia/cimsweep) 
- [**459**星][6m] [palantir/osquery-configuration](https://github.com/palantir/osquery-configuration) 使用 osquery 做事件检测和响应
- [**452**星][28d] [Py] [controlscanmdr/cyphon](https://github.com/controlscanmdr/cyphon) 事件管理和响应平台
- [**286**星][1m] [Py] [alexandreborges/malwoverview](https://github.com/alexandreborges/malwoverview) 
- [**251**星][1m] [C#] [orlikoski/cylr](https://github.com/orlikoski/CyLR) 
- [**225**星][2y] [palantir/alerting-detection-strategy-framework](https://github.com/palantir/alerting-detection-strategy-framework) 
- [**210**星][2y] [C#] [shanek2/invtero.net](https://github.com/shanek2/invtero.net) 
- [**204**星][2m] [PowerShell] [wiredpulse/posh-r2](https://github.com/wiredpulse/posh-r2) 
- [**183**星][6y] [Py] [danmcinerney/dnsspoof](https://github.com/danmcinerney/dnsspoof) 
- [**176**星][9m] [Py] [riramar/hsecscan](https://github.com/riramar/hsecscan) 
- [**173**星][19d] [Rust] [insanitybit/grapl](https://github.com/insanitybit/grapl) 
- [**156**星][2y] [swannman/ircapabilities](https://github.com/swannman/ircapabilities) 
- [**147**星][3m] [Py] [stuhli/dfirtrack](https://github.com/stuhli/dfirtrack) DFIRTrack: 数字取证, 与事件响应追踪. 基于Django
- [**120**星][2m] [Py] [yelp/amira](https://github.com/yelp/amira) 
- [**104**星][3y] [Py] [opensourcesec/cirtkit](https://github.com/opensourcesec/CIRTKit) 
- [**103**星][1y] [PowerShell] [harmj0y/asreproast](https://github.com/harmj0y/asreproast) 
- [**92**星][6m] [PowerShell] [mgreen27/invoke-liveresponse](https://github.com/mgreen27/Invoke-LiveResponse) 
- [**86**星][2m] [Py] [thomaspatzke/wase](https://github.com/thomaspatzke/wase) 
- [**79**星][2y] [Py] [brianwrf/hackrequests](https://github.com/brianwrf/hackrequests) 
- [**77**星][2m] [C] [cyberdefenseinstitute/cdir](https://github.com/cyberdefenseinstitute/cdir) 
- [**75**星][3y] [magoo/incident-response-plan](https://github.com/magoo/incident-response-plan) 
- [**62**星][2y] [Go] [yara-rules/yara-endpoint](https://github.com/yara-rules/yara-endpoint) 
- [**57**星][4y] [PHP] [jcarlosn/gzip-http-time](https://github.com/jcarlosn/gzip-http-time) 
- [**44**星][2y] [Py] [illusivenetworks-labs/historicprocesstree](https://github.com/illusivenetworks-labs/historicprocesstree) 
- [**43**星][9m] [C++] [vletoux/detectpasswordviantlminflow](https://github.com/vletoux/detectpasswordviantlminflow) 
- [**40**星][2y] [deadbits/analyst-casefile](https://github.com/deadbits/analyst-casefile) 
- [**39**星][1y] [Py] [netspi/spoofspotter](https://github.com/netspi/spoofspotter) 
- [**37**星][2y] [edoverflow/bug-bounty-responses](https://github.com/edoverflow/bug-bounty-responses) 
- [**36**星][2y] [C++] [illusivenetworks-labs/getconsolehistoryandoutput](https://github.com/illusivenetworks-labs/getconsolehistoryandoutput) 
- [**33**星][3m] [Ruby] [veeral-patel/incidents](https://github.com/veeral-patel/incidents) 
- [**32**星][2y] [Py] [jipegit/fect](https://github.com/jipegit/fect) 
- [**31**星][1y] [Shell] [hestat/blazescan](https://github.com/hestat/blazescan) 
- [**31**星][3y] [Py] [staaldraad/fastfluxanalysis](https://github.com/staaldraad/fastfluxanalysis) 
- [**28**星][8m] [Py] [ctxis/cbrcli](https://github.com/ctxis/cbrcli) 
- [**27**星][2y] [Py] [vpnguy-zz/handyheaderhacker](https://github.com/vpnguy-zz/HandyHeaderHacker) 
- [**26**星][10m] [Py] [thehive-project/synapse](https://github.com/thehive-project/synapse) 
- [**24**星][7m] [Ruby] [sensu-plugins/sensu-plugins-network-checks](https://github.com/sensu-plugins/sensu-plugins-network-checks) 
- [**23**星][6y] [PHP] [cyberisltd/gzipbloat](https://github.com/cyberisltd/gzipbloat) 
- [**16**星][1y] [Py] [nogoodconfig/pyarascanner](https://github.com/nogoodconfig/pyarascanner) 


### <a id="1fc5d3621bb13d878f337c8031396484"></a>取证&&Forensics&&数字取证&&内存取证


- [**3315**星][2m] [Py] [google/grr](https://github.com/google/grr) 
- [**2714**星][3y] [Py] [hephaest0s/usbkill](https://github.com/hephaest0s/usbkill) 反取证开关. 监控USB端口变化, 有变化时立即关闭计算机
- [**1486**星][9m] [Py] [google/rekall](https://github.com/google/rekall) 
- [**1465**星][18d] [C] [sleuthkit/sleuthkit](https://github.com/sleuthkit/sleuthkit) 
- [**1200**星][27d] [Py] [google/timesketch](https://github.com/google/timesketch) 
- [**1152**星][2m] [Go] [mozilla/mig](https://github.com/mozilla/mig) mig：分布式实时数字取证和研究平台
- [**953**星][1m] [Rich Text Format] [decalage2/oletools](https://github.com/decalage2/oletools) 
- [**940**星][17d] [C++] [hasherezade/pe-sieve](https://github.com/hasherezade/pe-sieve) 
- [**933**星][2y] [C#] [invoke-ir/powerforensics](https://github.com/invoke-ir/powerforensics) 
- [**909**星][2m] [Py] [ondyari/faceforensics](https://github.com/ondyari/faceforensics) 
- [**826**星][12d] [Java] [sleuthkit/autopsy](https://github.com/sleuthkit/autopsy) 
- [**817**星][21d] [cugu/awesome-forensics](https://github.com/cugu/awesome-forensics) 
- [**802**星][14d] [Py] [yampelo/beagle](https://github.com/yampelo/beagle) 
- [**744**星][19d] [Py] [snovvcrash/usbrip](https://github.com/snovvcrash/usbrip) 
    - 重复区段: [工具/硬件设备&&USB&树莓派/USB](#48c53d1304b1335d9addf45b959b7d8a) |
- [**541**星][2y] [Go] [biggiesmallsag/nighthawkresponse](https://github.com/biggiesmallsag/nighthawkresponse) 
- [**440**星][2y] [Objective-C] [aburgh/disk-arbitrator](https://github.com/aburgh/disk-arbitrator) 
- [**419**星][2m] [Py] [obsidianforensics/hindsight](https://github.com/obsidianforensics/hindsight) 
- [**400**星][14d] [Py] [forensicartifacts/artifacts](https://github.com/forensicartifacts/artifacts) 
- [**396**星][2y] [PowerShell] [cryps1s/darksurgeon](https://github.com/cryps1s/darksurgeon) 
- [**391**星][10m] [Go] [mozilla/masche](https://github.com/mozilla/masche) 
- [**373**星][5y] [JS] [le4f/pcap-analyzer](https://github.com/le4f/pcap-analyzer) 
- [**335**星][1y] [C] [natebrune/silk-guardian](https://github.com/natebrune/silk-guardian) 
- [**321**星][10m] [Py] [alessandroz/lazagneforensic](https://github.com/alessandroz/lazagneforensic) 
- [**317**星][3m] [HTML] [intezer/linux-explorer](https://github.com/intezer/linux-explorer) linux-explorer: 针对Linux 系统的现场取证工具箱. Web 界面, 简单易用
- [**315**星][2y] [C] [fireeye/rvmi](https://github.com/fireeye/rvmi) rvmi：steroids 调试器，利用 VMI（Virtual Machine Introspection） 和内存取证来提供全面的系统分析
- [**311**星][8m] [Py] [n0fate/chainbreaker](https://github.com/n0fate/chainbreaker) 
- [**301**星][2m] [Py] [google/turbinia](https://github.com/google/turbinia) 
- [**296**星][24d] [Shell] [vitaly-kamluk/bitscout](https://github.com/vitaly-kamluk/bitscout) bitscout：远程数据取证工具
- [**294**星][1y] [Shell] [sevagas/swap_digger](https://github.com/sevagas/swap_digger) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/后渗透/未分类-post-exp](#12abc279c69d1fcf10692b9cb89bcdf7) |
- [**292**星][3y] [invoke-ir/forensicposters](https://github.com/invoke-ir/forensicposters) 
- [**268**星][12d] [Perl] [owasp/o-saft](https://github.com/owasp/o-saft) 
- [**265**星][3y] [Py] [ghirensics/ghiro](https://github.com/ghirensics/ghiro) 
- [**255**星][6m] [Batchfile] [diogo-fernan/ir-rescue](https://github.com/diogo-fernan/ir-rescue) 
- [**250**星][21d] [Py] [google/docker-explorer](https://github.com/google/docker-explorer) 
- [**248**星][12m] [C++] [comaeio/swishdbgext](https://github.com/comaeio/SwishDbgExt) 
- [**243**星][11m] [Py] [crowdstrike/forensics](https://github.com/crowdstrike/forensics) 
- [**241**星][1m] [Py] [orlikoski/cdqr](https://github.com/orlikoski/CDQR) 
- [**227**星][30d] [C] [elfmaster/libelfmaster](https://github.com/elfmaster/libelfmaster) 
- [**221**星][4y] [Java] [nowsecure/android-forensics](https://github.com/nowsecure/android-forensics) 
- [**217**星][2m] [Py] [crowdstrike/automactc](https://github.com/crowdstrike/automactc) 
- [**187**星][14d] [Py] [lazza/recuperabit](https://github.com/lazza/recuperabit) 
- [**186**星][1y] [Py] [pstirparo/mac4n6](https://github.com/pstirparo/mac4n6) 
- [**174**星][4y] [Py] [csababarta/ntdsxtract](https://github.com/csababarta/ntdsxtract) 
- [**170**星][2m] [Py] [markbaggett/srum-dump](https://github.com/markbaggett/srum-dump) 
- [**169**星][4y] [Shell] [halpomeranz/lmg](https://github.com/halpomeranz/lmg) 
- [**164**星][2y] [Py] [monrocoury/forensic-tools](https://github.com/monrocoury/forensic-tools) 
- [**162**星][5m] [Py] [cvandeplas/elk-forensics](https://github.com/cvandeplas/elk-forensics) 
- [**158**星][1m] [C++] [gregwar/fatcat](https://github.com/gregwar/fatcat) 
- [**148**星][4y] [Py] [arxsys/dff](https://github.com/arxsys/dff) 
- [**136**星][2y] [Py] [jrbancel/chromagnon](https://github.com/jrbancel/chromagnon) 
- [**133**星][1m] [C++] [dfir-orc/dfir-orc](https://github.com/dfir-orc/dfir-orc) 
- [**127**星][25d] [Py] [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) 
- [**122**星][3y] [PowerShell] [silverhack/voyeur](https://github.com/silverhack/voyeur) 
- [**117**星][26d] [Py] [travisfoley/dfirtriage](https://github.com/travisfoley/dfirtriage) 
- [**115**星][1m] [Py] [benjeems/packetstrider](https://github.com/benjeems/packetstrider) 
- [**115**星][2m] [Py] [redaelli/imago-forensics](https://github.com/redaelli/imago-forensics) 
- [**114**星][1y] [Shell] [theflakes/ultimate-forensics-vm](https://github.com/theflakes/ultimate-forensics-vm) 
- [**110**星][7m] [PHP] [xplico/xplico](https://github.com/xplico/xplico) 
- [**109**星][1y] [C#] [damonmohammadbagher/meterpreter_payload_detection](https://github.com/damonmohammadbagher/meterpreter_payload_detection) 
- [**109**星][1m] [Py] [domainaware/parsedmarc](https://github.com/domainaware/parsedmarc) parsedmarc: 解析DMARC报告的Python脚本, 含cli
- [**108**星][3y] [projectretroscope/retroscope](https://github.com/projectretroscope/retroscope) 
- [**102**星][6y] [santoku/santoku-linux](https://github.com/santoku/santoku-linux) 
- [**96**星][3m] [Py] [woanware/usbdeviceforensics](https://github.com/woanware/usbdeviceforensics) 
- [**95**星][2y] [JS] [anttikurittu/kirjuri](https://github.com/anttikurittu/kirjuri) 
- [**92**星][1m] [ashemery/linuxforensics](https://github.com/ashemery/LinuxForensics) 
- [**90**星][25d] [Py] [log2timeline/dftimewolf](https://github.com/log2timeline/dftimewolf) 
- [**87**星][5m] [Go] [coinbase/dexter](https://github.com/coinbase/dexter) 
- [**87**星][2y] [C++] [google/aff4](https://github.com/google/aff4) 
- [**82**星][1y] [HTML] [google/rekall-profiles](https://github.com/google/rekall-profiles) 
- [**81**星][5m] [Py] [quantika14/guasap-whatsapp-foresincs-tool](https://github.com/quantika14/guasap-whatsapp-foresincs-tool) 
- [**80**星][2y] [Py] [cheeky4n6monkey/4n6-scripts](https://github.com/cheeky4n6monkey/4n6-scripts) 
- [**78**星][2m] [Py] [google/giftstick](https://github.com/google/giftstick) 
- [**78**星][3y] [C++] [jeffbryner/nbdserver](https://github.com/jeffbryner/nbdserver) 
- [**77**星][2y] [C] [elfmaster/saruman](https://github.com/elfmaster/saruman) 
- [**75**星][2y] [Py] [busindre/dumpzilla](https://github.com/busindre/dumpzilla) 
- [**75**星][2y] [Py] [trolldbois/python-haystack](https://github.com/trolldbois/python-haystack) 
- [**72**星][2m] [ivbeg/awesome-forensicstools](https://github.com/ivbeg/awesome-forensicstools) 
- [**72**星][2m] [ivbeg/awesome-forensicstools](https://github.com/ivbeg/awesome-forensicstools) 
- [**70**星][3y] [Py] [monnappa22/hollowfind](https://github.com/monnappa22/hollowfind) 
- [**66**星][2y] [Shell] [trpt/usbdeath](https://github.com/trpt/usbdeath) 
- [**64**星][2y] [Py] [darkquasar/wmi_persistence](https://github.com/darkquasar/wmi_persistence) WMI_Persistence：Python脚本，直接解析 OBJECTS.DATA 文件（无需访问用户WMI 名称空间）查找 WMI persistence
- [**63**星][2m] [C] [carmaa/interrogate](https://github.com/carmaa/interrogate) 
- [**63**星][1y] [Py] [ralphje/imagemounter](https://github.com/ralphje/imagemounter) 
- [**62**星][2y] [Shell] [yukinoshita47/pentest-tools-auto-installer](https://github.com/yukinoshita47/pentest-tools-auto-installer) 
- [**61**星][4y] [Py] [sysinsider/usbtracker](https://github.com/sysinsider/usbtracker) 
- [**52**星][5y] [Py] [osandamalith/chromefreak](https://github.com/osandamalith/chromefreak) 
- [**46**星][3y] [PowerShell] [n3l5/irfartpull](https://github.com/n3l5/irfartpull) 
- [**46**星][1y] [Py] [sentenza/gimp-ela](https://github.com/sentenza/gimp-ela) 
- [**46**星][7m] [YARA] [xumeiquer/yara-forensics](https://github.com/xumeiquer/yara-forensics) 
- [**46**星][13d] [PowerShell] [s3cur3th1ssh1t/creds](https://github.com/S3cur3Th1sSh1t/Creds) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |
- [**43**星][2m] [TSQL] [abrignoni/dfir-sql-query-repo](https://github.com/abrignoni/dfir-sql-query-repo) 
- [**39**星][2y] [HTML] [scorelab/androphsy](https://github.com/scorelab/androphsy) 
- [**38**星][1y] [C] [adulau/dcfldd](https://github.com/adulau/dcfldd) 
- [**38**星][4y] [AutoIt] [ajmartel/irtriage](https://github.com/ajmartel/irtriage) 
- [**36**星][4y] [Shell] [pwnagentsmith/ir_tool](https://github.com/pwnagentsmith/ir_tool) 
- [**35**星][12d] [Py] [ydkhatri/macforensics](https://github.com/ydkhatri/macforensics) 
- [**34**星][9m] [Py] [att/docker-forensics](https://github.com/att/docker-forensics) 
- [**34**星][5y] [Py] [eurecom-s3/actaeon](https://github.com/eurecom-s3/actaeon) 
- [**33**星][2y] [Py] [google/amt-forensics](https://github.com/google/amt-forensics) 
- [**33**星][12m] [C] [ntraiseharderror/kaiser](https://github.com/ntraiseharderror/kaiser) 
- [**32**星][7m] [Py] [am0nt31r0/osint-search](https://github.com/am0nt31r0/osint-search) 
- [**32**星][1y] [Py] [andreafortuna/autotimeliner](https://github.com/andreafortuna/autotimeliner) autotimeliner: 自动从volatile内存转储中提取取证时间线
- [**32**星][2y] [Py] [bltsec/violent-python3](https://github.com/bltsec/violent-python3) 
- [**32**星][2y] [C] [weaknetlabs/byteforce](https://github.com/weaknetlabs/byteforce) 
- [**31**星][7y] [Perl] [appliedsec/forensicscanner](https://github.com/appliedsec/forensicscanner) 
- [**31**星][5y] [Py] [madpowah/forensicpcap](https://github.com/madpowah/forensicpcap) 
- [**27**星][3y] [Java] [animeshshaw/chromeforensics](https://github.com/animeshshaw/chromeforensics) 
- [**27**星][6y] [Py] [c0d3sh3lf/android_forensics](https://github.com/c0d3sh3lf/android_forensics) 
- [**27**星][5y] [Py] [flo354/iosforensic](https://github.com/flo354/iosforensic) 
- [**26**星][4y] [Py] [cyberhatcoil/acf](https://github.com/cyberhatcoil/acf) 
- [**24**星][6y] [Ruby] [chrislee35/flowtag](https://github.com/chrislee35/flowtag) 
- [**24**星][3y] [Py] [forensicmatt/pancakeviewer](https://github.com/forensicmatt/pancakeviewer) 
- [**24**星][2y] [packtpublishing/digital-forensics-with-kali-linux](https://github.com/packtpublishing/digital-forensics-with-kali-linux) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Kali](#7667f6a0381b6cded2014a0d279b5722) |
- [**23**星][1m] [Pascal] [nannib/imm2virtual](https://github.com/nannib/imm2virtual) 
- [**22**星][1y] [C] [paul-tew/lifer](https://github.com/paul-tew/lifer) 
- [**22**星][1y] [Py] [sebastienbr/volatility](https://github.com/sebastienbr/volatility) 
- [**22**星][2m] [Py] [circl/forensic-tools](https://github.com/circl/forensic-tools) 
- [**21**星][2y] [Py] [harris21/afot](https://github.com/harris21/afot) 
- [**21**星][2y] [C] [lorecioni/imagesplicingdetection](https://github.com/lorecioni/imagesplicingdetection) 
- [**20**星][5y] [JS] [jonstewart/sifter](https://github.com/jonstewart/sifter) 
- [**20**星][3y] [Py] [ncatlin/lockwatcher](https://github.com/ncatlin/lockwatcher) 
- [**19**星][2y] [Py] [lukdog/backtolife](https://github.com/lukdog/backtolife) 
- [**18**星][3y] [C++] [nshadov/screensaver-mouse-jiggler](https://github.com/nshadov/screensaver-mouse-jiggler) 
- [**17**星][Java] [marten4n6/email4n6](https://github.com/marten4n6/email4n6) 


### <a id="4d2a33083a894d6e6ef01b360929f30a"></a>Volatility


- [**3199**星][2m] [Py] [volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility) 
- [**308**星][7m] [Py] [jasonstrimpel/volatility-trading](https://github.com/jasonstrimpel/volatility-trading) 
- [**290**星][3y] [Py] [kevthehermit/volutility](https://github.com/kevthehermit/volutility) 
- [**224**星][2m] [Py] [volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles) 
- [**222**星][2y] [JS] [jameshabben/evolve](https://github.com/jameshabben/evolve) 
- [**219**星][1m] [Py] [volatilityfoundation/community](https://github.com/volatilityfoundation/community) 
- [**174**星][4m] [Py] [jpcertcc/malconfscan](https://github.com/jpcertcc/malconfscan) 
- [**159**星][2y] [Py] [aim4r/voldiff](https://github.com/aim4r/voldiff) 
- [**128**星][4y] [Py] [elceef/bitlocker](https://github.com/elceef/bitlocker) 
- [**128**星][7m] [Py] [kd8bny/limeaide](https://github.com/kd8bny/limeaide) 
- [**90**星][28d] [Py] [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) 
- [**89**星][4m] [Py] [tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns) 
- [**74**星][2y] [Py] [superponible/volatility-plugins](https://github.com/superponible/volatility-plugins) 
- [**60**星][3y] [Py] [fireeye/volatility-plugins](https://github.com/fireeye/volatility-plugins) 
- [**44**星][3y] [Py] [tribalchicken/volatility-filevault2](https://github.com/tribalchicken/volatility-filevault2) 
- [**43**星][6y] [Py] [sketchymoose/totalrecall](https://github.com/sketchymoose/totalrecall) 
- [**38**星][3y] [Py] [kevthehermit/volatility_plugins](https://github.com/kevthehermit/volatility_plugins) 
- [**38**星][4y] [Py] [takahiroharuyama/openioc_scan](https://github.com/takahiroharuyama/openioc_scan) 
- [**37**星][3y] [Py] [cysinfo/pymal](https://github.com/cysinfo/pymal) 
- [**32**星][12m] [Py] [eset/volatility-browserhooks](https://github.com/eset/volatility-browserhooks) 
- [**32**星][2y] [Py] [eurecom-s3/linux_screenshot_xwindows](https://github.com/eurecom-s3/linux_screenshot_xwindows) linux_screenshot_xwindows: Volatility插件, 从内存dump中提取Windows截屏
- [**30**星][4y] [Py] [csababarta/volatility_plugins](https://github.com/csababarta/volatility_plugins) 
- [**29**星][2y] [Py] [tribalchicken/volatility-bitlocker](https://github.com/tribalchicken/volatility-bitlocker) 
- [**28**星][5y] [Py] [phaeilo/vol-openvpn](https://github.com/phaeilo/vol-openvpn) 
- [**25**星][20d] [Py] [cube0x8/chrome_ragamuffin](https://github.com/cube0x8/chrome_ragamuffin) 
- [**23**星][4y] [Py] [monnappa22/linux_mem_diff_tool](https://github.com/monnappa22/linux_mem_diff_tool) 
- [**22**星][5y] [Py] [siliconblade/volatility](https://github.com/siliconblade/volatility) 
- [**21**星][6y] [Py] [carlpulley/volatility](https://github.com/carlpulley/volatility) 




***


## <a id="a2df15c7819a024c2f5c4a7489285597"></a>密罐&&Honeypot


### <a id="2af349669891f54649a577b357aa81a6"></a>未分类-Honeypot


- [**1784**星][1m] [Py] [threatstream/mhn](https://github.com/pwnlandia/mhn) 蜜罐网络
- [**1259**星][21d] [C] [dtag-dev-sec/tpotce](https://github.com/dtag-dev-sec/tpotce) tpotce：创建多蜜罐平台T-Pot ISO 镜像
- [**1201**星][24d] [Go] [hacklcx/hfish](https://github.com/hacklcx/hfish) 扩展企业安全测试主动诱导型开源蜜罐框架系统，记录黑客攻击手段
- [**848**星][4y] [utkusen/hidden-tear](https://github.com/utkusen/hidden-tear) 
- [**400**星][3m] [Py] [nsmfoo/antivmdetection](https://github.com/nsmfoo/antivmdetection) 
- [**356**星][2m] [Py] [p1r06u3/opencanary_web](https://github.com/p1r06u3/opencanary_web) 
- [**325**星][1y] [JS] [shmakov/honeypot](https://github.com/shmakov/honeypot) 
- [**303**星][1m] [Py] [hatching/vmcloak](https://github.com/hatching/vmcloak) 
- [**290**星][4y] [trustedsec/artillery](https://github.com/trustedsec/artillery) 
- [**271**星][1y] [Py] [gbafana25/esp8266_honeypot](https://github.com/gbafana25/esp8266_honeypot) 
- [**229**星][1y] [Shell] [aplura/tango](https://github.com/aplura/tango) 
- [**227**星][9m] [Py] [honeynet/beeswarm](https://github.com/honeynet/beeswarm) 
- [**219**星][1m] [Py] [jamesturk/django-honeypot](https://github.com/jamesturk/django-honeypot) 
- [**187**星][8m] [Go] [0x4d31/honeybits](https://github.com/0x4d31/honeybits) 
- [**167**星][2y] [PowerShell] [javelinnetworks/honeypotbuster](https://github.com/javelinnetworks/honeypotbuster) 
- [**152**星][3y] [C] [x0rz/ssh-honeypot](https://github.com/x0rz/ssh-honeypot) 
- [**148**星][5y] [Py] [rep/dionaea](https://github.com/rep/dionaea) 
- [**129**星][2y] [thec00n/smart-contract-honeypots](https://github.com/thec00n/smart-contract-honeypots) smart-contract-honeypots: 智能合约蜜罐收集
- [**125**星][3y] [PHP] [ikoniaris/kippo-graph](https://github.com/ikoniaris/kippo-graph) 
- [**105**星][1y] [Shell] [mattymcfatty/honeypi](https://github.com/mattymcfatty/honeypi) 
- [**104**星][11m] [Py] [ohmyadd/wetland](https://github.com/ohmyadd/wetland) 
- [**96**星][3m] [Py] [mushorg/tanner](https://github.com/mushorg/tanner) 
- [**77**星][9m] [Py] [cymmetria/honeycomb](https://github.com/cymmetria/honeycomb) 
- [**74**星][3y] [Py] [compoterhacker/mehrai](https://github.com/compoterhacker/mehrai) 
- [**72**星][2y] [Py] [gento/dionaea](https://github.com/gento/dionaea) dionaea：低交互蜜罐
- [**63**星][1y] [HTML] [secwiki/ipot](https://github.com/secwiki/ipot) 
- [**47**星][2m] [Py] [threatstream/shockpot](https://github.com/pwnlandia/shockpot) 
- [**46**星][7y] [C] [shjalayeri/mcedp](https://github.com/shjalayeri/mcedp) 
- [**46**星][7m] [turing-chain/honeypots-on-blockchain](https://github.com/turing-chain/honeypots-on-blockchain) 
- [**46**星][2m] [Py] [zdresearch/owasp-honeypot](https://github.com/zdresearch/owasp-honeypot) 
- [**40**星][3y] [Ruby] [mwrlabs/honeypot_recipes](https://github.com/FSecureLABS/honeypot_recipes) 
- [**39**星][6m] [Py] [kryptoslogic/rdppot](https://github.com/kryptoslogic/rdppot) 
- [**38**星][4y] [Py] [cudeso/cudeso-honeypot](https://github.com/cudeso/cudeso-honeypot) 
- [**37**星][4y] [Py] [fabio-d/honeypot](https://github.com/fabio-d/honeypot) 
- [**34**星][2y] [JS] [honeypotio/techmap](https://github.com/honeypotio/techmap) 
- [**31**星][4y] [Py] [basilfx/kippo-extra](https://github.com/basilfx/kippo-extra) 
- [**29**星][1y] [Go] [netxfly/docker_ssh_honeypot](https://github.com/netxfly/docker_ssh_honeypot) 
- [**26**星][4y] [Shell] [binkybear/honeypi](https://github.com/binkybear/honeypi) 
- [**23**星][15d] [F#] [paralax/burningdogs](https://github.com/paralax/burningdogs) 
- [**21**星][6y] [Py] [ikoniaris/kippo-malware](https://github.com/ikoniaris/kippo-malware) 
- [**21**星][2y] [Shell] [wolfvan/some-samples](https://github.com/wolfvan/some-samples) 


### <a id="d20acdc34ca7c084eb52ca1c14f71957"></a>密罐


- [**1222**星][3y] [Py] [desaster/kippo](https://github.com/desaster/kippo) 
- [**735**星][1m] [Py] [buffer/thug](https://github.com/buffer/thug) 
- [**687**星][4m] [Py] [mushorg/conpot](https://github.com/mushorg/conpot) 
- [**668**星][6m] [Go] [honeytrap/honeytrap](https://github.com/honeytrap/honeytrap) 高级蜜罐框架, 可以运行/监控/管理蜜罐. Go语言编写
- [**574**星][2m] [Py] [thinkst/opencanary](https://github.com/thinkst/opencanary) 
- [**396**星][2m] [Py] [mushorg/glastopf](https://github.com/mushorg/glastopf) 
- [**379**星][3m] [Py] [foospidy/honeypy](https://github.com/foospidy/honeypy) 
- [**371**星][1m] [Py] [dinotools/dionaea](https://github.com/dinotools/dionaea) 
- [**224**星][1m] [Py] [johnnykv/heralding](https://github.com/johnnykv/heralding) 
- [**215**星][1m] [Py] [mushorg/snare](https://github.com/mushorg/snare) 
- [**204**星][6y] [CoffeeScript] [fw42/honeymap](https://github.com/fw42/honeymap) 
- [**192**星][6y] [C] [datasoft/honeyd](https://github.com/datasoft/honeyd) 
- [**127**星][5y] [Shell] [mrschyte/dockerpot](https://github.com/mrschyte/dockerpot) 
- [**126**星][5m] [Go] [mushorg/glutton](https://github.com/mushorg/glutton) 
- [**116**星][3y] [Py] [shiva-spampot/shiva](https://github.com/shiva-spampot/shiva) 
- [**96**星][3y] [Py] [torque59/nosqlpot](https://github.com/torque59/nosqlpot) 
- [**82**星][4y] [Py] [omererdem/honeything](https://github.com/omererdem/honeything) 
- [**76**星][3y] [Py] [sjhilt/gaspot](https://github.com/sjhilt/gaspot) 
- [**75**星][4y] [PowerShell] [pwdrkeg/honeyport](https://github.com/pwdrkeg/honeyport) 
- [**72**星][3y] [C] [tillmannw/honeytrap](https://github.com/tillmannw/honeytrap) 
- [**71**星][5y] [Shell] [andrewmichaelsmith/honeypot-setup-script](https://github.com/andrewmichaelsmith/honeypot-setup-script) 
- [**65**星][3y] [PHP] [cymmetria/strutshoneypot](https://github.com/cymmetria/strutshoneypot) 
- [**65**星][7m] [JS] [plazmaz/mongodb-honeyproxy](https://github.com/plazmaz/mongodb-honeyproxy) 
- [**57**星][5y] [C++] [datasoft/nova](https://github.com/datasoft/nova) 
- [**54**星][5y] [C] [honeynet/ghost-usb-honeypot](https://github.com/honeynet/ghost-usb-honeypot) 
- [**53**星][4m] [HTML] [d1str0/drupot](https://github.com/d1str0/drupot) 
- [**53**星][5m] [Py] [masood-m/yalih](https://github.com/masood-m/yalih) 
- [**52**星][4y] [PHP] [gfoss/phpmyadmin_honeypot](https://github.com/gfoss/phpmyadmin_honeypot) 
- [**51**星][3y] [C] [buffer/libemu](https://github.com/buffer/libemu) 
- [**50**星][4y] [Py] [jpyorre/intelligenthoneynet](https://github.com/jpyorre/intelligenthoneynet) 
- [**48**星][2y] [Py] [rubenespadas/dionaeafr](https://github.com/rubenespadas/dionaeafr) 
- [**45**星][7y] [JS] [oguzy/ovizart](https://github.com/oguzy/ovizart) 
- [**44**星][5y] [Py] [andrew-morris/kippo_detect](https://github.com/andrew-morris/kippo_detect) 
- [**43**星][7m] [Py] [0x4d31/honeyku](https://github.com/0x4d31/honeyku) 
- [**43**星][6y] [Py] [fygrave/honeyntp](https://github.com/fygrave/honeyntp) 
- [**40**星][4y] [Py] [alexbredo/honeypot-camera](https://github.com/alexbredo/honeypot-camera) 
- [**39**星][5y] [Go] [dutchcoders/troje](https://github.com/dutchcoders/troje) 
- [**38**星][6y] [C] [shjalayeri/pwnypot](https://github.com/shjalayeri/pwnypot) 
- [**38**星][8m] [Py] [zeroq/amun](https://github.com/zeroq/amun) 
- [**37**星][6y] [Py] [johnnykv/mnemosyne](https://github.com/johnnykv/mnemosyne) 
- [**36**星][2y] [Go] [mojachieee/go-honeypot](https://github.com/mojachieee/go-honeypot) 
- [**36**星][5y] [C] [sk4ld/gridpot](https://github.com/sk4ld/gridpot) 
- [**35**星][5y] [Go] [traetox/sshforshits](https://github.com/traetox/sshforshits) 
- [**35**星][1y] [Go] [joshrendek/hnypots-agent](https://github.com/joshrendek/hnypots-agent) 
- [**34**星][1y] [JS] [cymmetria/ciscoasa_honeypot](https://github.com/cymmetria/ciscoasa_honeypot) 
- [**33**星][2y] [Py] [illusivenetworks-labs/webtrap](https://github.com/illusivenetworks-labs/webtrap) 
- [**33**星][5y] [Ruby] [madirish/kojoney2](https://github.com/madirish/kojoney2) 
- [**31**星][5y] [Go] [fzerorubigd/go0r](https://github.com/fzerorubigd/go0r) 
- [**30**星][2y] [Py] [revengecoming/demonhunter](https://github.com/revengecoming/demonhunter) 
- [**29**星][2m] [PHP] [eymengunay/eohoneypotbundle](https://github.com/eymengunay/eohoneypotbundle) 
- [**29**星][4y] [HTML] [schmalle/nodepot](https://github.com/schmalle/nodepot) 
- [**28**星][3m] [Py] [jekil/udpot](https://github.com/jekil/udpot) 
- [**28**星][3y] [Shell] [securitygeneration/honeyport](https://github.com/securitygeneration/honeyport) 
- [**27**星][6y] [C++] [hexgolems/pint](https://github.com/hexgolems/pint) 
- [**26**星][5y] [C] [honeynet/phoneyc](https://github.com/honeynet/phoneyc) 
- [**25**星][4y] [Shell] [cert-polska/hsn2-bundle](https://github.com/cert-polska/hsn2-bundle) 
- [**25**星][3y] [Py] [mzweilin/ipv6-attack-detector](https://github.com/mzweilin/ipv6-attack-detector) 
- [**25**星][2y] [Py] [scanfsec/ihoneyportscan](https://github.com/scanfsec/ihoneyportscan) 
- [**23**星][2y] [PHP] [freak3dot/wp-smart-honeypot](https://github.com/freak3dot/wp-smart-honeypot) 
- [**23**星][2y] [Shell] [mattcarothers/mhn-core-docker](https://github.com/mattcarothers/mhn-core-docker) 
- [**22**星][2y] [Perl] [jusafing/pnaf](https://github.com/jusafing/pnaf) 
- [**20**星][9m] [HTML] [cymmetria/honeycomb_plugins](https://github.com/cymmetria/honeycomb_plugins) 
- [**20**星][2y] [Py] [czardoz/hornet](https://github.com/czardoz/hornet) 
- [**20**星][3m] [C] [lnslbrty/potd](https://github.com/lnslbrty/potd) 
- [**19**星][9m] [Shell] [graneed/bwpot](https://github.com/graneed/bwpot) 
- [**19**星][4m] [Go] [magisterquis/vnclowpot](https://github.com/magisterquis/vnclowpot) 
- [**19**星][4y] [PHP] [martiningesen/honnypotter](https://github.com/martiningesen/honnypotter) 
- [**19**星][9y] [Perl] [mfontani/kippo-stats](https://github.com/mfontani/kippo-stats) 
- [**19**星][7y] [C#] [schmalle/mysqlpot](https://github.com/schmalle/mysqlpot) 
- [**18**星][6y] [PHP] [chh/stack-honeypot](https://github.com/chh/stack-honeypot) 
- [**18**星][6y] [Go] [mdp/honeypot.go](https://github.com/mdp/honeypot.go) 
- [**18**星][2y] [Py] [r0hi7/honeysmb](https://github.com/r0hi7/honeysmb) 
- [**17**星][11m] [C] [amv42/sshd-honeypot](https://github.com/amv42/sshd-honeypot) 
- [**17**星][2y] [Go] [ashmckenzie/go-sshoney](https://github.com/ashmckenzie/go-sshoney) 
- [**17**星][5y] [Shell] [free5ty1e/honeypotpi](https://github.com/free5ty1e/honeypotpi) 
- [**17**星][5y] [Shell] [sreinhardt/docker-honeynet](https://github.com/sreinhardt/docker-honeynet) 
- [**16**星][4y] [Perl] [miguelraulb/spamhat](https://github.com/miguelraulb/spamhat) 
- [**15**星][5y] [Shell] [andrewmichaelsmith/manuka](https://github.com/andrewmichaelsmith/manuka) 
- [**15**星][5y] [JS] [mycert/espot](https://github.com/mycert/espot) 
- [**14**星][7y] [Perl] [ayrus/afterglow-cloud](https://github.com/ayrus/afterglow-cloud) 
- [**14**星][5y] [Py] [canadianjeff/honeywrt](https://github.com/canadianjeff/honeywrt) 
- [**14**星][4y] [Py] [glaslos/honeyprint](https://github.com/glaslos/honeyprint) 
- [**13**星][5y] [Py] [bjeborn/basic-auth-pot](https://github.com/bjeborn/basic-auth-pot) 
- [**13**星][2y] [Py] [cymmetria/weblogic_honeypot](https://github.com/cymmetria/weblogic_honeypot) 
- [**13**星][6y] [PHP] [freak3dot/smart-honeypot](https://github.com/freak3dot/smart-honeypot) 
- [**13**星][5y] [Py] [inguardians/toms_honeypot](https://github.com/inguardians/toms_honeypot) 
- [**13**星][7y] [Py] [upa/ofpot](https://github.com/upa/ofpot) 
- [**12**星][2y] [Go] [yvesago/imap-honey](https://github.com/yvesago/imap-honey) 
- [**11**星][8m] [Go] [packetflare/amthoneypot](https://github.com/packetflare/amthoneypot) 
- [**11**星][7y] [Java] [schmalle/servletpot](https://github.com/schmalle/servletpot) 
- [**11**星][5y] [Py] [sneakersinc/honeymalt](https://github.com/SneakersInc/HoneyMalt) 
- [**11**星][1y] [Py] [johestephan/verysimplehoneypot](https://github.com/johestephan/VerySimpleHoneypot) 
- [**10**星][4y] [Py] [gregcmartin/kippo_junos](https://github.com/gregcmartin/kippo_junos) 
- [**10**星][6y] [Tcl] [hbhzwj/imalse](https://github.com/hbhzwj/imalse) 
- [**10**星][7y] [Py] [jedie/django-kippo](https://github.com/jedie/django-kippo) 
- [**10**星][7y] [JS] [yuchincheng/hpfeedshoneygraph](https://github.com/yuchincheng/hpfeedshoneygraph) 
- [**9**星][2y] [Py] [blaverick62/siren](https://github.com/blaverick62/siren) 
- [**9**星][9m] [Py] [bocajspear1/honeyhttpd](https://github.com/bocajspear1/honeyhttpd) 
- [**9**星][2y] [ASP] [cymmetria/micros_honeypot](https://github.com/cymmetria/micros_honeypot) 
- [**9**星][4y] [JS] [hgascon/acapulco](https://github.com/hgascon/acapulco) 
- [**9**星][6y] [CoffeeScript] [knalli/honeypot-for-tcp-32764](https://github.com/knalli/honeypot-for-tcp-32764) 
- [**9**星][2y] [Go] [magisterquis/sshlowpot](https://github.com/magisterquis/sshlowpot) 
- [**9**星][3y] [Py] [naorlivne/dshp](https://github.com/naorlivne/dshp) 
- [**9**星][6y] [Go] [paulmaddox/gohoney](https://github.com/paulmaddox/gohoney) 
- [**9**星][19d] [HTML] [uhh-iss/honeygrove](https://github.com/uhh-iss/honeygrove) 
- [**8**星][5y] [Py] [alexbredo/honeypot-ftp](https://github.com/alexbredo/honeypot-ftp) 
- [**8**星][2y] [Py] [darkarnium/kako](https://github.com/darkarnium/kako) 
- [**8**星][4y] [Go] [kingtuna/go-emulators](https://github.com/kingtuna/go-emulators) 
- [**8**星][4y] [Py] [mushorg/imhoneypot](https://github.com/mushorg/imhoneypot) 
- [**8**星][6y] [Shell] [rshipp/slipm-honeypot](https://github.com/rshipp/slipm-honeypot) 
- [**7**星][9y] [Java] [argomirr/honeypot](https://github.com/argomirr/honeypot) 
- [**7**星][9m] [Rust] [bartnv/portlurker](https://github.com/bartnv/portlurker) 
- [**6**星][2y] [Go] [betheroot/pghoney](https://github.com/betheroot/pghoney) 
- [**6**星][1m] [Ruby] [betheroot/sticky_elephant](https://github.com/betheroot/sticky_elephant) 
- [**6**星][3y] [Go] [ppacher/honeyssh](https://github.com/ppacher/honeyssh) 
- [**5**星][2y] [Go] [fnzv/yafh](https://github.com/fnzv/yafh) 
- [**5**星][2y] [Go] [justinazoff/ssh-auth-logger](https://github.com/justinazoff/ssh-auth-logger) 
- [**5**星][9m] [C] [sjinks/mysql-honeypotd](https://github.com/sjinks/mysql-honeypotd) 
- [**5**星][3y] [Py] [xiaoxiaoleo/honeymysql](https://github.com/xiaoxiaoleo/honeymysql) 
- [**5**星][4y] [Shell] [xme/dshield-docker](https://github.com/xme/dshield-docker) 
- [**4**星][1y] [CSS] [lcashdol/wapot](https://github.com/lcashdol/wapot) 
- [**4**星][3y] [Go] [sec51/honeymail](https://github.com/sec51/honeymail) 
- [**4**星][1y] [C] [sjinks/ssh-honeypotd](https://github.com/sjinks/ssh-honeypotd) 
- [**3**星][5y] [Py] [csirtgadgets/csirtg-honeypot](https://github.com/csirtgadgets/csirtg-honeypot) 
- [**3**星][2y] [Java] [helospark/tomcat-manager-honeypot](https://github.com/helospark/tomcat-manager-honeypot) 
- [**3**星][2y] [Py] [morian/blacknet](https://github.com/morian/blacknet) 
- [**3**星][3y] [Groovy] [schmalle/honeyalarmg2](https://github.com/schmalle/honeyalarmg2) 
- [**3**星][4y] [Py] [securitytw/delilah](https://github.com/securitytw/delilah) 
- [**3**星][1y] [shbhmsingh72/honeypot-research-papers](https://github.com/shbhmsingh72/honeypot-research-papers) 
- [**3**星][4y] [Shell] [ziemeck/bifrozt-ansible](https://github.com/ziemeck/bifrozt-ansible) 
- [**2**星][4y] [JS] [joss-steward/honeypotdisplay](https://github.com/joss-steward/honeypotdisplay) 
- [**2**星][27d] [Py] [jwxa2015/mongodb-honeyproxypy](https://github.com/jwxa2015/mongodb-honeyproxypy) 
- [**2**星][2y] [Go] [sahilm/hived](https://github.com/sahilm/hived) 
- [**2**星][2y] [Py] [xlfe/cowrie2neo](https://github.com/xlfe/cowrie2neo) 
- [**1**星][7y] [c++] [zaccone/quechua](https://bitbucket.org/zaccone/quechua) 
- [**1**星][2y] [Py] [ajackal/arctic-swallow](https://github.com/ajackal/arctic-swallow) 
- [**1**星][2y] [Perl] [batchmcnulty/malbait](https://github.com/batchmcnulty/malbait) 
- [**1**星][4y] [PHP] [govcert-cz/wordpot-frontend](https://github.com/govcert-cz/wordpot-frontend) 
- [**1**星][4y] [PHP] [jadb/honeypot](https://github.com/jadb/honeypot) 
- [**1**星][11y] [C] [provos/honeyd](https://github.com/provos/honeyd) 
- [**0**星][4y] [PHP] [govcert-cz/shockpot-frontend](https://github.com/govcert-cz/shockpot-frontend) 
- [**0**星][5y] [Perl] [katkad/glastopf-analytics](https://github.com/katkad/glastopf-analytics) 


### <a id="efde8c850d8d09e7c94aa65a1ab92acf"></a>收集


- [**3708**星][1m] [Py] [paralax/awesome-honeypots](https://github.com/paralax/awesome-honeypots) 


### <a id="c8f749888134d57b5fb32382c78ef2d1"></a>SSH&&Telnet


- [**2906**星][18d] [Py] [cowrie/cowrie](https://github.com/cowrie/cowrie) cowrie：中型/交互型 SSH/Telnet 蜜罐，
- [**959**星][3y] [Go] [jaksi/sshesame](https://github.com/jaksi/sshesame) 
- [**272**星][27d] [C] [droberson/ssh-honeypot](https://github.com/droberson/ssh-honeypot) 
- [**196**星][3y] [C] [robertdavidgraham/telnetlogger](https://github.com/robertdavidgraham/telnetlogger) 
- [**187**星][27d] [Py] [phype/telnet-iot-honeypot](https://github.com/phype/telnet-iot-honeypot) 
- [**144**星][2y] [Go] [magisterquis/sshhipot](https://github.com/magisterquis/sshhipot) 
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**124**星][9m] [Py] [stamparm/hontel](https://github.com/stamparm/hontel) 
- [**100**星][3y] [Py] [ncouture/mockssh](https://github.com/ncouture/mockssh) 
- [**93**星][3y] [Py] [cymmetria/mtpot](https://github.com/cymmetria/mtpot) 
- [**80**星][9m] [Go] [mkishere/sshsyrup](https://github.com/mkishere/sshsyrup) 
- [**54**星][2y] [Shell] [lanjelot/twisted-honeypots](https://github.com/lanjelot/twisted-honeypots) 
- [**1**星][7m] [Tcl] [cryptix720/hudinx](https://github.com/cryptix720/hudinx) 
- [**0**星][4y] [C#] [balte/telnethoney](https://github.com/balte/telnethoney) 


### <a id="356be393f6fb9215c14799e5cd723fca"></a>TCP&&UDP




### <a id="577fc2158ab223b65442fb0fd4eb8c3e"></a>HTTP&&Web


- [**433**星][1y] [Py] [0x4d31/honeylambda](https://github.com/0x4d31/honeylambda) 


### <a id="35c6098cbdc5202bf7f60979a76a5691"></a>ActiveDirectory


- [**432**星][3y] [Py] [secureworks/dcept](https://github.com/secureworks/dcept) 


### <a id="7ac08f6ae5c88efe2cd5b47a4d391e7e"></a>SMTP


- [**168**星][1y] [Py] [awhitehatter/mailoney](https://github.com/awhitehatter/mailoney) 


### <a id="8c58c819e0ba0442ae90d8555876d465"></a>打印机


- [**162**星][7m] [Py] [sa7mon/miniprint](https://github.com/sa7mon/miniprint) 


### <a id="1a6b81fd9550736d681d6d0e99ae69e3"></a>Elasticsearch


- [**127**星][4y] [Go] [jordan-wright/elastichoney](https://github.com/jordan-wright/elastichoney) 


### <a id="57356b67511a9dc7497b64b007047ee7"></a>ADB


- [**100**星][16d] [Py] [huuck/adbhoney](https://github.com/huuck/adbhoney) 


### <a id="c5b6762b3dc783a11d72dea648755435"></a>蓝牙&&Bluetooth 


- [**1261**星][1m] [Py] [virtualabs/btlejack](https://github.com/virtualabs/btlejack) 
- [**1120**星][9m] [evilsocket/bleah](https://github.com/evilsocket/bleah) 低功耗蓝牙扫描器
- [**865**星][3m] [Java] [googlearchive/android-bluetoothlegatt](https://github.com/googlearchive/android-BluetoothLeGatt) 
- [**292**星][11m] [JS] [jeija/bluefluff](https://github.com/jeija/bluefluff) 
- [**242**星][2y] [C#] [sparkfunx/skimmer_scanner](https://github.com/sparkfunx/skimmer_scanner) 
- [**212**星][2y] [Py] [mailinneberg/blueborne](https://github.com/mailinneberg/blueborne) 
- [**204**星][2y] [Java] [udark/underdark-android](https://github.com/udark/underdark-android) 
- [**97**星][4y] [Java] [andrewmichaelsmith/bluepot](https://github.com/andrewmichaelsmith/bluepot) 
    - 重复区段: [工具/蓝牙&&Bluetooth](#ceb90405292daed9bb32ac20836c219a) |
- [**80**星][7m] [Py] [nccgroup/blesuite](https://github.com/nccgroup/blesuite) 
- [**71**星][3y] [Py] [nccgroup/ble-replay](https://github.com/nccgroup/ble-replay) 
- [**34**星][2y] [Py] [x0rloser/ps4_wifi_bt](https://github.com/x0rloser/ps4_wifi_bt) 
- [**25**星][3y] [C] [zenware/bluemaho](https://github.com/zenware/bluemaho) 
- [**24**星][1y] [JS] [ioactive/bluecrawl](https://github.com/ioactive/bluecrawl) 
- [**24**星][3y] [Py] [nccgroup/blesuite-cli](https://github.com/nccgroup/blesuite-cli) 
- [**22**星][3y] [HTML] [pdjstone/cloudpets-web-bluetooth](https://github.com/pdjstone/cloudpets-web-bluetooth) 


### <a id="2a77601ce72f944679b8c5650d50148d"></a>其他类型


#### <a id="1d0819697e6bc533f564383d0b98b386"></a>Wordpress


- [**131**星][1y] [CSS] [gbrindisi/wordpot](https://github.com/gbrindisi/wordpot) 
- [**58**星][7m] [HTML] [dustyfresh/honeypress](https://github.com/dustyfresh/honeypress) 






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
- [**398**星][3y] [Py] [1an0rmus/tekdefense-automater](https://github.com/1an0rmus/tekdefense-automater) 
- [**374**星][7m] [Py] [hurricanelabs/machinae](https://github.com/hurricanelabs/machinae) 
- [**290**星][6m] [YARA] [supportintelligence/icewater](https://github.com/supportintelligence/icewater) 
- [**273**星][2y] [Py] [ptr32void/ostrica](https://github.com/ptr32void/ostrica) 
- [**256**星][2y] [paloaltonetworks/minemeld](https://github.com/paloaltonetworks/minemeld) 
- [**253**星][2m] [Py] [diogo-fernan/malsub](https://github.com/diogo-fernan/malsub) 
- [**234**星][2m] [Py] [cylance/cybot](https://github.com/cylance/CyBot) 
- [**231**星][1m] [Py] [anouarbensaad/vulnx](https://github.com/anouarbensaad/vulnx) An Intelligent Bot Auto Shell Injector that detect vulnerabilities in multiple types of CMS
- [**217**星][2m] [Py] [inquest/threatingestor](https://github.com/inquest/threatingestor) 
- [**208**星][18d] [Py] [inquest/omnibus](https://github.com/inquest/omnibus) 
- [**202**星][2y] [Py] [newbee119/ti_collector](https://github.com/NewBee119/Ti_Collector) 
- [**201**星][3m] [Py] [yelp/threat_intel](https://github.com/yelp/threat_intel) 
- [**194**星][1y] [scu-igroup/threat-intelligence](https://github.com/NewBee119/threat-intelligence) 
- [**181**星][6m] [Py] [keithjjones/hostintel](https://github.com/keithjjones/hostintel) 
- [**145**星][4y] [R] [mlsecproject/tiq-test](https://github.com/mlsecproject/tiq-test) 
- [**134**星][1y] [Go] [lanrat/certgraph](https://github.com/lanrat/certgraph) certgraph: 抓取 SSL 证书并创建有向图, 图中每个域都是一个节点, 域的证书的替代名称作为节点的边
- [**131**星][8m] [PowerShell] [logrhythm-labs/pie](https://github.com/logrhythm-labs/pie) Phishing Intelligence Engine 
- [**130**星][16d] [Py] [csirtgadgets/bearded-avenger](https://github.com/csirtgadgets/bearded-avenger) 
- [**130**星][1y] [Py] [thehive-project/hippocampe](https://github.com/thehive-project/hippocampe) 
- [**112**星][5y] [CSS] [syphon1c/threatelligence](https://github.com/syphon1c/threatelligence) 
- [**105**星][1y] [Py] [binarydefense/goatrider](https://github.com/binarydefense/goatrider) 
- [**103**星][4y] [Py] [tripwire/tardis](https://github.com/tripwire/tardis) 
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |
- [**94**星][6y] [Py] [crowdstrike/crowdfms](https://github.com/crowdstrike/crowdfms) 
- [**91**星][3y] [HTML] [stixproject/stix-viz](https://github.com/stixproject/stix-viz) 
- [**89**星][11m] [Py] [stratosphereips/manati](https://github.com/stratosphereips/manati) 
- [**76**星][2y] [Py] [mgeide/poortego](https://github.com/mgeide/poortego) 
- [**75**星][3y] [Py] [keithjjones/fileintel](https://github.com/keithjjones/fileintel) 
- [**75**星][4y] [Py] [qtek/qradio](https://github.com/qtek/qradio) 
- [**71**星][20d] [Py] [cert-polska/n6](https://github.com/cert-polska/n6) 
- [**71**星][4y] [Py] [exp0se/harbinger](https://github.com/exp0se/harbinger) 
- [**53**星][2y] [Py] [0x4d31/sqhunter](https://github.com/0x4d31/sqhunter) 
- [**43**星][8m] [Py] [misp/misp-taxii-server](https://github.com/misp/misp-taxii-server) 
- [**42**星][2y] [Go] [ocmdev/rita](https://github.com/ocmdev/rita) 
- [**37**星][3y] [Java] [cert-se/megatron-java](https://github.com/cert-se/megatron-java) 
- [**34**星][4y] [Ruby] [lookingglass/opentpx](https://github.com/lookingglass/opentpx) 
- [**31**星][3m] [dfw1n/dfw1n-osint](https://github.com/dfw1n/dfw1n-osint) 
- [**28**星][4y] [Py] [paulpc/nyx](https://github.com/paulpc/nyx) 
- [**23**星][3y] [Py] [kx499/ostip](https://github.com/kx499/ostip) 
- [**22**星][5m] [redshiftzero/awesome-threat-modeling](https://github.com/redshiftzero/awesome-threat-modeling) 
- [**21**星][3y] [Py] [misp/misp-workbench](https://github.com/misp/misp-workbench) 
- [**20**星][10m] [Py] [spacepatcher/firehol-ip-aggregator](https://github.com/spacepatcher/firehol-ip-aggregator) 
- [**19**星][3y] [Py] [johestephan/ibmxforceex.checker.py](https://github.com/johestephan/ibmxforceex.checker.py) 
- [**18**星][2y] [Py] [dougiep16/actortrackr](https://github.com/dougiep16/actortrackr) 
- [**15**星][2y] [Go] [jheise/threatcmd](https://github.com/jheise/threatcmd) 
- [**13**星][12d] [Py] [davidonzo/threat-intel](https://github.com/davidonzo/threat-intel) 
- [**9**星][2y] [Py] [jheise/threatcrowd_api](https://github.com/jheise/threatcrowd_api) 
- [**4**星][3m] [JS] [securityriskadvisors/sra-taxii2-server](https://github.com/securityriskadvisors/sra-taxii2-server) 
- [**2**星][9m] [Py] [fhightower/onemillion](https://github.com/fhightower/onemillion) 


### <a id="91dc39dc492ee8ef573e1199117bc191"></a>收集


- [**3117**星][5m] [hslatman/awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence) 
- [**1459**星][14d] [YARA] [cybermonitor/apt_cybercriminal_campagin_collections](https://github.com/cybermonitor/apt_cybercriminal_campagin_collections) 


### <a id="3e10f389acfbd56b79f52ab4765e11bf"></a>IOC


#### <a id="c94be209c558a65c5e281a36667fc27a"></a>未分类


- [**1408**星][1m] [Py] [neo23x0/loki](https://github.com/neo23x0/loki) 
- [**580**星][3y] [Py] [mlsecproject/combine](https://github.com/mlsecproject/combine) 从公开的资源中收集IOC
- [**208**星][4m] [Shell] [neo23x0/fenrir](https://github.com/neo23x0/fenrir) 
- [**146**星][2y] [Py] [mandiant/ioc_writer](https://github.com/mandiant/ioc_writer) 
- [**114**星][1y] [Py] [abhinavbom/threat-intelligence-hunter](https://github.com/abhinavbom/threat-intelligence-hunter) 
- [**106**星][1y] [Py] [aboutsecurity/rastrea2r](https://github.com/aboutsecurity/rastrea2r) 
- [**101**星][1y] [Go] [sroberts/cacador](https://github.com/sroberts/cacador) 从文本块中提取常见的IoC
- [**80**星][1y] [Py] [silascutler/malpipe](https://github.com/silascutler/malpipe) 
- [**69**星][1y] [Py] [stixproject/openioc-to-stix](https://github.com/stixproject/openioc-to-stix) 
- [**49**星][5y] [Py] [michael-yip/threattracker](https://github.com/michael-yip/threattracker) 监控由一组自定义谷歌搜索引擎索引的IoC，并生成告警
- [**49**星][4m] [Jupyter Notebook] [sroberts/jager](https://github.com/sroberts/jager) 
- [**32**星][1y] [JS] [s03d4-164/hiryu](https://github.com/s03d4-164/hiryu) 
- [**17**星][26d] [Py] [fhightower/ioc-finder](https://github.com/fhightower/ioc-finder) 
- [**14**星][2m] [Py] [ioc-fang/ioc_fanger](https://github.com/ioc-fang/ioc_fanger) 
- [**12**星][4y] [Py] [pidydx/pyioce](https://github.com/pidydx/pyioce) 


#### <a id="20a019435f1c5cc75e574294c01f3fee"></a>IOC集合


- [**405**星][8m] [Shell] [sroberts/awesome-iocs](https://github.com/sroberts/awesome-iocs) 
- [**347**星][3y] [fireeye/iocs](https://github.com/fireeye/iocs) 


#### <a id="1b1aa1dfcff3054bc20674230ee52cfe"></a>IOC提取


- [**303**星][2y] [Py] [armbues/ioc_parser](https://github.com/armbues/ioc_parser) 
- [**212**星][23d] [Py] [inquest/python-iocextract](https://github.com/inquest/python-iocextract) IoC提取器
- [**118**星][6y] [Py] [stephenbrannon/iocextractor](https://github.com/stephenbrannon/iocextractor) 


#### <a id="9bcb156b2e3b7800c42d5461c0062c02"></a>IOC获取


- [**6037**星][2y] [C] [jgamblin/mirai-source-code](https://github.com/jgamblin/mirai-source-code) 
- [**652**星][13d] [Py] [blackorbird/apt_report](https://github.com/blackorbird/apt_report) 
- [**626**星][28d] [YARA] [eset/malware-ioc](https://github.com/eset/malware-ioc) 
- [**418**星][1y] [JS] [ciscocsirt/gosint](https://github.com/ciscocsirt/gosint) 收集、处理、索引高质量IOC的框架
- [**406**星][3y] [C] [0x27/linux.mirai](https://github.com/0x27/linux.mirai) 
- [**303**星][1y] [Py] [fsecurelabs/win_driver_plugin](https://github.com/FSecureLABS/win_driver_plugin) 
- [**257**星][2m] [PHP] [pan-unit42/iocs](https://github.com/pan-unit42/iocs) 
- [**164**星][3m] [Py] [botherder/targetedthreats](https://github.com/botherder/targetedthreats) 
- [**156**星][9y] [Py] [jonty/idiocy](https://github.com/jonty/idiocy) 
- [**123**星][20d] [Java] [graylog2/graylog-plugin-threatintel](https://github.com/graylog2/graylog-plugin-threatintel) 
- [**122**星][1m] [Py] [rastrea2r/rastrea2r](https://github.com/rastrea2r/rastrea2r) 
- [**113**星][5m] [Java] [guardianproject/iocipher](https://github.com/guardianproject/iocipher) 
- [**110**星][2y] [Py] [cert-w/certitude](https://github.com/cert-w/certitude) 
- [**84**星][7m] [Go] [assafmo/xioc](https://github.com/assafmo/xioc) 
- [**73**星][4y] [Py] [tandasat/winioctldecoder](https://github.com/tandasat/winioctldecoder) IDA插件，将Windows设备IO控制码解码成为DeviceType, FunctionCode, AccessType, MethodType.
- [**69**星][3m] [C#] [antoniococo/runascs](https://github.com/antoniococo/runascs) 
- [**67**星][2m] [doctorwebltd/malware-iocs](https://github.com/doctorwebltd/malware-iocs) 
- [**60**星][12m] [Py] [conix-security/btg](https://github.com/conix-security/btg) 
- [**55**星][4m] [Py] [lion-gu/ioc-explorer](https://github.com/lion-gu/ioc-explorer) 
- [**54**星][5y] [Py] [yahooarchive/pyioce](https://github.com/YahooArchive/PyIOCe) 
- [**52**星][2y] [Py] [neo23x0/radiocarbon](https://github.com/neo23x0/radiocarbon) 
- [**43**星][2m] [HTML] [advanced-threat-research/iocs](https://github.com/advanced-threat-research/iocs) 
- [**35**星][2m] [spiderlabs/iocs-idps](https://github.com/spiderlabs/iocs-idps) 
- [**34**星][2m] [C++] [erickutcher/httpdownloader](https://github.com/erickutcher/httpdownloader) 
- [**33**星][3y] [Py] [cr4sh/aptiocalypsis](https://github.com/cr4sh/aptiocalypsis) 
- [**32**星][1m] [Go] [dcso/spyre](https://github.com/dcso/spyre) 
- [**25**星][4y] [Py] [threatminer/ioc_parser](https://github.com/threatminer/ioc_parser) 






***


## <a id="946d766c6a0fb23b480ff59d4029ec71"></a>防护&&Defense


### <a id="7a277f8b0e75533e0b50d93c902fb351"></a>未分类-Defense


- [**630**星][5m] [Py] [binarydefense/artillery](https://github.com/binarydefense/artillery) 
- [**167**星][29d] [C#] [n0dec/malwless](https://github.com/n0dec/malwless) 
- [**153**星][5m] [Shell] [maldevel/blue-team](https://github.com/maldevel/blue-team) 
- [**152**星][1m] [Shell] [securityriskadvisors/vectr](https://github.com/securityriskadvisors/vectr) 
- [**151**星][2m] [C++] [ion28/bluespawn](https://github.com/ion28/bluespawn) 
- [**99**星][1y] [PowerShell] [testingpens/malwarepersistencescripts](https://github.com/testingpens/malwarepersistencescripts) 
- [**58**星][5m] [Shell] [d4rk007/blueghost](https://github.com/d4rk007/blueghost) 
- [**57**星][2y] [Go] [sensepost/notruler](https://github.com/sensepost/notruler) 


### <a id="784ea32a3f4edde1cd424b58b17e7269"></a>WAF


- [**3248**星][2m] [C] [nbs-system/naxsi](https://github.com/nbs-system/naxsi) 
- [**3125**星][17d] [C++] [spiderlabs/modsecurity](https://github.com/spiderlabs/modsecurity) 
- [**2745**星][4y] [Lua] [loveshell/ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf) 
- [**870**星][2y] [Perl] [p0pr0ck5/lua-resty-waf](https://github.com/p0pr0ck5/lua-resty-waf) 
- [**617**星][2m] [Py] [3xp10it/xwaf](https://github.com/3xp10it/xwaf) waf 自动爆破(绕过)工具
- [**600**星][3m] [Lua] [jx-sec/jxwaf](https://github.com/jx-sec/jxwaf) 
- [**599**星][1y] [Lua] [unixhot/waf](https://github.com/unixhot/waf) 
- [**543**星][7m] [Py] [s0md3v/blazy](https://github.com/s0md3v/Blazy) 
- [**500**星][1m] [Go] [janusec/janusec](https://github.com/janusec/janusec) 
- [**462**星][7m] [Java] [chengdedeng/waf](https://github.com/chengdedeng/waf) 
- [**436**星][2m] [PHP] [akaunting/firewall](https://github.com/akaunting/firewall) 
- [**424**星][8m] [Py] [aws-samples/aws-waf-sample](https://github.com/aws-samples/aws-waf-sample) 
- [**416**星][2y] [Lua] [xsec-lab/x-waf](https://github.com/xsec-lab/x-waf) 
- [**406**星][1m] [C#] [jbe2277/waf](https://github.com/jbe2277/waf) 
- [**401**星][7m] [Py] [awslabs/aws-waf-security-automations](https://github.com/awslabs/aws-waf-security-automations) 
- [**401**星][10m] [C] [titansec/openwaf](https://github.com/titansec/openwaf) 
- [**255**星][2y] [Go] [netxfly/xsec-ip-database](https://github.com/netxfly/xsec-ip-database) xsec-ip-database：恶意IP 和域名库。通过爬虫定期拉取网络中公开的恶意ip 库来获取恶意IP和域名，且支持与自有的其他安全产品联动（HIDS、WAF、蜜罐、防火墙等产品），实时更新IP库
- [**243**星][1y] [Py] [warflop/cloudbunny](https://github.com/warflop/cloudbunny) 
- [**207**星][6m] [C] [coolervoid/raptor_waf](https://github.com/coolervoid/raptor_waf) 
- [**194**星][2m] [Py] [stamparm/identywaf](https://github.com/stamparm/identywaf) 
- [**190**星][1y] [Py] [frizb/bypassing-web-application-firewalls](https://github.com/frizb/bypassing-web-application-firewalls) 
- [**190**星][2y] [Py] [sheldoncoupeheure/autosqli](https://github.com/sheldoncoupeheure/AutoSQLi) 
- [**189**星][7m] [Py] [fastly/ftw](https://github.com/fastly/ftw) ftw：WAF 测试框架
- [**183**星][11m] [Py] [zerokeeper/webeye](https://github.com/zerokeeper/webeye) 快速简单地识别WEB服务器类型、CMS类型、WAF类型、WHOIS信息、以及语言框架的小脚本 
- [**180**星][2y] [PHP] [lcatro/php-webshell-bypass-waf](https://github.com/lcatro/php-webshell-bypass-waf) 
- [**163**星][6m] [Py] [wafpassproject/wafpass](https://github.com/wafpassproject/wafpass) wafpass：利用所有Payload 的绕过技巧分析参数，旨在为安全解决方案（例如WAF）确定基准。
- [**162**星][6y] [XSLT] [ironbee/waf-research](https://github.com/ironbee/waf-research) 
- [**129**星][11m] [Dockerfile] [theonemule/docker-waf](https://github.com/theonemule/docker-waf) 
- [**124**星][2y] [HTML] [chybeta/waf-bypass](https://github.com/chybeta/waf-bypass) 
- [**122**星][7m] [Py] [landgrey/abuse-ssl-bypass-waf](https://github.com/landgrey/abuse-ssl-bypass-waf) 
- [**119**星][6y] [Lua] [nixuehan/belial](https://github.com/nixuehan/belial) 
- [**116**星][3y] [Py] [exp-db/ai-driven-waf](https://github.com/exp-db/ai-driven-waf) 
- [**90**星][3m] [C#] [jbe2277/dotnetpad](https://github.com/jbe2277/dotnetpad) 
- [**81**星][3y] [C] [bluekezhou/binarywaf](https://github.com/bluekezhou/binarywaf) 
- [**81**星][4y] [PHP] [klaubert/waf-fle](https://github.com/klaubert/waf-fle) 
- [**72**星][7m] [PHP] [s9mf/s9mf-php-webshell-bypass](https://github.com/s9mf/s9mf-php-webshell-bypass) 
- [**67**星][3y] [Go] [xsec-lab/x-waf-admin](https://github.com/xsec-lab/x-waf-admin) 
- [**65**星][1y] [Py] [cerbo/aws-waf-security-automation](https://github.com/cerbo/aws-waf-security-automation) 
- [**60**星][2m] [Py] [crs-support/ftw](https://github.com/crs-support/ftw) 
- [**59**星][5y] [Py] [owtf/wafbypasser](https://github.com/owtf/wafbypasser) 
- [**35**星][2y] [Py] [webr0ck/waf_bypass_helper](https://github.com/sndvul/waf_bypass_helper) 


### <a id="ce6532938f729d4c9d66a5c75d1676d3"></a>防火墙&&FireWall


- [**4162**星][2m] [Py] [evilsocket/opensnitch](https://github.com/evilsocket/opensnitch) opensnitch：Little Snitch 应用程序防火墙的 GNU/Linux 版本。（Little Snitch：Mac操作系统的应用程序防火墙，能防止应用程序在你不知道的情况下自动访问网络）
- [**3186**星][1m] [Objective-C] [objective-see/lulu](https://github.com/objective-see/lulu) 
- [**1515**星][12d] [Java] [ukanth/afwall](https://github.com/ukanth/afwall) 
- [**1031**星][9m] [Shell] [firehol/firehol](https://github.com/firehol/firehol) 
- [**817**星][4m] [trimstray/iptables-essentials](https://github.com/trimstray/iptables-essentials) 
- [**588**星][2y] [Go] [nim4/dbshield](https://github.com/nim4/dbshield) 
- [**545**星][6m] [Go] [sysdream/chashell](https://github.com/sysdream/chashell) 
- [**482**星][2y] [Py] [khalilbijjou/wafninja](https://github.com/khalilbijjou/wafninja) 
- [**449**星][5m] [Shell] [vincentcox/bypass-firewalls-by-dns-history](https://github.com/vincentcox/bypass-firewalls-by-dns-history) 
- [**428**星][1y] [Py] [lightbulb-framework/lightbulb-framework](https://github.com/lightbulb-framework/lightbulb-framework) Web App 防火墙和过滤器的审计框架
- [**342**星][2y] [Py] [sarfata/voodooprivacy](https://github.com/sarfata/voodooprivacy) 
- [**323**星][3y] [Py] [faizann24/fwaf-machine-learning-driven-web-application-firewall](https://github.com/faizann24/fwaf-machine-learning-driven-web-application-firewall) 
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |
- [**303**星][2y] [Shell] [ugukkylbklaom/vultr-ss-firewall](https://github.com/ugukkylbklaom/vultr-ss-firewall) 
- [**269**星][6y] [C] [robertdavidgraham/isowall](https://github.com/robertdavidgraham/isowall) 
- [**245**星][3y] [Py] [tcstool/fireaway](https://github.com/tcstool/fireaway) 
- [**232**星][4m] [Shell] [essandess/macos-fortress](https://github.com/essandess/macos-fortress) 
- [**220**星][1y] [Go] [maksadbek/tcpovericmp](https://github.com/maksadbek/tcpovericmp) 
- [**195**星][10m] [JS] [comotion/vsf](https://github.com/comotion/vsf) 
- [**181**星][4y] [C++] [zecure/shadowd](https://github.com/zecure/shadowd) 
- [**163**星][4y] [C] [uptimejp/sql_firewall](https://github.com/uptimejp/sql_firewall) 
    - 重复区段: [工具/数据库&&SQL攻击&&SQL注入/SQL/未分类-SQL](#1cfe1b2a2c88cd92a414f81605c8d8e7) |
- [**148**星][2y] [C] [dekuan/vwfirewall](https://github.com/dekuan/vwfirewall) 
- [**133**星][1m] [Py] [wudimahua/firewall](https://github.com/wudimahua/firewall) 
- [**97**星][2y] [Go] [subgraph/fw-daemon](https://github.com/subgraph/fw-daemon) 
- [**74**星][3y] [Py] [spotify/gcp-firewall-enforcer](https://github.com/spotify/gcp-firewall-enforcer) 
- [**70**星][2y] [Py] [dxwu/binderfilter](https://github.com/dxwu/binderfilter) 
- [**64**星][7y] [C] [bskari/sqlassie](https://github.com/bskari/sqlassie) 
- [**64**星][7m] [Py] [k4yt3x/scutum](https://github.com/k4yt3x/scutum) 
- [**64**星][4m] [Shell] [rfxn/advanced-policy-firewall](https://github.com/rfxn/advanced-policy-firewall) advanced-policy-firewall：高级版策略防火墙
- [**61**星][6y] [C] [freewaf/waf-pe](https://github.com/freewaf/waf-pe) 
- [**60**星][4y] [PHP] [filetofirewall/fof](https://github.com/filetofirewall/fof) 
- [**55**星][1y] [JS] [ubeacsec/silverdog](https://github.com/ubeacsec/silverdog) 
- [**54**星][2y] [C++] [raymon-tian/wfpfirewall](https://github.com/raymon-tian/wfpfirewall) 
- [**35**星][6y] [Perl] [cyberisltd/egresser](https://github.com/cyberisltd/egresser) 


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
- [**216**星][2y] [Py] [feicong/jni_helper](https://github.com/feicong/jni_helper) jni_helper：AndroidSO自动化分析工具（非虫）
- [**127**星][1m] [Go] [0xrawsec/whids](https://github.com/0xrawsec/whids) 
- [**115**星][14d] [Py] [gridsync/gridsync](https://github.com/gridsync/gridsync) 
- [**102**星][3m] [suricata-rules/suricata-rules](https://github.com/suricata-rules/suricata-rules) 
- [**100**星][11m] [C] [kirillwow/ids_bypass](https://github.com/kirillwow/ids_bypass) ids_bypass: 入侵检测系统(IDS)绕过PoC
- [**87**星][1y] [Py] [tearsecurity/firstorder](https://github.com/tearsecurity/firstorder) 
- [**86**星][3y] [C] [waterslidelts/waterslide](https://github.com/waterslidelts/waterslide) 
- [**83**星][1y] [Py] [401trg/detections](https://github.com/401trg/detections) 
- [**68**星][3y] [Py] [zxsecurity/gpsnitch](https://github.com/zxsecurity/gpsnitch) 
- [**64**星][3y] [Shell] [da667/667s_shitlist](https://github.com/da667/667s_shitlist) 
- [**64**星][3y] [Py] [xorpd/idsearch](https://github.com/xorpd/idsearch) 搜索工具
- [**63**星][2y] [C] [plashchynski/viewssld](https://github.com/plashchynski/viewssld) 
- [**60**星][1y] [C++] [paranoidninja/scriptdotsh-malwaredevelopment](https://github.com/paranoidninja/scriptdotsh-malwaredevelopment) 
- [**53**星][2y] [Py] [ahm3dhany/ids-evasion](https://github.com/ahm3dhany/ids-evasion) 
- [**51**星][4y] [C++] [ikoz/androidsubstrate_hookingc_examples](https://github.com/ikoz/androidsubstrate_hookingc_examples) 
- [**46**星][12m] [Perl] [mrash/fwsnort](https://github.com/mrash/fwsnort) 
- [**43**星][3m] [Lua] [fsiamp/rhapis](https://github.com/fsiamp/rhapis) rhapis：网络入侵检测系统（IDS）模拟器。用户可在模拟环境中执行任意 IDS 操作
- [**41**星][2y] [grayddq/hids](https://github.com/grayddq/hids) 
- [**39**星][1y] [dcid/ossec-hids](https://bitbucket.org/dcid/ossec-hids) 
- [**34**星][3y] [Py] [mipu94/broids_unicorn](https://github.com/mipu94/broids_unicorn) 
- [**34**星][16d] [C++] [olegzhr/altprobe](https://github.com/olegzhr/altprobe) 
- [**31**星][5y] [C] [mitrecnd/pynids](https://github.com/mitrecnd/pynids) 
- [**27**星][3y] [Py] [fare9/androidswissknife](https://github.com/fare9/androidswissknife) 
- [**26**星][6m] [retarded-skid/skidsuite-3](https://github.com/retarded-skid/skidsuite-3) 
- [**26**星][2m] [PHP] [krowinski/tinyid](https://github.com/krowinski/tinyid) 
- [**25**星][10m] [Rust] [archer884/harsh](https://github.com/archer884/harsh) 




***


## <a id="785ad72c95e857273dce41842f5e8873"></a>爬虫


- [**741**星][19d] [Py] [nekmo/dirhunt](https://github.com/nekmo/dirhunt) Web爬虫, 针对搜索和分析路径做了优化
    - 重复区段: [工具/扫描器&&安全扫描&&App扫描&&漏洞扫描/未分类-Scanner](#de63a029bda6a7e429af272f291bb769) |


***


## <a id="609214b7c4d2f9bb574e2099313533a2"></a>wordlist


### <a id="af1d71122d601229dc4aa9d08f4e3e15"></a>未分类-wordlist


- [**1668**星][7m] [Py] [guelfoweb/knock](https://github.com/guelfoweb/knock) 使用 Wordlist 枚举子域名
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/子域名枚举&&爆破](#e945721056c78a53003e01c3d2f3b8fe) |
- [**605**星][4y] [jeanphorn/wordlist](https://github.com/jeanphorn/wordlist) 
- [**382**星][3m] [Ruby] [digininja/cewl](https://github.com/digininja/cewl) 
- [**328**星][4m] [Py] [initstring/passphrase-wordlist](https://github.com/initstring/passphrase-wordlist) 
- [**256**星][3y] [insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) 
- [**251**星][1y] [Py] [berzerk0/bewgor](https://github.com/berzerk0/bewgor) 
- [**187**星][3y] [Py] [droope/pwlist](https://github.com/droope/pwlist) 
- [**177**星][3m] [Py] [blackarch/wordlistctl](https://github.com/blackarch/wordlistctl) 
- [**174**星][7m] [kaonashi-passwords/kaonashi](https://github.com/kaonashi-passwords/kaonashi) 
- [**134**星][5m] [tarraschk/richelieu](https://github.com/tarraschk/richelieu) 
    - 重复区段: [工具/密码&&凭证/密码](#86dc226ae8a71db10e4136f4b82ccd06) |
- [**114**星][2y] [Ruby] [skahwah/wordsmith](https://github.com/skahwah/wordsmith) 
- [**87**星][4m] [Ruby] [digininja/rsmangler](https://github.com/digininja/rsmangler) 
- [**73**星][8m] [Py] [xajkep/wordlists](https://github.com/xajkep/wordlists) 
- [**54**星][4m] [Py] [r3nt0n/bopscrk](https://github.com/r3nt0n/bopscrk) 
- [**47**星][3y] [Py] [agusmakmun/python-wordlist-generator](https://github.com/agusmakmun/python-wordlist-generator) 
- [**33**星][3y] [Py] [smeegesec/smeegescrape](https://github.com/smeegesec/smeegescrape) 
- [**27**星][19d] [Py] [4n4nk3/wordlister](https://github.com/4n4nk3/wordlister) 
- [**26**星][1y] [Py] [undeadsec/goblinwordgenerator](https://github.com/undeadsec/goblinwordgenerator) 
- [**25**星][4m] [PowerShell] [codewatchorg/powersniper](https://github.com/codewatchorg/powersniper) 
- [**25**星][3m] [dustyfresh/dictionaries](https://github.com/dustyfresh/dictionaries) 


### <a id="3202d8212db5699ea5e6021833bf3fa2"></a>收集


- [**21409**星][14d] [PHP] [danielmiessler/seclists](https://github.com/danielmiessler/seclists) 多种类型资源收集：用户名、密码、URL、敏感数据类型、Fuzzing  Payload、WebShell等
    - 重复区段: [工具/webshell/收集](#e08366dcf7aa021c6973d9e2a8944dff) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload收集](#b5d99a78ddb383c208aae474fc2cb002) |
- [**5955**星][6m] [berzerk0/probable-wordlists](https://github.com/berzerk0/probable-wordlists) 


### <a id="f2c76d99a0b1fda124d210bd1bbc8f3f"></a>Wordlist生成


- [**580**星][2y] [Py] [sc0tfree/mentalist](https://github.com/sc0tfree/mentalist) mentalist：自定义wordlist 生成器，带界面，可生成与 Hashcat、Johnthe Ripper 兼容的 wordlist
- [**239**星][2y] [Shell] [pentester-io/commonspeak](https://github.com/pentester-io/commonspeak) Commonspeak: 利用谷歌BigQuery 平台的公共数据集生成 wordlist




***


## <a id="96171a80e158b8752595329dd42e8bcf"></a>泄漏&&Breach&&Leak


- [**1358**星][5m] [gitguardian/apisecuritybestpractices](https://github.com/gitguardian/apisecuritybestpractices) 
- [**885**星][21d] [Py] [woj-ciech/leaklooker](https://github.com/woj-ciech/leaklooker) 


***


## <a id="de81f9dd79c219c876c1313cd97852ce"></a>破解&&Crack&&爆破&&BruteForce


- [**8371**星][2y] [brannondorsey/wifi-cracking](https://github.com/brannondorsey/wifi-cracking) 破解WPA/WPA2 Wi-Fi 路由器
    - 重复区段: [工具/物联网(IoT)&&嵌入式设备&&路由器&&交换机&&智能设备&&打印机/未分类-IoT](#cda63179d132f43441f8844c5df10024) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/WPS&&WPA&&WPA2](#8d233e2d068cce2b36fd0cf44d10f5d8) |
- [**3217**星][18d] [C] [vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra) 网络登录破解，支持多种服务
- [**2220**星][2y] [Py] [rootphantomer/blasting_dictionary](https://github.com/rootphantomer/blasting_dictionary) 
- [**1885**星][1m] [Py] [lanjelot/patator](https://github.com/lanjelot/patator) 
- [**1042**星][3m] [Py] [landgrey/pydictor](https://github.com/landgrey/pydictor) 
- [**875**星][2m] [Py] [trustedsec/hate_crack](https://github.com/trustedsec/hate_crack) hate_crack: 使用HashCat 的自动哈希破解工具
- [**789**星][6m] [C] [brendan-rius/c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker) C 语言编写的 JWT 爆破工具
- [**780**星][10m] [Py] [mak-/parameth](https://github.com/mak-/parameth) 在文件中(例如PHP 文件)暴力搜索GET 和 POST 请求的参数
- [**748**星][4m] [Py] [s0md3v/hash-buster](https://github.com/s0md3v/Hash-Buster) 
- [**688**星][7y] [Ruby] [juuso/bozocrack](https://github.com/juuso/bozocrack) 
- [**679**星][7m] [Shell] [1n3/brutex](https://github.com/1n3/brutex) 
- [**655**星][2y] [Py] [galkan/crowbar](https://github.com/galkan/crowbar) 渗透测试期间使用的暴力破解工具
- [**625**星][2m] [JS] [animir/node-rate-limiter-flexible](https://github.com/animir/node-rate-limiter-flexible) 
- [**619**星][4m] [C#] [shack2/snetcracker](https://github.com/shack2/snetcracker) 
- [**606**星][1y] [C] [nfc-tools/mfoc](https://github.com/nfc-tools/mfoc) 
- [**551**星][5m] [PHP] [s3inlc/hashtopolis](https://github.com/s3inlc/hashtopolis) Hashcat wrapper, 用于跨平台分布式Hash破解
- [**546**星][1y] [CSS] [hashview/hashview](https://github.com/hashview/hashview) 密码破解和分析工具
- [**524**星][3y] [Py] [gojhonny/credcrack](https://github.com/gojhonny/credcrack) 
- [**520**星][2y] [C] [brannondorsey/naive-hashcat](https://github.com/brannondorsey/naive-hashcat) 
- [**516**星][3m] [C] [nmap/ncrack](https://github.com/nmap/ncrack) 
- [**507**星][1m] [Py] [pure-l0g1c/instagram](https://github.com/pure-l0g1c/instagram) 
- [**499**星][3m] [duyetdev/bruteforce-database](https://github.com/duyetdev/bruteforce-database) 
- [**487**星][1y] [C] [mikeryan/crackle](https://github.com/mikeryan/crackle) 
- [**437**星][1y] [C] [ryancdotorg/brainflayer](https://github.com/ryancdotorg/brainflayer) 
- [**435**星][5m] [JS] [coalfire-research/npk](https://github.com/coalfire-research/npk) 
- [**408**星][2y] [C++] [lyle-nel/siga](https://github.com/lyle-nel/siga) 
- [**380**星][25d] [Py] [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) jwt_tool：测试，调整和破解JSON Web Token 的工具包
- [**379**星][1y] [Py] [ex0dus-0x/brut3k1t](https://github.com/ex0dus-0x/brut3k1t) 
- [**363**星][2y] [Py] [cclabsinc/rfcrack](https://github.com/cclabsinc/rfcrack) 
- [**351**星][2m] [Py] [denyhosts/denyhosts](https://github.com/denyhosts/denyhosts) 
- [**325**星][2y] [notsosecure/password_cracking_rules](https://github.com/notsosecure/password_cracking_rules) 
- [**317**星][3y] [Shell] [nsakey/nsa-rules](https://github.com/nsakey/nsa-rules) 
- [**317**星][2y] [ysrc/f-scrack](https://github.com/ysrc/f-scrack) 
- [**316**星][7y] [Py] [moxie0/chapcrack](https://github.com/moxie0/chapcrack) A tool for parsing and decrypting MS-CHAPv2 network handshakes
- [**307**星][10m] [C] [e-ago/bitcracker](https://github.com/e-ago/bitcracker) bitcracker：BitLocker密码破解器
- [**287**星][11m] [Shell] [cyb0r9/socialbox](https://github.com/Cyb0r9/SocialBox) 
- [**271**星][4y] [C] [robertdavidgraham/pemcrack](https://github.com/robertdavidgraham/pemcrack) 
- [**265**星][11m] [C] [jmk-foofus/medusa](https://github.com/jmk-foofus/medusa) 
- [**256**星][17d] [Shell] [wuseman/emagnet](https://github.com/wuseman/emagnet) 
- [**250**星][1y] [Py] [avramit/instahack](https://github.com/avramit/instahack) 
- [**246**星][6m] [Go] [ropnop/kerbrute](https://github.com/ropnop/kerbrute) 
- [**245**星][11m] [Shell] [thelinuxchoice/instainsane](https://github.com/thelinuxchoice/instainsane) 
- [**233**星][2y] [Ruby] [nahamsec/hostilesubbruteforcer](https://github.com/nahamsec/hostilesubbruteforcer) 
- [**225**星][2m] [Py] [evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) 修改NTLMv1/NTLMv1-ESS/MSCHAPv1 Hask, 使其可以在hashcat中用DES模式14000破解
- [**220**星][6m] [Py] [blark/aiodnsbrute](https://github.com/blark/aiodnsbrute) 
- [**220**星][11m] [Py] [chris408/known_hosts-hashcat](https://github.com/chris408/known_hosts-hashcat) 
- [**215**星][7m] [Py] [paradoxis/stegcracker](https://github.com/paradoxis/stegcracker) 
- [**209**星][1m] [C] [hyc/fcrackzip](https://github.com/hyc/fcrackzip) 
- [**205**星][2y] [Py] [pirate-crew/iptv](https://github.com/pirate-crew/iptv) 
- [**203**星][3m] [Py] [isaacdelly/plutus](https://github.com/isaacdelly/plutus) 
- [**202**星][3y] [C++] [shinnok/johnny](https://github.com/shinnok/johnny) 
- [**200**星][2y] [Py] [m4ll0k/smbrute](https://github.com/m4ll0k/smbrute) 
- [**195**星][1y] [JS] [lmammino/jwt-cracker](https://github.com/lmammino/jwt-cracker) jwt-cracker：HS256JWT 令牌暴力破解工具，只对弱密码有效
- [**189**星][3y] [Py] [xyntax/dirbrute](https://github.com/xyntax/dirbrute) 
- [**186**星][16d] [Rust] [kpcyrd/badtouch](https://github.com/kpcyrd/badtouch) badtouch: 可编程的网络验证破解的库, Rust编写
- [**186**星][1y] [Perl] [moham3driahi/xbruteforcer](https://github.com/moham3driahi/xbruteforcer) 
- [**180**星][5y] [knoy/icloudhacker](https://github.com/knoy/icloudhacker) 
- [**179**星][10m] [Py] [r4stl1n/ssh-brute-forcer](https://github.com/r4stl1n/ssh-brute-forcer) 
- [**177**星][1m] [Go] [milo2012/pathbrute](https://github.com/milo2012/pathbrute) pathbrute: 服务器目录/文件爆破工具
- [**177**星][4y] [Shell] [nccgroup/cisco-snmp-enumeration](https://github.com/nccgroup/cisco-snmp-enumeration) 
- [**174**星][4y] [Py] [dc3l1ne/blasting_dictionary](https://github.com/dc3l1ne/blasting_dictionary) 
- [**174**星][4y] [Py] [secforce/snmp-brute](https://github.com/secforce/snmp-brute) 
- [**172**星][3m] [C] [aircrack-ng/mdk4](https://github.com/aircrack-ng/mdk4) a proof-of-concept tool to exploit common IEEE 802.11 protocol weaknesses.
- [**168**星][5m] [C] [noracodes/crackmes](https://github.com/NoraCodes/crackmes) 
- [**167**星][2y] [Py] [googulator/teslacrack](https://github.com/googulator/teslacrack) 
- [**167**星][4y] [Shell] [pr0x13/ibrutr](https://github.com/pr0x13/ibrutr) 
- [**167**星][4y] [Py] [praetorian-code/gladius](https://github.com/praetorian-code/gladius) 
- [**165**星][10m] [Py] [metachar/hatch](https://github.com/metachar/hatch) 
- [**162**星][3y] [Py] [wh1t3rh1n0/air-hammer](https://github.com/wh1t3rh1n0/air-hammer) A WPA Enterprise horizontal brute-force attack tool 
- [**161**星][2y] [Shell] [functionclub/fail2ban](https://github.com/functionclub/fail2ban) 
- [**157**星][4m] [JS] [k4m4/dcipher-cli](https://github.com/k4m4/dcipher-cli) Crack hashes using online rainbow & lookup table attack services, right from your terminal
- [**152**星][3m] [Py] [trustedsec/ridenum](https://github.com/trustedsec/ridenum) 
- [**151**星][2y] [Java] [floyd-fuh/jks-private-key-cracker-hashcat](https://github.com/floyd-fuh/jks-private-key-cracker-hashcat) 
- [**151**星][2y] [Py] [k4m4/dymerge](https://github.com/k4m4/dymerge) takes given wordlists and merges them into one dynamic dictionary that can then be used as ammunition for a successful dictionary based (or bruteforce) attack.
- [**134**星][3y] [Py] [laginimaineb/android_fde_bruteforce](https://github.com/laginimaineb/android_fde_bruteforce) 
- [**132**星][4y] [C] [bwall/pemcracker](https://github.com/bwall/pemcracker) 
- [**132**星][5m] [C] [glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks) 
- [**126**星][1y] [Py] [ekultek/dagon](https://github.com/ekultek/dagon) Dagon：哈希破解和操纵系统，可以爆破多种哈希类型，创建爆破字典，自动哈希算法验证，从 Unicode 到 ASCII 的随机salt 生成等。
- [**125**星][12m] [Perl] [philsmd/7z2hashcat](https://github.com/philsmd/7z2hashcat) 
- [**123**星][8m] [Py] [chg-hou/enmicromsg.db-password-cracker](https://github.com/chg-hou/enmicromsg.db-password-cracker) 
- [**119**星][4y] [PowerShell] [maaaaz/crackmapexecwin](https://github.com/maaaaz/crackmapexecwin) 
- [**119**星][1y] [Py] [wavestone-cdt/wavecrack](https://github.com/wavestone-cdt/wavecrack) wavecrack: 多用户之间共享Hastcat cracking box 的 Web 界面
- [**118**星][1y] [Py] [mikesiegel/ews-crack](https://github.com/mikesiegel/ews-crack) ews-crack: 利用 EWS 绕过 Office365 2FA/MDM
- [**117**星][3m] [Py] [lakiw/pcfg_cracker](https://github.com/lakiw/pcfg_cracker) 
- [**113**星][3y] [Py] [y1ng1996/f-scrack](https://github.com/y1ng1996/f-scrack) 
- [**112**星][6m] [Py] [tidesec/web_pwd_common_crack](https://github.com/tidesec/web_pwd_common_crack) 
- [**108**星][2y] [Py] [orsinium/django-bruteforce-protection](https://github.com/orsinium/django-bruteforce-protection) 
- [**106**星][3y] [Py] [moosedojo/mybff](https://github.com/moosedojo/mybff) 
- [**102**星][2y] [HTML] [ziplokk1/incapsula-cracker-py3](https://github.com/ziplokk1/incapsula-cracker-py3) 
- [**98**星][1y] [Py] [thehappydinoa/iosrestrictionbruteforce](https://github.com/thehappydinoa/iosrestrictionbruteforce) 
- [**97**星][2y] [Py] [pure-l0g1c/pulse](https://github.com/pure-l0g1c/pulse) 
- [**95**星][2m] [Java] [bastienjalbert/topguw](https://github.com/bastienjalbert/topguw) 
- [**92**星][6m] [Py] [abaykan/crawlbox](https://github.com/abaykan/crawlbox) crawlbox: Web目录爆破脚本
- [**91**星][1y] [Py] [getsecnow/instagram-py](https://github.com/getsecnow/instagram-py) 
- [**90**星][6m] [aprilahijriyan/w3brute](https://github.com/aprilahijriyan/w3brute) 
- [**89**星][1y] [Py] [martinvigo/voicemailautomator](https://github.com/martinvigo/voicemailautomator) 
- [**83**星][3y] [Py] [claudioviviani/wordbrutepress](https://github.com/claudioviviani/wordbrutepress) 
- [**81**星][6m] [C++] [kimci86/bkcrack](https://github.com/kimci86/bkcrack) 
- [**80**星][6m] [Py] [brutemap-dev/brutemap](https://github.com/brutemap-dev/brutemap) 
- [**80**星][9m] [C++] [pelock/pelock-software-protection-and-licensing-sdk](https://github.com/pelock/pelock-software-protection-and-licensing-sdk) 
- [**79**星][11m] [Py] [erforschr/bruteforce-http-auth](https://github.com/erforschr/bruteforce-http-auth) 
- [**75**星][3y] [Py] [va5c0/steghide-brute-force-tool](https://github.com/va5c0/steghide-brute-force-tool) 
- [**73**星][2y] [Py] [nickstadb/serialbrute](https://github.com/nickstadb/serialbrute) 
- [**71**星][7y] [C] [kholia/rc4-40-brute-office](https://github.com/kholia/rc4-40-brute-office) 
- [**71**星][3y] [Py] [xyntax/baiduyun-brute](https://github.com/xyntax/baiduyun-brute) 
- [**70**星][2y] [Py] [timbo05sec/autocrack](https://github.com/timbo05sec/autocrack) 
- [**69**星][28d] [Py] [m8r0wn/ldap_search](https://github.com/m8r0wn/ldap_search) 
- [**69**星][11m] [Py] [pure-l0g1c/instaburst](https://github.com/pure-l0g1c/instaburst) 
- [**69**星][4y] [Py] [sensepost/autoresponder](https://github.com/sensepost/autoresponder) 
- [**66**星][5m] [Py] [githacktools/brutedum](https://github.com/githacktools/brutedum) 
- [**66**星][2y] [Py] [hlldz/wildpwn](https://github.com/hlldz/wildpwn) 
- [**64**星][3y] [Py] [evilsocket/fang](https://github.com/evilsocket/fang) 
- [**62**星][1y] [Py] [pure-l0g1c/hyprpulse](https://github.com/pure-l0g1c/hyprpulse) 
- [**54**星][3m] [Py] [nccgroup/hashcrack](https://github.com/nccgroup/hashcrack) 
- [**53**星][1y] [Py] [m4ll0k/icloudbrutter](https://github.com/m4ll0k/icloudbrutter) 
- [**53**星][3y] [Perl] [msimerson/sentry](https://github.com/msimerson/sentry) 
- [**50**星][3y] [C] [vikasnkumar/wisecracker](https://github.com/vikasnkumar/wisecracker) 
- [**47**星][7m] [Go] [agilebits/crackme](https://github.com/agilebits/crackme) 
- [**47**星][2y] [Py] [intrd/nozzlr](https://github.com/intrd/nozzlr) 
- [**47**星][2y] [Py] [thelsa/awbruter](https://github.com/thelsa/awbruter) 
- [**46**星][1y] [PowerShell] [dafthack/passphrasegen](https://github.com/dafthack/passphrasegen) 
- [**46**星][7y] [spiderlabs/korelogic-rules](https://github.com/spiderlabs/korelogic-rules) 
- [**45**星][2y] [Py] [aress31/jwtcat](https://github.com/aress31/jwtcat) 
- [**44**星][2y] [Haskell] [giovanifss/dumb](https://github.com/giovanifss/dumb) 
- [**44**星][4y] [Py] [p0cl4bs/facebrute](https://github.com/p0cl4bs/facebrute) 
- [**44**星][1y] [Shell] [philcryer/wpa2own](https://github.com/philcryer/wpa2own) 
- [**44**星][4y] [PHP] [pupi1985/marfil](https://github.com/pupi1985/marfil) 
- [**44**星][1m] [Py] [tna0y/python-random-module-cracker](https://github.com/tna0y/python-random-module-cracker) 
- [**43**星][3y] [Py] [allyshka/vhostbrute](https://github.com/allyshka/vhostbrute) 
- [**43**星][1y] [Ruby] [lucifer1993/lasercrack](https://github.com/lucifer1993/lasercrack) 
- [**42**星][6m] [C] [x899/ssh_brute_force](https://github.com/x899/ssh_brute_force) 
- [**41**星][1y] [Java] [k0r0pt/project-tauro](https://github.com/k0r0pt/project-tauro) 
- [**40**星][2y] [C#] [aaaddress1/puzzcode](https://github.com/aaaddress1/puzzcode) 
- [**40**星][6y] [JS] [evilpacket/redis-sha-crack](https://github.com/evilpacket/redis-sha-crack) 
- [**40**星][4m] [Py] [kokokuo/scraper-fourone-jobs](https://github.com/kokokuo/scraper-fourone-jobs) 
- [**40**星][2y] [PHP] [mrsqar-ye/wpcrack](https://github.com/mrsqar-ye/wpcrack) 
- [**40**星][2y] [HTML] [thehackingsage/fluxion](https://github.com/thehackingsage/fluxion) 
- [**39**星][7y] [C++] [bend/rar_crack](https://github.com/bend/rar_crack) 
- [**39**星][6y] [Py] [viaforensics/android-encryption](https://github.com/viaforensics/android-encryption) 
- [**38**星][3y] [C++] [hasherezade/petya_recovery](https://github.com/hasherezade/petya_recovery) 
- [**37**星][3y] [C] [boywhp/wifi_crack_windows](https://github.com/boywhp/wifi_crack_windows) 
- [**37**星][6y] [C] [gdbinit/crackme_nr1](https://github.com/gdbinit/crackme_nr1) 
- [**36**星][4y] [C++] [bobotig/cracker-ng](https://github.com/bobotig/cracker-ng) 
- [**35**星][3y] [Py] [gauthamgoli/rarpasswordcracker](https://github.com/gauthamgoli/rarpasswordcracker) 
- [**35**星][4y] [Shell] [samyoyo/flux](https://github.com/samyoyo/flux) 
- [**34**星][4y] [Shell] [easonoutlook/rasticrac](https://github.com/easonoutlook/rasticrac) 
- [**33**星][3y] [Py] [davidwittman/wpxmlrpcbrute](https://github.com/davidwittman/wpxmlrpcbrute) 
- [**33**星][4m] [gsurma/password_cracker](https://github.com/gsurma/password_cracker) 
- [**33**星][7y] [Py] [tkisason/gcrack](https://github.com/tkisason/gcrack) 
- [**33**星][7y] [Py] [ml31415/wpscrack](https://github.com/ml31415/wpscrack) 
- [**32**星][1y] [C#] [tlgyt/wibr](https://github.com/tlgyt/wibr) 
- [**31**星][10m] [Py] [0xr0/hediye](https://github.com/0xr0/hediye) 
- [**31**星][12m] [Py] [northernsec/veracracker](https://github.com/northernsec/veracracker) 
- [**30**星][3y] [Py] [itsreallynick/office-crackros](https://github.com/itsreallynick/office-crackros) 
- [**30**星][2y] [Py] [lxiaogirl/hack](https://github.com/lxiaogirl/hack) 
- [**30**星][7y] [JS] [x/twitter-brute-force](https://github.com/x/twitter-brute-force) 
- [**28**星][4y] [PHP] [belove/avhbf](https://github.com/belove/avhbf) 
- [**28**星][8m] [Py] [xayon/pyrcrack](https://github.com/xayon/pyrcrack) 
- [**27**星][3y] [Java] [nccgroup/jmxbf](https://github.com/nccgroup/jmxbf) 
- [**26**星][4y] [PHP] [sinfocol/vboxdie-cracker](https://github.com/sinfocol/vboxdie-cracker) 
- [**26**星][2y] [Shell] [digivill/all-in-one-wifi-cracker](https://github.com/digivill/all-in-one-wifi-cracker) 
- [**25**星][5y] [Py] [averagesecurityguy/crack](https://github.com/averagesecurityguy/crack) 
- [**25**星][2y] [Shell] [crackpkcs12/crackpkcs12](https://github.com/crackpkcs12/crackpkcs12) 
- [**25**星][1m] [Py] [initstring/pentest-tools](https://github.com/initstring/pentest-tools) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Kali](#7667f6a0381b6cded2014a0d279b5722) |[工具/密码&&凭证/密码](#86dc226ae8a71db10e4136f4b82ccd06) |
- [**25**星][4y] [Go] [leechristensen/tgscrack](https://github.com/leechristensen/tgscrack) 
- [**25**星][8m] [C++] [rek7/descrypt-cpu-collision-cracker](https://github.com/rek7/descrypt-cpu-collision-cracker) 
- [**23**星][2m] [Py] [eleemosynator/writeups](https://github.com/eleemosynator/writeups) 
- [**23**星][5y] [Py] [vnik5287/wpa-autopwn](https://github.com/vnik5287/wpa-autopwn) 
- [**22**星][1m] [Rust] [aloxaf/rbkcrack](https://github.com/aloxaf/rbkcrack) 
- [**22**星][2y] [Go] [nachowski/warpwallet_cracker](https://github.com/nachowski/warpwallet_cracker) 
- [**21**星][10m] [Shell] [sensepost/common-substr](https://github.com/sensepost/common-substr) 
- [**21**星][7y] [Shell] [tjetzinger/cloudcrackinstaller](https://github.com/tjetzinger/cloudcrackinstaller) 


***


## <a id="13d067316e9894cc40fe55178ee40f24"></a>OSCP


- [**1710**星][20d] [olivierlaflamme/cheatsheet-god](https://github.com/olivierlaflamme/cheatsheet-god) 
    - 重复区段: [工具/收集&&集合/混合型收集](#664ff1dbdafefd7d856c88112948a65b) |
- [**756**星][1m] [HTML] [rewardone/oscprepo](https://github.com/rewardone/oscprepo) 
- [**667**星][8m] [XSLT] [adon90/pentest_compilation](https://github.com/adon90/pentest_compilation) 
    - 重复区段: [工具/收集&&集合/未分类](#e97d183e67fa3f530e7d0e7e8c33ee62) |
- [**516**星][2y] [Py] [ihack4falafel/oscp](https://github.com/ihack4falafel/oscp) 
- [**375**星][10m] [Py] [rustyshackleford221/oscp-prep](https://github.com/rustyshackleford221/oscp-prep) 
- [**375**星][3y] [slyth11907/cheatsheets](https://github.com/slyth11907/cheatsheets) 
- [**360**星][8m] [PowerShell] [ferreirasc/oscp](https://github.com/ferreirasc/oscp) 
- [**335**星][2y] [dostoevskylabs/dostoevsky-pentest-notes](https://github.com/dostoevskylabs/dostoevsky-pentest-notes) 
- [**300**星][2y] [burntmybagel/oscp-prep](https://github.com/burntmybagel/oscp-prep) 
- [**289**星][14d] [PowerShell] [mantvydasb/redteam-tactics-and-techniques](https://github.com/mantvydasb/RedTeam-Tactics-and-Techniques) 
- [**222**星][7m] [0x4d31/awesome-oscp](https://github.com/0x4d31/awesome-oscp) 
- [**210**星][1y] [foobarto/redteam-notebook](https://github.com/foobarto/redteam-notebook) 
- [**169**星][1m] [noraj/oscp-exam-report-template-markdown](https://github.com/noraj/oscp-exam-report-template-markdown) 
- [**167**星][1y] [sumas/oscp-cheatsheet-god](https://github.com/sumas/oscp-cheatsheet-god) 
- [**161**星][27d] [Py] [so87/oscp-pwk](https://github.com/so87/oscp-pwk) 
- [**118**星][3m] [whoisflynn/oscp-exam-report-template](https://github.com/whoisflynn/oscp-exam-report-template) 
- [**104**星][13d] [gajos112/oscp](https://github.com/gajos112/oscp) 
- [**95**星][3m] [Py] [ex16x41/oscp-prep](https://github.com/ex16x41/oscp-prep) 
- [**90**星][9m] [Py] [b1n4ry4rms/redteam-pentest-cheatsheets](https://github.com/b1n4ry4rms/redteam-pentest-cheatsheets) 
    - 重复区段: [工具/收集&&集合/未分类](#e97d183e67fa3f530e7d0e7e8c33ee62) |
- [**86**星][3m] [Shell] [anandkumar11u/oscp-60days](https://github.com/anandkumar11u/oscp-60days) 
- [**72**星][1m] [six2dez/oscp-human-guide](https://github.com/six2dez/oscp-human-guide) 
- [**68**星][2y] [PHP] [nairuzabulhul/roadmap](https://github.com/nairuzabulhul/roadmap) 
- [**57**星][23d] [akenofu/oscp-cheat-sheet](https://github.com/akenofu/oscp-cheat-sheet) 
- [**52**星][3y] [C] [pythonmaster41/go-for-oscp](https://github.com/pythonmaster41/go-for-oscp) 
- [**50**星][1m] [mohitkhemchandani/oscp-complete-guide](https://github.com/mohitkhemchandani/oscp-complete-guide) 
- [**46**星][12m] [Shell] [pablomansanet/c0toolkit](https://github.com/pablomansanet/c0toolkit) 
- [**46**星][5m] [Shell] [t3chnocat/oscp-ctf](https://github.com/t3chnocat/oscp-ctf) 
- [**28**星][26d] [mohitkhemchandani/oscp_bible](https://github.com/mohitkhemchandani/oscp_bible) 
- [**27**星][13d] [Py] [sinfulz/justtryharder](https://github.com/sinfulz/justtryharder) 
- [**25**星][2y] [Py] [eudoxier/security-utilities](https://github.com/eudoxier/security-utilities) 


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
- [**202**星][2y] [0x4d31/deception-as-detection](https://github.com/0x4d31/deception-as-detection) 
- [**187**星][2m] [infosecn1nja/awesome-mitre-attack](https://github.com/infosecn1nja/awesome-mitre-attack) 
- [**168**星][3m] [lengjibo/att-ck-cn](https://github.com/lengjibo/att-ck-cn) 
- [**155**星][1y] [malwarearchaeology/attack](https://github.com/malwarearchaeology/attack) 
- [**155**星][28d] [PowerShell] [olafhartong/attackdatamap](https://github.com/olafhartong/attackdatamap) 
- [**133**星][1y] [nsacyber/unfetter](https://github.com/nsacyber/unfetter) 
- [**132**星][6m] [Py] [mitrecnd/whodat](https://github.com/mitrecnd/whodat) 
- [**121**星][2m] [Py] [swimlane/pyattck](https://github.com/swimlane/pyattck) 
- [**109**星][4m] [JS] [baronpan/sysmonhunter](https://github.com/baronpan/sysmonhunter) 
- [**64**星][6m] [Py] [vysecurity/att-ck_analysis](https://github.com/vysecurity/att-ck_analysis) 
- [**63**星][12m] [Py] [gr4ym4ntx/attackintel](https://github.com/gr4ym4ntx/attackintel) 
- [**28**星][1y] [dwestgard/threat_hunting_tables](https://github.com/dwestgard/threat_hunting_tables) 
- [**28**星][12m] [travisfsmith/mitre_attack](https://github.com/travisfsmith/mitre_attack) 
- [**23**星][11m] [TypeScript] [mitre/attack-navigator](https://github.com/mitre/attack-navigator) ATT&CK导航/浏览工具. 以表格形式显示ATT&CK各种技术, 并执行某些操作. 基于Angular
- [**22**星][2m] [Ruby] [mitre-cyber-academy/ctf-scoreboard](https://github.com/mitre-cyber-academy/ctf-scoreboard) 


***


## <a id="76df273beb09f6732b37a6420649179c"></a>浏览器&&browser


- [**4591**星][2m] [JS] [beefproject/beef](https://github.com/beefproject/beef) 
- [**960**星][8m] [Py] [selwin/python-user-agents](https://github.com/selwin/python-user-agents) 
- [**852**星][3m] [escapingbug/awesome-browser-exploit](https://github.com/escapingbug/awesome-browser-exploit) 
- [**450**星][30d] [Py] [globaleaks/tor2web](https://github.com/globaleaks/tor2web) 
- [**446**星][2m] [m1ghtym0/browser-pwn](https://github.com/m1ghtym0/browser-pwn) 
- [**408**星][2m] [Pascal] [felipedaragon/sandcat](https://github.com/felipedaragon/sandcat) 为渗透测试和开发者准备的轻量级浏览器, 基于Chromium和Lua
- [**347**星][2y] [Shell] [mazen160/firefox-security-toolkit](https://github.com/mazen160/firefox-security-toolkit) 
- [**302**星][3y] [Perl] [julienbedard/browsersploit](https://github.com/julienbedard/browsersploit) 
- [**290**星][2m] [xsleaks/xsleaks](https://github.com/xsleaks/xsleaks) 
- [**215**星][2m] [Py] [icsec/airpwn-ng](https://github.com/icsec/airpwn-ng) force the target's browser to do what we want 
- [**212**星][1y] [C#] [djhohnstein/sharpweb](https://github.com/djhohnstein/sharpweb) 
- [**182**星][3m] [Py] [webfp/tor-browser-selenium](https://github.com/webfp/tor-browser-selenium) 
- [**115**星][1y] [JS] [brannondorsey/distributed-password-cracking](https://github.com/brannondorsey/distributed-password-cracking) 
- [**80**星][1m] [Shell] [rhaidiz/dribble](https://github.com/rhaidiz/dribble) 
- [**70**星][6y] [JS] [qburst/penq](https://github.com/qburst/penq) 
- [**63**星][6y] [JS] [owasp/appsec-browser-bundle](https://github.com/owasp/appsec-browser-bundle) 
- [**59**星][1y] [JS] [serain/netmap.js](https://github.com/serain/netmap.js) 
- [**48**星][3y] [Py] [el3ct71k/autobrowser](https://github.com/el3ct71k/autobrowser) 
- [**46**星][2y] [Py] [stormshadow07/beef-over-wan](https://github.com/stormshadow07/beef-over-wan) 
- [**31**星][3y] [JS] [desudesutalk/f5stegojs](https://github.com/desudesutalk/f5stegojs) 
- [**24**星][1y] [JS] [peterwilli/iota-ion.lib.js](https://github.com/peterwilli/iota-ion.lib.js) 


***


## <a id="ceb90405292daed9bb32ac20836c219a"></a>蓝牙&&Bluetooth


- [**218**星][18d] [Py] [ghostop14/sparrow-wifi](https://github.com/ghostop14/sparrow-wifi) 
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/未分类-Network](#99398a5a8aaf99228829dadff48fb6a7) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**181**星][1m] [Py] [seemoo-lab/internalblue](https://github.com/seemoo-lab/internalblue) 
- [**97**星][4y] [Java] [andrewmichaelsmith/bluepot](https://github.com/andrewmichaelsmith/bluepot) 
    - 重复区段: [工具/密罐&&Honeypot/蓝牙&&Bluetooth ](#c5b6762b3dc783a11d72dea648755435) |


***


## <a id="7d5d2d22121ed8456f0c79098f5012bb"></a>REST_API&&RESTFUL 


- [**1220**星][8m] [Py] [flipkart-incubator/astra](https://github.com/flipkart-incubator/astra) 自动化的REST API安全测试脚本
- [**395**星][2y] [Ruby] [fuzzapi/fuzzapi](https://github.com/Fuzzapi/fuzzapi) 
- [**39**星][17d] [Py] [bbva/apicheck](https://github.com/bbva/apicheck) 


***


## <a id="8cb1c42a29fa3e8825a0f8fca780c481"></a>恶意代码&&Malware&&APT


- [**2013**星][1m] [C++] [lordnoteworthy/al-khaser](https://github.com/lordnoteworthy/al-khaser) 
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |
- [**859**星][2m] [aptnotes/data](https://github.com/aptnotes/data) 
- [**195**星][3m] [Py] [thesph1nx/absolutezero](https://github.com/thesph1nx/absolutezero) 
- [**179**星][10m] [sapphirex00/threat-hunting](https://github.com/sapphirex00/threat-hunting) 
- [**174**星][13d] [JS] [strangerealintel/cyberthreatintel](https://github.com/strangerealintel/cyberthreatintel) 
- [**131**星][2m] [YARA] [citizenlab/malware-indicators](https://github.com/citizenlab/malware-indicators) 
- [**131**星][1m] [fdiskyou/threat-intel](https://github.com/fdiskyou/threat-intel) 
- [**96**星][2y] [Py] [dakotanelson/sneaky-creeper](https://github.com/dakotanelson/sneaky-creeper) 
- [**86**星][1y] [C] [chef-koch/malware-research](https://github.com/chef-koch/malware-research) 
- [**46**星][4y] [threatminer/aptnotes](https://github.com/threatminer/aptnotes) 
- [**43**星][2y] [Py] [nccgroup/royal_apt](https://github.com/nccgroup/royal_apt) 
- [**29**星][5m] [Py] [jacobsoo/threathunting](https://github.com/jacobsoo/threathunting) 


# 贡献
内容为系统自动导出, 有任何问题请提issue