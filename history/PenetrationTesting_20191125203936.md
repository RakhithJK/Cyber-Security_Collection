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


- [**3527**星][2m] [PowerShell] [bloodhoundad/bloodhound](https://github.com/BloodHoundAD/BloodHound) Six Degrees of Domain Admin
- [**1992**星][2m] [C++] [darthton/blackbone](https://github.com/darthton/blackbone) Windows memory hacking library
- [**1879**星][19d] [C] [chipsec/chipsec](https://github.com/chipsec/chipsec) Platform Security Assessment Framework
- [**1859**星][1y] [C++] [y-vladimir/smartdeblur](https://github.com/y-vladimir/smartdeblur) Restoration of defocused and blurred photos/images
- [**1773**星][5m] [Py] [veil-framework/veil](https://github.com/veil-framework/veil) Veil 3.1.X (Check version info in Veil at runtime)
- [**1560**星][1m] [Shell] [internetwache/gittools](https://github.com/internetwache/gittools) A repository with 3 tools for pwn'ing websites with .git repositories available
- [**1400**星][4m] [C] [ettercap/ettercap](https://github.com/ettercap/ettercap) Ettercap Project
- [**1384**星][1y] [Go] [filosottile/whosthere](https://github.com/filosottile/whosthere) A ssh server that knows who you are. $ ssh whoami.filippo.io
- [**1339**星][20d] [XSLT] [lolbas-project/lolbas](https://github.com/lolbas-project/lolbas) Living Off The Land Binaries And Scripts - (LOLBins and LOLScripts)
- [**1328**星][12m] [XSLT] [api0cradle/lolbas](https://github.com/api0cradle/lolbas) Living Off The Land Binaries And Scripts - (LOLBins and LOLScripts)
- [**1314**星][1y] [mortenoir1/virtualbox_e1000_0day](https://github.com/mortenoir1/virtualbox_e1000_0day) VirtualBox E1000 Guest-to-Host Escape
- [**1298**星][2m] [PowerShell] [peewpw/invoke-psimage](https://github.com/peewpw/invoke-psimage) Encodes a PowerShell script in the pixels of a PNG file and generates a oneliner to execute
- [**1272**星][1y] [JS] [sakurity/securelogin](https://github.com/sakurity/securelogin) This version won't be maintained!
- [**1218**星][1y] [Go] [cloudflare/redoctober](https://github.com/cloudflare/redoctober) Go server for two-man rule style file encryption and decryption.
- [**1209**星][1m] [Go] [google/martian](https://github.com/google/martian) Martian is a library for building custom HTTP/S proxies
- [**1136**星][3m] [C] [dgiese/dustcloud](https://github.com/dgiese/dustcloud) Xiaomi Smart Home Device Reverse Engineering and Hacking
- [**1128**星][2m] [HTML] [cure53/httpleaks](https://github.com/cure53/httpleaks) HTTPLeaks - All possible ways, a website can leak HTTP requests
- [**1105**星][2m] [Py] [thoughtfuldev/eagleeye](https://github.com/thoughtfuldev/eagleeye) Stalk your Friends. Find their Instagram, FB and Twitter Profiles using Image Recognition and Reverse Image Search.
- [**1073**星][14d] [Go] [looterz/grimd](https://github.com/looterz/grimd) 
- [**1052**星][1m] [PHP] [nbs-system/php-malware-finder](https://github.com/nbs-system/php-malware-finder) Detect potentially malicious PHP files
- [**1023**星][13d] [Py] [yelp/detect-secrets](https://github.com/yelp/detect-secrets) An enterprise friendly way of detecting and preventing secrets in code.
- [**967**星][25d] [HTML] [n0tr00t/sreg](https://github.com/n0tr00t/sreg) 可对使用者通过输入email、phone、username的返回用户注册的所有互联网护照信息。
- [**923**星][7m] [Py] [osirislab/hack-night](https://github.com/osirislab/Hack-Night) Hack Night is an open weekly training session run by the OSIRIS lab.
- [**904**星][26d] [Ruby] [david942j/one_gadget](https://github.com/david942j/one_gadget) The best tool for finding one gadget RCE in libc.so.6
- [**903**星][12m] [C++] [miek/inspectrum](https://github.com/miek/inspectrum) Offline radio signal analyser
- [**902**星][3m] [Go] [dominicbreuker/pspy](https://github.com/dominicbreuker/pspy) Monitor linux processes without root permissions
- [**894**星][25d] [C] [arm-software/arm-trusted-firmware](https://github.com/arm-software/arm-trusted-firmware) Read-only mirror of Trusted Firmware-A
- [**885**星][1m] [C#] [google/sandbox-attacksurface-analysis-tools](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) 沙箱攻击面（Attack Surface）分析工具，用于测试 Windows 上沙箱的各种属性
- [**874**星][4m] [JS] [dpnishant/appmon](https://github.com/dpnishant/appmon) Documentation:
- [**873**星][4m] [bugcrowd/bugcrowd_university](https://github.com/bugcrowd/bugcrowd_university) Open source education content for the researcher community
- [**852**星][20d] [Py] [shmilylty/oneforall](https://github.com/shmilylty/oneforall) 子域收集工具
- [**850**星][3m] [CSS] [outflanknl/redelk](https://github.com/outflanknl/redelk) Red Team's SIEM - tool for Red Teams used for tracking and alarming about Blue Team activities as well as better usability in long term operations.
- [**838**星][13d] [Py] [circl/ail-framework](https://github.com/circl/ail-framework) AIL framework - Analysis Information Leak framework
- [**835**星][13d] [Roff] [slimm609/checksec.sh](https://github.com/slimm609/checksec.sh) checksec.sh: 检查可执行文件(PIE, RELRO, PaX, Canaries, ASLR, Fortify Source)属性的 bash 脚本
- [**832**星][7m] [JS] [serpicoproject/serpico](https://github.com/serpicoproject/serpico) SimplE RePort wrIting and COllaboration tool
- [**819**星][10m] [Shell] [thelinuxchoice/userrecon](https://github.com/thelinuxchoice/userrecon) Find usernames across over 75 social networks
- [**818**星][21d] [C#] [borntoberoot/networkmanager](https://github.com/borntoberoot/networkmanager) A powerful tool for managing networks and troubleshoot network problems!
- [**814**星][9m] [Py] [ietf-wg-acme/acme](https://github.com/ietf-wg-acme/acme) A protocol for automating certificate issuance
- [**814**星][16d] [Py] [lylemi/learn-web-hacking](https://github.com/lylemi/learn-web-hacking) Study Notes For Web Hacking / Web安全学习笔记
- [**812**星][14d] [Java] [lamster2018/easyprotector](https://github.com/lamster2018/easyprotector) 一行代码检测XP/调试/多开/模拟器/root
- [**807**星][8m] [Py] [nccgroup/featherduster](https://github.com/nccgroup/featherduster) An automated, modular cryptanalysis tool; i.e., a Weapon of Math Destruction
- [**802**星][6m] [Py] [corelan/mona](https://github.com/corelan/mona) Corelan Repository for mona.py
- [**797**星][2m] [JS] [sindresorhus/is-online](https://github.com/sindresorhus/is-online) Check if the internet connection is up
- [**793**星][1m] [Py] [hellman/xortool](https://github.com/hellman/xortool) A tool to analyze multi-byte xor cipher
- [**769**星][1m] [Go] [dreddsa5dies/gohacktools](https://github.com/dreddsa5dies/gohacktools) Hacker tools on Go (Golang)
- [**765**星][12m] [PowerShell] [kevin-robertson/invoke-thehash](https://github.com/kevin-robertson/invoke-thehash) PowerShell Pass The Hash Utils
- [**761**星][24d] [C++] [shekyan/slowhttptest](https://github.com/shekyan/slowhttptest) Application Layer DoS attack simulator
- [**757**星][9m] [Py] [hlldz/spookflare](https://github.com/hlldz/spookflare) Loader, dropper generator with multiple features for bypassing client-side and network-side countermeasures.
- [**757**星][4m] [TSQL] [threathunterx/nebula](https://github.com/threathunterx/nebula) "星云"业务风控系统，主工程
- [**746**星][1y] [Py] [greatsct/greatsct](https://github.com/greatsct/greatsct) The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team.
- [**745**星][1m] [Go] [bishopfox/sliver](https://github.com/bishopfox/sliver) Implant framework
- [**739**星][1m] [PHP] [symfony/security-csrf](https://github.com/symfony/security-csrf) The Security CSRF (cross-site request forgery) component provides a class CsrfTokenManager for generating and validating CSRF tokens.
- [**738**星][2m] [C++] [snort3/snort3](https://github.com/snort3/snort3) Snort++
- [**735**星][7m] [Py] [ricterz/genpass](https://github.com/ricterz/genpass) 中国特色的弱口令生成器
- [**734**星][5m] [Go] [talkingdata/owl](https://github.com/talkingdata/owl) 企业级分布式监控告警系
- [**731**星][1m] [HTML] [m4cs/babysploit](https://github.com/m4cs/babysploit) 
- [**729**星][1y] [C#] [eladshamir/internal-monologue](https://github.com/eladshamir/internal-monologue) Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS
- [**719**星][5m] [Go] [anshumanbh/git-all-secrets](https://github.com/anshumanbh/git-all-secrets) 结合多个开源 git 搜索工具实现的代码审计工具
- [**711**星][3m] [Py] [f-secure/see](https://github.com/f-secure/see) Sandboxed Execution Environment
- [**709**星][24d] [Py] [globaleaks/globaleaks](https://github.com/globaleaks/globaleaks) The Open-Source Whistleblowing Software
- [**708**星][5m] [Py] [adamlaurie/rfidiot](https://github.com/adamlaurie/rfidiot) python RFID / NFC library & tools
- [**707**星][1m] [Perl] [gouveaheitor/nipe](https://github.com/GouveaHeitor/nipe) Nipe is a script to make Tor Network your default gateway.
- [**706**星][4m] [aleenzz/cobalt_strike_wiki](https://github.com/aleenzz/cobalt_strike_wiki) Cobalt Strike系列
- [**706**星][1y] [C#] [p3nt4/powershdll](https://github.com/p3nt4/powershdll) Run PowerShell with rundll32. Bypass software restrictions.
- [**706**星][1m] [Py] [shawndevans/smbmap](https://github.com/shawndevans/smbmap) SMBMap is a handy SMB enumeration tool
- [**698**星][13d] [C] [iaik/zombieload](https://github.com/iaik/zombieload) Proof-of-concept for the ZombieLoad attack
- [**692**星][3m] [netflix/security-bulletins](https://github.com/netflix/security-bulletins) Security Bulletins that relate to Netflix Open Source
- [**687**星][5m] [C++] [google/certificate-transparency](https://github.com/google/certificate-transparency) Auditing for TLS certificates.
- [**687**星][7m] [C] [hfiref0x/tdl](https://github.com/hfiref0x/tdl) Driver loader for bypassing Windows x64 Driver Signature Enforcement
- [**684**星][2m] [Py] [mjg59/python-broadlink](https://github.com/mjg59/python-broadlink) Python module for controlling Broadlink RM2/3 (Pro) remote controls, A1 sensor platforms and SP2/3 smartplugs
- [**684**星][25d] [streaak/keyhacks](https://github.com/streaak/keyhacks) Keyhacks is a repository which shows quick ways in which API keys leaked by a bug bounty program can be checked to see if they're valid.
- [**682**星][12d] [Java] [peergos/peergos](https://github.com/peergos/peergos) A decentralised, secure file storage and social network
- [**673**星][7m] [Py] [mr-un1k0d3r/powerlessshell](https://github.com/mr-un1k0d3r/powerlessshell) Run PowerShell command without invoking powershell.exe
- [**665**星][1y] [Py] [endgameinc/rta](https://github.com/endgameinc/rta) 
- [**665**星][12m] [PowerShell] [arvanaghi/sessiongopher](https://github.com/Arvanaghi/SessionGopher) SessionGopher is a PowerShell tool that uses WMI to extract saved session information for remote access tools such as WinSCP, PuTTY, SuperPuTTY, FileZilla, and Microsoft Remote Desktop. It can be run remotely or locally.
- [**664**星][2m] [Py] [skelsec/pypykatz](https://github.com/skelsec/pypykatz) 纯Python实现的Mimikatz
- [**662**星][2m] [Go] [pquerna/otp](https://github.com/pquerna/otp) TOTP library for Go
- [**658**星][5m] [Py] [golismero/golismero](https://github.com/golismero/golismero) GoLismero - The Web Knife
- [**654**星][1y] [Py] [deepzec/bad-pdf](https://github.com/deepzec/bad-pdf) create malicious PDF file to steal NTLM(NTLMv1/NTLMv2) Hashes from windows machines
- [**651**星][4m] [C#] [outflanknl/evilclippy](https://github.com/outflanknl/evilclippy) A cross-platform assistant for creating malicious MS Office documents. Can hide VBA macros, stomp VBA code (via P-Code) and confuse macro analysis tools. Runs on Linux, OSX and Windows.
- [**650**星][12d] [ptresearch/attackdetection](https://github.com/ptresearch/attackdetection) Attack Detection
- [**647**星][8m] [C] [samdenty/wi-pwn](https://github.com/samdenty/Wi-PWN)  performs deauth attacks on cheap Arduino boards
- [**642**星][11m] [C#] [wwillv/godofhacker](https://github.com/wwillv/godofhacker) 黑客神器
- [**637**星][3m] [C#] [ghostpack/rubeus](https://github.com/ghostpack/rubeus) Trying to tame the three-headed dog.
- [**631**星][2m] [Py] [gquere/pwn_jenkins](https://github.com/gquere/pwn_jenkins) Notes about attacking Jenkins servers
- [**628**星][5m] [PHP] [l3m0n/bypass_disable_functions_shell](https://github.com/l3m0n/bypass_disable_functions_shell) 一个各种方式突破Disable_functions达到命令执行的shell
- [**615**星][10m] [Py] [dirkjanm/privexchange](https://github.com/dirkjanm/privexchange) Exchange your privileges for Domain Admin privs by abusing Exchange
- [**606**星][1y] [Shell] [wireghoul/htshells](https://github.com/wireghoul/htshells) Self contained htaccess shells and attacks
- [**602**星][2m] [JS] [evilsocket/arc](https://github.com/evilsocket/arc) 可用于管理私密数据的工具. 后端是 Go 语言编写的 RESTful 服务器,  前台是Html + JavaScript
- [**592**星][2m] [PHP] [hongrisec/php-audit-labs](https://github.com/hongrisec/php-audit-labs) 一个关于PHP的代码审计项目
- [**592**星][1m] [PowerShell] [ramblingcookiemonster/powershell](https://github.com/ramblingcookiemonster/powershell) Various PowerShell functions and scripts
- [**589**星][3m] [Py] [webrecorder/pywb](https://github.com/webrecorder/pywb) Core Python Web Archiving Toolkit for replay and recording of web archives
- [**584**星][16d] [YARA] [didierstevens/didierstevenssuite](https://github.com/didierstevens/didierstevenssuite) Please no pull requests for this repository. Thanks!
- [**575**星][8m] [C#] [0xbadjuju/tokenvator](https://github.com/0xbadjuju/tokenvator) A tool to elevate privilege with Windows Tokens
- [**575**星][9m] [Py] [romanz/amodem](https://github.com/romanz/amodem) transmit a file between 2 computers, using a simple headset, allowing true air-gapped communication (via a speaker and a microphone), or an audio cable (for higher transmission speed)
- [**574**星][8m] [C] [mrexodia/titanhide](https://github.com/mrexodia/titanhide) Hiding kernel-driver for x86/x64.
- [**567**星][1y] [C#] [tyranid/dotnettojscript](https://github.com/tyranid/dotnettojscript) A tool to create a JScript file which loads a .NET v2 assembly from memory.
- [**561**星][1y] [Solidity] [trailofbits/not-so-smart-contracts](https://github.com/crytic/not-so-smart-contracts) Examples of Solidity security issues
- [**558**星][5m] [Py] [nidem/kerberoast](https://github.com/nidem/kerberoast)  a series of tools for attacking MS Kerberos implementations
- [**550**星][10m] [C] [justinsteven/dostackbufferoverflowgood](https://github.com/justinsteven/dostackbufferoverflowgood) 
- [**545**星][1y] [Go] [cw1997/natbypass](https://github.com/cw1997/natbypass) 内网穿透，端口转发工具
- [**545**星][3m] [Py] [its-a-feature/apfell](https://github.com/its-a-feature/apfell) A collaborative, multi-platform, red teaming framework
- [**543**星][1m] [Go] [shopify/kubeaudit](https://github.com/shopify/kubeaudit) kubeaudit helps you audit your Kubernetes clusters against common security controls
- [**536**星][8m] [C] [hfiref0x/upgdsed](https://github.com/hfiref0x/upgdsed) Universal PatchGuard and Driver Signature Enforcement Disable
- [**536**星][2m] [C] [vanhauser-thc/thc-ipv6](https://github.com/vanhauser-thc/thc-ipv6) IPv6 attack toolkit
- [**533**星][1m] [Go] [yggdrasil-network/yggdrasil-go](https://github.com/yggdrasil-network/yggdrasil-go) An experiment in scalable routing as an encrypted IPv6 overlay network
- [**530**星][5m] [HCL] [coalfire-research/red-baron](https://github.com/coalfire-research/red-baron) Automate creating resilient, disposable, secure and agile infrastructure for Red Teams.
- [**530**星][2m] [C] [eliasoenal/multimon-ng](https://github.com/EliasOenal/multimon-ng) 
- [**526**星][28d] [Ruby] [hdm/mac-ages](https://github.com/hdm/mac-ages) MAC address age tracking
- [**524**星][1y] [Py] [n00py/wpforce](https://github.com/n00py/wpforce) Wordpress Attack Suite
- [**523**星][1y] [C#] [ghostpack/safetykatz](https://github.com/ghostpack/safetykatz) SafetyKatz is a combination of slightly modified version of
- [**515**星][11m] [PowerShell] [a-min3/winspect](https://github.com/a-min3/winspect) Powershell-based Windows Security Auditing Toolbox
- [**513**星][1m] [Shell] [trailofbits/twa](https://github.com/trailofbits/twa) A tiny web auditor with strong opinions.
- [**509**星][11m] [Go] [mthbernardes/gtrs](https://github.com/mthbernardes/gtrs) Google Translator Reverse Shell
- [**507**星][1m] [JS] [mr-un1k0d3r/thundershell](https://github.com/mr-un1k0d3r/thundershell) Python / C# Unmanaged PowerShell based RAT
- [**505**星][7m] [Visual Basic] [mr-un1k0d3r/maliciousmacrogenerator](https://github.com/mr-un1k0d3r/maliciousmacrogenerator) Malicious Macro Generator
- [**501**星][24d] [Go] [sensepost/gowitness](https://github.com/sensepost/gowitness) Go 语言编写的网站快照工具
- [**489**星][2m] [PHP] [nzedb/nzedb](https://github.com/nzedb/nzedb) a fork of nnplus(2011) | NNTP / Usenet / Newsgroup indexer.
- [**485**星][2m] [Go] [gen2brain/cam2ip](https://github.com/gen2brain/cam2ip) 将任何网络摄像头转换为IP 摄像机
- [**480**星][1y] [Java] [continuumsecurity/bdd-security](https://github.com/continuumsecurity/bdd-security) BDD Automated Security Tests for Web Applications
- [**479**星][11m] [Go] [evanmiller/hecate](https://github.com/evanmiller/hecate) The Hex Editor From Hell
- [**475**星][1m] [C] [m0nad/diamorphine](https://github.com/m0nad/diamorphine) LKM rootkit for Linux Kernels 2.6.x/3.x/4.x (x86 and x86_64)
- [**474**星][10m] [Shell] [craigz28/firmwalker](https://github.com/craigz28/firmwalker) Script for searching the extracted firmware file system for goodies!
- [**474**星][2m] [Go] [gorilla/csrf](https://github.com/gorilla/csrf) gorilla/csrf provides Cross Site Request Forgery (CSRF) prevention middleware for Go web applications & services
- [**468**星][2m] [Py] [bashfuscator/bashfuscator](https://github.com/bashfuscator/bashfuscator) A fully configurable and extendable Bash obfuscation framework. This tool is intended to help both red team and blue team.
- [**465**星][18d] [Py] [aoii103/darknet_chinesetrading](https://github.com/aoii103/darknet_chinesetrading) 
- [**457**星][21d] [LLVM] [jonathansalwan/tigress_protection](https://github.com/jonathansalwan/tigress_protection) Playing with the Tigress binary protection. Break some of its protections and solve some of its challenges. Automatic deobfuscation using symbolic execution, taint analysis and LLVM.
- [**456**星][12m] [Py] [mehulj94/radium](https://github.com/mehulj94/Radium) Python keylogger with multiple features.
- [**454**星][5m] [C] [phoenhex/files](https://github.com/phoenhex/files) 
- [**453**星][27d] [Go] [gen0cide/gscript](https://github.com/gen0cide/gscript) 基于运行时参数，动态安装恶意软件
- [**449**星][3m] [C++] [omerya/invisi-shell](https://github.com/omerya/invisi-shell) Hide your Powershell script in plain sight. Bypass all Powershell security features
- [**448**星][2m] [Py] [bit4woo/teemo](https://github.com/bit4woo/teemo) A Domain Name & Email Address Collection Tool
- [**448**星][2m] [PowerShell] [rvrsh3ll/misc-powershell-scripts](https://github.com/rvrsh3ll/misc-powershell-scripts) Random Tools
- [**445**星][13d] [Shell] [wireghoul/graudit](https://github.com/wireghoul/graudit) 简单的脚本和签名集，进行源代码审计
- [**444**星][9m] [C] [martinmarinov/tempestsdr](https://github.com/martinmarinov/tempestsdr) Remote video eavesdropping using a software-defined radio platform
- [**443**星][2m] [Py] [portantier/habu](https://github.com/portantier/habu) Python 编写的网络工具工具包，主要用于教学/理解网络攻击中的一些概念
- [**443**星][1y] [JS] [simonepri/upash](https://github.com/simonepri/upash) 
- [**437**星][6m] [PHP] [flozz/p0wny-shell](https://github.com/flozz/p0wny-shell) Single-file PHP shell
- [**432**星][1m] [PowerShell] [mr-un1k0d3r/redteampowershellscripts](https://github.com/mr-un1k0d3r/redteampowershellscripts) Various PowerShell scripts that may be useful during red team exercise
- [**428**星][6m] [Pascal] [mojtabatajik/robber](https://github.com/mojtabatajik/robber) Robber is open source tool for finding executables prone to DLL hijacking
- [**426**星][6m] [Py] [stamparm/fetch-some-proxies](https://github.com/stamparm/fetch-some-proxies) Simple Python script for fetching "some" (usable) proxies
- [**423**星][28d] [Py] [super-l/superl-url](https://github.com/super-l/superl-url) 根据关键词，对搜索引擎内容检索结果的网址内容进行采集的一款轻量级软程序。 程序主要运用于安全渗透测试项目，以及批量评估各类CMS系统0DAY的影响程度，同时也是批量采集自己获取感兴趣的网站的一个小程序~~ 可自动从搜索引擎采集相关网站的真实地址与标题等信息，可保存为文件，自动去除重复URL。同时，也可以自定义忽略多条域名等。
- [**421**星][10m] [Py] [d4vinci/cuteit](https://github.com/d4vinci/cuteit) IP obfuscator made to make a malicious ip a bit cuter
- [**408**星][10m] [Py] [powerscript/katanaframework](https://github.com/powerscript/katanaframework) The New Hacking Framework
- [**404**星][2m] [C++] [hoshimin/kernel-bridge](https://github.com/hoshimin/kernel-bridge) Windows kernel hacking framework, driver template, hypervisor and API written on C++
- [**401**星][5m] [Py] [ytisf/pyexfil](https://github.com/ytisf/pyexfil) A Python Package for Data Exfiltration
- [**396**星][2m] [HTML] [w3c/webappsec](https://github.com/w3c/webappsec) Web Application Security Working Group repo
- [**387**星][1y] [C#] [squalr/squalr](https://github.com/squalr/squalr) Squalr Memory Editor - Game Hacking Tool Written in C#
- [**378**星][1y] [JS] [empireproject/empire-gui](https://github.com/empireproject/empire-gui) Empire client application
- [**376**星][1m] [JS] [nccgroup/tracy](https://github.com/nccgroup/tracy) tracy: 查找web app中所有的sinks and sources, 并以易于理解的方式显示这些结果
- [**375**星][13d] [C++] [simsong/bulk_extractor](https://github.com/simsong/bulk_extractor) This is the development tree. For downloads please see:
- [**375**星][8m] [Java] [tiagorlampert/saint](https://github.com/tiagorlampert/saint) a Spyware Generator for Windows systems written in Java
- [**372**星][8m] [Py] [k4m4/onioff](https://github.com/k4m4/onioff) onioff：url检测器，深度检测网页链接
- [**365**星][1m] [C++] [crypto2011/idr](https://github.com/crypto2011/idr) Interactive Delphi Reconstructor
- [**362**星][17d] [C#] [bloodhoundad/sharphound](https://github.com/bloodhoundad/sharphound) The BloodHound C# Ingestor
- [**361**星][20d] [Py] [emtunc/slackpirate](https://github.com/emtunc/slackpirate) Slack Enumeration and Extraction Tool - extract sensitive information from a Slack Workspace
- [**360**星][26d] [Ruby] [david942j/seccomp-tools](https://github.com/david942j/seccomp-tools) Provide powerful tools for seccomp analysis
- [**360**星][4m] [Shell] [trimstray/otseca](https://github.com/trimstray/otseca) otseca: 安全审计工具, 搜索并转储系统配置
- [**354**星][2m] [Py] [fox-it/bloodhound.py](https://github.com/fox-it/bloodhound.py) A Python based ingestor for BloodHound
- [**351**星][6m] [Py] [tidesec/tidefinger](https://github.com/tidesec/tidefinger) TideFinger——指纹识别小工具，汲取整合了多个web指纹库，结合了多种指纹检测方法，让指纹检测更快捷、准确。
- [**350**星][10m] [Py] [secynic/ipwhois](https://github.com/secynic/ipwhois) Retrieve and parse whois data for IPv4 and IPv6 addresses
- [**348**星][2m] [Py] [lockgit/hacking](https://github.com/lockgit/hacking) hacking is a kind of spirit !
- [**342**星][30d] [Ruby] [sunitparekh/data-anonymization](https://github.com/sunitparekh/data-anonymization) Want to use production data for testing, data-anonymization can help you.
- [**339**星][1m] [C] [nccgroup/phantap](https://github.com/nccgroup/phantap) Phantom Tap (PhanTap) - an ‘invisible’ network tap aimed at red teams
- [**338**星][1y] [Ruby] [srcclr/commit-watcher](https://github.com/srcclr/commit-watcher) Find interesting and potentially hazardous commits in git projects
- [**336**星][4m] [Perl] [keydet89/regripper2.8](https://github.com/keydet89/regripper2.8) RegRipper version 2.8
- [**331**星][12m] [Assembly] [egebalci/amber](https://github.com/egebalci/amber) Reflective PE packer.
- [**328**星][8m] [Py] [dirkjanm/ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) Active Directory information dumper via LDAP
- [**327**星][28d] [PowerShell] [joelgmsec/autordpwn](https://github.com/joelgmsec/autordpwn) The Shadow Attack Framework
- [**327**星][1y] [Py] [leapsecurity/inspy](https://github.com/leapsecurity/InSpy) A python based LinkedIn enumeration tool
- [**325**星][10m] [C#] [ghostpack/sharpdump](https://github.com/ghostpack/sharpdump) SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
- [**322**星][1y] [Shell] [1n3/goohak](https://github.com/1n3/goohak) Automatically Launch Google Hacking Queries Against A Target Domain
- [**318**星][22d] [Py] [codingo/interlace](https://github.com/codingo/interlace) Easily turn single threaded command line applications into a fast, multi-threaded application with CIDR and glob support.
- [**317**星][1y] [JS] [nccgroup/wssip](https://github.com/nccgroup/wssip) 服务器和客户端之间通信时自定义 WebSocket 数据的捕获、修改和发送。
- [**316**星][1m] [JS] [meituan-dianping/lyrebird](https://github.com/meituan-dianping/lyrebird) 基于拦截以及模拟HTTP/HTTPS网络请求的面向移动应用的插件化测试工作台
- [**316**星][1y] [Java] [ysrc/liudao](https://github.com/ysrc/liudao) “六道”实时业务风控系统
- [**314**星][1y] [Go] [benjojo/bgp-battleships](https://github.com/benjojo/bgp-battleships) Play battleships using BGP
- [**312**星][2m] [Py] [circl/lookyloo](https://github.com/circl/lookyloo) Lookyloo is a web interface allowing to scrape a website and then displays a tree of domains calling each other.
- [**312**星][11m] [crazywa1ker/darthsidious-chinese](https://github.com/crazywa1ker/darthsidious-chinese) 从0开始你的域渗透之旅
- [**311**星][12d] [C] [vanhauser-thc/aflplusplus](https://github.com/vanhauser-thc/aflplusplus) afl++ is afl 2.56b with community patches, AFLfast power schedules, qemu 3.1 upgrade + laf-intel support, MOpt mutators, InsTrim instrumentation, unicorn_mode and a lot more!
- [**310**星][5m] [YARA] [needmorecowbell/hamburglar](https://github.com/needmorecowbell/hamburglar)  collect useful information from urls, directories, and files
- [**307**星][1m] [Go] [wangyihang/platypus](https://github.com/wangyihang/platypus)  A modern multiple reverse shell sessions/clients manager via terminal written in go
- [**306**星][3m] [PowerShell] [enigma0x3/misc-powershell-stuff](https://github.com/enigma0x3/misc-powershell-stuff) random powershell goodness
- [**304**星][2m] [Py] [coalfire-research/slackor](https://github.com/coalfire-research/slackor) A Golang implant that uses Slack as a command and control server
- [**304**星][6m] [C] [pmem/syscall_intercept](https://github.com/pmem/syscall_intercept) Linux系统调用拦截框架，通过 hotpatching 进程标准C库的机器码实现。
- [**302**星][7m] [C] [tomac/yersinia](https://github.com/tomac/yersinia) yersinia：layer 2 攻击框架
- [**298**星][26d] [Py] [salls/angrop](https://github.com/salls/angrop) a rop gadget finder and chain builder 
- [**298**星][1m] [Py] [skylined/bugid](https://github.com/skylined/bugid) Detect, analyze and uniquely identify crashes in Windows applications
- [**296**星][1y] [PowerShell] [onelogicalmyth/zeroday-powershell](https://github.com/onelogicalmyth/zeroday-powershell) A PowerShell example of the Windows zero day priv esc
- [**295**星][6m] [HTML] [nccgroup/crosssitecontenthijacking](https://github.com/nccgroup/crosssitecontenthijacking) Content hijacking proof-of-concept using Flash, PDF and Silverlight
- [**295**星][1y] [C++] [nevermoe/unity_metadata_loader](https://github.com/nevermoe/unity_metadata_loader)  load strings and method/class names in global-metadata.dat to IDA
- [**295**星][1y] [JS] [xxxily/fiddler-plus](https://github.com/xxxily/fiddler-plus) 自定义的Fiddler规则，多环境切换、解决跨域开发、快速调试线上代码必备|高效调试分析利器
- [**294**星][27d] [JS] [doyensec/electronegativity](https://github.com/doyensec/electronegativity) Electronegativity is a tool to identify misconfigurations and security anti-patterns in Electron applications.
- [**294**星][13d] [C++] [squalr/squally](https://github.com/squalr/squally) 2D Platformer Game for Teaching Game Hacking - C++/cocos2d-x
- [**290**星][3m] [Shell] [fdiskyou/zines](https://github.com/fdiskyou/zines) Mirror of my favourite hacking Zines for the lulz, nostalgy, and reference
- [**290**星][1m] [C] [mboehme/aflfast](https://github.com/mboehme/aflfast) AFLFast (extends AFL with Power Schedules)
- [**288**星][2m] [C] [9176324/shark](https://github.com/9176324/shark) Turn off PatchGuard in real time for win7 (7600) ~ win10 (18950).
- [**288**星][3m] [Visual Basic] [itm4n/vba-runpe](https://github.com/itm4n/vba-runpe) A VBA implementation of the RunPE technique or how to bypass application whitelisting.
- [**286**星][8m] [C] [gianlucaborello/libprocesshider](https://github.com/gianlucaborello/libprocesshider) Hide a process under Linux using the ld preloader (
- [**286**星][1y] [Java] [webgoat/webgoat-legacy](https://github.com/webgoat/webgoat-legacy) Legacy WebGoat 6.0 - Deliberately insecure JavaEE application
- [**285**星][3m] [Py] [apache/incubator-spot](https://github.com/apache/incubator-spot) Mirror of Apache Spot
- [**284**星][6m] [C#] [matterpreter/offensivecsharp](https://github.com/matterpreter/offensivecsharp) Collection of Offensive C# Tooling
- [**279**星][11m] [Py] [justicerage/ffm](https://github.com/justicerage/ffm) Freedom Fighting Mode: open source hacking harness
- [**278**星][1m] [Go] [cruise-automation/fwanalyzer](https://github.com/cruise-automation/fwanalyzer) a tool to analyze filesystem images
- [**278**星][3m] [Py] [joxeankoret/pyew](https://github.com/joxeankoret/pyew) Official repository for Pyew.
- [**277**星][1y] [HTML] [google/p0tools](https://github.com/googleprojectzero/p0tools) Project Zero Docs and Tools
- [**277**星][16d] [Shell] [trimstray/mkchain](https://github.com/trimstray/mkchain) sslmerge: 建立从根证书到最终用户证书的有效的SSL证书链, 修复不完整的证书链并下载所有缺少的CA证书
- [**276**星][4m] [geerlingguy/ansible-role-security](https://github.com/geerlingguy/ansible-role-security) Ansible Role - Security
- [**276**星][2m] [Go] [mdsecactivebreach/o365-attack-toolkit](https://github.com/mdsecactivebreach/o365-attack-toolkit) A toolkit to attack Office365
- [**275**星][4m] [Py] [opsdisk/pagodo](https://github.com/opsdisk/pagodo) pagodo (Passive Google Dork) - Automate Google Hacking Database scraping
- [**273**星][3m] [PowerShell] [nullbind/powershellery](https://github.com/nullbind/powershellery) This repo contains Powershell scripts used for general hackery.
- [**272**星][9m] [C++] [anhkgg/superdllhijack](https://github.com/anhkgg/superdllhijack) SuperDllHijack：A general DLL hijack technology, don't need to manually export the same function interface of the DLL, so easy! 一种通用Dll劫持技术，不再需要手工导出Dll的函数接口了
- [**272**星][3m] [Py] [invernizzi/scapy-http](https://github.com/invernizzi/scapy-http) Support for HTTP in Scapy
- [**271**星][3m] [artsploit/solr-injection](https://github.com/artsploit/solr-injection) Apache Solr Injection Research
- [**269**星][6m] [Py] [ropnop/windapsearch](https://github.com/ropnop/windapsearch) Python script to enumerate users, groups and computers from a Windows domain through LDAP queries
- [**268**星][4m] [Py] [den1al/jsshell](https://github.com/den1al/jsshell) An interactive multi-user web JS shell
- [**264**星][7m] [s0md3v/mypapers](https://github.com/s0md3v/mypapers) Repository for hosting my research papers
- [**264**星][7m] [Py] [s0md3v/breacher](https://github.com/s0md3v/Breacher) An advanced multithreaded admin panel finder written in python.
- [**263**星][1y] [Ruby] [evait-security/envizon](https://github.com/evait-security/envizon) envizon: 网络可视化工具, 在渗透测试中快速识别最可能的目标
- [**261**星][2m] [Shell] [al0ne/linuxcheck](https://github.com/al0ne/linuxcheck) linux信息收集/应急响应/常见后门检测脚本
- [**260**星][10m] [Py] [ant4g0nist/susanoo](https://github.com/ant4g0nist/susanoo) A REST API security testing framework.
- [**260**星][5m] [C++] [d35ha/callobfuscator](https://github.com/d35ha/callobfuscator) Obfuscate specific windows apis with different apis
- [**260**星][3m] [C] [portcullislabs/linikatz](https://github.com/portcullislabs/linikatz) UNIX版本的Mimikatz
- [**259**星][2m] [C] [eua/wxhexeditor](https://github.com/eua/wxhexeditor) wxHexEditor official GIT repo
- [**258**星][25d] [Py] [frint0/email-enum](https://github.com/frint0/email-enum) Email-Enum searches mainstream websites and tells you if an email is registered!
- [**256**星][1y] [PowerShell] [fox-it/invoke-aclpwn](https://github.com/fox-it/invoke-aclpwn) 
- [**256**星][8m] [C] [landhb/hideprocess](https://github.com/landhb/hideprocess) A basic Direct Kernel Object Manipulation rootkit that removes a process from the EPROCESS list, hiding it from the Task Manager
- [**256**星][1y] [Py] [m4ll0k/galileo](https://github.com/m4ll0k/galileo) Galileo - Web Application Audit Framework
- [**256**星][11m] [Py] [hysnsec/devsecops-studio](https://github.com/hysnsec/DevSecOps-Studio) DevSecOps Distribution - Virtual Environment to learn DevSecOps
- [**254**星][1m] [Shell] [cytoscape/cytoscape](https://github.com/cytoscape/cytoscape) Cytoscape: an open source platform for network analysis and visualization
- [**254**星][9m] [C] [p0f/p0f](https://github.com/p0f/p0f) p0f unofficial git repo
- [**253**星][1y] [C] [benjamin-42/trident](https://github.com/benjamin-42/trident) 
- [**253**星][1y] [Java] [jackofmosttrades/gadgetinspector](https://github.com/jackofmosttrades/gadgetinspector) A byte code analyzer for finding deserialization gadget chains in Java applications
- [**252**星][2m] [C++] [poweradminllc/paexec](https://github.com/poweradminllc/paexec) Remote execution, like PsExec
- [**251**星][6m] [Go] [lavalamp-/ipv666](https://github.com/lavalamp-/ipv666) ipv666: IPV6地址枚举工具. Go编写
- [**250**星][14d] [C++] [fransbouma/injectablegenericcamerasystem](https://github.com/fransbouma/injectablegenericcamerasystem) This is a generic camera system to be used as the base for cameras for taking screenshots within games. The main purpose of the system is to hijack the in-game 3D camera by overwriting values in its camera structure with our own values so we can control where the camera is located, it's pitch/yaw/roll values, its FoV and the camera's look vector.
- [**250**星][2m] [Py] [hacktoolspack/hack-tools](https://github.com/hacktoolspack/hack-tools) hack tools
- [**249**星][6m] [Py] [itskindred/procspy](https://github.com/itskindred/procspy) Python tool that monitors and logs user-run commands on a Linux system for either offensive or defensive purposes..
- [**247**星][14d] [Py] [rvrsh3ll/findfrontabledomains](https://github.com/rvrsh3ll/findfrontabledomains) Search for potential frontable domains
- [**246**星][4m] [Py] [redteamoperations/pivotsuite](https://github.com/redteamoperations/pivotsuite) Network Pivoting Toolkit
- [**244**星][7m] [ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet](https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet) wordpress_plugin_security_testing_cheat_sheet：WordPress插件安全测试备忘录。
- [**243**星][9m] [Py] [wh0ale/src-experience](https://github.com/wh0ale/src-experience) 工欲善其事，必先利其器
- [**239**星][7m] [Py] [openstack/syntribos](https://github.com/openstack/syntribos) 自动化的 API 安全测试工具
- [**236**星][1y] [Py] [matthewclarkmay/geoip-attack-map](https://github.com/matthewclarkmay/geoip-attack-map) Cyber security geoip attack map that follows syslog and parses IPs/port numbers to visualize attackers in real time.
- [**236**星][8m] [Py] [mazen160/bfac](https://github.com/mazen160/bfac) 自动化 web app 备份文件测试工具，可检测备份文件是否会泄露 web  app 源代码
- [**234**星][15d] [Py] [cisco-config-analysis-tool/ccat](https://github.com/cisco-config-analysis-tool/ccat) Cisco Config Analysis Tool
- [**234**星][3m] [Rust] [hippolot/anevicon](https://github.com/Hippolot/anevicon) 
- [**233**星][2m] [JS] [martinzhou2015/srcms](https://github.com/martinzhou2015/srcms) SRCMS企业应急响应与缺陷管理系统
- [**231**星][11m] [xcsh/unity-game-hacking](https://github.com/xcsh/unity-game-hacking) A guide for hacking unity games
- [**230**星][29d] [Py] [timlib/webxray](https://github.com/timlib/webxray) webxray is a tool for analyzing third-party content on webpages and identifying the companies which collect user data.
- [**226**星][10m] [duoergun0729/2book](https://github.com/duoergun0729/2book) 《Web安全之深度学习实战》
- [**226**星][7m] [Shell] [r00t-3xp10it/meterpreter_paranoid_mode-ssl](https://github.com/r00t-3xp10it/meterpreter_paranoid_mode-ssl) Meterpreter Paranoid Mode - SSL/TLS connections
- [**225**星][1y] [Go] [netxfly/sec_check](https://github.com/netxfly/sec_check) 服务器安全检测的辅助工具
- [**224**星][6m] [JS] [jesusprubio/strong-node](https://github.com/jesusprubio/strong-node) 
- [**222**星][22d] [Py] [webbreacher/whatsmyname](https://github.com/webbreacher/whatsmyname) This repository has the unified data required to perform user enumeration on various websites. Content is in a JSON file and can easily be used in other projects.
- [**221**星][2m] [Py] [guimaizi/get_domain](https://github.com/guimaizi/get_domain) 域名收集与监测
- [**217**星][6m] [bhdresh/dejavu](https://github.com/bhdresh/dejavu) deception framework which can be used to deploy decoys across the infrastructure
- [**215**星][9m] [Py] [mckinsey666/vocabs](https://github.com/Mckinsey666/vocabs) A lightweight online dictionary integration to the command line
- [**213**星][3m] [JS] [varchashva/letsmapyournetwork](https://github.com/varchashva/letsmapyournetwork) Lets Map Your Network enables you to visualise your physical network in form of graph with zero manual error
- [**212**星][4m] [Shell] [cryptolok/crykex](https://github.com/cryptolok/crykex) Linux Memory Cryptographic Keys Extractor
- [**212**星][1m] [Py] [wazuh/wazuh-ruleset](https://github.com/wazuh/wazuh-ruleset) ruleset is used to detect attacks, intrusions, software misuse, configuration problems, application errors, malware, rootkits, system anomalies or security policy violations.
- [**212**星][8m] [JS] [zhuyingda/veneno](https://github.com/zhuyingda/veneno) 用Node.js编写的Web安全测试框架
- [**209**星][1y] [basilfx/tradfri-hacking](https://github.com/basilfx/tradfri-hacking) Hacking the IKEA TRÅDFRI light bulbs and accessories.
- [**208**星][5m] [C#] [erfg12/memory.dll](https://github.com/erfg12/memory.dll) C# Hacking library for making PC game trainers.
- [**208**星][2m] [Py] [jordanpotti/cloudscraper](https://github.com/jordanpotti/cloudscraper) Tool to enumerate targets in search of cloud resources. S3 Buckets, Azure Blobs, Digital Ocean Storage Space.
- [**205**星][4m] [PowerShell] [harmj0y/damp](https://github.com/harmj0y/damp) The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification
- [**205**星][12m] [Py] [orf/xcat](https://github.com/orf/xcat) 辅助盲 Xpath 注入，检索正在由 Xpath 查询处理的整个 XML 文档，读取主机文件系统上的任意文件，并使用出站 HTTP 请求，使服务器将数据直接发送到xcat
- [**205**星][12m] [C#] [tevora-threat/sharpview](https://github.com/tevora-threat/sharpview) C# implementation of harmj0y's PowerView
- [**204**星][8m] [1hack0/facebook-bug-bounty-write-ups](https://github.com/1hack0/facebook-bug-bounty-write-ups) Hunting Bugs for Fun and Profit
- [**203**星][14d] [Py] [seahoh/gotox](https://github.com/seahoh/gotox) 本地自动代理，修改自 goagent。
- [**201**星][12d] [CoffeeScript] [bevry/getmac](https://github.com/bevry/getmac) Get the mac address of the current machine you are on via Node.js
- [**201**星][6m] [JS] [wingleung/save-page-state](https://github.com/wingleung/save-page-state) A chrome extension to save the state of a page for further analysis
- [**200**星][1m] [Py] [nyxgeek/lyncsmash](https://github.com/nyxgeek/lyncsmash) locate and attack Lync/Skype for Business


### <a id="f34b4da04f2a77a185729b5af752efc5"></a>未分类






***


## <a id="cc80626cfd1f8411b968373eb73bc4ea"></a>人工智能&&机器学习&&深度学习&&神经网络


### <a id="19dd474da6b715024ff44d27484d528a"></a>未分类-AI


- [**4216**星][25d] [Py] [tensorflow/cleverhans](https://github.com/tensorflow/cleverhans) cleverhans：基准测试（benchmark）机器学习系统的漏洞生成（to）对抗样本（adversarial examples）
- [**3263**星][18d] [jivoi/awesome-ml-for-cybersecurity](https://github.com/jivoi/awesome-ml-for-cybersecurity) 针对网络安全的机器学习资源列表
- [**2480**星][15d] [Py] [evilsocket/pwnagotchi](https://github.com/evilsocket/pwnagotchi) (⌐■_■) - Deep Reinforcement Learning instrumenting bettercap for WiFi pwning.
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**1049**星][1m] [Py] [13o-bbr-bbq/machine_learning_security](https://github.com/13o-bbr-bbq/machine_learning_security) Source code about machine learning and security.
- [**569**星][20d] [404notf0und/ai-for-security-learning](https://github.com/404notf0und/ai-for-security-learning) 安全场景、基于AI的安全算法和安全数据分析学习资料整理
- [**513**星][21d] [Py] [gyoisamurai/gyoithon](https://github.com/gyoisamurai/gyoithon) 使用机器学习的成长型渗透测试工具
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/渗透多合一&&渗透框架](#2051fd9e171f2698d8e7486e3dd35d87) |
- [**445**星][4m] [Py] [cchio/deep-pwning](https://github.com/cchio/deep-pwning) Metasploit for machine learning.
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Metasploit/未分类-metasploit](#01be61d5bb9f6f7199208ff0fba86b5d) |
- [**283**星][1m] [Py] [bishopfox/eyeballer](https://github.com/bishopfox/eyeballer) Convolutional neural network for analyzing pentest screenshots
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |


### <a id="bab8f2640d6c5eb981003b3fd1ecc042"></a>收集






***


## <a id="a4ee2f4d4a944b54b2246c72c037cd2e"></a>收集&&集合


### <a id="e97d183e67fa3f530e7d0e7e8c33ee62"></a>未分类


- [**4097**星][20d] [qazbnm456/awesome-web-security](https://github.com/qazbnm456/awesome-web-security) web 安全资源列表
- [**2778**星][4m] [C] [juliocesarfort/public-pentesting-reports](https://github.com/juliocesarfort/public-pentesting-reports) Curated list of public penetration test reports released by several consulting firms and academic security groups
- [**2747**星][2m] [infosecn1nja/red-teaming-toolkit](https://github.com/infosecn1nja/red-teaming-toolkit) A collection of open source and commercial tools that aid in red team operations.
- [**2592**星][1m] [rmusser01/infosec_reference](https://github.com/rmusser01/infosec_reference) An Information Security Reference That Doesn't Suck
- [**2483**星][2m] [kbandla/aptnotes](https://github.com/kbandla/aptnotes) Various public documents, whitepapers and articles about APT campaigns
- [**2353**星][22d] [Py] [0xinfection/awesome-waf](https://github.com/0xinfection/awesome-waf) 
- [**2253**星][11m] [yeyintminthuhtut/awesome-red-teaming](https://github.com/yeyintminthuhtut/awesome-red-teaming) List of Awesome Red Teaming Resources
- [**2058**星][3m] [infoslack/awesome-web-hacking](https://github.com/infoslack/awesome-web-hacking) A list of web application security
- [**2024**星][1y] [bluscreenofjeff/red-team-infrastructure-wiki](https://github.com/bluscreenofjeff/red-team-infrastructure-wiki) Wiki to collect Red Team infrastructure hardening resources
- [**2008**星][1m] [tanprathan/mobileapp-pentest-cheatsheet](https://github.com/tanprathan/mobileapp-pentest-cheatsheet) The Mobile App Pentest cheat sheet was created to provide concise collection of high value information on specific mobile application penetration testing topics.
- [**1897**星][2m] [toolswatch/blackhat-arsenal-tools](https://github.com/toolswatch/blackhat-arsenal-tools) Black Hat 武器库
- [**1767**星][1m] [djadmin/awesome-bug-bounty](https://github.com/djadmin/awesome-bug-bounty) A comprehensive curated list of available Bug Bounty & Disclosure Programs and Write-ups.
- [**1706**星][4m] [ngalongc/bug-bounty-reference](https://github.com/ngalongc/bug-bounty-reference) Inspired by
- [**1698**星][1y] [coreb1t/awesome-pentest-cheat-sheets](https://github.com/coreb1t/awesome-pentest-cheat-sheets) Collection of the cheat sheets useful for pentesting
- [**1602**星][6m] [Py] [w1109790800/penetration](https://github.com/w1109790800/penetration) 渗透 超全面的渗透资料
- [**1587**星][6m] [Ruby] [brunofacca/zen-rails-security-checklist](https://github.com/brunofacca/zen-rails-security-checklist) Checklist of security precautions for Ruby on Rails applications.
- [**1510**星][24d] [emijrp/awesome-awesome](https://github.com/emijrp/awesome-awesome) A curated list of awesome curated lists of many topics.
- [**1340**星][19d] [grrrdog/java-deserialization-cheat-sheet](https://github.com/grrrdog/java-deserialization-cheat-sheet) The cheat sheet about Java Deserialization vulnerabilities
- [**1170**星][7m] [joe-shenouda/awesome-cyber-skills](https://github.com/joe-shenouda/awesome-cyber-skills) A curated list of hacking environments where you can train your cyber skills legally and safely
- [**1126**星][2m] [Batchfile] [ckjbug/hacking](https://github.com/ckjbug/hacking) 
- [**1124**星][2m] [m4ll0k/awesome-hacking-tools](https://github.com/m4ll0k/awesome-hacking-tools) Awesome Hacking Tools
- [**1095**星][13d] [w00t3k/awesome-cellular-hacking](https://github.com/w00t3k/awesome-cellular-hacking) Awesome-Cellular-Hacking
- [**1095**星][1y] [paulsec/awesome-windows-domain-hardening](https://github.com/PaulSec/awesome-windows-domain-hardening) A curated list of awesome Security Hardening techniques for Windows.
- [**1088**星][4m] [zbetcheckin/security_list](https://github.com/zbetcheckin/security_list) Great security list for fun and profit
- [**994**星][1y] [JS] [0xsobky/hackvault](https://github.com/0xsobky/hackvault) A container repository for my public web hacks!
- [**961**星][4m] [Py] [jekil/awesome-hacking](https://github.com/jekil/awesome-hacking) Awesome hacking is an awesome collection of hacking tools.
- [**944**星][7m] [0x4d31/awesome-threat-detection](https://github.com/0x4d31/awesome-threat-detection) A curated list of awesome threat detection and hunting resources
- [**940**星][6m] [sundowndev/hacker-roadmap](https://github.com/sundowndev/hacker-roadmap) 
- [**908**星][9m] [wtsxdev/penetration-testing](https://github.com/wtsxdev/penetration-testing) List of awesome penetration testing resources, tools and other shiny things
- [**905**星][6m] [PowerShell] [api0cradle/ultimateapplockerbypasslist](https://github.com/api0cradle/ultimateapplockerbypasslist) The goal of this repository is to document the most common techniques to bypass AppLocker.
- [**899**星][6m] [cn0xroot/rfsec-toolkit](https://github.com/cn0xroot/rfsec-toolkit) RFSec-ToolKit is a collection of Radio Frequency Communication Protocol Hacktools.无线通信协议相关的工具集，可借助SDR硬件+相关工具对无线通信进行研究。Collect with ♥ by HackSmith
- [**894**星][24d] [tom0li/collection-document](https://github.com/tom0li/collection-document) Collection of quality safety articles
- [**862**星][5m] [Shell] [dominicbreuker/stego-toolkit](https://github.com/dominicbreuker/stego-toolkit) Collection of steganography tools - helps with CTF challenges
- [**848**星][13d] [explife0011/awesome-windows-kernel-security-development](https://github.com/explife0011/awesome-windows-kernel-security-development) windows kernel security development
- [**803**星][4m] [Shell] [danielmiessler/robotsdisallowed](https://github.com/danielmiessler/robotsdisallowed) A curated list of the most common and most interesting robots.txt disallowed directories.
- [**762**星][10m] [v2-dev/awesome-social-engineering](https://github.com/v2-dev/awesome-social-engineering) awesome-social-engineering：社会工程学资源集合
- [**761**星][1m] [daviddias/awesome-hacking-locations](https://github.com/daviddias/awesome-hacking-locations) 
- [**723**星][1y] [Py] [averagesecurityguy/scripts](https://github.com/averagesecurityguy/scripts) Scripts I use during pentest engagements.
- [**709**星][1y] [snifer/security-cheatsheets](https://github.com/snifer/security-cheatsheets) A collection of cheatsheets for various infosec tools and topics.
- [**696**星][4m] [bit4woo/python_sec](https://github.com/bit4woo/python_sec) python安全和代码审计相关资料收集 resource collection of python security and code review
- [**685**星][2m] [C#] [harleyqu1nn/aggressorscripts](https://github.com/harleyqu1nn/aggressorscripts) Collection of Aggressor scripts for Cobalt Strike 3.0+ pulled from multiple sources
- [**681**星][1m] [andrewjkerr/security-cheatsheets](https://github.com/andrewjkerr/security-cheatsheets) 
- [**667**星][8m] [XSLT] [adon90/pentest_compilation](https://github.com/adon90/pentest_compilation) Compilation of commands, tips and scripts that helped me throughout Vulnhub, Hackthebox, OSCP and real scenarios
    - 重复区段: [工具/OSCP](#13d067316e9894cc40fe55178ee40f24) |
- [**649**星][1y] [dsasmblr/hacking-online-games](https://github.com/dsasmblr/hacking-online-games) A curated list of tutorials/resources for hacking online games.
- [**628**星][9m] [webbreacher/offensiveinterview](https://github.com/webbreacher/offensiveinterview) Interview questions to screen offensive (red team/pentest) candidates
- [**627**星][2m] [redhuntlabs/awesome-asset-discovery](https://github.com/redhuntlabs/awesome-asset-discovery) List of Awesome Asset Discovery Resources
- [**619**星][3m] [3gstudent/pentest-and-development-tips](https://github.com/3gstudent/pentest-and-development-tips) A collection of pentest and development tips
- [**603**星][2m] [Shell] [ashishb/osx-and-ios-security-awesome](https://github.com/ashishb/osx-and-ios-security-awesome) OSX and iOS related security tools
- [**589**星][1y] [jiangsir404/audit-learning](https://github.com/jiangsir404/audit-learning) 记录自己对《代码审计》的理解和总结，对危险函数的深入分析以及在p牛的博客和代码审计圈的收获
- [**587**星][11m] [pandazheng/ioshackstudy](https://github.com/pandazheng/ioshackstudy) IOS安全学习资料汇总
- [**575**星][16d] [Py] [hslatman/awesome-industrial-control-system-security](https://github.com/hslatman/awesome-industrial-control-system-security) awesome-industrial-control-system-security：工控系统安全资源列表
- [**552**星][8m] [guardrailsio/awesome-python-security](https://github.com/guardrailsio/awesome-python-security) Awesome Python Security resources
- [**452**星][8m] [gradiuscypher/infosec_getting_started](https://github.com/gradiuscypher/infosec_getting_started) A collection of resources/documentation/links/etc to help people learn about Infosec and break into the field.
- [**444**星][7m] [jnusimba/miscsecnotes](https://github.com/jnusimba/miscsecnotes) some learning notes about Web/Cloud/Docker Security、 Penetration Test、 Security Building
- [**426**星][1y] [meitar/awesome-lockpicking](https://github.com/meitar/awesome-lockpicking) awesome-lockpicking：有关锁、保险箱、钥匙的指南、工具及其他资源的列表
- [**404**星][19d] [meitar/awesome-cybersecurity-blueteam](https://github.com/meitar/awesome-cybersecurity-blueteam) 
- [**398**星][21d] [Py] [bl4de/security-tools](https://github.com/bl4de/security-tools) Collection of small security tools created mostly in Python. CTFs, pentests and so on
- [**394**星][3m] [re4lity/hacking-with-golang](https://github.com/re4lity/hacking-with-golang) Golang安全资源合集
- [**390**星][6m] [HTML] [gexos/hacking-tools-repository](https://github.com/gexos/hacking-tools-repository) A list of security/hacking tools that have been collected from the internet. Suggestions are welcomed.
- [**384**星][1m] [husnainfareed/awesome-ethical-hacking-resources](https://github.com/husnainfareed/Awesome-Ethical-Hacking-Resources) 
- [**380**星][1m] [dsopas/assessment-mindset](https://github.com/dsopas/assessment-mindset) 安全相关的思维导图, 可用于pentesting, bug bounty, red-teamassessments
- [**350**星][16d] [fkromer/awesome-ros2](https://github.com/fkromer/awesome-ros2) The Robot Operating System Version 2.0 is awesome!
- [**331**星][1m] [softwareunderground/awesome-open-geoscience](https://github.com/softwareunderground/awesome-open-geoscience) Curated from repositories that make our lives as geoscientists, hackers and data wranglers easier or just more awesome
- [**328**星][27d] [PowerShell] [mgeeky/penetration-testing-tools](https://github.com/mgeeky/penetration-testing-tools) A collection of my Penetration Testing scripts, tools, cheatsheets collected over years, used during real-world assignments or collected from various good quality sources.
- [**308**星][16d] [cryptax/confsec](https://github.com/cryptax/confsec) Security, hacking conferences (list)
- [**303**星][4m] [trimstray/technical-whitepapers](https://github.com/trimstray/technical-whitepapers) 收集：IT白皮书、PPT、PDF、Hacking、Web应用程序安全性、数据库、逆向等
- [**299**星][1m] [HTML] [eugenekolo/sec-tools](https://github.com/eugenekolo/sec-tools) A set of security related tools
- [**289**星][1m] [hongrisec/web-security-attack](https://github.com/hongrisec/web-security-attack) Web安全相关内容
- [**265**星][1y] [JS] [ropnop/serverless_toolkit](https://github.com/ropnop/serverless_toolkit) A collection of useful Serverless functions I use when pentesting
- [**260**星][3m] [mattnotmax/cyber-chef-recipes](https://github.com/mattnotmax/cyber-chef-recipes) A list of cyber-chef recipes
- [**243**星][4m] [zhaoweiho/web-sec-interview](https://github.com/zhaoweiho/web-sec-interview) Information Security (Web Security/Penetration Testing Direction) Interview Questions/Solutions 信息安全(Web安全/渗透测试方向)面试题/解题思路
- [**232**星][21d] [pe3zx/my-infosec-awesome](https://github.com/pe3zx/my-infosec-awesome) My curated list of awesome links, resources and tools on infosec related topics
- [**224**星][25d] [euphrat1ca/security_w1k1](https://github.com/euphrat1ca/security_w1k1) collect
- [**211**星][5m] [guardrailsio/awesome-dotnet-security](https://github.com/guardrailsio/awesome-dotnet-security) Awesome .NET Security Resources
- [**207**星][9m] [jeansgit/redteam](https://github.com/jeansgit/redteam) RedTeam资料收集整理
- [**205**星][9m] [puresec/awesome-serverless-security](https://github.com/puresec/awesome-serverless-security) A curated list of awesome serverless security resources such as (e)books, articles, whitepapers, blogs and research papers.
- [**201**星][1y] [faizann24/resources-for-learning-hacking](https://github.com/faizann24/resources-for-learning-hacking) All the resources I could find for learning Ethical Hacking and penetration testing.
- [**201**星][1y] [sigp/solidity-security-blog](https://github.com/sigp/solidity-security-blog) Comprehensive list of known attack vectors and common anti-patterns


### <a id="664ff1dbdafefd7d856c88112948a65b"></a>混合型收集


- [**24225**星][15d] [trimstray/the-book-of-secret-knowledge](https://github.com/trimstray/the-book-of-secret-knowledge) A collection of inspiring lists, manuals, cheatsheets, blogs, hacks, one-liners, cli/web tools and more.
- [**10176**星][17d] [enaqx/awesome-pentest](https://github.com/enaqx/awesome-pentest) 渗透测试资源/工具集
- [**5384**星][8m] [carpedm20/awesome-hacking](https://github.com/carpedm20/awesome-hacking) Hacking教程、工具和资源
- [**4994**星][1m] [sbilly/awesome-security](https://github.com/sbilly/awesome-security) 与安全相关的软件、库、文档、书籍、资源和工具等收集
- [**3116**星][20d] [Rich Text Format] [the-art-of-hacking/h4cker](https://github.com/The-Art-of-Hacking/h4cker) 资源收集：hacking、渗透、数字取证、事件响应、漏洞研究、漏洞开发、逆向
- [**1710**星][20d] [olivierlaflamme/cheatsheet-god](https://github.com/olivierlaflamme/cheatsheet-god) Penetration Testing Biggest Reference Bank - OSCP / PTP & PTX Cheatsheet
    - 重复区段: [工具/OSCP](#13d067316e9894cc40fe55178ee40f24) |
- [**573**星][5m] [d30sa1/rootkits-list-download](https://github.com/d30sa1/rootkits-list-download) Rootkit收集
- [**551**星][17d] [Perl] [bollwarm/sectoolset](https://github.com/bollwarm/sectoolset) 安全项目工具集合


### <a id="67acc04b20c99f87ee625b073330d8c2"></a>无工具类收集


- [**33516**星][1y] [Py] [minimaxir/big-list-of-naughty-strings](https://github.com/minimaxir/big-list-of-naughty-strings) “淘气”的字符串列表，当作为用户输入时很容易引发问题
- [**8929**星][2m] [vitalysim/awesome-hacking-resources](https://github.com/vitalysim/awesome-hacking-resources) A collection of hacking / penetration testing resources to make you better!
- [**2935**星][1m] [blacckhathaceekr/pentesting-bible](https://github.com/blacckhathaceekr/pentesting-bible) links reaches 10000 links & 10000 pdf files .Learn Ethical Hacking and penetration testing .hundreds of ethical hacking & penetration testing & red team & cyber security & computer science resources.
- [**2660**星][1m] [secwiki/sec-chart](https://github.com/secwiki/sec-chart) 安全思维导图集合
- [**2580**星][1y] [HTML] [chybeta/web-security-learning](https://github.com/chybeta/web-security-learning) Web-Security-Learning
- [**2427**星][1y] [onlurking/awesome-infosec](https://github.com/onlurking/awesome-infosec) A curated list of awesome infosec courses and training resources.
- [**2306**星][10m] [hack-with-github/free-security-ebooks](https://github.com/hack-with-github/free-security-ebooks) Free Security and Hacking eBooks
- [**2054**星][2m] [yeahhub/hacking-security-ebooks](https://github.com/yeahhub/hacking-security-ebooks) Top 100 Hacking & Security E-Books (Free Download)
- [**1917**星][3m] [Py] [nixawk/pentest-wiki](https://github.com/nixawk/pentest-wiki) PENTEST-WIKI is a free online security knowledge library for pentesters / researchers. If you have a good idea, please share it with others.
- [**1434**星][4m] [hmaverickadams/beginner-network-pentesting](https://github.com/hmaverickadams/beginner-network-pentesting) Notes for Beginner Network Pentesting Course


### <a id="24707dd322098f73c7e450d6b1eddf12"></a>收集类的收集


- [**32197**星][2m] [hack-with-github/awesome-hacking](https://github.com/hack-with-github/awesome-hacking) A collection of various awesome lists for hackers, pentesters and security researchers


### <a id="9101434a896f20263d09c25ace65f398"></a>教育资源&&课程&&教程&&书籍


- [**10844**星][1m] [CSS] [hacker0x01/hacker101](https://github.com/hacker0x01/hacker101) Hacker101
- [**3897**星][3m] [PHP] [paragonie/awesome-appsec](https://github.com/paragonie/awesome-appsec) A curated list of resources for learning about application security


### <a id="8088e46fc533286d88b945f1d472bf57"></a>笔记&&Tips&&Tricks&&Talk&&Conference


#### <a id="f57ccaab4279b60c17a03f90d96b815c"></a>未分类


- [**2786**星][29d] [paulsec/awesome-sec-talks](https://github.com/paulsec/awesome-sec-talks) A collected list of awesome security talks
- [**671**星][2m] [uknowsec/active-directory-pentest-notes](https://github.com/uknowsec/active-directory-pentest-notes) 个人域渗透学习笔记
- [**540**星][9m] [PowerShell] [threatexpress/red-team-scripts](https://github.com/threatexpress/red-team-scripts) A collection of Red Team focused tools, scripts, and notes


#### <a id="0476f6b97e87176da0a0d7328f8747e7"></a>blog


- [**1231**星][5m] [chalker/notes](https://github.com/chalker/notes) Some public notes






***


## <a id="06fccfcc4faa7da54d572c10ef29b42e"></a>移动&&Mobile


### <a id="4a64f5e8fdbd531a8c95d94b28c6c2c1"></a>未分类-Mobile


- [**4885**星][14d] [HTML] [owasp/owasp-mstg](https://github.com/owasp/owasp-mstg) 关于移动App安全开发、测试和逆向的相近手册
- [**4785**星][13d] [JS] [mobsf/mobile-security-framework-mobsf](https://github.com/MobSF/Mobile-Security-Framework-MobSF) Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis.
- [**1940**星][20d] [Py] [sensepost/objection](https://github.com/sensepost/objection) objection： runtimemobile exploration
- [**1839**星][6m] [Java] [fuzion24/justtrustme](https://github.com/fuzion24/justtrustme) An xposed module that disables SSL certificate checking for the purposes of auditing an app with cert pinning
- [**604**星][6m] [JS] [vincentcox/stacoan](https://github.com/vincentcox/stacoan) StaCoAn is a crossplatform tool which aids developers, bugbounty hunters and ethical hackers performing static code analysis on mobile applications.
    - 重复区段: [工具/审计&&安全审计&&代码审计/未分类-Audit](#6a5e7dd060e57d9fdb3fed8635d61bc7) |
- [**529**星][17d] [Shell] [owasp/owasp-masvs](https://github.com/owasp/owasp-masvs) OWASP 移动App安全标准
- [**370**星][1y] [CSS] [nowsecure/secure-mobile-development](https://github.com/nowsecure/secure-mobile-development) A Collection of Secure Mobile Development Best Practices
- [**320**星][5m] [Java] [datatheorem/trustkit-android](https://github.com/datatheorem/trustkit-android) Easy SSL pinning validation and reporting for Android.


### <a id="fe88ee8c0df10870b44c2dedcd86d3d3"></a>Android


- [**4221**星][23d] [Shell] [ashishb/android-security-awesome](https://github.com/ashishb/android-security-awesome) A collection of android security related resources
- [**2294**星][1y] [Java] [csploit/android](https://github.com/csploit/android) cSploit - The most complete and advanced IT security professional toolkit on Android.
- [**2089**星][8m] [Py] [linkedin/qark](https://github.com/linkedin/qark) 查找Android App的漏洞, 支持源码或APK文件
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞扫描&&挖掘&&发现/漏洞扫描/未分类](#0ed7e90d216a8a5be1dafebaf9eaeb5d) |
- [**2033**星][9m] [jermic/android-crack-tool](https://github.com/jermic/android-crack-tool) 
- [**1966**星][7m] [Py] [fsecurelabs/drozer](https://github.com/FSecureLABS/drozer) The Leading Security Assessment Framework for Android.
- [**1414**星][10m] [Java] [aslody/legend](https://github.com/aslody/legend) (Android)无需Root即可Hook Java方法的框架, 支持Dalvik和Art环境
- [**1393**星][13d] [Java] [chrisk44/hijacker](https://github.com/chrisk44/hijacker) Aircrack, Airodump, Aireplay, MDK3 and Reaver GUI Application for Android
- [**1202**星][26d] [Java] [find-sec-bugs/find-sec-bugs](https://github.com/find-sec-bugs/find-sec-bugs) The SpotBugs plugin for security audits of Java web applications and Android applications. (Also work with Kotlin, Groovy and Scala projects)
- [**1199**星][2m] [Java] [javiersantos/piracychecker](https://github.com/javiersantos/piracychecker) An Android library that prevents your app from being pirated / cracked using Google Play Licensing (LVL), APK signature protection and more. API 14+ required.
- [**781**星][2m] [sh4hin/androl4b](https://github.com/sh4hin/androl4b) 用于评估Android应用程序，逆向工程和恶意软件分析的虚拟机
    - 重复区段: [工具/环境配置&&分析系统/未分类-Env](#f5a7a43f964b2c50825f3e2fee5078c8) |
- [**664**星][17d] [doridori/android-security-reference](https://github.com/doridori/android-security-reference) A W.I.P Android Security Ref
- [**511**星][3m] [JS] [wooyundota/droidsslunpinning](https://github.com/wooyundota/droidsslunpinning) Android certificate pinning disable tools
- [**462**星][3m] [JS] [lyxhh/lxhtoolhttpdecrypt](https://github.com/lyxhh/lxhtoolhttpdecrypt) Simple Android/iOS protocol analysis and utilization tool
- [**383**星][1y] [Py] [thehackingsage/hacktronian](https://github.com/thehackingsage/hacktronian) All in One Hacking Tool for Linux & Android
- [**372**星][3m] [Java] [megatronking/netbare](https://github.com/megatronking/netbare) Net packets capture & injection library designed for Android
- [**358**星][4m] [C] [the-cracker-technology/andrax-mobile-pentest](https://github.com/the-cracker-technology/andrax-mobile-pentest) ANDRAX The first and unique Penetration Testing platform for Android smartphones
- [**348**星][4m] [Makefile] [crifan/android_app_security_crack](https://github.com/crifan/android_app_security_crack) 安卓应用的安全和破解
- [**341**星][4m] [b3nac/android-reports-and-resources](https://github.com/b3nac/android-reports-and-resources) A big list of Android Hackerone disclosed reports and other resources.
- [**326**星][14d] [TypeScript] [shroudedcode/apk-mitm](https://github.com/shroudedcode/apk-mitm) 
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/未分类-Network](#99398a5a8aaf99228829dadff48fb6a7) |[工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**248**星][9m] [C] [chef-koch/android-vulnerabilities-overview](https://github.com/chef-koch/android-vulnerabilities-overview) An small overview of known Android vulnerabilities
- [**233**星][1y] [Ruby] [hahwul/droid-hunter](https://github.com/hahwul/droid-hunter) Android application vulnerability analysis and Android pentest tool


### <a id="dbde77352aac39ee710d3150a921bcad"></a>iOS&&MacOS&&iPhone&&iPad&&iWatch


- [**5299**星][5m] [C] [pwn20wndstuff/undecimus](https://github.com/pwn20wndstuff/undecimus) unc0ver jailbreak for iOS 11.0 - 12.4
- [**5097**星][2m] [Py] [axi0mx/ipwndfu](https://github.com/axi0mx/ipwndfu) open-source jailbreaking tool for many iOS devices
- [**4143**星][7m] [Objective-C] [alonemonkey/monkeydev](https://github.com/alonemonkey/monkeydev) CaptainHook Tweak、Logos Tweak and Command-line Tool、Patch iOS Apps, Without Jailbreak.
- [**3411**星][6m] [icodesign/potatso](https://github.com/icodesign/Potatso) Potatso is an iOS client that implements different proxies with the leverage of NetworkExtension framework in iOS 10+.
- [**3072**星][9m] [JS] [jipegit/osxauditor](https://github.com/jipegit/osxauditor) OS X Auditor is a free Mac OS X computer forensics tool
- [**1685**星][5m] [Py] [yelp/osxcollector](https://github.com/yelp/osxcollector) A forensic evidence collection & analysis toolkit for OS X
- [**1366**星][6m] [Objective-C] [nabla-c0d3/ssl-kill-switch2](https://github.com/nabla-c0d3/ssl-kill-switch2) Blackbox tool to disable SSL certificate validation - including certificate pinning - within iOS and OS X Apps
- [**1259**星][5m] [JS] [feross/spoof](https://github.com/feross/spoof) Easily spoof your MAC address in macOS, Windows, & Linux!
- [**1218**星][5m] [Vue] [chaitin/passionfruit](https://github.com/chaitin/passionfruit) iOSapp 黑盒评估工具。功能丰富，自带基于web的 GUI
- [**1214**星][19d] [C] [datatheorem/trustkit](https://github.com/datatheorem/trustkit) Easy SSL pinning validation and reporting for iOS, macOS, tvOS and watchOS.
- [**1174**星][29d] [YARA] [horsicq/detect-it-easy](https://github.com/horsicq/detect-it-easy) Program for determining types of files for Windows, Linux and MacOS.
- [**1121**星][4m] [JS] [alonemonkey/frida-ios-dump](https://github.com/alonemonkey/frida-ios-dump) pull decrypted ipa from jailbreak device
- [**1094**星][1y] [Objective-C] [neoneggplant/eggshell](https://github.com/neoneggplant/eggshell) iOS/macOS/Linux Remote Administration Tool
- [**969**星][1y] [Py] [mwrlabs/needle](https://github.com/FSecureLABS/needle) The iOS Security Testing Framework
- [**898**星][2m] [Objective-C] [ptoomey3/keychain-dumper](https://github.com/ptoomey3/keychain-dumper) A tool to check which keychain items are available to an attacker once an iOS device has been jailbroken
- [**577**星][2m] [siguza/ios-resources](https://github.com/siguza/ios-resources) Useful resources for iOS hacking
- [**475**星][1y] [Swift] [icepa/icepa](https://github.com/icepa/icepa) iOS system-wide VPN based Tor client
- [**385**星][3m] [ansjdnakjdnajkd/ios](https://github.com/ansjdnakjdnajkd/ios) Most usable tools for iOS penetration testing
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |
- [**321**星][30d] [Objective-C] [auth0/simplekeychain](https://github.com/auth0/simplekeychain) A Keychain helper for iOS to make it very simple to store/obtain values from iOS Keychain
- [**213**星][10m] [AppleScript] [lifepillar/csvkeychain](https://github.com/lifepillar/csvkeychain) Import/export between Apple Keychain.app and plain CSV file.
- [**204**星][7m] [C] [owasp/igoat](https://github.com/owasp/igoat) OWASP iGoat - A Learning Tool for iOS App Pentesting and Security by Swaroop Yermalkar




***


## <a id="c7f35432806520669b15a28161a4d26a"></a>CTF&&HTB


### <a id="c0fea206256a42e41fd5092cecf54d3e"></a>未分类-CTF&&HTB


- [**952**星][2m] [ctfs/resources](https://github.com/ctfs/resources) A general collection of information, tools, and tips regarding CTFs and similar security competitions
- [**744**星][1m] [Py] [ashutosh1206/crypton](https://github.com/ashutosh1206/crypton) Library consisting of explanation and implementation of all the existing attacks on various Encryption Systems, Digital Signatures, Authentication methods along with example challenges from CTFs
- [**634**星][8m] [cryptogenic/exploit-writeups](https://github.com/cryptogenic/exploit-writeups) A collection where my current and future writeups for exploits/CTF will go
- [**474**星][5m] [PHP] [wonderkun/ctf_web](https://github.com/wonderkun/ctf_web) a project aim to collect CTF web practices .
- [**472**星][3m] [PHP] [susers/writeups](https://github.com/susers/writeups) 国内各大CTF赛题及writeup整理
- [**450**星][8m] [Py] [christhecoolhut/zeratool](https://github.com/christhecoolhut/zeratool) Automatic Exploit Generation (AEG) and remote flag capture for exploitable CTF problems
- [**410**星][3m] [ctftraining/ctftraining](https://github.com/ctftraining/ctftraining) CTF Training 经典赛题复现环境
- [**307**星][5m] [C] [sixstars/ctf](https://github.com/sixstars/ctf) A writeup summary for CTF competitions, problems.
- [**294**星][28d] [HTML] [balsn/ctf_writeup](https://github.com/balsn/ctf_writeup) CTF writeups from Balsn
- [**290**星][9m] [HTML] [s1gh/ctf-literature](https://github.com/s1gh/ctf-literature) Collection of free books, papers and articles related to CTF challenges.
- [**283**星][10m] [Shell] [ctf-wiki/ctf-tools](https://github.com/ctf-wiki/ctf-tools) CTF 工具集合
- [**260**星][5m] [CSS] [l4wio/ctf-challenges-by-me](https://github.com/l4wio/ctf-challenges-by-me) Pwnable|Web Security|Cryptography CTF-style challenges
- [**253**星][6m] [Shell] [lieanu/libcsearcher](https://github.com/lieanu/libcsearcher) glibc offset search for ctf.
- [**233**星][8m] [harmoc/ctftools](https://github.com/harmoc/ctftools) Personal CTF Toolkit
- [**209**星][1y] [Py] [3summer/ctf-rsa-tool](https://github.com/3summer/CTF-RSA-tool) a little tool help CTFer solve RSA problem


### <a id="30c4df38bcd1abaaaac13ffda7d206c6"></a>收集


- [**3857**星][1m] [JS] [apsdehal/awesome-ctf](https://github.com/apsdehal/awesome-ctf) A curated list of CTF frameworks, libraries, resources and softwares
- [**3857**星][1m] [JS] [apsdehal/awesome-ctf](https://github.com/apsdehal/awesome-ctf) A curated list of CTF frameworks, libraries, resources and softwares
- [**1709**星][1m] [PHP] [orangetw/my-ctf-web-challenges](https://github.com/orangetw/my-ctf-web-challenges) Collection of CTF Web challenges I made
- [**945**星][19d] [C] [bt3gl/pentesting-toolkit](https://github.com/bt3gl/Pentesting-Toolkit) Tools for pentesting, CTFs & wargames.
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |
- [**358**星][4m] [xtiankisutsa/awesome-mobile-ctf](https://github.com/xtiankisutsa/awesome-mobile-ctf) This is a curated list of mobile based CTFs, write-ups and vulnerable apps. Most of them are android based due to the popularity of the platform.
    - 重复区段: [工具/靶机&&漏洞环境&&漏洞App/收集](#383ad9174d3f7399660d36cd6e0b2c00) |


### <a id="0d871dfb0d2544d6952c04f69a763059"></a>HTB


- [**642**星][28d] [hackplayers/hackthebox-writeups](https://github.com/hackplayers/hackthebox-writeups) Writeups for HacktheBox 'boot2root' machines


### <a id="e64cedb2d91d06b3eeac5ea414e12b27"></a>CTF


#### <a id="e8853f1153694b24db203d960e394827"></a>未分类-CTF


- [**6102**星][1y] [Hack] [facebook/fbctf](https://github.com/facebook/fbctf) Platform to host Capture the Flag competitions
- [**5861**星][14d] [Py] [gallopsled/pwntools](https://github.com/gallopsled/pwntools) CTF framework and exploit development library
- [**4317**星][1m] [Shell] [zardus/ctf-tools](https://github.com/zardus/ctf-tools) Some setup scripts for security research tools.
- [**2756**星][19d] [HTML] [ctf-wiki/ctf-wiki](https://github.com/ctf-wiki/ctf-wiki) CTF Wiki Online. Come and join us, we need you!
- [**2295**星][19d] [Py] [ctfd/ctfd](https://github.com/CTFd/CTFd) CTFs as you need them
- [**1531**星][1m] [C] [firmianay/ctf-all-in-one](https://github.com/firmianay/ctf-all-in-one) CTF竞赛入门指南
- [**1343**星][4m] [Go] [google/google-ctf](https://github.com/google/google-ctf) Google CTF
- [**1340**星][3m] [C] [taviso/ctftool](https://github.com/taviso/ctftool) Interactive CTF Exploration Tool
- [**1248**星][11m] [Py] [unapibageek/ctfr](https://github.com/unapibageek/ctfr) Abusing Certificate Transparency logs for getting HTTPS websites subdomains.
- [**1244**星][2m] [Py] [ganapati/rsactftool](https://github.com/ganapati/rsactftool) RSA攻击工具，主要用于CTF，从弱公钥和/或uncipher数据中回复私钥
- [**1132**星][16d] [Py] [p4-team/ctf](https://github.com/p4-team/ctf) Ctf solutions from p4 team
- [**1034**星][2m] [C] [trailofbits/ctf](https://github.com/trailofbits/ctf) CTF Field Guide
- [**1013**星][12m] [naetw/ctf-pwn-tips](https://github.com/naetw/ctf-pwn-tips) Here record some tips about pwn. Something is obsoleted and won't be updated. Sorry about that.
- [**845**星][1m] [Ruby] [w181496/web-ctf-cheatsheet](https://github.com/w181496/web-ctf-cheatsheet) Web CTF CheatSheet
- [**824**星][28d] [ignitetechnologies/privilege-escalation](https://github.com/ignitetechnologies/privilege-escalation) This cheasheet is aimed at the CTF Players and Beginners to help them understand the fundamentals of Privilege Escalation with examples.
- [**780**星][2m] [Py] [acmesec/ctfcracktools](https://github.com/Acmesec/CTFCrackTools) 中国国内首个CTF工具框架,旨在帮助CTFer快速攻克难关
- [**609**星][1m] [Shell] [diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration) Linux enumeration tool for pentesting and CTFs with verbosity levels
- [**423**星][6m] [HTML] [ctf-wiki/ctf-challenges](https://github.com/ctf-wiki/ctf-challenges) 
- [**397**星][2m] [Py] [j00ru/ctf-tasks](https://github.com/j00ru/ctf-tasks) An archive of low-level CTF challenges developed over the years
- [**381**星][14d] [Py] [moloch--/rootthebox](https://github.com/moloch--/rootthebox) A Game of Hackers (CTF Scoreboard & Game Manager)
- [**373**星][4m] [C] [hackgnar/ble_ctf](https://github.com/hackgnar/ble_ctf) A Bluetooth low energy capture the flag
- [**309**星][2m] [PHP] [nakiami/mellivora](https://github.com/nakiami/mellivora) Mellivora is a CTF engine written in PHP
- [**302**星][7m] [Py] [screetsec/brutesploit](https://github.com/screetsec/brutesploit) BruteSploit is a collection of method for automated Generate, Bruteforce and Manipulation wordlist with interactive shell. That can be used during a penetration test to enumerate and maybe can be used in CTF for manipulation,combine,transform and permutation some words or file text :p
- [**292**星][2m] [Py] [christhecoolhut/pinctf](https://github.com/christhecoolhut/pinctf) Using Intel's PIN tool to solve CTF problems
- [**275**星][11m] [Py] [hongrisec/ctf-training](https://github.com/hongrisec/ctf-training) 收集各大比赛的题目和Writeup
- [**252**星][5m] [Shell] [ctfhacker/epictreasure](https://github.com/ctfhacker/EpicTreasure) Batteries included CTF VM
- [**236**星][12m] [Java] [shiltemann/ctf-writeups-public](https://github.com/shiltemann/ctf-writeups-public) Writeups for infosec Capture the Flag events by team Galaxians
- [**218**星][2m] [HTML] [sectalks/sectalks](https://github.com/sectalks/sectalks) CTFs, solutions and presentations
- [**215**星][1m] [C] [david942j/ctf-writeups](https://github.com/david942j/ctf-writeups) Collection of scripts and writeups


#### <a id="0591f47788c6926c482f385b1d71efec"></a>Writeup


- [**1813**星][1y] [CSS] [ctfs/write-ups-2015](https://github.com/ctfs/write-ups-2015) Wiki-like CTF write-ups repository, maintained by the community. 2015
- [**1763**星][11m] [Py] [ctfs/write-ups-2017](https://github.com/ctfs/write-ups-2017) Wiki-like CTF write-ups repository, maintained by the community. 2017
- [**586**星][1m] [Py] [pwning/public-writeup](https://github.com/pwning/public-writeup) CTF write-ups by Plaid Parliament of Pwning
- [**489**星][8m] [manoelt/50m_ctf_writeup](https://github.com/manoelt/50m_ctf_writeup) $50 Million CTF from Hackerone - Writeup
- [**275**星][7m] [HTML] [bl4de/ctf](https://github.com/bl4de/ctf) CTF (Capture The Flag) writeups, code snippets, notes, scripts
- [**222**星][1y] [Shell] [ctfs/write-ups-2018](https://github.com/ctfs/write-ups-2018) Wiki-like CTF write-ups repository, maintained by the community. 2018


#### <a id="dc89088263fc944901fd7a58197a5f6d"></a>收集








***


## <a id="683b645c2162a1fce5f24ac2abfa1973"></a>漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing


### <a id="9d1ce4a40c660c0ce15aec6daf7f56dd"></a>未分类-Vul


- [**1968**星][12d] [Java] [jeremylong/dependencycheck](https://github.com/jeremylong/dependencycheck) OWASP dependency-check is a software composition analysis utility that detects publicly disclosed vulnerabilities in application dependencies.
- [**1797**星][27d] [TypeScript] [snyk/snyk](https://github.com/snyk/snyk) CLI and build-time tool to find & fix known vulnerabilities in open-source dependencies
- [**1619**星][18d] [roave/securityadvisories](https://github.com/roave/securityadvisories) ensures that your application doesn't have installed dependencies with known security vulnerabilities
- [**1535**星][1m] [Java] [spotbugs/spotbugs](https://github.com/spotbugs/spotbugs) SpotBugs is FindBugs' successor. A tool for static analysis to look for bugs in Java code.
- [**1284**星][12m] [Py] [xyntax/poc-t](https://github.com/xyntax/poc-t) 脚本调用框架，用于渗透测试中 采集|爬虫|爆破|批量PoC 等需要并发的任务
- [**1232**星][30d] [JS] [archerysec/archerysec](https://github.com/archerysec/archerysec) Centralize Vulnerability Assessment and Management for DevSecOps Team
- [**1079**星][19d] [Jupyter Notebook] [ibm/adversarial-robustness-toolbox](https://github.com/ibm/adversarial-robustness-toolbox) Python library for adversarial machine learning, attacks and defences for neural networks, logistic regression, decision trees, SVM, gradient boosted trees, Gaussian processes and more with multiple framework support
- [**1074**星][1y] [PowerShell] [rasta-mouse/sherlock](https://github.com/rasta-mouse/sherlock) PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities.
- [**1018**星][16d] [HTML] [defectdojo/django-defectdojo](https://github.com/defectdojo/django-defectdojo) DefectDojo is an open-source application vulnerability correlation and security orchestration tool.
- [**901**星][19d] [Py] [knownsec/pocsuite3](https://github.com/knownsec/pocsuite3) 远程漏洞测试与PoC开发框架
- [**814**星][6m] [numirias/security](https://github.com/numirias/security) Some of my security stuff and vulnerabilities. Nothing advanced. More to come.
- [**813**星][3m] [JS] [creditease-sec/insight](https://github.com/creditease-sec/insight) 洞察-宜信集应用系统资产管理、漏洞全生命周期管理、安全知识库管理三位一体的平台。
- [**806**星][1y] [Py] [leviathan-framework/leviathan](https://github.com/tearsecurity/leviathan) 多功能审计工具包，包括多种服务发现（FTP、SSH、Talnet、RDP、MYSQL）、爆破、远程命令执行、SQL注入扫描、指定漏洞利用，集成了Masscan、Ncrack、DSSS等工具。
- [**625**星][5m] [Py] [pyupio/safety](https://github.com/pyupio/safety) 检查所有已安装 Python 包, 查找已知的安全漏洞
- [**578**星][7m] [Java] [olacabs/jackhammer](https://github.com/olacabs/jackhammer) 安全漏洞评估和管理工具
- [**567**星][12d] [arkadiyt/bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) This repo contains hourly-updated data dumps of bug bounty platform scopes (like Hackerone/Bugcrowd/etc) that are eligible for reports
- [**541**星][1y] [Java] [mr5m1th/poc-collect](https://github.com/Mr5m1th/POC-Collect) 各种开源CMS 各种版本的漏洞以及EXP 该项目将不断更新
- [**540**星][10m] [PHP] [zhuifengshaonianhanlu/pikachu](https://github.com/zhuifengshaonianhanlu/pikachu) 一个好玩的Web安全-漏洞测试平台
- [**462**星][1m] [Java] [joychou93/java-sec-code](https://github.com/joychou93/java-sec-code) Java common vulnerabilities and security code.
- [**430**星][28d] [Py] [google/vulncode-db](https://github.com/google/vulncode-db)  a database for vulnerabilities and their corresponding source code if available
- [**428**星][4m] [Py] [crocs-muni/roca](https://github.com/crocs-muni/roca) 测试公共 RSA 密钥是否存在某些漏洞
- [**409**星][4m] [Java] [nccgroup/freddy](https://github.com/nccgroup/freddy) 自动识别 Java/.NET 应用程序中的反序列化漏洞
- [**395**星][17d] [Go] [cbeuw/cloak](https://github.com/cbeuw/cloak) A universal pluggable transport utilising TLS domain fronting to evade deep packet inspection and active probing from state-level adversaries
- [**379**星][10m] [skyblueeternal/thinkphp-rce-poc-collection](https://github.com/skyblueeternal/thinkphp-rce-poc-collection) thinkphp v5.x 远程代码执行漏洞-POC集合
- [**372**星][6m] [tidesec/tide](https://github.com/tidesec/tide) 目前实现了网络空间资产探测、指纹检索、漏洞检测、漏洞全生命周期管理、poc定向检测、暗链检测、挂马监测、敏感字检测、DNS监测、网站可用性监测、漏洞库管理、安全预警等等~
- [**361**星][12m] [hannob/vulns](https://github.com/hannob/vulns) Named vulnerabilities and their practical impact
- [**357**星][8m] [C] [vulnreproduction/linuxflaw](https://github.com/vulnreproduction/linuxflaw) This repo records all the vulnerabilities of linux software I have reproduced in my local workspace
- [**354**星][6m] [PHP] [fate0/prvd](https://github.com/fate0/prvd) PHP Runtime Vulnerability Detection
- [**351**星][6m] [Py] [orangetw/awesome-jenkins-rce-2019](https://github.com/orangetw/awesome-jenkins-rce-2019) There is no pre-auth RCE in Jenkins since May 2017, but this is the one!
- [**342**星][2m] [snyk/zip-slip-vulnerability](https://github.com/snyk/zip-slip-vulnerability) Zip Slip Vulnerability (Arbitrary file write through archive extraction)
- [**335**星][2m] [Java] [denimgroup/threadfix](https://github.com/denimgroup/threadfix) threadfix：软件漏洞汇总和管理系统，可帮助组织汇总漏洞数据，生成虚拟补丁，并与软件缺陷跟踪系统进行交互
- [**314**星][27d] [Java] [sap/vulnerability-assessment-tool](https://github.com/sap/vulnerability-assessment-tool) Analyses your Java and Python applications for open-source dependencies with known vulnerabilities, using both static analysis and testing to determine code context and usage for greater accuracy.
- [**312**星][11m] [cryin/paper](https://github.com/cryin/paper) Web Security Technology & Vulnerability Analysis Whitepapers
- [**299**星][16d] [Py] [ym2011/poc-exp](https://github.com/ym2011/poc-exp) Collecting and writing PoC or EXP for vulnerabilities on some application
- [**291**星][3m] [Py] [christhecoolhut/firmware_slap](https://github.com/christhecoolhut/firmware_slap) Discovering vulnerabilities in firmware through concolic analysis and function clustering.
- [**286**星][2m] [Py] [fplyth0ner-combie/bug-project-framework](https://github.com/fplyth0ner-combie/bug-project-framework) 漏洞利用框架模块分享仓库
- [**283**星][4m] [C#] [l0ss/grouper2](https://github.com/l0ss/grouper2) Find vulnerabilities in AD Group Policy
- [**283**星][7m] [C] [tangsilian/android-vuln](https://github.com/tangsilian/android-vuln) 安卓内核提权漏洞分析
- [**271**星][21d] [disclose/disclose](https://github.com/disclose/disclose) Driving safety, simplicity, and standardization in vulnerability disclosure.
- [**265**星][1y] [Py] [ucsb-seclab/bootstomp](https://github.com/ucsb-seclab/bootstomp) a bootloader vulnerability finder
- [**263**星][1y] [JS] [portswigger/hackability](https://github.com/portswigger/hackability) Probe a rendering engine for vulnerabilities and other features
- [**249**星][5m] [Py] [jcesarstef/dotdotslash](https://github.com/jcesarstef/dotdotslash) Python脚本, 查找目录遍历漏洞
- [**234**星][19d] [HTML] [edoverflow/bugbountyguide](https://github.com/edoverflow/bugbountyguide) Bug Bounty Guide is a launchpad for bug bounty programs and bug bounty hunters.
- [**220**星][2m] [Py] [ismailtasdelen/hackertarget](https://github.com/pyhackertarget/hackertarget) attack surface discovery and identification of security vulnerabilities
- [**211**星][2m] [C++] [atxsinn3r/vulncases](https://github.com/atxsinn3r/VulnCases) Oh it's just a bunch of vulns for references.
- [**207**星][6m] [Py] [jas502n/cnvd-c-2019-48814](https://github.com/jas502n/cnvd-c-2019-48814) WebLogic wls9-async反序列化远程命令执行漏洞
- [**202**星][6m] [Py] [greekn/rce-bug](https://github.com/greekn/rce-bug) 新漏洞感知项目 主要帮助大家 记录一些重大漏洞 漏洞方面的细节
- [**201**星][2m] [Ruby] [appfolio/gemsurance](https://github.com/appfolio/gemsurance) Gem vulnerability checker using rubysec/ruby-advisory-db
- [**201**星][7m] [C++] [j00ru/kfetch-toolkit](https://github.com/googleprojectzero/bochspwn) A Bochs-based instrumentation project designed to log kernel memory references, to identify "double fetches" and other OS vulnerabilities


### <a id="750f4c05b5ab059ce4405f450b56d720"></a>资源收集


- [**3444**星][8m] [C] [rpisec/mbe](https://github.com/rpisec/mbe) Course materials for Modern Binary Exploitation by RPISEC
- [**3429**星][4m] [PHP] [hanc00l/wooyun_public](https://github.com/hanc00l/wooyun_public) This repo is archived. Thanks for wooyun! 乌云公开漏洞、知识库爬虫和搜索 crawl and search for wooyun.org public bug(vulnerability) and drops
- [**2954**星][8m] [C] [secwiki/linux-kernel-exploits](https://github.com/secwiki/linux-kernel-exploits) linux-kernel-exploits Linux平台提权漏洞集合
- [**2600**星][1m] [xairy/linux-kernel-exploitation](https://github.com/xairy/linux-kernel-exploitation) Linux 内核 Fuzz 和漏洞利用的资源收集
- [**2072**星][14d] [PowerShell] [k8gege/k8tools](https://github.com/k8gege/k8tools) K8工具合集(内网渗透/提权工具/远程溢出/漏洞利用/扫描工具/密码破解/免杀工具/Exploit/APT/0day/Shellcode/Payload/priviledge/BypassUAC/OverFlow/WebShell/PenTest) Web GetShell Exploit(Struts2/Zimbra/Weblogic/Tomcat/Apache/Jboss/DotNetNuke/zabbix)
- [**1962**星][14d] [qazbnm456/awesome-cve-poc](https://github.com/qazbnm456/awesome-cve-poc) CVE PoC列表
- [**1882**星][1m] [HTML] [gtfobins/gtfobins.github.io](https://github.com/gtfobins/gtfobins.github.io) Curated list of Unix binaries that can be exploited to bypass system security restrictions
- [**1701**星][3m] [tunz/js-vuln-db](https://github.com/tunz/js-vuln-db) A collection of JavaScript engine CVEs with PoCs
- [**1196**星][1y] [felixgr/secure-ios-app-dev](https://github.com/felixgr/secure-ios-app-dev) secure-ios-app-dev：iOSApp 最常见漏洞收集
- [**1093**星][5m] [Py] [coffeehb/some-poc-or-exp](https://github.com/coffeehb/some-poc-or-exp) 各种漏洞poc、Exp的收集或编写
- [**1044**星][14d] [Py] [offensive-security/exploitdb-bin-sploits](https://github.com/offensive-security/exploitdb-bin-sploits) Exploit Database binary exploits located in the /sploits directory
- [**1020**星][1m] [C] [xairy/kernel-exploits](https://github.com/xairy/kernel-exploits) My proof-of-concept exploits for the Linux kernel
- [**1006**星][19d] [Py] [thekingofduck/fuzzdicts](https://github.com/thekingofduck/fuzzdicts) Web Pentesting Fuzz 字典,一个就够了。
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞扫描&&挖掘&&发现/Fuzzing/未分类-Fuzz](#1c2903ee7afb903ccfaa26f766924385) |
- [**977**星][10m] [Py] [xiphosresearch/exploits](https://github.com/xiphosresearch/exploits) Miscellaneous exploit code
- [**962**星][11m] [PHP] [secwiki/cms-hunter](https://github.com/secwiki/cms-hunter) CMS漏洞测试用例集合
- [**938**星][5m] [C] [dhavalkapil/heap-exploitation](https://github.com/dhavalkapil/heap-exploitation) This book on heap exploitation is a guide to understanding the internals of glibc's heap and various attacks possible on the heap structure.
- [**894**星][2m] [Py] [nullsecuritynet/tools](https://github.com/nullsecuritynet/tools) Security and Hacking Tools, Exploits, Proof of Concepts, Shellcodes, Scripts.
- [**672**星][1y] [C] [billy-ellis/exploit-challenges](https://github.com/billy-ellis/exploit-challenges) A collection of vulnerable ARM binaries for practicing exploit development
- [**609**星][7m] [yeyintminthuhtut/awesome-advanced-windows-exploitation-references](https://github.com/yeyintminthuhtut/Awesome-Advanced-Windows-Exploitation-References) List of Awesome Advanced Windows Exploitation References
- [**568**星][1y] [C] [externalist/exploit_playground](https://github.com/externalist/exploit_playground) Analysis of public exploits or my 1day exploits
- [**483**星][7m] [C] [jiayy/android_vuln_poc-exp](https://github.com/jiayy/android_vuln_poc-exp) This project contains pocs and exploits for vulneribilities I found (mostly)
- [**417**星][9m] [C] [hardenedlinux/linux-exploit-development-tutorial](https://github.com/hardenedlinux/linux-exploit-development-tutorial) a series tutorial for linux exploit development to newbie.
- [**329**星][1y] [snyk/vulnerabilitydb](https://github.com/snyk/vulnerabilitydb) Snyk's public vulnerability database
- [**268**星][10m] [Py] [secwiki/office-exploits](https://github.com/secwiki/office-exploits) office-exploits Office漏洞集合
- [**222**星][2m] [Py] [boy-hack/airbug](https://github.com/boy-hack/airbug) Airbug(空气洞)，收集漏洞poc用于安全产品
- [**222**星][1y] [C++] [wnagzihxa1n/browsersecurity](https://github.com/wnagzihxa1n/browsersecurity) 我在学习浏览器安全过程中整理的漏洞分析笔记与相关的学习资料


### <a id="605b1b2b6eeb5138cb4bc273a30b28a5"></a>漏洞开发


#### <a id="68a64028eb1f015025d6f5a6ee6f6810"></a>未分类-VulDev


- [**3705**星][10m] [Py] [longld/peda](https://github.com/longld/peda) Python Exploit Development Assistance for GDB
- [**2488**星][13d] [Py] [hugsy/gef](https://github.com/hugsy/gef) gdb增强工具，使用Python API，用于漏洞开发和逆向分析。
- [**2362**星][22d] [Py] [pwndbg/pwndbg](https://github.com/pwndbg/pwndbg) GDB插件，辅助漏洞开发和逆向
- [**465**星][10m] [Py] [wapiflapi/villoc](https://github.com/wapiflapi/villoc) Visualization of heap operations.


#### <a id="019cf10dbc7415d93a8d22ef163407ff"></a>ROP


- [**2101**星][27d] [Py] [jonathansalwan/ropgadget](https://github.com/jonathansalwan/ropgadget) This tool lets you search your gadgets on your binaries to facilitate your ROP exploitation. ROPgadget supports ELF, PE and Mach-O format on x86, x64, ARM, ARM64, PowerPC, SPARC and MIPS architectures.
- [**931**星][13d] [Py] [sashs/ropper](https://github.com/sashs/ropper) Display information about files in different file formats and find gadgets to build rop chains for different architectures (x86/x86_64, ARM/ARM64, MIPS, PowerPC, SPARC64). For disassembly ropper uses the awesome Capstone Framework.
- [**677**星][11m] [HTML] [zhengmin1989/myarticles](https://github.com/zhengmin1989/myarticles) 蒸米的文章（iOS冰与火之歌系列，一步一步学ROP系列，安卓动态调试七种武器系列等）




### <a id="c0bec2b143739028ff4ec439e077aa63"></a>漏洞扫描&&挖掘&&发现


#### <a id="5d02822c22d815c94c58cdaed79d6482"></a>未分类




#### <a id="661f41705ac69ad4392372bd4bd02f01"></a>漏洞扫描


##### <a id="0ed7e90d216a8a5be1dafebaf9eaeb5d"></a>未分类


- [**6953**星][24d] [Go] [future-architect/vuls](https://github.com/future-architect/vuls) 针对Linux/FreeBSD 编写的漏洞扫描器. Go 语言编写
- [**6516**星][16d] [Java] [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy) 在开发和测试Web App时自动发现安全漏洞
- [**5563**星][17d] [Ruby] [presidentbeef/brakeman](https://github.com/presidentbeef/brakeman) ROR程序的静态分析工具
- [**2904**星][21d] [Py] [andresriancho/w3af](https://github.com/andresriancho/w3af) Web App安全扫描器, 辅助开发者和渗透测试人员识别和利用Web App中的漏洞
    - 重复区段: [工具/扫描器&&安全扫描&&App扫描&&漏洞扫描/未分类-Scanner](#de63a029bda6a7e429af272f291bb769) |
- [**2440**星][6m] [Py] [ysrc/xunfeng](https://github.com/ysrc/xunfeng) 巡风是一款适用于企业内网的漏洞快速应急，巡航扫描系统。
- [**2403**星][28d] [Go] [knqyf263/trivy](https://github.com/aquasecurity/trivy) A Simple and Comprehensive Vulnerability Scanner for Containers, Suitable for CI
- [**2089**星][8m] [Py] [linkedin/qark](https://github.com/linkedin/qark) 查找Android App的漏洞, 支持源码或APK文件
    - 重复区段: [工具/移动&&Mobile/Android](#fe88ee8c0df10870b44c2dedcd86d3d3) |
- [**1873**星][1m] [Py] [j3ssie/osmedeus](https://github.com/j3ssie/osmedeus) Fully automated offensive security framework for reconnaissance and vulnerability scanning
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/信息收集&&侦查&&Recon&&InfoGather](#375a8baa06f24de1b67398c1ac74ed24) |
- [**1864**星][3m] [Py] [python-security/pyt](https://github.com/python-security/pyt) Python Web App 安全漏洞检测和静态分析工具
- [**1629**星][1y] [Py] [evyatarmeged/raccoon](https://github.com/evyatarmeged/raccoon) 高性能的侦查和漏洞扫描工具
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/信息收集&&侦查&&Recon&&InfoGather](#375a8baa06f24de1b67398c1ac74ed24) |
- [**1370**星][6m] [Py] [almandin/fuxploider](https://github.com/almandin/fuxploider) 文件上传漏洞扫描和利用工具
- [**1339**星][5m] [Py] [s0md3v/striker](https://github.com/s0md3v/Striker) Striker is an offensive information and vulnerability scanner.
- [**1023**星][7m] [Py] [lucifer1993/angelsword](https://github.com/lucifer1993/angelsword) Python3编写的CMS漏洞检测框架
- [**932**星][1y] [Java] [google/firing-range](https://github.com/google/firing-range)  a test bed for web application security scanners, providing synthetic, wide coverage for an array of vulnerabilities.
- [**913**星][4m] [threathuntingproject/threathunting](https://github.com/threathuntingproject/threathunting) An informational repo about hunting for adversaries in your IT environment.
- [**884**星][1m] [Go] [opensec-cn/kunpeng](https://github.com/opensec-cn/kunpeng) Golang编写的开源POC框架/库，以动态链接库的形式提供各种语言调用，通过此项目可快速开发漏洞检测类的系统。
- [**884**星][2m] [Py] [hasecuritysolutions/vulnwhisperer](https://github.com/HASecuritySolutions/VulnWhisperer) Create actionable data from your Vulnerability Scans
- [**852**星][3m] [Py] [boy-hack/w9scan](https://github.com/w-digital-scanner/w9scan) Plug-in type web vulnerability scanner
- [**840**星][3m] [Py] [lijiejie/bbscan](https://github.com/lijiejie/bbscan) A vulnerability scanner focus on scanning large number of targets in short time with a minimal set of rules.
- [**725**星][10m] [PowerShell] [l0ss/grouper](https://github.com/l0ss/grouper) A PowerShell script for helping to find vulnerable settings in AD Group Policy. (deprecated, use Grouper2 instead!)
- [**643**星][5m] [Perl] [moham3driahi/xattacker](https://github.com/moham3driahi/xattacker) X Attacker Tool ☣ Website Vulnerability Scanner & Auto Exploiter
- [**632**星][5m] [PHP] [mattiasgeniar/php-exploit-scripts](https://github.com/mattiasgeniar/php-exploit-scripts) A collection of PHP exploit scripts, found when investigating hacked servers. These are stored for educational purposes and to test fuzzers and vulnerability scanners. Feel free to contribute.
- [**602**星][10m] [Dockerfile] [aquasecurity/microscanner](https://github.com/aquasecurity/microscanner) Scan your container images for package vulnerabilities with Aqua Security
- [**539**星][5m] [JS] [seccubus/seccubus](https://github.com/seccubus/seccubus) Easy automated vulnerability scanning, reporting and analysis
- [**523**星][3m] [Py] [hatboy/struts2-scan](https://github.com/hatboy/struts2-scan) Struts2全漏洞扫描利用工具
- [**513**星][7m] [Py] [wyatu/perun](https://github.com/wyatu/perun) 主要适用于乙方安服、渗透测试人员和甲方RedTeam红队人员的网络资产漏洞扫描器/扫描框架
- [**491**星][14d] [C#] [k8gege/ladon](https://github.com/k8gege/ladon) Ladon一款用于大型网络渗透的多线程插件化综合扫描神器，含端口扫描、服务识别、网络资产、密码爆破、高危漏洞检测以及一键GetShell，支持批量A段/B段/C段以及跨网段扫描，支持URL、主机、域名列表扫描。5.5版本内置39个功能模块,通过多种协议以及方法快速获取目标网络存活主机IP、计算机名、工作组、共享资源、网卡地址、操作系统版本、网站、子域名、中间件、开放服务、路由器、数据库等信息，漏洞检测包含MS17010、Weblogic、ActiveMQ、Tomcat、Struts2等，密码爆破11种含数据库(Mysql、Oracle、MSSQL)、FTP、SSH(Linux主机)、VNC、Windows密码(IPC、WMI、SMB)、Weblogic后台、Rar压缩包密码等，Web指…
- [**488**星][2m] [Perl 6] [rezasp/joomscan](https://github.com/rezasp/joomscan) Perl语言编写的Joomla CMS漏洞扫描器
- [**452**星][1m] [C] [greenbone/openvas-scanner](https://github.com/greenbone/openvas) Open Vulnerability Assessment Scanner
- [**443**星][5m] [Py] [dr0op/weblogicscan](https://github.com/dr0op/weblogicscan) 增强版WeblogicScan、检测结果更精确、插件化、添加CVE-2019-2618，CVE-2019-2729检测，Python3支持
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


- [**351**星][1m] [C#] [security-code-scan/security-code-scan](https://github.com/security-code-scan/security-code-scan) Vulnerability Patterns Detector for C# and VB.NET
- [**343**星][2m] [Py] [chenjj/corscanner](https://github.com/chenjj/corscanner) Fast CORS misconfiguration vulnerabilities scanner
- [**319**星][3m] [Py] [vulmon/vulmap](https://github.com/vulmon/vulmap) Vulmap Online Local Vulnerability Scanners Project
- [**318**星][7m] [C#] [yalcinyolalan/wssat](https://github.com/yalcinyolalan/wssat) web service security scanning tool which provides a dynamic environment to add, update or delete vulnerabilities by just editing its configuration files
- [**297**星][4m] [Py] [zhaoweiho/securitymanageframwork](https://github.com/zhaoweiho/securitymanageframwork) Security Manage Framwork is a security management platform for enterprise intranet, which includes asset management, vulnerability management, account management, knowledge base management, security scanning automation function modules, and can be used for internal security management. This platform is designed to help Party A with fewer securit…
- [**287**星][1y] [Py] [flipkart-incubator/watchdog](https://github.com/flipkart-incubator/watchdog) 全面的安全扫描和漏洞管理工具
- [**285**星][2m] [Py] [utiso/dorkbot](https://github.com/utiso/dorkbot) dorkbot：扫描谷歌搜索返回的网页，查找网页漏洞
- [**279**星][7m] [Py] [vulscanteam/vulscan](https://github.com/vulscanteam/vulscan) vulscan 扫描系统：最新的poc&exp漏洞扫描，redis未授权、敏感文件、java反序列化、tomcat命令执行及各种未授权扫描等...
- [**276**星][5m] [Perl] [rezasp/vbscan](https://github.com/rezasp/vbscan) OWASP VBScan is a Black Box vBulletin Vulnerability Scanner
- [**257**星][2m] [JS] [stono/hawkeye](https://github.com/hawkeyesec/scanner-cli) A project security/vulnerability/risk scanning tool
- [**246**星][4m] [Shell] [peterpt/eternal_scanner](https://github.com/peterpt/eternal_scanner) eternal_scanner：永恒之蓝漏洞的网络扫描器
- [**226**星][1y] [Py] [leapsecurity/libssh-scanner](https://github.com/leapsecurity/libssh-scanner) Script to identify hosts vulnerable to CVE-2018-10933
- [**222**星][1y] [C++] [ucsb-seclab/dr_checker](https://github.com/ucsb-seclab/dr_checker) 用于Linux 内核驱动程序的漏洞检测工具
- [**218**星][7m] [Py] [skewwg/vulscan](https://github.com/skewwg/vulscan) 漏洞扫描：st2、tomcat、未授权访问等等
- [**211**星][6m] [Py] [kingkaki/weblogic-scan](https://github.com/kingkaki/weblogic-scan) weblogic 漏洞扫描工具
- [**208**星][20d] [Py] [sethsec/celerystalk](https://github.com/sethsec/celerystalk) An asynchronous enumeration & vulnerability scanner. Run all the tools on all the hosts.


##### <a id="d22e52bd9f47349df896ca85675d1e5c"></a>Web漏洞




##### <a id="060dd7b419423ee644794fccd67c22a8"></a>系统漏洞




##### <a id="67939d66cf2a9d9373cc0a877a8c72c2"></a>App漏洞




##### <a id="2076af46c7104737d06dbe29eb7c9d3a"></a>移动平台漏洞






#### <a id="382aaa11dea4036c5b6d4a8b06f8f786"></a>Fuzzing


##### <a id="1c2903ee7afb903ccfaa26f766924385"></a>未分类-Fuzz


- [**4649**星][29d] [C] [google/oss-fuzz](https://github.com/google/oss-fuzz) oss-fuzz：开源软件fuzzing
- [**3992**星][12d] [Py] [google/clusterfuzz](https://github.com/google/clusterfuzz) Scalable fuzzing infrastructure.
- [**3169**星][1m] [Go] [dvyukov/go-fuzz](https://github.com/dvyukov/go-fuzz) Randomized testing for Go
- [**1706**星][1y] [PowerShell] [fuzzysecurity/powershell-suite](https://github.com/fuzzysecurity/powershell-suite) My musings with PowerShell
- [**1335**星][2m] [C] [googleprojectzero/winafl](https://github.com/googleprojectzero/winafl) A fork of AFL for fuzzing Windows binaries
- [**1107**星][9m] [Py] [openrce/sulley](https://github.com/openrce/sulley) A pure-python fully automated and unattended fuzzing framework.
- [**1100**星][28d] [bo0om/fuzz.txt](https://github.com/bo0om/fuzz.txt) Potentially dangerous files
- [**1006**星][19d] [Py] [thekingofduck/fuzzdicts](https://github.com/thekingofduck/fuzzdicts) Web Pentesting Fuzz 字典,一个就够了。
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/资源收集](#750f4c05b5ab059ce4405f450b56d720) |
- [**990**星][28d] [C] [google/fuzzer-test-suite](https://github.com/google/fuzzer-test-suite) Set of tests for fuzzing engines
- [**859**星][18d] [Py] [swisskyrepo/ssrfmap](https://github.com/swisskyrepo/ssrfmap) Automatic SSRF fuzzer and exploitation tool
- [**850**星][25d] [Go] [sahilm/fuzzy](https://github.com/sahilm/fuzzy) Go library that provides fuzzy string matching optimized for filenames and code symbols in the style of Sublime Text, VSCode, IntelliJ IDEA et al.
- [**808**星][1m] [C] [rust-fuzz/afl.rs](https://github.com/rust-fuzz/afl.rs) 
- [**788**星][17d] [Swift] [googleprojectzero/fuzzilli](https://github.com/googleprojectzero/fuzzilli) A JavaScript Engine Fuzzer
- [**748**星][23d] [Py] [jtpereyda/boofuzz](https://github.com/jtpereyda/boofuzz) 网络协议Fuzzing框架, sulley的继任者
- [**736**星][7m] [HTML] [tennc/fuzzdb](https://github.com/tennc/fuzzdb) 一个fuzzdb扩展库
- [**689**星][14d] [Go] [ffuf/ffuf](https://github.com/ffuf/ffuf) Fast web fuzzer written in Go
- [**634**星][28d] [Go] [google/gofuzz](https://github.com/google/gofuzz) Fuzz testing for go.
- [**628**星][4m] [C] [kernelslacker/trinity](https://github.com/kernelslacker/trinity) Linux system call fuzzer
- [**608**星][14d] [C] [google/afl](https://github.com/google/afl) american fuzzy lop - a security-oriented fuzzer
- [**588**星][4m] [Py] [nongiach/arm_now](https://github.com/nongiach/arm_now) arm_now: 快速创建并运行不同CPU架构的虚拟机, 用于逆向分析或执行二进制文件. 基于QEMU
- [**569**星][19d] [Py] [1n3/blackwidow](https://github.com/1n3/blackwidow) A Python based web application scanner to gather OSINT and fuzz for OWASP vulnerabilities on a target website.
- [**541**星][8m] [Py] [shellphish/fuzzer](https://github.com/shellphish/fuzzer) fuzzer：Americanfuzzy lop 的 Python 版本接口
- [**516**星][2m] [C++] [angorafuzzer/angora](https://github.com/angorafuzzer/angora) Angora is a mutation-based fuzzer. The main goal of Angora is to increase branch coverage by solving path constraints without symbolic execution.
- [**500**星][12d] [Py] [mozillasecurity/funfuzz](https://github.com/mozillasecurity/funfuzz) A collection of fuzzers in a harness for testing the SpiderMonkey JavaScript engine.
- [**472**星][1y] [Py] [c0ny1/upload-fuzz-dic-builder](https://github.com/c0ny1/upload-fuzz-dic-builder) 上传漏洞fuzz字典生成脚本
- [**471**星][16d] [Py] [trailofbits/deepstate](https://github.com/trailofbits/deepstate) A unit test-like interface for fuzzing and symbolic execution
- [**453**星][1m] [Rust] [rust-fuzz/cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) cargo-fuzz：libFuzzer的wrapper
- [**424**星][2m] [Perl] [wireghoul/dotdotpwn](https://github.com/wireghoul/dotdotpwn) DotDotPwn - The Directory Traversal Fuzzer
- [**404**星][6m] [Ruby] [tidesec/fuzzscanner](https://github.com/tidesec/fuzzscanner) 一个主要用于信息搜集的工具集，主要是用于对网站子域名、开放端口、端口指纹、c段地址、敏感目录等信息进行批量搜集。
- [**398**星][4m] [C] [mykter/afl-training](https://github.com/mykter/afl-training) Exercises to learn how to fuzz with American Fuzzy Lop
- [**384**星][6m] [C] [coolervoid/0d1n](https://github.com/coolervoid/0d1n) Web security tool to make fuzzing at HTTP/S, Beta
- [**379**星][27d] [Haskell] [crytic/echidna](https://github.com/crytic/echidna) echidna: Ethereum fuzz testing framework
- [**378**星][3m] [Rust] [microsoft/lain](https://github.com/microsoft/lain) A fuzzer framework built in Rust
- [**370**星][1m] [TypeScript] [fuzzitdev/jsfuzz](https://github.com/fuzzitdev/jsfuzz) coverage guided fuzz testing for javascript
- [**364**星][1y] [C] [battelle/afl-unicorn](https://github.com/Battelle/afl-unicorn) afl-unicorn lets you fuzz any piece of binary that can be emulated by Unicorn Engine.
- [**357**星][3m] [C++] [googleprojectzero/brokentype](https://github.com/googleprojectzero/BrokenType) TrueType and OpenType font fuzzing toolset
- [**340**星][4m] [Java] [google/graphicsfuzz](https://github.com/google/graphicsfuzz) A testing framework for automatically finding and simplifying bugs in graphics shader compilers.
- [**340**星][1m] [C++] [sslab-gatech/qsym](https://github.com/sslab-gatech/qsym) QSYM: A Practical Concolic Execution Engine Tailored for Hybrid Fuzzing
- [**337**星][11m] [Py] [joxeankoret/nightmare](https://github.com/joxeankoret/nightmare) A distributed fuzzing testing suite with web administration
- [**311**星][3m] [lcatro/source-and-fuzzing](https://github.com/lcatro/Source-and-Fuzzing) 一些阅读源码和Fuzzing 的经验,涵盖黑盒与白盒测试..
- [**306**星][5m] [Py] [cisco-talos/mutiny-fuzzer](https://github.com/cisco-talos/mutiny-fuzzer) 
- [**304**星][9m] [Py] [cisco-sas/kitty](https://github.com/cisco-sas/kitty) Fuzzing framework written in python
- [**298**星][10m] [Py] [mseclab/pyjfuzz](https://github.com/mseclab/pyjfuzz) PyJFuzz - Python JSON Fuzzer
- [**292**星][5m] [Py] [mozillasecurity/dharma](https://github.com/mozillasecurity/dharma) Generation-based, context-free grammar fuzzer.
- [**283**星][10m] [C++] [gamozolabs/applepie](https://github.com/gamozolabs/applepie) A hypervisor for fuzzing built with WHVP and Bochs
- [**278**星][11m] [Py] [mrash/afl-cov](https://github.com/mrash/afl-cov) Produce code coverage results with gcov from afl-fuzz test cases
- [**278**星][10m] [C] [samhocevar/zzuf](https://github.com/samhocevar/zzuf) Application fuzzer
- [**277**星][1m] [Py] [tomato42/tlsfuzzer](https://github.com/tomato42/tlsfuzzer) SSL and TLS protocol test suite and fuzzer
- [**273**星][17d] [HTML] [mozillasecurity/fuzzdata](https://github.com/mozillasecurity/fuzzdata) Fuzzing resources for feeding various fuzzers with input.
- [**272**星][1y] [C++] [dekimir/ramfuzz](https://github.com/dekimir/ramfuzz) Combining Unit Tests, Fuzzing, and AI
- [**268**星][17d] [C] [aflsmart/aflsmart](https://github.com/aflsmart/aflsmart) Smart Greybox Fuzzing (
- [**263**星][8m] [Py] [mozillasecurity/peach](https://github.com/mozillasecurity/peach) Peach is a fuzzing framework which uses a DSL for building fuzzers and an observer based architecture to execute and monitor them.
- [**245**星][7m] [C++] [ucsb-seclab/difuze](https://github.com/ucsb-seclab/difuze) difuze: 针对 Linux 内核驱动的 Fuzzer
- [**239**星][5m] [C] [compsec-snu/razzer](https://github.com/compsec-snu/razzer) A Kernel fuzzer focusing on race bugs
- [**239**星][1y] [Py] [hgascon/pulsar](https://github.com/hgascon/pulsar) pulsar：具有自动学习、模拟协议功能的网络 fuzzer
- [**230**星][4m] [HTML] [rootup/bfuzz](https://github.com/rootup/bfuzz) Fuzzing Browsers
- [**222**星][3m] [C] [pagalaxylab/unifuzzer](https://github.com/PAGalaxyLab/uniFuzzer) A fuzzing tool for closed-source binaries based on Unicorn and LibFuzzer
- [**221**星][3m] [C] [dongdongshe/neuzz](https://github.com/dongdongshe/neuzz) neural network assisted fuzzer
- [**214**星][27d] [cpuu/awesome-fuzzing](https://github.com/cpuu/awesome-fuzzing) A curated list of awesome Fuzzing(or Fuzz Testing) for software security
- [**212**星][3m] [C++] [lifting-bits/grr](https://github.com/lifting-bits/grr) High-throughput fuzzer and emulator of DECREE binaries
- [**210**星][4m] [C] [hunter-ht-2018/ptfuzzer](https://github.com/hunter-ht-2018/ptfuzzer) Improving AFL by using Intel PT to collect branch information
- [**207**星][4m] [HTML] [ajinabraham/droid-application-fuzz-framework](https://github.com/ajinabraham/droid-application-fuzz-framework) Android application fuzzing framework with fuzzers and crash monitor.
- [**203**星][2m] [Py] [jwilk/python-afl](https://github.com/jwilk/python-afl) American Fuzzy Lop fork server and instrumentation for pure-Python code


##### <a id="a9a8b68c32ede78eee0939cf16128300"></a>资源收集


- [**3792**星][1m] [PHP] [fuzzdb-project/fuzzdb](https://github.com/fuzzdb-project/fuzzdb) 通过动态App安全测试来查找App安全漏洞, 算是不带扫描器的漏洞扫描器
- [**2864**星][5m] [secfigo/awesome-fuzzing](https://github.com/secfigo/awesome-fuzzing) A curated list of fuzzing resources ( Books, courses - free and paid, videos, tools, tutorials and vulnerable applications to practice on ) for learning Fuzzing and initial phases of Exploit Development like root cause analysis.


##### <a id="ff703caa7c3f7b197608abaa76b1a263"></a>Fuzzer


- [**2629**星][17d] [Go] [google/syzkaller](https://github.com/google/syzkaller) 一个unsupervised、以 coverage 为导向的Linux 系统调用fuzzer
- [**2346**星][1m] [Py] [xmendez/wfuzz](https://github.com/xmendez/wfuzz) Web application fuzzer
- [**1699**星][21d] [C] [google/honggfuzz](https://github.com/google/honggfuzz) Security oriented fuzzer with powerful analysis options. Supports evolutionary, feedback-driven fuzzing based on code coverage (software- and hardware-based)
- [**1051**星][2m] [Py] [googleprojectzero/domato](https://github.com/googleprojectzero/domato) ProjectZero 开源的 DOM fuzzer






### <a id="41ae40ed61ab2b61f2971fea3ec26e7c"></a>漏洞利用


#### <a id="c83f77f27ccf5f26c8b596979d7151c3"></a>漏洞利用


- [**3933**星][3m] [Py] [nullarray/autosploit](https://github.com/nullarray/autosploit) Automated Mass Exploiter
- [**3364**星][1m] [C] [shellphish/how2heap](https://github.com/shellphish/how2heap) how2heap：学习各种堆利用技巧的repo
- [**2175**星][10m] [JS] [secgroundzero/warberry](https://github.com/secgroundzero/warberry) WarBerryPi - Tactical Exploitation
- [**1448**星][3m] [Py] [epinna/tplmap](https://github.com/epinna/tplmap) 代码注入和服务器端模板注入（Server-Side Template Injection）漏洞利用，若干沙箱逃逸技巧。
- [**1180**星][15d] [Py] [codingo/nosqlmap](https://github.com/codingo/NoSQLMap) Automated NoSQL database enumeration and web application exploitation tool.
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |[工具/数据库&&SQL攻击&&SQL注入/NoSQL/未分类-NoSQL](#af0aaaf233cdff3a88d04556dc5871e0) |
- [**1080**星][6m] [Go] [sensepost/ruler](https://github.com/sensepost/ruler) ruler：自动化利用Exchange 服务的repo
- [**822**星][1m] [Py] [nil0x42/phpsploit](https://github.com/nil0x42/phpsploit) Stealth post-exploitation framework
- [**818**星][7m] [Shell] [niklasb/libc-database](https://github.com/niklasb/libc-database) Build a database of libc offsets to simplify exploitation
- [**797**星][28d] [Ruby] [rastating/wordpress-exploit-framework](https://github.com/rastating/wordpress-exploit-framework) wordpress-exploit-framework：WordPress 漏洞利用框架
- [**792**星][12d] [cveproject/cvelist](https://github.com/cveproject/cvelist) Pilot program for CVE submission through GitHub
- [**665**星][10m] [JS] [theori-io/pwnjs](https://github.com/theori-io/pwnjs) 辅助开发浏览器exploit 的 JS 模块
- [**600**星][5m] [Java] [sigploiter/sigploit](https://github.com/sigploiter/sigploit) Telecom Signaling Exploitation Framework - SS7, GTP, Diameter & SIP
- [**568**星][1y] [Py] [spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop) 内核提权枚举和漏洞利用框架
- [**510**星][8m] [Py] [dark-lbp/isf](https://github.com/dark-lbp/isf) 工控漏洞利用框架，基于Python
- [**474**星][25d] [C] [r0hi7/binexp](https://github.com/r0hi7/binexp) Linux Binary Exploitation
- [**449**星][5m] [Py] [shellphish/rex](https://github.com/shellphish/rex) Shellphish's automated exploitation engine, originally created for the Cyber Grand Challenge.
- [**429**星][11m] [Py] [neohapsis/bbqsql](https://github.com/neohapsis/bbqsql) SQL Injection Exploitation Tool
- [**394**星][20d] [Py] [corkami/collisions](https://github.com/corkami/collisions) Hash collisions and their exploitations
- [**378**星][2m] [Py] [sab0tag3d/siet](https://github.com/sab0tag3d/siet) Smart Install Exploitation Tool
- [**346**星][9m] [C] [wapiflapi/exrs](https://github.com/wapiflapi/exrs) Exercises for learning Reverse Engineering and Exploitation.
- [**345**星][29d] [JS] [fsecurelabs/dref](https://github.com/FSecureLABS/dref) DNS 重绑定利用框架
- [**315**星][1y] [C] [tharina/blackhoodie-2018-workshop](https://github.com/tharina/blackhoodie-2018-workshop) Slides and challenges for my binary exploitation workshop at BlackHoodie 2018.
- [**314**星][13d] [Shell] [zmarch/orc](https://github.com/zmarch/orc) Orc is a post-exploitation framework for Linux written in Bash
- [**300**星][4m] [JS] [vngkv123/asiagaming](https://github.com/vngkv123/asiagaming) Chrome, Safari Exploitation
- [**288**星][9m] [Py] [immunit/drupwn](https://github.com/immunit/drupwn) Drupal enumeration & exploitation tool
- [**284**星][1m] [xairy/vmware-exploitation](https://github.com/xairy/vmware-exploitation) A bunch of links related to VMware escape exploits
- [**282**星][12m] [C] [str8outtaheap/heapwn](https://github.com/str8outtaheap/heapwn) Linux Heap Exploitation Practice
- [**280**星][1y] [Py] [novicelive/bintut](https://github.com/novicelive/bintut) Teach you a binary exploitation for great good.
- [**273**星][12m] [Py] [fox-it/aclpwn.py](https://github.com/fox-it/aclpwn.py) 与BloodHound交互, 识别并利用基于ACL的提权路径
- [**266**星][22d] [Py] [0xinfection/xsrfprobe](https://github.com/0xinfection/xsrfprobe) The Prime Cross Site Request Forgery (CSRF) Audit and Exploitation Toolkit.
- [**257**星][3m] [HTML] [sp1d3r/swf_json_csrf](https://github.com/sp1d3r/swf_json_csrf) swf_json_csrf：简化基于 SWF的 JSON CSRF exploitation
- [**250**星][7m] [Py] [xairy/easy-linux-pwn](https://github.com/xairy/easy-linux-pwn) A set of Linux binary exploitation tasks for beginners on various architectures
- [**243**星][26d] [Py] [0xinfection/xsrfprobe](https://github.com/0xInfection/XSRFProbe) The Prime Cross Site Request Forgery (CSRF) Audit and Exploitation Toolkit.
- [**231**星][10m] [C] [r3x/how2kernel](https://github.com/r3x/how2kernel) This Repository aims at giving a basic idea about Kernel Exploitation.


#### <a id="5c1af335b32e43dba993fceb66c470bc"></a>Exp&&PoC


- [**1363**星][1m] [Py] [bitsadmin/wesng](https://github.com/bitsadmin/wesng) Windows Exploit Suggester - Next Generation
- [**1353**星][6m] [Py] [vulnerscom/getsploit](https://github.com/vulnerscom/getsploit) Command line utility for searching and downloading exploits
- [**1322**星][4m] [Py] [lijiejie/githack](https://github.com/lijiejie/githack) git泄露利用脚本，通过泄露的.git文件夹下的文件，重建还原工程源代码
- [**1120**星][4m] [Py] [qyriad/fusee-launcher](https://github.com/Qyriad/fusee-launcher) NVIDIA Tegra X1处理器Fusée Gelée漏洞exploit的launcher. (Fusée Gelée: 冷启动漏洞，允许在bootROM早期, 通过NVIDIA Tegra系列嵌入式处理器上的Tegra恢复模式(RCM)执行完整、未经验证的任意代码)
- [**930**星][10m] [Shell] [1n3/findsploit](https://github.com/1n3/findsploit) Find exploits in local and online databases instantly
- [**918**星][5m] [JS] [reswitched/pegaswitch](https://github.com/reswitched/pegaswitch) PegaSwitch is an exploit toolkit for the Nintendo Switch
- [**881**星][3m] [C] [theofficialflow/h-encore](https://github.com/theofficialflow/h-encore) Fully chained kernel exploit for the PS Vita on firmwares 3.65-3.68
- [**711**星][1y] [Py] [rfunix/pompem](https://github.com/rfunix/pompem) Find exploit tool
- [**707**星][11m] [HTML] [juansacco/exploitpack](https://github.com/juansacco/exploitpack) Exploit Pack -The next generation exploit framework
- [**703**星][4m] [Py] [rhinosecuritylabs/security-research](https://github.com/rhinosecuritylabs/security-research) Exploits written by the Rhino Security Labs team
- [**695**星][6m] [C] [unamer/vmware_escape](https://github.com/unamer/vmware_escape) VMwareWorkStation 12.5.5 之前版本的逃逸 Exploit
- [**681**星][1y] [C] [saelo/pwn2own2018](https://github.com/saelo/pwn2own2018) Pwn2Own 2018 Safari+macOS 漏洞利用链
- [**636**星][4m] [smgorelik/windows-rce-exploits](https://github.com/smgorelik/windows-rce-exploits) The exploit samples database is a repository for **RCE** (remote code execution) exploits and Proof-of-Concepts for **WINDOWS**, the samples are uploaded for education purposes for red and blue teams.
- [**621**星][4m] [C++] [eliboa/tegrarcmgui](https://github.com/eliboa/tegrarcmgui) C++ GUI for TegraRcmSmash (Fusée Gelée exploit for Nintendo Switch)
- [**617**星][4m] [Perl] [jondonas/linux-exploit-suggester-2](https://github.com/jondonas/linux-exploit-suggester-2) Next-Generation Linux Kernel Exploit Suggester
- [**608**星][3m] [C] [matheus-garbelini/esp32_esp8266_attacks](https://github.com/matheus-garbelini/esp32_esp8266_attacks) Proof of Concept of ESP32/8266 Wi-Fi vulnerabilties (CVE-2019-12586, CVE-2019-12587, CVE-2019-12588)
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**607**星][8m] [Py] [al-azif/ps4-exploit-host](https://github.com/al-azif/ps4-exploit-host) Easy PS4 Exploit Hosting
- [**580**星][1y] [JS] [cryptogenic/ps4-5.05-kernel-exploit](https://github.com/cryptogenic/ps4-5.05-kernel-exploit) A fully implemented kernel exploit for the PS4 on 5.05FW
- [**580**星][10m] [mtivadar/windows10_ntfs_crash_dos](https://github.com/mtivadar/windows10_ntfs_crash_dos) Windows NTFS文件系统崩溃漏洞PoC
- [**552**星][9m] [C] [t00sh/rop-tool](https://github.com/t00sh/rop-tool) binary exploits编写辅助脚本
- [**544**星][2m] [Py] [tarunkant/gopherus](https://github.com/tarunkant/gopherus) This tool generates gopher link for exploiting SSRF and gaining RCE in various servers
- [**523**星][5m] [Py] [bignerd95/chimay-red](https://github.com/bignerd95/chimay-red) Working POC of Mikrotik exploit from Vault 7 CIA Leaks
- [**489**星][6m] [Py] [danigargu/heap-viewer](https://github.com/danigargu/heap-viewer) 查看glibc堆, 主要用于漏洞开发
- [**489**星][5m] [Py] [metachar/phonesploit](https://github.com/metachar/phonesploit) Using open Adb ports we can exploit a Andriod Device
- [**488**星][7m] [Py] [lijiejie/ds_store_exp](https://github.com/lijiejie/ds_store_exp) A .DS_Store file disclosure exploit. It parses .DS_Store file and downloads files recursively.
- [**481**星][5m] [PHP] [cfreal/exploits](https://github.com/cfreal/exploits) Some of my exploits.
- [**473**星][2m] [JS] [acmesec/pocbox](https://github.com/Acmesec/PoCBox) 赏金猎人的脆弱性测试辅助平台
- [**472**星][9m] [Py] [insecurityofthings/jackit](https://github.com/insecurityofthings/jackit) Exploit Code for Mousejack
- [**435**星][1y] [Py] [jfoote/exploitable](https://github.com/jfoote/exploitable) The 'exploitable' GDB plugin. I don't work at CERT anymore, but here is the original homepage:
- [**431**星][9m] [Shell] [r00t-3xp10it/fakeimageexploiter](https://github.com/r00t-3xp10it/fakeimageexploiter) Use a Fake image.jpg to exploit targets (hide known file extensions)
- [**418**星][11m] [Shell] [nilotpalbiswas/auto-root-exploit](https://github.com/nilotpalbiswas/auto-root-exploit) Auto Root Exploit Tool
- [**412**星][3m] [Py] [misterch0c/malsploitbase](https://github.com/misterch0c/malsploitbase) Malware exploits
- [**402**星][1y] [C] [ww9210/linux_kernel_exploits](https://github.com/ww9210/linux_kernel_exploits) Repo for FUZE project. I will also publish some Linux kernel LPE exploits for various real world kernel vulnerabilities here. the samples are uploaded for education purposes for red and blue teams.
- [**390**星][7m] [Py] [jm33-m0/massexpconsole](https://github.com/jm33-m0/mec) for concurrent exploiting
- [**383**星][12m] [JS] [linushenze/webkit-regex-exploit](https://github.com/linushenze/webkit-regex-exploit) 
- [**378**星][12m] [PHP] [bo0om/php_imap_open_exploit](https://github.com/bo0om/php_imap_open_exploit) Bypassing disabled exec functions in PHP (c) CRLF
- [**372**星][2m] [PHP] [mm0r1/exploits](https://github.com/mm0r1/exploits) Pwn stuff.
- [**349**星][1m] [Shell] [th3xace/sudo_killer](https://github.com/th3xace/sudo_killer) A tool to identify and exploit sudo rules' misconfigurations and vulnerabilities within sudo
- [**348**星][8m] [C] [p0cl4bs/kadimus](https://github.com/p0cl4bs/kadimus) Kadimus is a tool to check sites to lfi vulnerability , and also exploit it...
- [**339**星][4m] [C] [theofficialflow/trinity](https://github.com/theofficialflow/trinity) Trinity Exploit - Emulator Escape
- [**331**星][6m] [C++] [thezdi/poc](https://github.com/thezdi/poc) Proofs-of-concept
- [**305**星][1y] [Shell] [jas502n/st2-057](https://github.com/jas502n/st2-057) St2-057 Poc Example
- [**302**星][3m] [PowerShell] [kevin-robertson/powermad](https://github.com/kevin-robertson/powermad) PowerShell MachineAccountQuota and DNS exploit tools
- [**300**星][1m] [Py] [admintony/svnexploit](https://github.com/admintony/svnexploit) SvnExploit支持SVN源代码泄露全版本Dump源码
- [**276**星][1m] [C] [0xdea/exploits](https://github.com/0xdea/exploits) 研究员 0xdeadbeef 的公开exploits 收集
- [**275**星][3m] [Shell] [cryptolok/aslray](https://github.com/cryptolok/aslray) Linux ELF x32/x64 ASLR DEP/NX bypass exploit with stack-spraying
- [**269**星][1y] [Py] [mwrlabs/wepwnise](https://github.com/FSecureLABS/wePWNise) WePWNise generates architecture independent VBA code to be used in Office documents or templates and automates bypassing application control and exploit mitigation software.
- [**266**星][4m] [Java] [c0ny1/fastjsonexploit](https://github.com/c0ny1/fastjsonexploit) Fastjson vulnerability quickly exploits the framework（fastjson漏洞快速利用框架）
- [**263**星][12m] [Py] [c0rel0ader/east](https://github.com/c0rel0ader/east) Exploits and Security Tools Framework 2.0.1
- [**251**星][4m] [C] [bcoles/kernel-exploits](https://github.com/bcoles/kernel-exploits) Various kernel exploits
- [**245**星][9m] [Visual Basic] [houjingyi233/office-exploit-case-study](https://github.com/houjingyi233/office-exploit-case-study) 
- [**234**星][19d] [C#] [tyranid/exploitremotingservice](https://github.com/tyranid/exploitremotingservice) A tool to exploit .NET Remoting Services
- [**219**星][8m] [Py] [coalfire-research/deathmetal](https://github.com/coalfire-research/deathmetal) Red team & penetration testing tools to exploit the capabilities of Intel AMT
- [**218**星][3m] [PowerShell] [byt3bl33d3r/offensivedlr](https://github.com/byt3bl33d3r/offensivedlr) Toolbox containing research notes & PoC code for weaponizing .NET's DLR
- [**218**星][1m] [C++] [soarqin/finalhe](https://github.com/soarqin/finalhe) Final h-encore, a tool to push h-encore exploit for PS VITA/PS TV automatically
- [**215**星][3m] [C] [semmle/securityexploits](https://github.com/semmle/securityexploits) PoC exploits from the Semmle Security Research team
- [**210**星][1y] [Py] [kurobeats/fimap](https://github.com/kurobeats/fimap) fimap is a little python tool which can find, prepare, audit, exploit and even google automatically for local and remote file inclusion bugs in webapps.
- [**207**星][1y] [C] [crozone/spectrepoc](https://github.com/crozone/spectrepoc) Proof of concept code for the Spectre CPU exploit.
- [**201**星][6m] [Py] [invictus1306/beebug](https://github.com/invictus1306/beebug) A tool for checking exploitability




### <a id="5d7191f01544a12bdaf1315c3e986dff"></a>XSS&&XXE


#### <a id="493e36d0ceda2fb286210a27d617c44d"></a>收集


- [**2671**星][5m] [JS] [s0md3v/awesomexss](https://github.com/s0md3v/AwesomeXSS) Awesome XSS stuff
- [**454**星][1y] [HTML] [metnew/uxss-db](https://github.com/metnew/uxss-db) 


#### <a id="648e49b631ea4ba7c128b53764328c39"></a>未分类-XSS


- [**7288**星][25d] [Py] [s0md3v/xsstrike](https://github.com/s0md3v/XSStrike) Most advanced XSS scanner.
    - 重复区段: [工具/扫描器&&安全扫描&&App扫描&&漏洞扫描/未分类-Scanner](#de63a029bda6a7e429af272f291bb769) |
- [**1641**星][10m] [JS] [evilcos/xssor2](https://github.com/evilcos/xssor2) XSS'OR - Hack with JavaScript.
- [**1318**星][3m] [Go] [microcosm-cc/bluemonday](https://github.com/microcosm-cc/bluemonday) a fast golang HTML sanitizer (inspired by the OWASP Java HTML Sanitizer) to scrub user generated content of XSS
- [**705**星][2m] [JS] [mandatoryprogrammer/xsshunter](https://github.com/mandatoryprogrammer/xsshunter) The XSS Hunter service - a portable version of XSSHunter.com
- [**683**星][18d] [C#] [mganss/htmlsanitizer](https://github.com/mganss/htmlsanitizer) Cleans HTML to avoid XSS attacks
- [**674**星][21d] [PHP] [ssl/ezxss](https://github.com/ssl/ezxss) ezXSS is an easy way for penetration testers and bug bounty hunters to test (blind) Cross Site Scripting.
- [**638**星][10m] [HTML] [bl4de/security_whitepapers](https://github.com/bl4de/security_whitepapers) Collection of misc IT Security related whitepapers, presentations, slides - hacking, bug bounty, web application security, XSS, CSRF, SQLi
- [**504**星][4m] [Py] [opensec-cn/vtest](https://github.com/opensec-cn/vtest) 用于辅助安全工程师漏洞挖掘、测试、复现，集合了mock、httplog、dns tools、xss，可用于测试各类无回显、无法直观判断或特定场景下的漏洞。
- [**495**星][4m] [PHP] [nettitude/xss_payloads](https://github.com/nettitude/xss_payloads) Exploitation for XSS
- [**477**星][1y] [JS] [koto/xsschef](https://github.com/koto/xsschef) Chrome extension Exploitation Framework
- [**460**星][12m] [C] [laruence/taint](https://github.com/laruence/taint) Taint is a PHP extension, used for detecting XSS codes
- [**334**星][12m] [Py] [varbaek/xsser](https://github.com/varbaek/xsser) From XSS to RCE 2.75 - Black Hat Europe Arsenal 2017 + Extras
- [**325**星][7m] [Py] [s0md3v/jshell](https://github.com/s0md3v/JShell) JShell - Get a JavaScript shell with XSS.
- [**289**星][1m] [JS] [wicg/trusted-types](https://github.com/w3c/webappsec-trusted-types) A browser API to prevent DOM-Based Cross Site Scripting in modern web applications.
- [**287**星][13d] [Py] [stamparm/dsxs](https://github.com/stamparm/dsxs) Damn Small XSS Scanner
- [**286**星][13d] [PHP] [voku/anti-xss](https://github.com/voku/anti-xss) 
- [**251**星][3m] [PHP] [dotboris/vuejs-serverside-template-xss](https://github.com/dotboris/vuejs-serverside-template-xss) Demo of a Vue.js app that mixes both clientside templates and serverside templates leading to an XSS vulnerability
- [**243**星][4m] [JS] [lewisardern/bxss](https://github.com/lewisardern/bxss) bXSS is a utility which can be used by bug hunters and organizations to identify Blind Cross-Site Scripting.
- [**241**星][2m] [JS] [antswordproject/ant](https://github.com/antswordproject/ant) 实时上线的 XSS 盲打平台




### <a id="f799ff186643edfcf7ac1e94f08ba018"></a>知名漏洞&&CVE&&特定产品


#### <a id="309751ccaee413cbf35491452d80480f"></a>未分类


- [**1066**星][28d] [Go] [neex/phuip-fpizdam](https://github.com/neex/phuip-fpizdam) Exploit for CVE-2019-11043
- [**886**星][1y] [Py] [nixawk/labs](https://github.com/nixawk/labs) 漏洞分析实验室。包含若干CVE 漏洞（CVE-2016-6277、CVE-2017-5689…）
- [**601**星][1y] [C] [scottybauer/android_kernel_cve_pocs](https://github.com/scottybauer/android_kernel_cve_pocs) A list of my CVE's with POCs
- [**562**星][10m] [Py] [fs0c131y/esfileexploreropenportvuln](https://github.com/fs0c131y/esfileexploreropenportvuln) ES File Explorer Open Port Vulnerability - CVE-2019-6447
- [**456**星][3m] [Py] [blacknbunny/libssh-authentication-bypass](https://github.com/blacknbunny/CVE-2018-10933) Spawn to shell without any credentials by using CVE-2018-10933 (LibSSH)
- [**449**星][6m] [Py] [n1xbyte/cve-2019-0708](https://github.com/n1xbyte/cve-2019-0708) dump
- [**394**星][9m] [Ruby] [dreadlocked/drupalgeddon2](https://github.com/dreadlocked/drupalgeddon2) Exploit for Drupal v7.x + v8.x (Drupalgeddon 2 / CVE-2018-7600 / SA-CORE-2018-002)
- [**371**星][1y] [Py] [rhynorater/cve-2018-15473-exploit](https://github.com/rhynorater/cve-2018-15473-exploit) Exploit written in Python for CVE-2018-15473 with threading and export formats
- [**370**星][9m] [Py] [wyatu/cve-2018-20250](https://github.com/wyatu/cve-2018-20250) exp for
- [**357**星][9m] [Go] [frichetten/cve-2019-5736-poc](https://github.com/frichetten/cve-2019-5736-poc) PoC for CVE-2019-5736
- [**339**星][1m] [PHP] [opsxcq/exploit-cve-2016-10033](https://github.com/opsxcq/exploit-cve-2016-10033) PHPMailer < 5.2.18 Remote Code Execution exploit and vulnerable container
- [**318**星][8m] [Py] [a2u/cve-2018-7600](https://github.com/a2u/cve-2018-7600) 
- [**300**星][10m] [Py] [basucert/winboxpoc](https://github.com/basucert/winboxpoc) Proof of Concept of Winbox Critical Vulnerability (CVE-2018-14847)
- [**299**星][1y] [Py] [bhdresh/cve-2017-8759](https://github.com/bhdresh/cve-2017-8759) Exploit toolkit CVE-2017-8759 - v1.0 is a handy python script which provides pentesters and security researchers a quick and effective way to test Microsoft .NET Framework RCE. It could generate a malicious RTF file and deliver metasploit / meterpreter / other payload to victim without any complex configuration.
- [**299**星][27d] [Py] [rhinosecuritylabs/cves](https://github.com/rhinosecuritylabs/cves) A collection of proof-of-concept exploit scripts written by the team at Rhino Security Labs for various CVEs.
- [**282**星][4m] [Py] [lufeirider/cve-2019-2725](https://github.com/lufeirider/cve-2019-2725) CVE-2019-2725 命令回显
- [**281**星][1y] [Py] [mazen160/struts-pwn_cve-2018-11776](https://github.com/mazen160/struts-pwn_cve-2018-11776) An exploit for Apache Struts CVE-2018-11776
- [**280**星][4m] [marcinguy/cve-2019-2107](https://github.com/marcinguy/cve-2019-2107) CVE-2019-2107
- [**276**星][11m] [Py] [wyatu/cve-2018-8581](https://github.com/wyatu/cve-2018-8581) CVE-2018-8581 | Microsoft Exchange Server Elevation of Privilege Vulnerability
- [**269**星][5m] [Py] [ridter/exchange2domain](https://github.com/ridter/exchange2domain) CVE-2018-8581
- [**259**星][1y] [C++] [alpha1ab/cve-2018-8120](https://github.com/alpha1ab/cve-2018-8120) CVE-2018-8120 Exploit for Win2003 Win2008 WinXP Win7
- [**253**星][1m] [C] [a2nkf/macos-kernel-exploit](https://github.com/a2nkf/macos-kernel-exploit) macOS Kernel Exploit for CVE-2019-8781. Credit for the bug goes to
- [**252**星][29d] [Vue] [nluedtke/linux_kernel_cves](https://github.com/nluedtke/linux_kernel_cves) Tracking CVEs for the linux Kernel
- [**243**星][3m] [Shell] [projectzeroindia/cve-2019-11510](https://github.com/projectzeroindia/cve-2019-11510) Exploit for Arbitrary File Read on Pulse Secure SSL VPN (CVE-2019-11510)
- [**238**星][8m] [JS] [exodusintel/cve-2019-5786](https://github.com/exodusintel/cve-2019-5786) FileReader Exploit
- [**237**星][10m] [C] [geosn0w/osirisjailbreak12](https://github.com/geosn0w/osirisjailbreak12) iOS 12.0 -> 12.1.2 Incomplete Osiris Jailbreak with CVE-2019-6225 by GeoSn0w (FCE365)
- [**234**星][9m] [JS] [adamyordan/cve-2019-1003000-jenkins-rce-poc](https://github.com/adamyordan/cve-2019-1003000-jenkins-rce-poc) Jenkins RCE Proof-of-Concept: SECURITY-1266 / CVE-2019-1003000 (Script Security), CVE-2019-1003001 (Pipeline: Groovy), CVE-2019-1003002 (Pipeline: Declarative)
- [**211**星][12m] [Py] [evict/poc_cve-2018-1002105](https://github.com/evict/poc_cve-2018-1002105) PoC for CVE-2018-1002105.
- [**203**星][8m] [C++] [rogue-kdc/cve-2019-0841](https://github.com/rogue-kdc/cve-2019-0841) PoC code for CVE-2019-0841 Privilege Escalation vulnerability
- [**200**星][1y] [C] [bazad/blanket](https://github.com/bazad/blanket) CVE-2018-4280: Mach port replacement vulnerability in launchd on iOS 11.2.6 leading to sandbox escape, privilege escalation, and codesigning bypass.
- [**200**星][2m] [Go] [kotakanbe/go-cve-dictionary](https://github.com/kotakanbe/go-cve-dictionary) Build a local copy of CVE (NVD and Japanese JVN). Server mode for easy querying.


#### <a id="33386e1e125e0653f7a3c8b8aa75c921"></a>CVE


- [**1058**星][3m] [C] [zerosum0x0/cve-2019-0708](https://github.com/zerosum0x0/cve-2019-0708) Scanner PoC for CVE-2019-0708 RDP RCE vuln


#### <a id="67f7ce74d12e16cdee4e52c459afcba2"></a>Spectre&&Meltdown


- [**3728**星][29d] [C] [iaik/meltdown](https://github.com/iaik/meltdown) This repository contains several applications, demonstrating the Meltdown bug.
- [**2999**星][2m] [Shell] [speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker) 检查 Linux 主机是否受处理器漏洞Spectre & Meltdown 的影响
- [**531**星][1y] [C] [ionescu007/specucheck](https://github.com/ionescu007/specucheck) SpecuCheck is a Windows utility for checking the state of the software mitigations and hardware against CVE-2017-5754 (Meltdown), CVE-2017-5715 (Spectre v2), CVE-2018-3260 (Foreshadow), and CVE-2018-3639 (Spectre v4)
- [**249**星][5m] [nsacyber/hardware-and-firmware-security-guidance](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance) Guidance for the Spectre, Meltdown, Speculative Store Bypass, Rogue System Register Read, Lazy FP State Restore, Bounds Check Bypass Store, TLBleed, and L1TF/Foreshadow vulnerabilities as well as general hardware and firmware security guidance. #nsacyber


#### <a id="10baba9b8e7a2041ad6c55939cf9691f"></a>BlueKeep


- [**973**星][3m] [Py] [ekultek/bluekeep](https://github.com/ekultek/bluekeep) Proof of concept for CVE-2019-0708
- [**633**星][6m] [C] [robertdavidgraham/rdpscan](https://github.com/robertdavidgraham/rdpscan) A quick scanner for the CVE-2019-0708 "BlueKeep" vulnerability.
- [**303**星][4m] [Py] [algo7/bluekeep_cve-2019-0708_poc_to_exploit](https://github.com/algo7/bluekeep_cve-2019-0708_poc_to_exploit) Porting BlueKeep PoC from
- [**267**星][6m] [Py] [k8gege/cve-2019-0708](https://github.com/k8gege/cve-2019-0708) 3389远程桌面代码执行漏洞CVE-2019-0708批量检测工具(Rdpscan Bluekeep Check)


#### <a id="a6ebcba5cc1b4d2e3a72509b47b84ade"></a>Heartbleed




#### <a id="d84e7914572f626b338beeb03ea613de"></a>DirtyCow




#### <a id="dacdbd68d9ca31cee9688d6972698f63"></a>Blueborne






### <a id="79ed781159b7865dc49ffb5fe2211d87"></a>CSRF


- [**1668**星][4m] [JS] [expressjs/csurf](https://github.com/expressjs/csurf) CSRF token middleware
- [**220**星][11m] [PHP] [paragonie/anti-csrf](https://github.com/paragonie/anti-csrf) Full-Featured Anti-CSRF Library


### <a id="edbf1e5f4d570ed44080b30bc782c350"></a>容器&&Docker


- [**5906**星][13d] [Go] [quay/clair](https://github.com/quay/clair) Vulnerability Static Analysis for Containers
- [**5905**星][13d] [Go] [quay/clair](https://github.com/quay/clair) clair：容器（appc、docker）漏洞静态分析工具。
- [**661**星][1y] [Shell] [c0ny1/vulstudy](https://github.com/c0ny1/vulstudy) 使用docker快速搭建各大漏洞学习平台，目前可以一键搭建12个平台。
- [**636**星][13d] [Go] [ullaakut/gorsair](https://github.com/ullaakut/gorsair) Gorsair hacks its way into remote docker containers that expose their APIs
- [**602**星][6m] [Py] [eliasgranderubio/dagda](https://github.com/eliasgranderubio/dagda) Docker安全套件
- [**475**星][5m] [Go] [arminc/clair-scanner](https://github.com/arminc/clair-scanner) Docker containers vulnerability scan
- [**332**星][6m] [Dockerfile] [mykings/docker-vulnerability-environment](https://github.com/mykings/docker-vulnerability-environment) Use the docker to build a vulnerability environment
- [**299**星][1y] [Dockerfile] [ston3o/docker-hacklab](https://github.com/ston3o/docker-hacklab) My personal hacklab, create your own.


### <a id="9f068ea97c2e8865fac21d6fc50f86b3"></a>漏洞管理


- [**2381**星][2m] [Py] [infobyte/faraday](https://github.com/infobyte/faraday) 渗透测试和漏洞管理平台
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/渗透多合一&&渗透框架](#2051fd9e171f2698d8e7486e3dd35d87) |
- [**1177**星][17d] [Py] [cve-search/cve-search](https://github.com/cve-search/cve-search) 导入CVE/CPE 到本地 MongoDB 数据库，以便后续在本地进行搜索和处理


### <a id="4c80728d087c2f08c6012afd2377d544"></a>漏洞数据库


- [**4770**星][13d] [C] [offensive-security/exploitdb](https://github.com/offensive-security/exploitdb) The official Exploit Database repository
- [**1265**星][2m] [PHP] [friendsofphp/security-advisories](https://github.com/friendsofphp/security-advisories) A database of PHP security advisories


### <a id="13fb2b7d1617dd6e0f503f52b95ba86b"></a>CORS


- [**2716**星][8m] [JS] [cyu/rack-cors](https://github.com/cyu/rack-cors) Rack Middleware for handling Cross-Origin Resource Sharing (CORS), which makes cross-origin AJAX possible.


### <a id="0af37d7feada6cb8ccd0c81097d0f115"></a>漏洞分析






***


## <a id="7e840ca27f1ff222fd25bc61a79b07ba"></a>特定目标


### <a id="eb2d1ffb231cee014ed24d59ca987da2"></a>未分类-XxTarget




### <a id="c71ad1932bbf9c908af83917fe1fd5da"></a>AWS


- [**4138**星][3m] [Py] [dxa4481/trufflehog](https://github.com/dxa4481/trufflehog) Searches through git repositories for high entropy strings and secrets, digging deep into commit history
- [**3130**星][17d] [Shell] [toniblyx/my-arsenal-of-aws-security-tools](https://github.com/toniblyx/my-arsenal-of-aws-security-tools) List of open source tools for AWS security: defensive, offensive, auditing, DFIR, etc.
- [**2758**星][12d] [Go] [99designs/aws-vault](https://github.com/99designs/aws-vault) A vault for securely storing and accessing AWS credentials in development environments
- [**2633**星][3m] [Java] [teevity/ice](https://github.com/teevity/ice) AWS Usage Tool
- [**2347**星][4m] [Go] [mlabouardy/komiser](https://github.com/mlabouardy/komiser) 
- [**1892**星][19d] [Py] [mozilla/mozdef](https://github.com/mozilla/mozdef) Mozilla Enterprise Defense Platform
- [**1805**星][20d] [Shell] [toniblyx/prowler](https://github.com/toniblyx/prowler) AWS Security Best Practices Assessment, Auditing, Hardening and Forensics Readiness Tool. It follows guidelines of the CIS Amazon Web Services Foundations Benchmark and DOZENS of additional checks including GDPR and HIPAA (+100). Official CIS for AWS guide:
- [**1597**星][1y] [Py] [nccgroup/scout2](https://github.com/nccgroup/Scout2) Security auditing tool for AWS environments
- [**1374**星][11m] [Py] [eth0izzle/bucket-stream](https://github.com/eth0izzle/bucket-stream) 通过certstream 监控多种证书 transparency 日志, 进而查找有趣的 Amazon S3 Buckets
- [**1161**星][17d] [Py] [lyft/cartography](https://github.com/lyft/cartography) Cartography is a Python tool that consolidates infrastructure assets and the relationships between them in an intuitive graph view powered by a Neo4j database.
- [**1105**星][3m] [Py] [rhinosecuritylabs/pacu](https://github.com/rhinosecuritylabs/pacu) The AWS exploitation framework, designed for testing the security of Amazon Web Services environments.
- [**887**星][2m] [Py] [sa7mon/s3scanner](https://github.com/sa7mon/s3scanner) Scan for open AWS S3 buckets and dump the contents
- [**824**星][5m] [Py] [jordanpotti/awsbucketdump](https://github.com/jordanpotti/awsbucketdump) 快速枚举 AWS S3 Buckets，查找感兴趣的文件。类似于子域名爆破，但针对S3 Bucket，有额外功能，例如下载文件等
- [**756**星][28d] [Go] [rebuy-de/aws-nuke](https://github.com/rebuy-de/aws-nuke) Nuke a whole AWS account and delete all its resources.
- [**749**星][1m] [Java] [tmobile/pacbot](https://github.com/tmobile/pacbot) PacBot (Policy as Code Bot)
- [**592**星][17d] [Shell] [securityftw/cs-suite](https://github.com/securityftw/cs-suite) Cloud Security Suite - One stop tool for auditing the security posture of AWS/GCP/Azure infrastructure.
- [**525**星][25d] [Ruby] [stelligent/cfn_nag](https://github.com/stelligent/cfn_nag) Linting tool for CloudFormation templates
- [**490**星][16d] [Py] [salesforce/policy_sentry](https://github.com/salesforce/policy_sentry) IAM Least Privilege Policy Generator
- [**480**星][6m] [Py] [netflix-skunkworks/diffy](https://github.com/netflix-skunkworks/diffy) Diffy is a triage tool used during cloud-centric security incidents, to help digital forensics and incident response (DFIR) teams quickly identify suspicious hosts on which to focus their response.
- [**433**星][7m] [Py] [ustayready/fireprox](https://github.com/ustayready/fireprox) AWS API Gateway management tool for creating on the fly HTTP pass-through proxies for unique IP rotation
- [**391**星][3m] [Py] [duo-labs/cloudtracker](https://github.com/duo-labs/cloudtracker) CloudTracker helps you find over-privileged IAM users and roles by comparing CloudTrail logs with current IAM policies.
- [**382**星][20d] [Py] [riotgames/cloud-inquisitor](https://github.com/riotgames/cloud-inquisitor) Enforce ownership and data security within AWS
- [**365**星][6m] [Py] [carnal0wnage/weirdaal](https://github.com/carnal0wnage/weirdaal) WeirdAAL (AWS Attack Library)
- [**363**星][10m] [Py] [awslabs/aws-security-automation](https://github.com/awslabs/aws-security-automation) Collection of scripts and resources for DevSecOps and Automated Incident Response Security
- [**311**星][1y] [Py] [securing/dumpsterdiver](https://github.com/securing/dumpsterdiver) Tool to search secrets in various filetypes.
- [**273**星][7m] [Py] [cesar-rodriguez/terrascan](https://github.com/cesar-rodriguez/terrascan) Collection of security and best practice test for static code analysis of terraform templates
- [**264**星][23d] [Py] [nccgroup/pmapper](https://github.com/nccgroup/pmapper) A tool for quickly evaluating IAM permissions in AWS.
- [**224**星][29d] [HCL] [nozaq/terraform-aws-secure-baseline](https://github.com/nozaq/terraform-aws-secure-baseline) Terraform module to set up your AWS account with the secure baseline configuration based on CIS Amazon Web Services Foundations.
- [**216**星][26d] [Dockerfile] [thinkst/canarytokens-docker](https://github.com/thinkst/canarytokens-docker) Docker configuration to quickly setup your own Canarytokens.
- [**202**星][2m] [Py] [voulnet/barq](https://github.com/voulnet/barq) The AWS Cloud Post Exploitation framework!


### <a id="88716f4591b1df2149c2b7778d15d04e"></a>Phoenix


- [**810**星][16d] [Elixir] [nccgroup/sobelow](https://github.com/nccgroup/sobelow) Phoenix 框架安全方面的静态分析工具（Phoenix  框架：支持对webUI,接口, web性能,mobile app 或 mobile browser 进行自动化测试和监控的平台）


### <a id="4fd96686a470ff4e9e974f1503d735a2"></a>Kubernetes


- [**1761**星][27d] [Py] [aquasecurity/kube-hunter](https://github.com/aquasecurity/kube-hunter) Hunt for security weaknesses in Kubernetes clusters
- [**379**星][2m] [Shell] [kabachook/k8s-security](https://github.com/kabachook/k8s-security) Kubernetes security notes and best practices


### <a id="786201db0bcc40fdf486cee406fdad31"></a>Azure




### <a id="40dbffa18ec695a618eef96d6fd09176"></a>Nginx


- [**6164**星][1m] [Py] [yandex/gixy](https://github.com/yandex/gixy) Nginx 配置静态分析工具，防止配置错误导致安全问题，自动化错误配置检测


### <a id="6b90a3993f9846922396ec85713dc760"></a>ELK


- [**1875**星][18d] [CSS] [cyb3rward0g/helk](https://github.com/cyb3rward0g/helk) 对ELK栈进行分析，具备多种高级功能，例如SQL声明性语言，图形，结构化流，机器学习等




***


## <a id="d55d9dfd081aa2a02e636b97ca1bad0b"></a>物联网(IoT)&&嵌入式设备&&路由器&&交换机&&智能设备&&打印机


### <a id="cda63179d132f43441f8844c5df10024"></a>未分类-IoT


- [**1119**星][6m] [nebgnahz/awesome-iot-hacks](https://github.com/nebgnahz/awesome-iot-hacks) A Collection of Hacks in IoT Space so that we can address them (hopefully).
- [**817**星][14d] [v33ru/iotsecurity101](https://github.com/v33ru/iotsecurity101) From IoT Pentesting to IoT Security
- [**791**星][30d] [Py] [ct-open-source/tuya-convert](https://github.com/ct-open-source/tuya-convert) A collection of scripts to flash Tuya IoT devices to alternative firmwares
- [**582**星][8m] [Py] [woj-ciech/danger-zone](https://github.com/woj-ciech/danger-zone) Correlate data between domains, IPs and email addresses, present it as a graph and store everything into Elasticsearch and JSON files.
- [**465**星][2m] [Py] [iti/ics-security-tools](https://github.com/iti/ics-security-tools) Tools, tips, tricks, and more for exploring ICS Security.
- [**437**星][18d] [Py] [rabobank-cdc/dettect](https://github.com/rabobank-cdc/dettect) Detect Tactics, Techniques & Combat Threats
- [**330**星][1y] [Py] [vmware/liota](https://github.com/vmware/liota) 
- [**307**星][1m] [Java] [erudika/para](https://github.com/erudika/para) Open source back-end server for web, mobile and IoT. The backend for busy developers. (self-hosted or hosted)


### <a id="72bffacc109d51ea286797a7d5079392"></a>打印机 




### <a id="c9fd442ecac4e22d142731165b06b3fe"></a>路由器&&交换机




### <a id="3d345feb9fee1c101aea3838da8cbaca"></a>嵌入式设备


- [**7428**星][3m] [Py] [threat9/routersploit](https://github.com/threat9/routersploit) Exploitation Framework for Embedded Devices




***


## <a id="1a9934198e37d6d06b881705b863afc8"></a>通信&&代理&&反向代理&&隧道


### <a id="56acb7c49c828d4715dce57410d490d1"></a>未分类-Proxy


- [**19800**星][2m] [Shell] [streisandeffect/streisand](https://github.com/StreisandEffect/streisand) Streisand sets up a new server running your choice of WireGuard, OpenConnect, OpenSSH, OpenVPN, Shadowsocks, sslh, Stunnel, or a Tor bridge. It also generates custom instructions for all of these services. At the end of the run you are given an HTML file with instructions that can be shared with friends, family members, and fellow activists.
- [**16743**星][18d] [Py] [mitmproxy/mitmproxy](https://github.com/mitmproxy/mitmproxy) An interactive TLS-capable intercepting HTTP proxy for penetration testers and software developers.
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**10723**星][13d] [getlantern/download](https://github.com/getlantern/download) 蓝灯Windows下载
- [**5481**星][3m] [C] [rofl0r/proxychains-ng](https://github.com/rofl0r/proxychains-ng) proxychains ng (new generation) - a preloader which hooks calls to sockets in dynamically linked programs and redirects it through one or more socks/http proxies. continuation of the unmaintained proxychains project. the sf.net page is currently not updated, use releases from github release page instead.
- [**4915**星][13d] [Go] [dnscrypt/dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy) 灵活的DNS代理，支持现代的加密DNS协议，例如：DNS protocols such as DNSCrypt v2, DNS-over-HTTPS and Anonymized DNSCrypt.
- [**4662**星][28d] [Go] [alexellis/inlets](https://github.com/inlets/inlets) Expose your local endpoints to the Internet
- [**4468**星][22d] [C] [jedisct1/dsvpn](https://github.com/jedisct1/dsvpn) A Dead Simple VPN.
- [**4223**星][5m] [Go] [ginuerzh/gost](https://github.com/ginuerzh/gost) GO语言实现的安全隧道
- [**4039**星][4m] [Py] [spiderclub/haipproxy](https://github.com/spiderclub/haipproxy) 
- [**3592**星][2m] [hq450/fancyss_history_package](https://github.com/hq450/fancyss_history_package) 科学上网插件的离线安装包储存在这里
- [**3348**星][4m] [Go] [jpillora/chisel](https://github.com/jpillora/chisel) 基于HTTP的快速 TCP 隧道
- [**2804**星][8m] [C++] [wangyu-/udpspeeder](https://github.com/wangyu-/udpspeeder) A Tunnel which Improves your Network Quality on a High-latency Lossy Link by using Forward Error Correction,for All Traffics(TCP/UDP/ICMP)
- [**2468**星][3m] [C] [yrutschle/sslh](https://github.com/yrutschle/sslh) Applicative Protocol Multiplexer (e.g. share SSH and HTTPS on the same port)
- [**2450**星][17d] [Shell] [teddysun/across](https://github.com/teddysun/across) This is a shell script for configure and start WireGuard VPN server
- [**2352**星][6m] [Lua] [snabbco/snabb](https://github.com/snabbco/snabb) Simple and fast packet networking
- [**2133**星][1m] [Go] [mmatczuk/go-http-tunnel](https://github.com/mmatczuk/go-http-tunnel) Fast and secure tunnels over HTTP/2
- [**1874**星][4m] [C] [darkk/redsocks](https://github.com/darkk/redsocks) transparent TCP-to-proxy redirector
- [**1844**星][1y] [Py] [aploium/zmirror](https://github.com/aploium/zmirror) The next-gen reverse proxy for full site mirroring
- [**1813**星][3m] [C] [tinyproxy/tinyproxy](https://github.com/tinyproxy/tinyproxy) a light-weight HTTP/HTTPS proxy daemon for POSIX operating systems
- [**1678**星][9m] [Py] [constverum/proxybroker](https://github.com/constverum/proxybroker) Proxy [Finder | Checker | Server]. HTTP(S) & SOCKS
- [**1665**星][4m] [C] [networkprotocol/netcode.io](https://github.com/networkprotocol/netcode.io) A protocol for secure client/server connections over UDP
- [**1611**星][6m] [Go] [sipt/shuttle](https://github.com/sipt/shuttle) A web proxy in Golang with amazing features.
- [**1495**星][1m] [C] [ntop/n2n](https://github.com/ntop/n2n) Peer-to-peer VPN
- [**1448**星][7m] [C++] [wangyu-/tinyfecvpn](https://github.com/wangyu-/tinyfecvpn) A VPN Designed for Lossy Links, with Build-in Forward Error Correction(FEC) Support. Improves your Network Quality on a High-latency Lossy Link.
- [**1334**星][1m] [Go] [davrodpin/mole](https://github.com/davrodpin/mole) cli app to create ssh tunnels
- [**1308**星][12m] [C] [madeye/proxydroid](https://github.com/madeye/proxydroid) Global Proxy for Android
- [**1222**星][4m] [JS] [bubenshchykov/ngrok](https://github.com/bubenshchykov/ngrok) Expose your localhost to the web. Node wrapper for ngrok.
- [**1199**星][21d] [Objective-C] [onionbrowser/onionbrowser](https://github.com/onionbrowser/onionbrowser) An open-source, privacy-enhancing web browser for iOS, utilizing the Tor anonymity network
- [**1048**星][5m] [C] [tcurdt/iproxy](https://github.com/tcurdt/iproxy) Let's you connect your laptop to the iPhone to surf the web.
- [**1042**星][28d] [Go] [pusher/oauth2_proxy](https://github.com/pusher/oauth2_proxy) A reverse proxy that provides authentication with Google, Github or other providers. #Hacktoberfest
- [**999**星][7m] [Go] [adtac/autovpn](https://github.com/adtac/autovpn) THIS PROJECT IS UNMAINTAINED.
- [**946**星][9m] [JS] [lukechilds/reverse-shell](https://github.com/lukechilds/reverse-shell) Reverse Shell as a Service
- [**927**星][3m] [Py] [christophetd/cloudflair](https://github.com/christophetd/cloudflair) a tool to find origin servers of websites protected by CloudFlare who are publicly exposed and don't restrict network access to the CloudFlare IP ranges as they should
- [**836**星][2m] [Py] [anorov/pysocks](https://github.com/anorov/pysocks) A SOCKS proxy client and wrapper for Python.
- [**810**星][1m] [Go] [henson/proxypool](https://github.com/henson/proxypool) Golang实现的IP代理池
- [**790**星][3m] [Py] [secforce/tunna](https://github.com/secforce/tunna) Tunna is a set of tools which will wrap and tunnel any TCP communication over HTTP. It can be used to bypass network restrictions in fully firewalled environments.
- [**753**星][1m] [C#] [justcoding121/titanium-web-proxy](https://github.com/justcoding121/titanium-web-proxy) A cross-platform asynchronous HTTP(S) proxy server in C#.
- [**738**星][30d] [Shell] [zfl9/ss-tproxy](https://github.com/zfl9/ss-tproxy) SS/SSR/V2Ray/Socks5 透明代理 for Linux
- [**737**星][1m] [C#] [damianh/proxykit](https://github.com/damianh/proxykit) A toolkit to create code-first HTTP reverse proxies on ASP.NET Core
- [**674**星][1m] [Go] [dliv3/venom](https://github.com/dliv3/venom) Venom - A Multi-hop Proxy for Penetration Testers
- [**674**星][24d] [JS] [mellow-io/mellow](https://github.com/mellow-io/mellow) Mellow is a rule-based global transparent proxy client for Windows, macOS and Linux.
- [**664**星][19d] [Kotlin] [mygod/vpnhotspot](https://github.com/mygod/vpnhotspot) Share your VPN connection over hotspot or repeater! (root required)
- [**651**星][27d] [Py] [abhinavsingh/proxy.py](https://github.com/abhinavsingh/proxy.py) ⚡⚡⚡Fast, Lightweight, Programmable, TLS interception capable proxy server for your Home and Application debugging, testing and development
- [**616**星][4m] [JS] [derhuerst/tcp-over-websockets](https://github.com/derhuerst/tcp-over-websockets) Tunnel TCP through WebSockets.
- [**574**星][4m] [Py] [trustedsec/trevorc2](https://github.com/trustedsec/trevorc2) trevorc2：通过正常的可浏览的网站隐藏 C&C 指令的客户端/服务器模型，因为时间间隔不同，检测变得更加困难，并且获取主机数据时不会使用 POST 请求
- [**568**星][12d] [Go] [cloudflare/cloudflared](https://github.com/cloudflare/cloudflared) Argo Tunnel client
- [**558**星][8m] [JS] [blinksocks/blinksocks](https://github.com/blinksocks/blinksocks) A framework for building composable proxy protocol stack.
- [**556**星][27d] [clarketm/proxy-list](https://github.com/clarketm/proxy-list) A list of free, public, forward proxy servers. UPDATED DAILY!
- [**545**星][1y] [Py] [fate0/getproxy](https://github.com/fate0/getproxy) 是一个抓取发放代理网站，获取 http/https 代理的程序
- [**513**星][10m] [Erlang] [heroku/vegur](https://github.com/heroku/vegur) HTTP Proxy Library
- [**473**星][1y] [Go] [yinqiwen/gsnova](https://github.com/yinqiwen/gsnova) Private proxy solution & network troubleshooting tool.
- [**449**星][28d] [Py] [aidaho12/haproxy-wi](https://github.com/aidaho12/haproxy-wi) Web interface for managing Haproxy servers
- [**397**星][9m] [Go] [evilsocket/shellz](https://github.com/evilsocket/shellz) shellz is a small utility to track and control your ssh, telnet, web and custom shells and tunnels.
- [**382**星][1y] [Ruby] [aphyr/tund](https://github.com/aphyr/tund) SSH reverse tunnel daemon
- [**361**星][1m] [Py] [lyft/metadataproxy](https://github.com/lyft/metadataproxy) A proxy for AWS's metadata service that gives out scoped IAM credentials from STS
- [**355**星][1y] [C] [emptymonkey/revsh](https://github.com/emptymonkey/revsh) A reverse shell with terminal support, data tunneling, and advanced pivoting capabilities.
- [**345**星][6m] [Go] [coreos/jwtproxy](https://github.com/coreos/jwtproxy) An HTTP-Proxy that adds AuthN through JWTs
- [**336**星][8m] [Py] [iphelix/dnschef](https://github.com/iphelix/dnschef) dnschef：DNS 代理，用于渗透测试和恶意代码分析
- [**331**星][6m] [Py] [fbkcs/thunderdns](https://github.com/fbkcs/thunderdns) 使用DNS协议转发TCP流量. Python编写, 无需编译客户端, 支持socks5
- [**325**星][4m] [Go] [sysdream/hershell](https://github.com/sysdream/hershell) Go 语言编写的反向 Shell
- [**320**星][9m] [JS] [mhzed/wstunnel](https://github.com/mhzed/wstunnel) tunnel over websocket
- [**301**星][4m] [Py] [rootviii/proxy_requests](https://github.com/rootviii/proxy_requests) a class that uses scraped proxies to make an http GET/POST request (Python requests)
- [**293**星][2m] [JS] [bettercap/caplets](https://github.com/bettercap/caplets) 使用.cap脚本, 自动化bettercap的交互式会话
- [**290**星][8m] [C] [basil00/reqrypt](https://github.com/basil00/reqrypt) reqrypt：HTTP 请求 tunneling 工具
- [**289**星][2m] [Py] [covertcodes/multitun](https://github.com/covertcodes/multitun) Tunnel arbitrary traffic through an innocuous WebSocket. Clients can 'see' each other, resulting in a stealth WebSocket VPN.
- [**278**星][11m] [C] [dgoulet/torsocks](https://github.com/dgoulet/torsocks) Library to torify application - NOTE: upstream has been moved to
- [**276**星][5m] [Py] [mthbernardes/rsg](https://github.com/mthbernardes/rsg) 多种方式生成反向Shell
- [**273**星][12d] [a2u/free-proxy-list](https://github.com/a2u/free-proxy-list) 
- [**273**星][9m] [Py] [chenjiandongx/async-proxy-pool](https://github.com/chenjiandongx/async-proxy-pool) 
- [**272**星][4m] [Go] [suyashkumar/ssl-proxy](https://github.com/suyashkumar/ssl-proxy) 
- [**257**星][8m] [C] [rofl0r/microsocks](https://github.com/rofl0r/microsocks) tiny, portable SOCKS5 server with very moderate resource usage
- [**254**星][3m] [Py] [fwkz/riposte](https://github.com/fwkz/riposte) Python package for wrapping applications inside a tailored interactive shell
- [**245**星][4m] [Shell] [thesecondsun/revssl](https://github.com/thesecondsun/revssl) A simple script that automates generation of OpenSSL reverse shells
- [**242**星][17d] [Go] [adguardteam/dnsproxy](https://github.com/adguardteam/dnsproxy) Simple DNS proxy with DoH, DoT, and DNSCrypt support
- [**242**星][4m] [Go] [lesnuages/hershell](https://github.com/lesnuages/hershell) Multiplatform reverse shell generator
- [**241**星][9m] [C] [pegasuslab/ghosttunnel](https://github.com/PegasusLab/GhostTunnel) GhostTunnel is a covert backdoor transmission method that can be used in an isolated environment.
- [**236**星][11m] [Go] [fardog/secureoperator](https://github.com/fardog/secureoperator) A DNS-protocol proxy for DNS-over-HTTPS providers, such as Google and Cloudflare
- [**224**星][1m] [Ruby] [zt2/sqli-hunter](https://github.com/zt2/sqli-hunter) SQLi-Hunter is a simple HTTP proxy server and a SQLMAP API wrapper that makes digging SQLi easy.
- [**216**星][1y] [PHP] [softius/php-cross-domain-proxy](https://github.com/softius/php-cross-domain-proxy) PHP Proxy for Cross Domain Requests
- [**213**星][8m] [Go] [joncooperworks/judas](https://github.com/joncooperworks/judas) a phishing proxy
- [**207**星][9m] [Go] [justmao945/mallory](https://github.com/justmao945/mallory) HTTP/HTTPS proxy over SSH
- [**202**星][1y] [C#] [damonmohammadbagher/nativepayload_dns](https://github.com/damonmohammadbagher/nativepayload_dns) C# code for Transferring Backdoor Payloads by DNS Traffic and Bypassing Anti-viruses


### <a id="837c9f22a3e1bb2ce29a0fb2bcd90b8f"></a>翻墙&&GFW


#### <a id="fe72fb9498defbdbb98448511cd1eaca"></a>未分类


- [**2918**星][11m] [Shell] [91yun/serverspeeder](https://github.com/91yun/serverspeeder) 锐速破解版


#### <a id="6e28befd418dc5b22fb3fd234db322d3"></a>翻墙


- [**12874**星][8m] [JS] [bannedbook/fanqiang](https://github.com/bannedbook/fanqiang) 翻墙-科学上网
- [**6211**星][20d] [Py] [h2y/shadowrocket-adblock-rules](https://github.com/h2y/shadowrocket-adblock-rules) 提供多款 Shadowrocket 规则，带广告过滤功能。用于 iOS 未越狱设备选择性地自动翻墙。
- [**3046**星][4m] [Shell] [softwaredownload/openwrt-fanqiang](https://github.com/softwaredownload/openwrt-fanqiang) 最好的路由器翻墙、科学上网教程—OpenWrt—shadowsocks


#### <a id="e9cc4e00d5851a7430a9b28d74f297db"></a>GFW


- [**14484**星][21d] [gfwlist/gfwlist](https://github.com/gfwlist/gfwlist) gfwlist
- [**3531**星][14d] [acl4ssr/acl4ssr](https://github.com/acl4ssr/acl4ssr) SSR 去广告ACL规则/SS完整GFWList规则，Telegram频道订阅地址
- [**2482**星][2m] [C++] [trojan-gfw/trojan](https://github.com/trojan-gfw/trojan) An unidentifiable mechanism that helps you bypass GFW.
- [**202**星][16d] [Shell] [zfl9/gfwlist2privoxy](https://github.com/zfl9/gfwlist2privoxy) 将 gfwlist.txt（Adblock Plus 规则）转换为 privoxy.action




### <a id="21cbd08576a3ead42f60963cdbfb8599"></a>代理


- [**7149**星][14d] [Go] [snail007/goproxy](https://github.com/snail007/goproxy) Proxy是高性能全功能的http代理、https代理、socks5代理、内网穿透、内网穿透p2p、内网穿透代理、内网穿透反向代理、内网穿透服务器、Websocket代理、TCP代理、UDP代理、DNS代理、DNS加密代理，代理API认证，全能跨平台代理服务器。
- [**5971**星][14d] [JS] [avwo/whistle](https://github.com/avwo/whistle) 基于Node实现的跨平台抓包调试代理工具（HTTP, HTTP2, HTTPS, Websocket）
- [**1380**星][1m] [C] [z3apa3a/3proxy](https://github.com/z3apa3a/3proxy) 3proxy - tiny free proxy server
- [**304**星][17d] [Shell] [brainfucksec/kalitorify](https://github.com/brainfucksec/kalitorify) Transparent proxy through Tor for Kali Linux OS


### <a id="a136c15727e341b9427b6570910a3a1f"></a>反向代理&&穿透


- [**29549**星][23d] [Go] [fatedier/frp](https://github.com/fatedier/frp) 快速的反向代理, 将NAT或防火墙之后的本地服务器暴露到公网
- [**9114**星][2m] [JS] [localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) expose yourself
- [**8706**星][2m] [Go] [cnlh/nps](https://github.com/cnlh/nps) 一款轻量级、功能强大的内网穿透代理服务器。支持tcp、udp流量转发，支持内网http代理、内网socks5代理，同时支持snappy压缩、站点保护、加密传输、多路复用、header修改等。支持web图形化管理，集成多用户模式。
- [**4887**星][10m] [Go] [bitly/oauth2_proxy](https://github.com/bitly/oauth2_proxy) 反向代理，静态文件服务器，提供Providers(Google/Github)认证
- [**3521**星][1m] [Java] [ffay/lanproxy](https://github.com/ffay/lanproxy) lanproxy是一个将局域网个人电脑、服务器代理到公网的内网穿透工具，支持tcp流量转发，可支持任何tcp上层协议（访问内网网站、本地支付接口调试、ssh访问、远程桌面...）。目前市面上提供类似服务的有花生壳、TeamView、GoToMyCloud等等，但要使用第三方的公网服务器就必须为第三方付费，并且这些服务都有各种各样的限制，此外，由于数据包会流经第三方，因此对数据安全也是一大隐患。技术交流QQ群 946273429
- [**2586**星][1m] [C++] [fanout/pushpin](https://github.com/fanout/pushpin) Reverse proxy for realtime web services
- [**2476**星][5m] [Go] [drk1wi/modlishka](https://github.com/drk1wi/modlishka) Modlishka. Reverse Proxy.
- [**656**星][4m] [Py] [aploium/shootback](https://github.com/aploium/shootback) a reverse TCP tunnel let you access target behind NAT or firewall


### <a id="e996f5ff54050629de0d9d5e68fcb630"></a>隧道


- [**3271**星][4m] [C++] [wangyu-/udp2raw-tunnel](https://github.com/wangyu-/udp2raw-tunnel) udp2raw-tunnel：udp 打洞。通过raw socket给UDP包加上TCP或ICMP header，进而绕过UDP屏蔽或QoS，或在UDP不稳定的环境下提升稳定性
- [**3131**星][3m] [C] [yarrick/iodine](https://github.com/yarrick/iodine) 通过DNS服务器传输(tunnel)IPV4数据
- [**1779**星][5m] [C++] [iagox86/dnscat2](https://github.com/iagox86/dnscat2) dnscat2：在 DNS 协议上创建加密的 C&C channel


### <a id="b2241c68725526c88e69f1d71405c6b2"></a>代理爬取&&代理池


- [**4882**星][1y] [Go] [yinghuocho/firefly-proxy](https://github.com/yinghuocho/firefly-proxy) A proxy software to help circumventing the Great Firewall.


### <a id="b03a7c05fd5b154ad593b6327578718b"></a>匿名网络


#### <a id="f0979cd783d1d455cb5e3207d574aa1e"></a>未分类




#### <a id="e99ba5f3de02f68412b13ca718a0afb6"></a>Tor&&&Onion&&洋葱


- [**1302**星][1m] [C++] [purplei2p/i2pd](https://github.com/purplei2p/i2pd) a full-featured C++ implementation of I2P client
- [**423**星][2m] [Py] [nullhypothesis/exitmap](https://github.com/nullhypothesis/exitmap) A fast and modular scanner for Tor exit relays.
- [**406**星][13d] [Awk] [alecmuffett/eotk](https://github.com/alecmuffett/eotk) Enterprise Onion Toolkit
- [**387**星][1m] [JS] [ayms/node-tor](https://github.com/ayms/node-tor) Javascript implementation of the Tor (or Tor like) anonymizer project (The Onion Router)
- [**377**星][1m] [Py] [maqp/tfc](https://github.com/maqp/tfc) Tinfoil Chat - Onion-routed, endpoint secure messaging system
- [**353**星][2m] [Py] [micahflee/torbrowser-launcher](https://github.com/micahflee/torbrowser-launcher) Securely and easily download, verify, install, and launch Tor Browser in Linux
- [**286**星][28d] [Perl] [alecmuffett/real-world-onion-sites](https://github.com/alecmuffett/real-world-onion-sites) An index of the non-dark web...
- [**261**星][9m] [C++] [wbenny/mini-tor](https://github.com/wbenny/mini-tor) mini-tor：使用 MSCNG/CryptoAPI 实现的 Tor 协议
- [**250**星][30d] [C] [basil00/torwall](https://github.com/basil00/torwall) Tallow - Transparent Tor for Windows
- [**219**星][5m] [Py] [ruped24/toriptables2](https://github.com/ruped24/toriptables2) Tor Iptables script is an anonymizer that sets up iptables and tor to route all services and traffic including DNS through the Tor network.




### <a id="f932418b594acb6facfc35c1ec414188"></a>Socks&&ShadowSocksXx


- [**25047**星][14d] [Swift] [shadowsocks/shadowsocksx-ng](https://github.com/shadowsocks/shadowsocksx-ng) Next Generation of ShadowsocksX
- [**12355**星][1m] [C] [shadowsocks/shadowsocks-libev](https://github.com/shadowsocks/shadowsocks-libev) libev port of shadowsocks
- [**7061**星][7m] [Shell] [teddysun/shadowsocks_install](https://github.com/teddysun/shadowsocks_install) Auto Install Shadowsocks Server for CentOS/Debian/Ubuntu
- [**4154**星][15d] [Swift] [yanue/v2rayu](https://github.com/yanue/v2rayu) V2rayU,基于v2ray核心的mac版客户端,用于科学上网,使用swift编写,支持vmess,shadowsocks,socks5等服务协议,支持订阅, 支持二维码,剪贴板导入,手动配置,二维码分享等
- [**3797**星][29d] [JS] [shadowsocks/shadowsocks-manager](https://github.com/shadowsocks/shadowsocks-manager) A shadowsocks manager tool for multi user and traffic control.
- [**3174**星][15d] [Smarty] [anankke/sspanel-uim](https://github.com/anankke/sspanel-uim) 专为 Shadowsocks / ShadowsocksR / V2Ray 设计的多用户管理面板
- [**2946**星][1m] [Go] [gwuhaolin/lightsocks](https://github.com/gwuhaolin/lightsocks) 轻量级网络混淆代理，基于 SOCKS5 协议，可用来代替 Shadowsocks
- [**2751**星][24d] [Makefile] [shadowsocks/openwrt-shadowsocks](https://github.com/shadowsocks/openwrt-shadowsocks) Shadowsocks-libev for OpenWrt/LEDE
- [**2300**星][10m] [C] [haad/proxychains](https://github.com/haad/proxychains) a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4, SOCKS5 or HTTP(S) proxy. Supported auth-types: "user/pass" for SOCKS4/5, "basic" for HTTP.
- [**2029**星][15d] [C#] [netchx/netch](https://github.com/netchx/netch) Game accelerator. Support Socks5, Shadowsocks, ShadowsocksR, V2Ray protocol. UDP NAT FullCone
- [**1821**星][3m] [C] [shadowsocks/simple-obfs](https://github.com/shadowsocks/simple-obfs) A simple obfuscating tool (Deprecated)
- [**1683**星][1y] [Swift] [haxpor/potatso](https://github.com/haxpor/potatso) Potatso is an iOS client that implements Shadowsocks proxy with the leverage of NetworkExtension framework. ***This project is unmaintained, try taking a look at this fork
- [**1621**星][17d] [Py] [ehco1996/django-sspanel](https://github.com/ehco1996/django-sspanel) 用diango开发的全新的shadowsocks网络面板
- [**1567**星][16d] [C#] [hmbsbige/shadowsocksr-windows](https://github.com/hmbsbige/shadowsocksr-windows) 【自用】Bug-Oriented Programming
- [**1306**星][4m] [Rust] [shadowsocks/shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) A Rust port of shadowsocks
- [**1177**星][6m] [ssrbackup/shadowsocks-rss](https://github.com/ssrarchive/shadowsocks-rss) Shadowsocksr project backup
- [**1068**星][1m] [jadagates/shadowsocksbio](https://github.com/jadagates/shadowsocksbio) 记录一下SS的前世今生，以及一个简单的教程总结
- [**922**星][1y] [Shell] [ywb94/openwrt-ssr](https://github.com/ywb94/openwrt-ssr) ShadowsocksR-libev for OpenWrt
- [**900**星][1y] [Go] [huacnlee/flora-kit](https://github.com/huacnlee/flora-kit) 基于 shadowsocks-go 做的完善实现，完全兼容 Surge 的配置文件
- [**899**星][2m] [zhaoweih/shadowsocks-tutorial](https://github.com/zhaoweih/shadowsocks-tutorial) 
- [**840**星][11m] [PHP] [walkor/shadowsocks-php](https://github.com/walkor/shadowsocks-php) A php port of shadowsocks based on workerman. A socks5 proxy written in PHP.
- [**830**星][1m] [C] [shadowsocksr-live/shadowsocksr-native](https://github.com/shadowsocksr-live/shadowsocksr-native) 从容翻越党国敏感日 ShadowsocksR (SSR) native implementation for all platforms, GFW terminator
- [**730**星][6m] [Go] [cbeuw/goquiet](https://github.com/cbeuw/goquiet) A Shadowsocks obfuscation plugin utilising domain fronting to evade deep packet inspection
- [**517**星][9m] [JS] [mrluanma/shadowsocks-heroku](https://github.com/mrluanma/shadowsocks-heroku) shadowsocks over WebSocket, support Heroku.
- [**421**星][2m] [PowerShell] [p3nt4/invoke-socksproxy](https://github.com/p3nt4/invoke-socksproxy) Socks proxy server using powershell. Supports local and reverse connections for pivoting.
- [**402**星][3m] [JS] [lolimay/shadowsocks-deepin](https://github.com/lolimay/shadowsocks-deepin) 
- [**374**星][1y] [Go] [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2) Experimental Shadowsocks in Go. Stable fork at
- [**337**星][16d] [Py] [leitbogioro/ssr.go](https://github.com/leitbogioro/ssr.go) A new shadowsocksR config manager
- [**318**星][3m] [Py] [qwj/python-proxy](https://github.com/qwj/python-proxy) HTTP/Socks4/Socks5/Shadowsocks/ShadowsocksR/SSH/Redirect/Pf TCP/UDP asynchronous tunnel proxy implemented in Python 3 asyncio.
- [**301**星][13d] [Shell] [loyess/shell](https://github.com/loyess/shell) Shadowsocks-libev with plugins one-click installation. For example: v2ray-plugin, kcptun, simple-obfs, goquiet, cloak...
- [**250**星][4m] [Py] [fsgmhoward/shadowsocks-py-mu](https://github.com/fsgmhoward/shadowsocks-py-mu) A fast tunnel proxy server for multiple users


### <a id="dbc310300d300ae45b04779281fe6ec8"></a>V2Ray


- [**23571**星][28d] [Go] [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core) A platform for building proxies to bypass network restrictions.
- [**2804**星][2m] [Dockerfile] [thinkdevelop/free-ss-ssr](https://github.com/thinkdevelop/free-ss-ssr) SS账号、SSR账号、V2Ray账号
- [**2484**星][2m] [Py] [jrohy/multi-v2ray](https://github.com/jrohy/multi-v2ray) v2ray easy delpoy & manage tool， support multiple user & protocol manage
- [**1656**星][1m] [Shell] [wulabing/v2ray_ws-tls_bash_onekey](https://github.com/wulabing/v2ray_ws-tls_bash_onekey) V2Ray Nginx+vmess+ws+tls/ http2 over tls 一键安装脚本
- [**1556**星][4m] [CSS] [functionclub/v2ray.fun](https://github.com/functionclub/v2ray.fun) 正在开发的全新 V2ray.Fun
- [**1432**星][12d] [selierlin/share-ssr-v2ray](https://github.com/selierlin/share-ssr-v2ray) 
- [**1070**星][1m] [Go] [xiaoming2028/freenet](https://github.com/xiaoming2028/freenet) 科学上网/梯子/自由上网/翻墙 SSR/V2Ray/Brook 最全搭建教程
- [**783**星][16d] [HTML] [sprov065/v2-ui](https://github.com/sprov065/v2-ui) 支持多协议多用户的 v2ray 面板，Support multi-protocol multi-user v2ray panel
- [**589**星][21d] [Shell] [toutyrater/v2ray-guide](https://github.com/toutyrater/v2ray-guide) 
- [**553**星][29d] [ntkernel/lantern](https://github.com/ntkernel/lantern) V2Ray配置文件，蓝灯(Lantern)破解，手机版+win版
- [**360**星][2m] [Dockerfile] [onplus/v2hero](https://github.com/onplus/v2hero) All Free . Deploy V2Ray to Heroku . v2ray学习参考
- [**307**星][2m] [Shell] [zw963/asuswrt-merlin-transparent-proxy](https://github.com/zw963/asuswrt-merlin-transparent-proxy) transparent proxy base on ss, v2ray, ipset, iptables, chinadns on asuswrt merlin.
- [**256**星][24d] [Py] [jiangxufeng/v2rayl](https://github.com/jiangxufeng/v2rayl) v2ray linux GUI客户端，支持订阅、vemss、ss等协议，自动更新订阅、检查版本更新


### <a id="891b953fda837ead9eff17ff2626b20a"></a>VPN


- [**419**星][19d] [hugetiny/awesome-vpn](https://github.com/hugetiny/awesome-vpn) A curated list of awesome free VPNs and proxies.免费的代理,科学上网,翻墙，梯子大集合




***


## <a id="1233584261c0cd5224b6e90a98cc9a94"></a>渗透&&offensive&&渗透框架&&后渗透框架


### <a id="2e40f2f1df5d7f93a7de47bf49c24a0e"></a>未分类-Pentest


- [**3005**星][3m] [Py] [spiderlabs/responder](https://github.com/spiderlabs/responder) LLMNR/NBT-NS/MDNS投毒，内置HTTP/SMB/MSSQL/FTP/LDAP认证服务器, 支持NTLMv1/NTLMv2/LMv2
- [**2013**星][1m] [C++] [lordnoteworthy/al-khaser](https://github.com/lordnoteworthy/al-khaser) Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.
    - 重复区段: [工具/恶意代码&&Malware&&APT](#8cb1c42a29fa3e8825a0f8fca780c481) |
- [**1721**星][1m] [Go] [chaitin/xray](https://github.com/chaitin/xray) xray 安全评估工具
- [**1444**星][1m] [C] [ufrisk/pcileech](https://github.com/ufrisk/pcileech) 直接内存访问（DMA：Direct Memory Access）攻击工具。通过 PCIe 硬件设备使用 DMA，直接读写目标系统的内存。目标系统不需要安装驱动。
- [**1393**星][4m] [yadox666/the-hackers-hardware-toolkit](https://github.com/yadox666/the-hackers-hardware-toolkit) The best hacker's gadgets for Red Team pentesters and security researchers.
- [**1361**星][2m] [Py] [ekultek/whatwaf](https://github.com/ekultek/whatwaf) Detect and bypass web application firewalls and protection systems
- [**1212**星][3m] [Py] [owtf/owtf](https://github.com/owtf/owtf) 进攻性 Web 测试框架。着重于 OWASP + PTES，尝试统合强大的工具，提高渗透测试的效率。大部分以Python 编写
- [**945**星][19d] [C] [bt3gl/pentesting-toolkit](https://github.com/bt3gl/Pentesting-Toolkit) Tools for pentesting, CTFs & wargames.
    - 重复区段: [工具/CTF&&HTB/收集](#30c4df38bcd1abaaaac13ffda7d206c6) |
- [**943**星][4m] [Py] [hatriot/zarp](https://github.com/hatriot/zarp) 网络攻击工具，主要是本地网络攻击
- [**918**星][1m] [Py] [d4vinci/one-lin3r](https://github.com/d4vinci/one-lin3r) 轻量级框架，提供在渗透测试中需要的所有one-liners
- [**808**星][1m] [Py] [jeffzh3ng/fuxi](https://github.com/jeffzh3ng/fuxi) Penetration Testing Platform
- [**784**星][6m] [Py] [jivoi/pentest](https://github.com/jivoi/pentest) 
- [**728**星][7m] [Py] [gkbrk/slowloris](https://github.com/gkbrk/slowloris) Low bandwidth DoS tool. Slowloris rewrite in Python.
- [**687**星][16d] [voorivex/pentest-guide](https://github.com/voorivex/pentest-guide) Penetration tests guide based on OWASP including test cases, resources and examples.
- [**666**星][5m] [leezj9671/pentest_interview](https://github.com/leezj9671/pentest_interview) 个人准备渗透测试和安全面试的经验之谈，和去部分厂商的面试题，干货真的满满~
- [**610**星][9m] [Py] [epsylon/ufonet](https://github.com/epsylon/ufonet) UFONet - Denial of Service Toolkit
- [**489**星][13d] [netbiosx/checklists](https://github.com/netbiosx/checklists) Pentesting checklists for various engagements
- [**487**星][16d] [Ruby] [hackplayers/evil-winrm](https://github.com/hackplayers/evil-winrm) The ultimate WinRM shell for hacking/pentesting
- [**487**星][1y] [Shell] [leonteale/pentestpackage](https://github.com/leonteale/pentestpackage) a package of Pentest scripts I have made or commonly use
- [**479**星][10m] [Ruby] [sidaf/homebrew-pentest](https://github.com/sidaf/homebrew-pentest) Homebrew Tap - Pen Test Tools
- [**464**星][7m] [Java] [alpha1e0/pentestdb](https://github.com/alpha1e0/pentestdb) WEB渗透测试数据库
- [**459**星][2m] [C++] [fsecurelabs/c3](https://github.com/FSecureLABS/C3) Custom Command and Control (C3). A framework for rapid prototyping of custom C2 channels, while still providing integration with existing offensive toolkits.
- [**457**星][10m] [PHP] [l3m0n/pentest_tools](https://github.com/l3m0n/pentest_tools) 收集一些小型实用的工具
- [**444**星][15d] [C++] [danielkrupinski/osiris](https://github.com/danielkrupinski/osiris) Free open-source training software / cheat for Counter-Strike: Global Offensive, written in modern C++. GUI powered by imgui.
- [**439**星][7m] [C++] [rek7/mxtract](https://github.com/rek7/mxtract) Offensive Memory Extractor & Analyzer
- [**432**星][3m] [mel0day/redteam-bcs](https://github.com/mel0day/redteam-bcs) BCS（北京网络安全大会）2019 红队行动会议重点内容
- [**414**星][18d] [PHP] [gwen001/pentest-tools](https://github.com/gwen001/pentest-tools) Custom pentesting tools
- [**404**星][1m] [Py] [admintony/prepare-for-awd](https://github.com/admintony/prepare-for-awd) AWD攻防赛脚本集合
- [**401**星][9m] [Py] [christruncer/pentestscripts](https://github.com/christruncer/pentestscripts) Scripts that are useful for me on pen tests
- [**398**星][27d] [PowerShell] [s3cur3th1ssh1t/winpwn](https://github.com/S3cur3Th1sSh1t/WinPwn) Automation for internal Windows Penetrationtest / AD-Security
- [**388**星][12m] [Py] [cr4shcod3/pureblood](https://github.com/cr4shcod3/pureblood) A Penetration Testing Framework created for Hackers / Pentester / Bug Hunter
- [**386**星][9m] [Go] [amyangxyz/assassingo](https://github.com/amyangxyz/assassingo) An extensible and concurrency pentest framework in Go, also with WebGUI. Feel free to CONTRIBUTE!
- [**385**星][3m] [ansjdnakjdnajkd/ios](https://github.com/ansjdnakjdnajkd/ios) Most usable tools for iOS penetration testing
    - 重复区段: [工具/移动&&Mobile/iOS&&MacOS&&iPhone&&iPad&&iWatch](#dbde77352aac39ee710d3150a921bcad) |
- [**385**星][23d] [Py] [clr2of8/dpat](https://github.com/clr2of8/dpat) Domain Password Audit Tool for Pentesters
- [**378**星][6m] [unprovable/pentesthardware](https://github.com/unprovable/pentesthardware) Kinda useful notes collated together publicly
- [**371**星][8m] [C] [ridter/pentest](https://github.com/ridter/pentest) tools
- [**368**星][4m] [C#] [bitsadmin/nopowershell](https://github.com/bitsadmin/nopowershell) 使用C#"重写"的PowerShell, 支持执行与PowerShell类似的命令, 然而对所有的PowerShell日志机制都不可见
- [**350**星][2m] [Shell] [maldevel/pentestkit](https://github.com/maldevel/pentestkit) Useful tools and scripts used during Penetration Tests.
- [**346**星][10m] [Py] [darkspiritz/darkspiritz](https://github.com/darkspiritz/darkspiritz) A penetration testing framework for Linux, MacOS, and Windows systems.
- [**341**星][15d] [Py] [ym2011/pest](https://github.com/ym2011/PEST) this is some pentest script based on python, just simple but useful, maybe it can help you do something else. just have a try
- [**338**星][3m] [Py] [xuanhun/pythonhackingbook1](https://github.com/xuanhun/pythonhackingbook1) Python黑客编程之极速入门
- [**337**星][1y] [Java] [rub-nds/ws-attacker](https://github.com/rub-nds/ws-attacker) WS-Attacker is a modular framework for web services penetration testing. It is developed by the Chair of Network and Data Security, Ruhr University Bochum (
- [**327**星][1y] [PowerShell] [rootclay/powershell-attack-guide](https://github.com/rootclay/powershell-attack-guide) Powershell攻击指南----黑客后渗透之道
- [**320**星][2m] [PowerShell] [kmkz/pentesting](https://github.com/kmkz/pentesting) Tricks for penetration testing
- [**316**星][28d] [Py] [m8r0wn/nullinux](https://github.com/m8r0wn/nullinux) nullinux：SMB null 会话识别和枚举工具
- [**307**星][2m] [PowerShell] [d0nkeys/redteam](https://github.com/d0nkeys/redteam) Red Team Scripts by d0nkeys (ex SnadoTeam)
- [**300**星][3m] [HTML] [koutto/jok3r](https://github.com/koutto/jok3r) Jok3r v3 BETA 2 - Network and Web Pentest Automation Framework
- [**298**星][2m] [Ruby] [fozavci/viproy-voipkit](https://github.com/fozavci/viproy-voipkit) VoIP渗透测试工具和 Metasploit 框架
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Metasploit/未分类-metasploit](#01be61d5bb9f6f7199208ff0fba86b5d) |
- [**295**星][11m] [stardustsky/saidict](https://github.com/stardustsky/saidict) 弱口令,敏感目录,敏感文件等渗透测试常用攻击字典
- [**292**星][27d] [Lua] [pentesteracademy/patoolkit](https://github.com/pentesteracademy/patoolkit) PA Toolkit is a collection of traffic analysis plugins focused on security
- [**286**星][1y] [C++] [paranoidninja/pandoras-box](https://github.com/paranoidninja/pandoras-box) This repo contains my custom scripts for Penetration Testing and Red Team Assessments. I will keep on updating this repo as and when I get time.
- [**283**星][1m] [Py] [bishopfox/eyeballer](https://github.com/bishopfox/eyeballer) Convolutional neural network for analyzing pentest screenshots
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |
- [**267**星][18d] [Go] [rmikehodges/hidensneak](https://github.com/rmikehodges/hidensneak) a CLI for ephemeral penetration testing
- [**252**星][13d] [anyeduke/enterprise-security-skill](https://github.com/anyeduke/enterprise-security-skill) 用于记录企业安全规划，建设，运营，攻防的相关资源
- [**251**星][3m] [Py] [giantbranch/python-hacker-code](https://github.com/giantbranch/python-hacker-code) 《python黑帽子：黑客与渗透测试编程之道》代码及实验文件，字典等
- [**240**星][2m] [Shell] [leviathan36/kaboom](https://github.com/leviathan36/kaboom) An automated pentest tool
- [**238**星][25d] [PowerShell] [sdcampbell/internal-pentest-playbook](https://github.com/sdcampbell/internal-pentest-playbook) Internal Network Penetration Test Playbook
- [**225**星][8m] [Go] [stevenaldinger/decker](https://github.com/stevenaldinger/decker) Declarative penetration testing orchestration framework
- [**216**星][5m] [Py] [mgeeky/tomcatwardeployer](https://github.com/mgeeky/tomcatwardeployer) Apache Tomcat auto WAR deployment & pwning penetration testing tool.
- [**211**星][19d] [JS] [giper45/dockersecurityplayground](https://github.com/giper45/dockersecurityplayground) A Microservices-based framework for the study of Network Security and Penetration Test techniques


### <a id="9081db81f6f4b78d5c263723a3f7bd6d"></a>收集


- [**903**星][8m] [C] [0x90/wifi-arsenal](https://github.com/0x90/wifi-arsenal) WiFi arsenal
- [**803**星][2m] [Shell] [shr3ddersec/shr3dkit](https://github.com/shr3ddersec/shr3dkit) Red Team Tool Kit
- [**537**星][6m] [Py] [0xdea/tactical-exploitation](https://github.com/0xdea/tactical-exploitation) 渗透测试辅助工具包. Python/PowerShell脚本


### <a id="39931e776c23e80229368dfc6fd54770"></a>无线&&WiFi&&AP&&802.11


#### <a id="d4efda1853b2cb0909727188116a2a8c"></a>未分类-WiFi


- [**8337**星][17d] [Py] [wifiphisher/wifiphisher](https://github.com/wifiphisher/wifiphisher) 流氓AP框架, 用于RedTeam和Wi-Fi安全测试
    - 重复区段: [工具/社工(SET)&&钓鱼&&鱼叉攻击/钓鱼&&Phish](#290e9ae48108d21d6d8b9ea9e74d077d) |
- [**6109**星][9m] [Py] [schollz/howmanypeoplearearound](https://github.com/schollz/howmanypeoplearearound) 检测 Wifi 信号统计你周围的人数
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |
- [**5597**星][1m] [C] [spacehuhn/esp8266_deauther](https://github.com/spacehuhn/esp8266_deauther) 使用ESP8266 制作Wifi干扰器
- [**4313**星][27d] [Py] [jopohl/urh](https://github.com/jopohl/urh) Universal Radio Hacker: investigate wireless protocols like a boss
- [**2723**星][1y] [C] [vanhoefm/krackattacks-scripts](https://github.com/vanhoefm/krackattacks-scripts) 检测客户端和AP是否受KRACK漏洞影响
- [**2706**星][8m] [Py] [p0cl4bs/wifi-pumpkin](https://github.com/P0cL4bs/WiFi-Pumpkin) AP攻击框架, 创建虚假网络, 取消验证攻击、请求和凭证监控、透明代理、Windows更新攻击、钓鱼管理、ARP投毒、DNS嗅探、Pumpkin代理、动态图片捕获等
- [**2480**星][15d] [Py] [evilsocket/pwnagotchi](https://github.com/evilsocket/pwnagotchi) (⌐■_■) - Deep Reinforcement Learning instrumenting bettercap for WiFi pwning.
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |[工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**2433**星][2m] [C] [martin-ger/esp_wifi_repeater](https://github.com/martin-ger/esp_wifi_repeater) A full functional WiFi Repeater (correctly: a WiFi NAT Router)
- [**2374**星][1y] [Py] [danmcinerney/lans.py](https://github.com/danmcinerney/lans.py) Inject code and spy on wifi users
- [**2194**星][22d] [Shell] [v1s1t0r1sh3r3/airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) This is a multi-use bash script for Linux systems to audit wireless networks.
- [**1816**星][1y] [Py] [derv82/wifite2](https://github.com/derv82/wifite2) 无线网络审计工具wifite 的升级版/重制版
- [**1799**星][4m] [Shell] [arismelachroinos/lscript](https://github.com/arismelachroinos/lscript) 自动化无线渗透和Hacking 任务的脚本
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/自动化](#fc8737aef0f59c3952d11749fe582dac) |
- [**1527**星][1m] [Py] [k4m4/kickthemout](https://github.com/k4m4/kickthemout) 使用ARP欺骗，将设备从网络中踢出去
- [**1525**星][1y] [HTML] [qiwihui/hiwifi-ss](https://github.com/qiwihui/hiwifi-ss) 极路由+ss配置
- [**1244**星][1m] [C] [seemoo-lab/nexmon](https://github.com/seemoo-lab/nexmon) The C-based Firmware Patching Framework for Broadcom/Cypress WiFi Chips that enables Monitor Mode, Frame Injection and much more
- [**1219**星][12d] [C] [aircrack-ng/aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) WiFi security auditing tools suite
- [**1022**星][1m] [C] [t6x/reaver-wps-fork-t6x](https://github.com/t6x/reaver-wps-fork-t6x) 攻击 Wi-Fi Protected Setup (WPS)， 恢复 WPA/WPA2 密码
- [**998**星][12m] [Py] [entropy1337/infernal-twin](https://github.com/entropy1337/infernal-twin) 自动化无线Hack 工具
- [**987**星][1y] [Py] [tylous/sniffair](https://github.com/tylous/sniffair) 无线渗透框架. 解析被动收集的无线数据, 执行复杂的无线攻击
- [**983**星][1y] [HTML] [sensepost/mana](https://github.com/sensepost/mana) *DEPRECATED* mana toolkit for wifi rogue AP attacks and MitM
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**977**星][14d] [C] [s0lst1c3/eaphammer](https://github.com/s0lst1c3/eaphammer) 针对WPA2-Enterprise 网络的定向双重攻击（evil twin attacks）
- [**903**星][1m] [TeX] [ethereum/yellowpaper](https://github.com/ethereum/yellowpaper) The "Yellow Paper": Ethereum's formal specification
- [**818**星][2m] [C] [spacehuhn/wifi_ducky](https://github.com/spacehuhn/wifi_ducky) Upload, save and run keystroke injection payloads with an ESP8266 + ATMEGA32U4
- [**796**星][1y] [Objective-C] [igrsoft/kismac2](https://github.com/igrsoft/kismac2) KisMAC is a free, open source wireless stumbling and security tool for Mac OS X.
- [**766**星][22d] [Py] [konradit/gopro-py-api](https://github.com/konradit/gopro-py-api) Unofficial GoPro API Library for Python - connect to GoPro via WiFi.
- [**755**星][7m] [Py] [misterbianco/boopsuite](https://github.com/MisterBianco/BoopSuite) 无线审计与安全测试
- [**676**星][10m] [Objective-C] [unixpickle/jamwifi](https://github.com/unixpickle/jamwifi) A GUI, easy to use WiFi network jammer for Mac OS X
- [**649**星][7m] [C] [wifidog/wifidog-gateway](https://github.com/wifidog/wifidog-gateway) Repository for the wifidog-gateway captive portal designed for embedded systems
- [**608**星][3m] [C] [matheus-garbelini/esp32_esp8266_attacks](https://github.com/matheus-garbelini/esp32_esp8266_attacks) Proof of Concept of ESP32/8266 Wi-Fi vulnerabilties (CVE-2019-12586, CVE-2019-12587, CVE-2019-12588)
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞利用/Exp&&PoC](#5c1af335b32e43dba993fceb66c470bc) |
- [**502**星][14d] [C++] [cyberman54/esp32-paxcounter](https://github.com/cyberman54/esp32-paxcounter) Wifi & BLE driven passenger flow metering with cheap ESP32 boards
- [**463**星][2m] [Shell] [staz0t/hashcatch](https://github.com/staz0t/hashcatch) Capture handshakes of nearby WiFi networks automatically
- [**455**星][3m] [Java] [lennartkoopmann/nzyme](https://github.com/lennartkoopmann/nzyme) 直接收集空中的802.11 管理帧，并将其发送到 Graylog，用于WiFi IDS, 监控, 及事件响应。（Graylog：开源的日志管理系统）
- [**450**星][1m] [Py] [savio-code/fern-wifi-cracker](https://github.com/savio-code/fern-wifi-cracker) 无线安全审计和攻击工具, 能破解/恢复 WEP/WPA/WPSkey等
- [**396**星][18d] [C] [freifunk-gluon/gluon](https://github.com/freifunk-gluon/gluon) a modular framework for creating OpenWrt-based firmwares for wireless mesh nodes
- [**387**星][1y] [Py] [jpaulmora/pyrit](https://github.com/jpaulmora/pyrit) The famous WPA precomputed cracker, Migrated from Google.
- [**373**星][3m] [C++] [bastibl/gr-ieee802-11](https://github.com/bastibl/gr-ieee802-11) IEEE 802.11 a/g/p Transceiver
- [**320**星][2m] [Shell] [vanhoefm/modwifi](https://github.com/vanhoefm/modwifi) 
- [**316**星][2m] [Java] [wiglenet/wigle-wifi-wardriving](https://github.com/wiglenet/wigle-wifi-wardriving) Nethugging client for Android, from wigle.net
- [**310**星][3m] [TeX] [chronaeon/beigepaper](https://github.com/chronaeon/beigepaper) Rewrite of the Yellowpaper in non-Yellowpaper syntax.
- [**266**星][6m] [C] [br101/horst](https://github.com/br101/horst) “horst” - lightweight IEEE802.11 wireless LAN analyzer with a text interface
- [**265**星][2m] [C] [sensepost/hostapd-mana](https://github.com/sensepost/hostapd-mana) SensePost's modified hostapd for wifi attacks.
- [**253**星][1y] [Py] [wipi-hunter/pidense](https://github.com/wipi-hunter/pidense) Monitor illegal wireless network activities.
- [**237**星][7m] [Py] [lionsec/wifresti](https://github.com/lionsec/wifresti) Find your wireless network password in Windows , Linux and Mac OS
- [**234**星][2m] [C] [mame82/logitacker](https://github.com/mame82/logitacker) Enumerate and test Logitech wireless input devices for vulnerabilities with a nRF52840 radio dongle.
- [**218**星][18d] [Py] [ghostop14/sparrow-wifi](https://github.com/ghostop14/sparrow-wifi) Next-Gen GUI-based WiFi and Bluetooth Analyzer for Linux
    - 重复区段: [工具/蓝牙&&Bluetooth](#ceb90405292daed9bb32ac20836c219a) |[工具/浏览嗅探&&流量拦截&&流量分析&&中间人/未分类-Network](#99398a5a8aaf99228829dadff48fb6a7) |


#### <a id="8d233e2d068cce2b36fd0cf44d10f5d8"></a>WPS&&WPA&&WPA2


- [**302**星][4m] [Py] [hash3lizer/wifibroot](https://github.com/hash3lizer/wifibroot) A WiFi Pentest Cracking tool for WPA/WPA2 (Handshake, PMKID, Cracking, EAPOL, Deauthentication)


#### <a id="8863b7ba27658d687a85585e43b23245"></a>802.11






### <a id="80301821d0f5d8ec2dd3754ebb1b4b10"></a>Payload&&远控&&RAT


#### <a id="6602e118e0245c83b13ff0db872c3723"></a>未分类-payload


- [**1231**星][19d] [PowerShell] [hak5/bashbunny-payloads](https://github.com/hak5/bashbunny-payloads) The Official Bash Bunny Payload Repository
- [**962**星][27d] [C] [zardus/preeny](https://github.com/zardus/preeny) Some helpful preload libraries for pwning stuff.
- [**560**星][10m] [Py] [genetic-malware/ebowla](https://github.com/genetic-malware/ebowla) Framework for Making Environmental Keyed Payloads (NO LONGER SUPPORTED)
- [**529**星][2m] [C++] [screetsec/brutal](https://github.com/screetsec/brutal) Payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy . Brutal is a toolkit to quickly create various payload,powershell attack , virus attack and launch listener for a Human Interface Device ( Payload Teensy )
- [**438**星][12d] [Py] [ctxis/cape](https://github.com/ctxis/cape) Malware Configuration And Payload Extraction
- [**339**星][11m] [JS] [gabemarshall/brosec](https://github.com/gabemarshall/brosec) Brosec - An interactive reference tool to help security professionals utilize useful payloads and commands.
- [**259**星][3m] [Py] [felixweyne/imaginaryc2](https://github.com/felixweyne/imaginaryc2) Imaginary C2 is a python tool which aims to help in the behavioral (network) analysis of malware. Imaginary C2 hosts a HTTP server which captures HTTP requests towards selectively chosen domains/IPs. Additionally, the tool aims to make it easy to replay captured Command-and-Control responses/served payloads.
- [**234**星][3m] [cujanovic/markdown-xss-payloads](https://github.com/cujanovic/markdown-xss-payloads) XSS payloads for exploiting Markdown syntax
- [**229**星][17d] [cujanovic/open-redirect-payloads](https://github.com/cujanovic/open-redirect-payloads) Open Redirect Payloads
- [**226**星][5m] [cr0hn/nosqlinjection_wordlists](https://github.com/cr0hn/nosqlinjection_wordlists) This repository contains payload to test NoSQL Injections
- [**216**星][2m] [Py] [whitel1st/docem](https://github.com/whitel1st/docem) Uility to embed XXE and XSS payloads in docx,odt,pptx,etc (OXML_XEE on steroids)
- [**210**星][1m] [Py] [brent-stone/can_reverse_engineering](https://github.com/brent-stone/can_reverse_engineering) Automated Payload Reverse Engineering Pipeline for the Controller Area Network (CAN) protocol
- [**210**星][24d] [C] [shchmue/lockpick_rcm](https://github.com/shchmue/lockpick_rcm) Nintendo Switch encryption key derivation bare metal RCM payload
- [**210**星][20d] [PHP] [zigoo0/jsonbee](https://github.com/zigoo0/jsonbee) A ready to use JSONP endpoints/payloads to help bypass content security policy (CSP) of different websites.


#### <a id="b5d99a78ddb383c208aae474fc2cb002"></a>Payload收集


- [**21409**星][14d] [PHP] [danielmiessler/seclists](https://github.com/danielmiessler/seclists) 多种类型资源收集：用户名、密码、URL、敏感数据类型、Fuzzing  Payload、WebShell等
    - 重复区段: [工具/webshell/收集](#e08366dcf7aa021c6973d9e2a8944dff) |[工具/wordlist/收集](#3202d8212db5699ea5e6021833bf3fa2) |
- [**10579**星][14d] [Py] [swisskyrepo/payloadsallthethings](https://github.com/swisskyrepo/payloadsallthethings) A list of useful payloads and bypass for Web Application Security and Pentest/CTF
- [**1994**星][8m] [Shell] [foospidy/payloads](https://github.com/foospidy/payloads) payloads：web 攻击 Payload 集合
- [**1989**星][26d] [edoverflow/bugbounty-cheatsheet](https://github.com/edoverflow/bugbounty-cheatsheet) A list of interesting payloads, tips and tricks for bug bounty hunters.
- [**1856**星][10m] [PHP] [bartblaze/php-backdoors](https://github.com/bartblaze/php-backdoors) A collection of PHP backdoors. For educational or testing purposes only.
- [**717**星][2m] [HTML] [ismailtasdelen/xss-payload-list](https://github.com/payloadbox/xss-payload-list) XSS 漏洞Payload列表
- [**367**星][2m] [renwax23/xss-payloads](https://github.com/renwax23/xss-payloads) List of XSS Vectors/Payloads
- [**272**星][3m] [Py] [thekingofduck/easyxsspayload](https://github.com/thekingofduck/easyxsspayload) XssPayload List . Usage:
- [**238**星][3m] [payloadbox/command-injection-payload-list](https://github.com/payloadbox/command-injection-payload-list) 


#### <a id="b318465d0d415e35fc0883e9894261d1"></a>远控&&RAT


- [**5045**星][3m] [Py] [n1nj4sec/pupy](https://github.com/n1nj4sec/pupy) Pupy is an opensource, cross-platform (Windows, Linux, OSX, Android) remote administration and post-exploitation tool mainly written in python
- [**1696**星][6m] [Smali] [ahmyth/ahmyth-android-rat](https://github.com/ahmyth/ahmyth-android-rat) Android Remote Administration Tool
- [**1306**星][1y] [Py] [marten4n6/evilosx](https://github.com/marten4n6/evilosx) An evil RAT (Remote Administration Tool) for macOS / OS X.
- [**763**星][22d] [Py] [kevthehermit/ratdecoders](https://github.com/kevthehermit/ratdecoders) Python Decoders for Common Remote Access Trojans
- [**597**星][1y] [PowerShell] [fortynorthsecurity/wmimplant](https://github.com/FortyNorthSecurity/WMImplant) This is a PowerShell based tool that is designed to act like a RAT. Its interface is that of a shell where any command that is supported is translated into a WMI-equivalent for use on a network/remote machine. WMImplant is WMI based.
- [**477**星][5m] [Visual Basic] [nyan-x-cat/lime-rat](https://github.com/nyan-x-cat/lime-rat) LimeRAT | Simple, yet powerful remote administration tool for Windows (RAT)
- [**352**星][2m] [C++] [werkamsus/lilith](https://github.com/werkamsus/lilith) Lilith, The Open Source C++ Remote Administration Tool (RAT)
- [**307**星][5m] [Py] [mvrozanti/rat-via-telegram](https://github.com/mvrozanti/rat-via-telegram) Windows Remote Administration Tool via Telegram
- [**271**星][1m] [C#] [nyan-x-cat/asyncrat-c-sharp](https://github.com/nyan-x-cat/asyncrat-c-sharp) Open-Source Remote Administration Tool For Windows C# (RAT)
- [**269**星][3m] [C++] [yuanyuanxiang/simpleremoter](https://github.com/yuanyuanxiang/simpleremoter) 基于gh0st的远程控制器：实现了终端管理、进程管理、窗口管理、远程桌面、文件管理、语音管理、视频管理、服务管理、注册表管理等功能，优化全部代码及整理排版，修复内存泄漏缺陷，程序运行稳定。此项目初版见：


#### <a id="ad92f6b801a18934f1971e2512f5ae4f"></a>Payload生成


- [**3268**星][2m] [C] [screetsec/thefatrat](https://github.com/screetsec/thefatrat) Thefatrat a massive exploiting tool : Easy tool to generate backdoor and easy tool to post exploitation attack like browser attack and etc . This tool compiles a malware with popular payload and then the compiled malware can be execute on windows, android, mac . The malware that created with this tool also have an ability to bypass most AV softw…
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/后渗透/未分类-post-exp](#12abc279c69d1fcf10692b9cb89bcdf7) |
- [**2591**星][3m] [Java] [frohoff/ysoserial](https://github.com/frohoff/ysoserial) 生成会利用不安全的Java对象反序列化的Payload
- [**1741**星][21d] [Shell] [leebaird/discover](https://github.com/leebaird/discover) 自定义的bash脚本, 用于自动化多个渗透测试任务, 包括: 侦查、扫描、解析、在Metasploit中创建恶意Payload和Listener
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/自动化](#fc8737aef0f59c3952d11749fe582dac) |[工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Metasploit/未分类-metasploit](#01be61d5bb9f6f7199208ff0fba86b5d) |
- [**1061**星][5m] [Py] [nccgroup/winpayloads](https://github.com/nccgroup/winpayloads) Undetectable Windows Payload Generation
- [**1003**星][1y] [Py] [d4vinci/dr0p1t-framework](https://github.com/d4vinci/dr0p1t-framework) 创建免杀的Dropper
- [**857**星][10m] [Visual Basic] [mdsecactivebreach/sharpshooter](https://github.com/mdsecactivebreach/sharpshooter) Payload Generation Framework
- [**816**星][6m] [Go] [tiagorlampert/chaos](https://github.com/tiagorlampert/chaos) a PoC that allow generate payloads and control remote operating system
- [**810**星][2m] [PHP] [ambionics/phpggc](https://github.com/ambionics/phpggc) PHPGGC is a library of PHP unserialize() payloads along with a tool to generate them, from command line or programmatically.
- [**794**星][1m] [C#] [pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net) ysoserial.net：生成Payload，恶意利用不安全的 .NET 对象反序列化
- [**733**星][12m] [Py] [oddcod3/phantom-evasion](https://github.com/oddcod3/phantom-evasion) Python AV evasion tool capable to generate FUD executable even with the most common 32 bit metasploit payload(exe/elf/dmg/apk)
- [**684**星][3m] [Py] [sevagas/macro_pack](https://github.com/sevagas/macro_pack) 自动生成并混淆MS 文档, 用于渗透测试、演示、社会工程评估等
- [**618**星][8m] [Shell] [g0tmi1k/mpc](https://github.com/g0tmi1k/msfpc) MSFvenom Payload Creator (MSFPC)
- [**560**星][14d] [C] [thewover/donut](https://github.com/thewover/donut) Generates x86, x64, or AMD64+x86 position-independent shellcode that loads .NET Assemblies, PE files, and other Windows payloads from memory and runs them with parameters
- [**397**星][28d] [Perl] [chinarulezzz/pixload](https://github.com/chinarulezzz/pixload) Image Payload Creating/Injecting tools
- [**287**星][7m] [Py] [0xacb/viewgen](https://github.com/0xacb/viewgen) viewgen is a ViewState tool capable of generating both signed and encrypted payloads with leaked validation keys
- [**268**星][1y] [Shell] [abedalqaderswedan1/aswcrypter](https://github.com/abedalqaderswedan1/aswcrypter) An Bash&Python Script For Generating Payloads that Bypasses All Antivirus so far [FUD]
- [**262**星][1y] [Java] [ewilded/shelling](https://github.com/ewilded/shelling) SHELLING - a comprehensive OS command injection payload generator
- [**222**星][1y] [Java] [ewilded/psychopath](https://github.com/ewilded/psychopath) psychoPATH - an advanced path traversal tool. Features: evasive techniques, dynamic web root list generation, output encoding, site map-searching payload generator, LFI mode, nix & windows support, single byte generator, payload export.


#### <a id="c45a90ab810d536a889e4e2dd45132f8"></a>Botnet&&僵尸网络


- [**3690**星][3m] [Py] [malwaredllc/byob](https://github.com/malwaredllc/byob) BYOB (Build Your Own Botnet)
- [**2135**星][1y] [C++] [maestron/botnets](https://github.com/maestron/botnets) This is a collection of #botnet source codes, unorganized. For EDUCATIONAL PURPOSES ONLY
- [**390**星][19d] [C++] [souhardya/uboat](https://github.com/souhardya/uboat) HTTP Botnet Project
- [**319**星][5m] [Go] [saturnsvoid/gobot2](https://github.com/saturnsvoid/gobot2) Second Version of The GoBot Botnet, But more advanced.


#### <a id="b6efee85bca01cde45faa45a92ece37f"></a>后门&&添加后门


- [**378**星][7m] [C] [zerosum0x0/smbdoor](https://github.com/zerosum0x0/smbdoor) Windows kernel backdoor via registering a malicious SMB handler
- [**364**星][2m] [Shell] [screetsec/vegile](https://github.com/screetsec/vegile) This tool will setting up your backdoor/rootkits when backdoor already setup it will be hidden your spesisifc process,unlimited your session in metasploit and transparent. Even when it killed, it will re-run again. There always be a procces which while run another process,So we can assume that this procces is unstopable like a Ghost in The Shell
- [**362**星][7m] [Py] [s0md3v/cloak](https://github.com/s0md3v/Cloak) Cloak can backdoor any python script with some tricks.
- [**341**星][11m] [Shell] [r00t-3xp10it/backdoorppt](https://github.com/r00t-3xp10it/backdoorppt) backdoorppt：将Exe格式Payload伪装成Doc（.ppt）
- [**317**星][1y] [Ruby] [carletonstuberg/browser-backdoor](https://github.com/CarletonStuberg/browser-backdoor) BrowserBackdoor is an Electron Application with a JavaScript WebSocket Backdoor and a Ruby Command-Line Listener
- [**287**星][3m] [C#] [mvelazc0/defcon27_csharp_workshop](https://github.com/mvelazc0/defcon27_csharp_workshop) Writing custom backdoor payloads with C# - Defcon 27
- [**201**星][8m] [C] [paradoxis/php-backdoor](https://github.com/Paradoxis/PHP-Backdoor) Your interpreter isn’t safe anymore  —  The PHP module backdoor


#### <a id="85bb0c28850ffa2b4fd44f70816db306"></a>混淆器&&Obfuscate


- [**1351**星][9m] [PowerShell] [danielbohannon/invoke-obfuscation](https://github.com/danielbohannon/invoke-obfuscation) PowerShell Obfuscator


#### <a id="78d0ac450a56c542e109c07a3b0225ae"></a>Payload管理


- [**930**星][1y] [JS] [netflix/sleepy-puppy](https://github.com/Netflix-Skunkworks/sleepy-puppy) Sleepy Puppy XSS Payload Management Framework


#### <a id="d08b7bd562a4bf18275c63ffe7d8fc91"></a>勒索软件


- [**379**星][1y] [Go] [mauri870/ransomware](https://github.com/mauri870/ransomware) A POC Windows crypto-ransomware (Academic)
- [**313**星][13d] [Batchfile] [mitchellkrogza/ultimate.hosts.blacklist](https://github.com/mitchellkrogza/ultimate.hosts.blacklist) The Ultimate Unified Hosts file for protecting your network, computer, smartphones and Wi-Fi devices against millions of bad web sites. Protect your children and family from gaining access to bad web sites and protect your devices and pc from being infected with Malware or Ransomware.


#### <a id="82f546c7277db7919986ecf47f3c9495"></a>键盘记录器


- [**359**星][11m] [Py] [ajinabraham/xenotix-python-keylogger](https://github.com/ajinabraham/xenotix-python-keylogger) Xenotix Python Keylogger for Windows.


#### <a id="8f99087478f596139922cd1ad9ec961b"></a>Meterpreter


- [**233**星][5m] [Py] [mez0cc/ms17-010-python](https://github.com/mez0cc/ms17-010-python) MS17-010: Python and Meterpreter


#### <a id="63e0393e375e008af46651a3515072d8"></a>Payload投递


- [**255**星][3m] [Py] [no0be/dnslivery](https://github.com/no0be/dnslivery) Easy files and payloads delivery over DNS




### <a id="2051fd9e171f2698d8e7486e3dd35d87"></a>渗透多合一&&渗透框架


- [**4965**星][4m] [PowerShell] [empireproject/empire](https://github.com/EmpireProject/Empire) 后渗透框架. Windows客户端用PowerShell, Linux/OSX用Python. 之前PowerShell Empire和Python EmPyre的组合
- [**4576**星][22d] [Py] [manisso/fsociety](https://github.com/manisso/fsociety) fsociety Hacking Tools Pack – A Penetration Testing Framework
- [**3313**星][5m] [PowerShell] [samratashok/nishang](https://github.com/samratashok/nishang) 渗透框架，脚本和Payload收集，主要是PowerShell，涵盖渗透的各个阶段
- [**3053**星][1m] [Shell] [1n3/sn1per](https://github.com/1n3/sn1per) 自动化渗透测试框架
- [**3041**星][1m] [Py] [byt3bl33d3r/crackmapexec](https://github.com/byt3bl33d3r/crackmapexec) 后渗透工具，自动化评估大型Active Directory网络的安全性
- [**2961**星][17d] [Py] [guardicore/monkey](https://github.com/guardicore/monkey) 自动化渗透测试工具, 测试数据中心的弹性, 以防范周边(perimeter)泄漏和内部服务器感染
- [**2767**星][7m] [C#] [quasar/quasarrat](https://github.com/quasar/quasarrat) Remote Administration Tool for Windows
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
- [**3268**星][2m] [C] [screetsec/thefatrat](https://github.com/screetsec/thefatrat) Thefatrat a massive exploiting tool : Easy tool to generate backdoor and easy tool to post exploitation attack like browser attack and etc . This tool compiles a malware with popular payload and then the compiled malware can be execute on windows, android, mac . The malware that created with this tool also have an ability to bypass most AV softw…
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload生成](#ad92f6b801a18934f1971e2512f5ae4f) |
- [**2346**星][1m] [Shell] [rebootuser/linenum](https://github.com/rebootuser/linenum) Scripted Local Linux Enumeration & Privilege Escalation Checks
- [**2136**星][14d] [Py] [commixproject/commix](https://github.com/commixproject/commix) Automated All-in-One OS command injection and exploitation tool.
- [**1226**星][9m] [C] [a0rtega/pafish](https://github.com/a0rtega/pafish) Pafish is a demonstration tool that employs several techniques to detect sandboxes and analysis environments in the same way as malware families do.
- [**1191**星][1y] [C#] [cn33liz/p0wnedshell](https://github.com/cn33liz/p0wnedshell) PowerShell Runspace Post Exploitation Toolkit
- [**1045**星][8m] [Py] [0x00-0x00/shellpop](https://github.com/0x00-0x00/shellpop) 在渗透中生产简易的/复杂的反向/绑定Shell
- [**1029**星][28d] [Boo] [byt3bl33d3r/silenttrinity](https://github.com/byt3bl33d3r/silenttrinity) An asynchronous, collaborative post-exploitation agent powered by Python and .NET's DLR
- [**1015**星][3m] [Py] [byt3bl33d3r/deathstar](https://github.com/byt3bl33d3r/deathstar) 在Active Directory环境中使用Empire自动获取域管理员权限
- [**754**星][4m] [Py] [lgandx/pcredz](https://github.com/lgandx/pcredz) This tool extracts Credit card numbers, NTLM(DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface.
- [**737**星][4m] [PowerShell] [hausec/adape-script](https://github.com/hausec/adape-script) Active Directory Assessment and Privilege Escalation Script
- [**668**星][1m] [C#] [cobbr/sharpsploit](https://github.com/cobbr/sharpsploit) SharpSploit is a .NET post-exploitation library written in C#
- [**405**星][4m] [Shell] [thesecondsun/bashark](https://github.com/thesecondsun/bashark) Bash post exploitation toolkit
- [**341**星][4m] [Py] [adrianvollmer/powerhub](https://github.com/adrianvollmer/powerhub) A post exploitation tool based on a web application, focusing on bypassing endpoint protection and application whitelisting
- [**282**星][1y] [JS] [chrisallenlane/novahot](https://github.com/chrisallenlane/novahot) Webshell框架，实现了基于Json的API，可与任何语言编写的后门（默认支持PHP/Ruby/Python）进行通信。
    - 重复区段: [工具/webshell/未分类-webshell](#faa91844951d2c29b7b571c6e8a3eb54) |
- [**212**星][2m] [Go] [brompwnie/botb](https://github.com/brompwnie/botb) A container analysis and exploitation tool for pentesters and engineers.


#### <a id="4c2095e7e192ac56f6ae17c8fc045c51"></a>提权&&PrivilegeEscalation


- [**3509**星][4m] [C] [secwiki/windows-kernel-exploits](https://github.com/secwiki/windows-kernel-exploits) windows-kernel-exploits Windows平台提权漏洞集合
- [**1245**星][2m] [Py] [alessandroz/beroot](https://github.com/alessandroz/beroot) Privilege Escalation Project - Windows / Linux / Mac
- [**583**星][11m] [C++] [ohpe/juicy-potato](https://github.com/ohpe/juicy-potato) A sugared version of RottenPotatoNG, with a bit of juice, i.e. another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM.
- [**529**星][4m] [rhinosecuritylabs/aws-iam-privilege-escalation](https://github.com/rhinosecuritylabs/aws-iam-privilege-escalation) A centralized source of all AWS IAM privilege escalation methods released by Rhino Security Labs.
- [**492**星][7m] [Py] [initstring/dirty_sock](https://github.com/initstring/dirty_sock) Linux privilege escalation exploit via snapd (CVE-2019-7304)
- [**467**星][8m] [C] [nongiach/sudo_inject](https://github.com/nongiach/sudo_inject) [Linux] Two Privilege Escalation techniques abusing sudo token
- [**443**星][1m] [C#] [rasta-mouse/watson](https://github.com/rasta-mouse/watson) Enumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilities
- [**383**星][3m] [PowerShell] [cyberark/aclight](https://github.com/cyberark/ACLight) A script for advanced discovery of Privileged Accounts - includes Shadow Admins
- [**353**星][2m] [PowerShell] [gdedrouas/exchange-ad-privesc](https://github.com/gdedrouas/exchange-ad-privesc) Exchange privilege escalations to Active Directory
- [**337**星][20d] [Shell] [nullarray/roothelper](https://github.com/nullarray/roothelper) 辅助在被攻克系统上的提权过程：自动枚举、下载、解压并执行提权脚本
- [**302**星][4m] [Batchfile] [frizb/windows-privilege-escalation](https://github.com/frizb/windows-privilege-escalation) Windows Privilege Escalation Techniques and Scripts
- [**258**星][3m] [PHP] [lawrenceamer/0xsp-mongoose](https://github.com/lawrenceamer/0xsp-mongoose) Privilege Escalation Enumeration Toolkit (64/32 ) , fast , intelligent enumeration with Web API integration . Mastering Your Own Finding


#### <a id="caab36bba7fa8bb931a9133e37d397f6"></a>Windows


##### <a id="7ed8ee71c4a733d5e5e5d239f0e8b9e0"></a>未分类


- [**328**星][2m] [C] [mattiwatti/efiguard](https://github.com/mattiwatti/efiguard) Disable PatchGuard and DSE at boot time
- [**209**星][1y] [C++] [tandasat/pgresarch](https://github.com/tandasat/pgresarch) PatchGuard Research


##### <a id="58f3044f11a31d0371daa91486d3694e"></a>UAC


- [**2283**星][15d] [C] [hfiref0x/uacme](https://github.com/hfiref0x/uacme) Defeating Windows User Account Control


##### <a id="b84c84a853416b37582c3b7f13eabb51"></a>AppLocker




##### <a id="e3c4c83dfed529ceee65040e565003c4"></a>ActiveDirectory


- [**1943**星][2m] [infosecn1nja/ad-attack-defense](https://github.com/infosecn1nja/ad-attack-defense) Attack and defend active directory using modern post exploitation adversary tradecraft activity


##### <a id="25697cca32bd8c9492b8e2c8a3a93bfe"></a>域渗透






#### <a id="2dd40db455d3c6f1f53f8a9c25bbe63e"></a>驻留&&Persistence


- [**271**星][2m] [C#] [fireeye/sharpersist](https://github.com/fireeye/sharpersist) Windows persistence toolkit 
- [**260**星][1y] [C++] [ewhitehats/invisiblepersistence](https://github.com/ewhitehats/invisiblepersistence) Persisting in the Windows registry "invisibly"




### <a id="fc8737aef0f59c3952d11749fe582dac"></a>自动化


- [**1799**星][4m] [Shell] [arismelachroinos/lscript](https://github.com/arismelachroinos/lscript) 自动化无线渗透和Hacking 任务的脚本
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**1741**星][21d] [Shell] [leebaird/discover](https://github.com/leebaird/discover) 自定义的bash脚本, 用于自动化多个渗透测试任务, 包括: 侦查、扫描、解析、在Metasploit中创建恶意Payload和Listener
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload生成](#ad92f6b801a18934f1971e2512f5ae4f) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Metasploit/未分类-metasploit](#01be61d5bb9f6f7199208ff0fba86b5d) |
- [**1656**星][2m] [Py] [rootm0s/winpwnage](https://github.com/rootm0s/winpwnage) UAC bypass, Elevate, Persistence and Execution methods


### <a id="3ae4408f4ab03f99bab9ef9ee69642a8"></a>数据渗透


- [**453**星][3m] [Py] [viralmaniar/powershell-rat](https://github.com/viralmaniar/powershell-rat) Python based backdoor that uses Gmail to exfiltrate data through attachment. This RAT will help during red team engagements to backdoor any Windows machines. It tracks the user activity using screen capture and sends it to an attacker as an e-mail attachment.


### <a id="adfa06d452147ebacd35981ce56f916b"></a>横向渗透




### <a id="39e9a0fe929fffe5721f7d7bb2dae547"></a>Burp


#### <a id="6366edc293f25b57bf688570b11d6584"></a>收集


- [**1920**星][1y] [BitBake] [1n3/intruderpayloads](https://github.com/1n3/intruderpayloads) A collection of Burpsuite Intruder payloads, BurpBounty payloads, fuzz lists, malicious file uploads and web pentesting methodologies and checklists.
- [**1058**星][27d] [snoopysecurity/awesome-burp-extensions](https://github.com/snoopysecurity/awesome-burp-extensions) Burp扩展收集


#### <a id="5b761419863bc686be12c76451f49532"></a>未分类-Burp


- [**1091**星][1y] [Py] [bugcrowd/hunt](https://github.com/bugcrowd/HUNT) Burp和ZAP的扩展收集
- [**742**星][13d] [Batchfile] [mr-xn/burpsuite-collections](https://github.com/mr-xn/burpsuite-collections) BurpSuite收集：包括不限于 Burp 文章、破解版、插件(非BApp Store)、汉化等相关教程，欢迎添砖加瓦
- [**705**星][1y] [Java] [d3vilbug/hackbar](https://github.com/d3vilbug/hackbar) HackBar plugin for Burpsuite v1.0
- [**646**星][8m] [Java] [vulnerscom/burp-vulners-scanner](https://github.com/vulnerscom/burp-vulners-scanner) Vulnerability scanner based on vulners.com search API
- [**563**星][1y] [Java] [federicodotta/brida](https://github.com/federicodotta/brida) The new bridge between Burp Suite and Frida!
- [**549**星][8m] [Java] [c0ny1/chunked-coding-converter](https://github.com/c0ny1/chunked-coding-converter) Burp suite 分块传输辅助插件
- [**466**星][19d] [Java] [wagiro/burpbounty](https://github.com/wagiro/burpbounty) Burp Bounty (Scan Check Builder in BApp Store) is a extension of Burp Suite that allows you, in a quick and simple way, to improve the active and passive scanner by means of personalized rules through a very intuitive graphical interface.
- [**436**星][5m] [Py] [albinowax/activescanplusplus](https://github.com/albinowax/activescanplusplus) ActiveScan++ Burp Suite Plugin
- [**434**星][1m] [Py] [romanzaikin/burpextension-whatsapp-decryption-checkpoint](https://github.com/romanzaikin/burpextension-whatsapp-decryption-checkpoint) This tool was created during our research at Checkpoint Software Technologies on Whatsapp Protocol (This repository will be updated after BlackHat 2019)
- [**402**星][4m] [Java] [bit4woo/recaptcha](https://github.com/bit4woo/recaptcha) reCAPTCHA = REcognize CAPTCHA: A Burp Suite Extender that recognize CAPTCHA and use for intruder payload 自动识别图形验证码并用于burp intruder爆破模块的插件
- [**397**星][7m] [Java] [nccgroup/burpsuitehttpsmuggler](https://github.com/nccgroup/burpsuitehttpsmuggler) A Burp Suite extension to help pentesters to bypass WAFs or test their effectiveness using a number of techniques
- [**373**星][1y] [Py] [rhinosecuritylabs/sleuthql](https://github.com/rhinosecuritylabs/sleuthql) Python3 Burp History parsing tool to discover potential SQL injection points. To be used in tandem with SQLmap.
- [**371**星][2m] [Java] [nccgroup/autorepeater](https://github.com/nccgroup/autorepeater) Automated HTTP Request Repeating With Burp Suite
- [**352**星][4m] [Java] [bit4woo/domain_hunter](https://github.com/bit4woo/domain_hunter) A Burp Suite Extender that try to find sub-domain, similar-domain and related-domain of an organization, not only a domain! 利用burp收集整个企业、组织的域名（不仅仅是单个主域名）的插件
- [**327**星][2m] [Kotlin] [portswigger/turbo-intruder](https://github.com/portswigger/turbo-intruder) Turbo Intruder is a Burp Suite extension for sending large numbers of HTTP requests and analyzing the results.
- [**309**星][1y] [Java] [ebryx/aes-killer](https://github.com/ebryx/aes-killer) Burp plugin to decrypt AES Encrypted traffic of mobile apps on the fly
- [**300**星][3m] [Java] [bit4woo/knife](https://github.com/bit4woo/knife) A burp extension that add some useful function to Context Menu 添加一些右键菜单让burp用起来更顺畅
- [**300**星][7m] [Java] [ilmila/j2eescan](https://github.com/ilmila/j2eescan) J2EEScan is a plugin for Burp Suite Proxy. The goal of this plugin is to improve the test coverage during web application penetration tests on J2EE applications.
- [**299**星][2m] [Java] [portswigger/http-request-smuggler](https://github.com/PortSwigger/http-request-smuggler) an extension for Burp Suite designed to help you launch HTTP Request Smuggling attack
- [**297**星][11m] [Shell] [yw9381/burp_suite_doc_zh_cn](https://github.com/yw9381/burp_suite_doc_zh_cn) 这是基于Burp Suite官方文档翻译而来的中文版文档
- [**296**星][1y] [Java] [vmware/burp-rest-api](https://github.com/vmware/burp-rest-api) REST/JSON API to the Burp Suite security tool.
- [**272**星][1y] [Java] [elkokc/reflector](https://github.com/elkokc/reflector) reflector：Burp 插件，浏览网页时实时查找反射 XSS
- [**264**星][18d] [Py] [quitten/autorize](https://github.com/quitten/autorize) Automatic authorization enforcement detection extension for burp suite written in Jython developed by Barak Tawily in order to ease application security people work and allow them perform an automatic authorization tests
- [**250**星][2m] [Py] [rhinosecuritylabs/iprotate_burp_extension](https://github.com/rhinosecuritylabs/iprotate_burp_extension) Extension for Burp Suite which uses AWS API Gateway to rotate your IP on every request.
- [**241**星][4m] [Py] [initroot/burpjslinkfinder](https://github.com/initroot/burpjslinkfinder) Burp Extension for a passive scanning JS files for endpoint links.
- [**235**星][1m] [Java] [samlraider/samlraider](https://github.com/samlraider/samlraider) SAML2 Burp Extension
- [**231**星][1y] [Java] [nccgroup/burpsuiteloggerplusplus](https://github.com/nccgroup/burpsuiteloggerplusplus) Burp Suite Logger++: Log activities of all the tools in Burp Suite
- [**230**星][1y] [Py] [audibleblink/doxycannon](https://github.com/audibleblink/doxycannon) DoxyCannon: 为一堆OpenVPN文件分别创建Docker容器, 每个容器开启SOCKS5代理服务器并绑定至Docker主机端口, 再结合使用Burp或ProxyChains, 构建私有的Botnet
- [**230**星][1y] [Java] [difcareer/sqlmap4burp](https://github.com/difcareer/sqlmap4burp) sqlmap embed in burpsuite
- [**222**星][6m] [Java] [c0ny1/jsencrypter](https://github.com/c0ny1/jsencrypter) 一个用于加密传输爆破的Burp Suite插件
- [**214**星][2m] [Java] [c0ny1/passive-scan-client](https://github.com/c0ny1/passive-scan-client) Burp被动扫描流量转发插件
- [**205**星][2m] [Java] [h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator) ZAP/Burp plugin that generate script to reproduce a specific HTTP request (Intended for fuzzing or scripted attacks)
- [**202**星][5m] [Perl] [modzero/mod0burpuploadscanner](https://github.com/modzero/mod0burpuploadscanner) HTTP file upload scanner for Burp Proxy




### <a id="8e7a6a74ff322cbf2bad59092598de77"></a>Metasploit


#### <a id="01be61d5bb9f6f7199208ff0fba86b5d"></a>未分类-metasploit


- [**18724**星][14d] [Ruby] [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework) Metasploit Framework
- [**1741**星][21d] [Shell] [leebaird/discover](https://github.com/leebaird/discover) 自定义的bash脚本, 用于自动化多个渗透测试任务, 包括: 侦查、扫描、解析、在Metasploit中创建恶意Payload和Listener
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/自动化](#fc8737aef0f59c3952d11749fe582dac) |[工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload生成](#ad92f6b801a18934f1971e2512f5ae4f) |
- [**1284**星][1y] [Shell] [dana-at-cp/backdoor-apk](https://github.com/dana-at-cp/backdoor-apk) backdoor-apk is a shell script that simplifies the process of adding a backdoor to any Android APK file. Users of this shell script should have working knowledge of Linux, Bash, Metasploit, Apktool, the Android SDK, smali, etc. This shell script is provided as-is without warranty of any kind and is intended for educational purposes only.
- [**709**星][2m] [C] [rapid7/metasploit-payloads](https://github.com/rapid7/metasploit-payloads) Unified repository for different Metasploit Framework payloads
- [**683**星][2m] [Java] [isafeblue/trackray](https://github.com/isafeblue/trackray) 溯光 (TrackRay) 3 beta⚡渗透测试框架（资产扫描|指纹识别|暴力破解|网页爬虫|端口扫描|漏洞扫描|代码审计|AWVS|NMAP|Metasploit|SQLMap）
- [**445**星][4m] [Py] [cchio/deep-pwning](https://github.com/cchio/deep-pwning) Metasploit for machine learning.
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |
- [**389**星][5m] [Ruby] [praetorian-code/purple-team-attack-automation](https://github.com/praetorian-code/purple-team-attack-automation) Praetorian's public release of our Metasploit automation of MITRE ATT&CK™ TTPs
- [**309**星][10m] [Ruby] [darkoperator/metasploit-plugins](https://github.com/darkoperator/metasploit-plugins) Plugins for Metasploit Framework
- [**298**星][2m] [Ruby] [fozavci/viproy-voipkit](https://github.com/fozavci/viproy-voipkit) VoIP渗透测试工具和 Metasploit 框架
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |
- [**296**星][1m] [Py] [3ndg4me/autoblue-ms17-010](https://github.com/3ndg4me/autoblue-ms17-010) This is just an semi-automated fully working, no-bs, non-metasploit version of the public exploit code for MS17-010
- [**265**星][3m] [Vue] [zerx0r/kage](https://github.com/Zerx0r/Kage) Kage is Graphical User Interface for Metasploit Meterpreter and Session Handler




### <a id="b1161d6c4cb520d0cd574347cd18342e"></a>免杀&&躲避AV检测


- [**1009**星][4m] [C] [govolution/avet](https://github.com/govolution/avet) avet：免杀工具
- [**698**星][9m] [Py] [mr-un1k0d3r/dkmc](https://github.com/mr-un1k0d3r/dkmc) DKMC - Dont kill my cat - Malicious payload evasion tool
- [**620**星][6m] [Py] [paranoidninja/carboncopy](https://github.com/paranoidninja/carboncopy) A tool which creates a spoofed certificate of any online website and signs an Executable for AV Evasion. Works for both Windows and Linux
- [**461**星][1y] [Go] [arvanaghi/checkplease](https://github.com/arvanaghi/checkplease) Sandbox evasion modules written in PowerShell, Python, Go, Ruby, C, C#, Perl, and Rust.
- [**299**星][1y] [Py] [two06/inception](https://github.com/two06/inception) Provides In-memory compilation and reflective loading of C# apps for AV evasion.
- [**280**星][1m] [C#] [ch0pin/aviator](https://github.com/ch0pin/aviator) Antivirus evasion project
- [**252**星][1m] [C#] [hackplayers/salsa-tools](https://github.com/hackplayers/salsa-tools) Salsa Tools - ShellReverse TCP/UDP/ICMP/DNS/SSL/BINDTCP/Shellcode/SILENTTRINITY and AV bypass, AMSI patched


### <a id="98a851c8e6744850efcb27b8e93dff73"></a>C&C


- [**2387**星][3m] [Go] [ne0nd0g/merlin](https://github.com/ne0nd0g/merlin) Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
- [**1104**星][1y] [Py] [byt3bl33d3r/gcat](https://github.com/byt3bl33d3r/gcat) A PoC backdoor that uses Gmail as a C&C server
- [**917**星][19d] [C#] [cobbr/covenant](https://github.com/cobbr/covenant) Covenant is a collaborative .NET C2 framework for red teamers.
- [**632**星][10m] [Py] [mehulj94/braindamage](https://github.com/mehulj94/braindamage) Remote administration tool which uses Telegram as a C&C server
- [**314**星][1y] [C#] [spiderlabs/dohc2](https://github.com/spiderlabs/dohc2) DoHC2 allows the ExternalC2 library from Ryan Hanson (
- [**240**星][14d] [PowerShell] [nettitude/poshc2](https://github.com/nettitude/poshc2) Python Server for PoshC2
- [**240**星][14d] [PowerShell] [nettitude/poshc2](https://github.com/nettitude/PoshC2) Python Server for PoshC2


### <a id="a0897294e74a0863ea8b83d11994fad6"></a>DDOS


- [**2443**星][17d] [C++] [pavel-odintsov/fastnetmon](https://github.com/pavel-odintsov/fastnetmon) 快速 DDoS 检测/分析工具，支持 sflow/netflow/mirror
- [**1174**星][29d] [Shell] [mitchellkrogza/nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) Nginx Block Bad Bots, Spam Referrer Blocker, Vulnerability Scanners, User-Agents, Malware, Adware, Ransomware, Malicious Sites, with anti-DDOS, Wordpress Theme Detector Blocking and Fail2Ban Jail for Repeat Offenders
- [**831**星][2m] [Py] [649/memcrashed-ddos-exploit](https://github.com/649/memcrashed-ddos-exploit) DDoS attack tool for sending forged UDP packets to vulnerable Memcached servers obtained using Shodan API
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/Shodan](#18c7c1df2e6ae5e9135dfa2e4eb1d4db) |
- [**457**星][6m] [Shell] [jgmdev/ddos-deflate](https://github.com/jgmdev/ddos-deflate) Fork of DDoS Deflate with fixes, improvements and new features.
- [**451**星][2m] [JS] [codemanki/cloudscraper](https://github.com/codemanki/cloudscraper) Node.js library to bypass cloudflare's anti-ddos page
- [**374**星][12m] [C] [markus-go/bonesi](https://github.com/markus-go/bonesi) BoNeSi - the DDoS Botnet Simulator
- [**293**星][3m] [Shell] [anti-ddos/anti-ddos](https://github.com/anti-ddos/Anti-DDOS) 
- [**243**星][12m] [Py] [wenfengshi/ddos-dos-tools](https://github.com/wenfengshi/ddos-dos-tools) some sort of ddos-tools


### <a id="8e1069b2bce90b87eea762ee3d0935d8"></a>OWASP


- [**10690**星][13d] [Py] [owasp/cheatsheetseries](https://github.com/owasp/cheatsheetseries) The OWASP Cheat Sheet Series was created to provide a concise collection of high value information on specific application security topics.
- [**2245**星][13d] [Go] [owasp/amass](https://github.com/owasp/amass) In-depth Attack Surface Mapping and Asset Discovery
- [**1902**星][28d] [Perl] [spiderlabs/owasp-modsecurity-crs](https://github.com/spiderlabs/owasp-modsecurity-crs) OWASP ModSecurity Core Rule Set (CRS) Project (Official Repository)
- [**1680**星][1y] [owasp/devguide](https://github.com/owasp/devguide) The OWASP Guide
- [**1390**星][2m] [HTML] [owasp/top10](https://github.com/owasp/top10) Official OWASP Top 10 Document Repository
- [**1000**星][3m] [HTML] [owasp/nodegoat](https://github.com/owasp/nodegoat) 学习OWASP安全威胁Top10如何应用到Web App的，以及如何处理
- [**731**星][2m] [Java] [owasp/securityshepherd](https://github.com/owasp/securityshepherd) Web and mobile application security training platform
- [**665**星][13d] [HTML] [owasp/asvs](https://github.com/owasp/asvs) Application Security Verification Standard
- [**597**星][10m] [Py] [zdresearch/owasp-nettacker](https://github.com/zdresearch/OWASP-Nettacker) Automated Penetration Testing Framework
- [**480**星][17d] [owasp/wstg](https://github.com/OWASP/wstg) The OWASP Web Security Testing Guide includes a "best practice" penetration testing framework which users can implement in their own organizations and a "low level" penetration testing guide that describes techniques for testing most common web application and web service security issues.
- [**480**星][17d] [owasp/wstg](https://github.com/owasp/wstg) The OWASP Web Security Testing Guide includes a "best practice" penetration testing framework which users can implement in their own organizations and a "low level" penetration testing guide that describes techniques for testing most common web application and web service security issues.
- [**461**星][7m] [Java] [owasp/owasp-webscarab](https://github.com/owasp/owasp-webscarab) OWASP WebScarab
- [**402**星][5m] [Py] [stanislav-web/opendoor](https://github.com/stanislav-web/opendoor) OWASP WEB Directory Scanner
- [**360**星][1m] [Java] [zaproxy/zap-extensions](https://github.com/zaproxy/zap-extensions) OWASP ZAP Add-ons
- [**341**星][1m] [Java] [esapi/esapi-java-legacy](https://github.com/esapi/esapi-java-legacy) ESAPI (The OWASP Enterprise Security API) is a free, open source, web application security control library that makes it easier for programmers to write lower-risk applications.
- [**292**星][5m] [0xradi/owasp-web-checklist](https://github.com/0xradi/owasp-web-checklist) OWASP Web Application Security Testing Checklist
- [**271**星][5m] [JS] [mike-goodwin/owasp-threat-dragon](https://github.com/mike-goodwin/owasp-threat-dragon) An open source, online threat modelling tool from OWASP
- [**269**星][4m] [tanprathan/owasp-testing-checklist](https://github.com/tanprathan/owasp-testing-checklist) OWASP based Web Application Security Testing Checklist is an Excel based checklist which helps you to track the status of completed and pending test cases.
- [**248**星][11m] [Java] [owasp/owasp-java-encoder](https://github.com/owasp/owasp-java-encoder) The OWASP Java Encoder is a Java 1.5+ simple-to-use drop-in high-performance encoder class with no dependencies and little baggage. This project will help Java web developers defend against Cross Site Scripting!
- [**225**星][1m] [owasp/api-security](https://github.com/owasp/api-security) OWASP API Security Project


### <a id="7667f6a0381b6cded2014a0d279b5722"></a>Kali


- [**2522**星][7m] [offensive-security/kali-nethunter](https://github.com/offensive-security/kali-nethunter) The Kali NetHunter Project
- [**2332**星][7m] [Py] [lionsec/katoolin](https://github.com/lionsec/katoolin) Automatically install all Kali linux tools
- [**1690**星][2m] [PHP] [xtr4nge/fruitywifi](https://github.com/xtr4nge/fruitywifi) FruityWiFi is a wireless network auditing tool. The application can be installed in any Debian based system (Jessie) adding the extra packages. Tested in Debian, Kali Linux, Kali Linux ARM (Raspberry Pi), Raspbian (Raspberry Pi), Pwnpi (Raspberry Pi), Bugtraq, NetHunter.
- [**849**星][10m] [Shell] [esc0rtd3w/wifi-hacker](https://github.com/esc0rtd3w/wifi-hacker) Shell Script For Attacking Wireless Connections Using Built-In Kali Tools. Supports All Securities (WEP, WPS, WPA, WPA2)
- [**714**星][3m] [Py] [rajkumrdusad/tool-x](https://github.com/rajkumrdusad/tool-x) Tool-X is a kali linux hacking Tool installer. Tool-X developed for termux and other android terminals. using Tool-X you can install almost 263 hacking tools in termux app and other linux based distributions.
- [**667**星][7m] [offensive-security/kali-arm-build-scripts](https://github.com/offensive-security/kali-arm-build-scripts) Kali Linux ARM build scripts
- [**542**星][1m] [Shell] [offensive-security/kali-linux-docker](https://github.com/offensive-security/kali-linux-docker) PLEASE USE GITLAB
- [**385**星][3m] [jack-liang/kalitools](https://github.com/jack-liang/kalitools) Kali Linux工具清单
- [**328**星][7m] [offensive-security/kali-linux-recipes](https://github.com/offensive-security/kali-linux-recipes) Kali Linux Recipes


### <a id="0b8e79b79094082d0906153445d6ef9a"></a>CobaltStrike


- [**389**星][1y] [Shell] [killswitch-gui/cobaltstrike-toolkit](https://github.com/killswitch-gui/cobaltstrike-toolkit) Some useful scripts for CobaltStrike
- [**203**星][1y] [C#] [spiderlabs/sharpcompile](https://github.com/spiderlabs/sharpcompile) SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime. This is a more slick approach than manually compiling an .NET assembly and loading it into Cobalt Strike. The project aims to make it easier to move away from adhoc PowerShell execution instead creating a temporary assembly and executing…




***


## <a id="8f92ead9997a4b68d06a9acf9b01ef63"></a>扫描器&&安全扫描&&App扫描&&漏洞扫描


### <a id="de63a029bda6a7e429af272f291bb769"></a>未分类-Scanner


- [**11006**星][2m] [C] [robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) masscan：世界上最快的互联网端口扫描器，号称可6分钟内扫描整个互联网
- [**7288**星][25d] [Py] [s0md3v/xsstrike](https://github.com/s0md3v/XSStrike) Most advanced XSS scanner.
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/XSS&&XXE/未分类-XSS](#648e49b631ea4ba7c128b53764328c39) |
- [**5245**星][1m] [Go] [zricethezav/gitleaks](https://github.com/zricethezav/gitleaks) Audit git repos for secrets
- [**4474**星][16d] [Ruby] [wpscanteam/wpscan](https://github.com/wpscanteam/wpscan) WPScan is a free, for non-commercial use, black box WordPress Vulnerability Scanner written for security professionals and blog maintainers to test the security of their WordPress websites.
- [**4101**星][24d] [we5ter/scanners-box](https://github.com/we5ter/scanners-box)  安全行业从业者自研开源扫描器合辑
- [**3375**星][1m] [Perl] [sullo/nikto](https://github.com/sullo/nikto) Nikto web server scanner
- [**3119**星][2m] [Go] [mozilla/sops](https://github.com/mozilla/sops) Simple and flexible tool for managing secrets
- [**3049**星][20d] [Py] [maurosoria/dirsearch](https://github.com/maurosoria/dirsearch) Web path scanner
- [**3022**星][2m] [C] [zmap/zmap](https://github.com/zmap/zmap) ZMap is a fast single packet network scanner designed for Internet-wide network surveys.
- [**2904**星][21d] [Py] [andresriancho/w3af](https://github.com/andresriancho/w3af) Web App安全扫描器, 辅助开发者和渗透测试人员识别和利用Web App中的漏洞
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞扫描&&挖掘&&发现/漏洞扫描/未分类](#0ed7e90d216a8a5be1dafebaf9eaeb5d) |
- [**2261**星][3m] [JS] [retirejs/retire.js](https://github.com/retirejs/retire.js) scanner detecting the use of JavaScript libraries with known vulnerabilities
- [**2027**星][2m] [Ruby] [urbanadventurer/whatweb](https://github.com/urbanadventurer/whatweb) Next generation web scanner
- [**2023**星][2m] [Py] [nabla-c0d3/sslyze](https://github.com/nabla-c0d3/sslyze) SSL/TLS服务器扫描
- [**1630**星][1m] [NSIS] [angryip/ipscan](https://github.com/angryip/ipscan) Angry IP Scanner - fast and friendly network scanner
- [**1530**星][7m] [Py] [m4ll0k/wascan](https://github.com/m4ll0k/WAScan) WAScan - Web Application Scanner
- [**1494**星][4m] [Py] [hannob/snallygaster](https://github.com/hannob/snallygaster) Python脚本, 扫描HTTP服务器"秘密文件"
- [**1060**星][2m] [PHP] [tuhinshubhra/red_hawk](https://github.com/tuhinshubhra/red_hawk) 信息收集、漏洞扫描、爬虫多合一
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |
- [**1054**星][3m] [Py] [gerbenjavado/linkfinder](https://github.com/gerbenjavado/linkfinder) A python script that finds endpoints in JavaScript files
- [**1037**星][7m] [Py] [lucifer1993/struts-scan](https://github.com/lucifer1993/struts-scan) struts2漏洞全版本检测和利用工具
- [**985**星][3m] [Py] [h4ckforjob/dirmap](https://github.com/h4ckforjob/dirmap) 一个高级web目录、文件扫描工具，功能将会强于DirBuster、Dirsearch、cansina、御剑。
- [**905**星][2m] [Py] [tuhinshubhra/cmseek](https://github.com/tuhinshubhra/cmseek) CMS Detection and Exploitation suite - Scan WordPress, Joomla, Drupal and over 170 other CMSs
- [**880**星][5m] [PHP] [tidesec/wdscanner](https://github.com/tidesec/wdscanner) 分布式web漏洞扫描、客户管理、漏洞定期扫描、子域名枚举、端口扫描、网站爬虫、暗链检测、坏链检测、网站指纹搜集、专项漏洞检测、代理搜集及部署等功能。
- [**862**星][1m] [Py] [ajinabraham/nodejsscan](https://github.com/ajinabraham/nodejsscan) NodeJsScan is a static security code scanner for Node.js applications.
- [**759**星][17d] [Py] [vesche/scanless](https://github.com/vesche/scanless) scanless：端口扫描器
- [**741**星][19d] [Py] [nekmo/dirhunt](https://github.com/nekmo/dirhunt) Web爬虫, 针对搜索和分析路径做了优化
    - 重复区段: [工具/爬虫](#785ad72c95e857273dce41842f5e8873) |
- [**722**星][6m] [Py] [ztgrace/changeme](https://github.com/ztgrace/changeme) 默认证书扫描器
- [**694**星][4m] [CSS] [ajinabraham/cmsscan](https://github.com/ajinabraham/cmsscan) Scan Wordpress, Drupal, Joomla, vBulletin websites for Security issues
- [**690**星][2m] [CSS] [boy-hack/w12scan](https://github.com/w-digital-scanner/w12scan) a network asset discovery engine that can automatically aggregate related assets for analysis and use
- [**681**星][28d] [C] [scanmem/scanmem](https://github.com/scanmem/scanmem) memory scanner for Linux
- [**671**星][1m] [Ruby] [mozilla/ssh_scan](https://github.com/mozilla/ssh_scan) A prototype SSH configuration and policy scanner (Blog:
- [**657**星][7m] [Py] [m4ll0k/wpseku](https://github.com/m4ll0k/wpseku) WPSeku - Wordpress Security Scanner
- [**656**星][2m] [Py] [kevthehermit/pastehunter](https://github.com/kevthehermit/pastehunter) Scanning pastebin with yara rules
- [**649**星][5m] [Py] [droope/droopescan](https://github.com/droope/droopescan) A plugin-based scanner that aids security researchers in identifying issues with several CMSs, mainly Drupal & Silverstripe.
- [**636**星][1y] [Py] [lmco/laikaboss](https://github.com/lmco/laikaboss) Laika BOSS: Object Scanning System
- [**613**星][5m] [Py] [rabbitmask/weblogicscan](https://github.com/rabbitmask/weblogicscan) Weblogic一键漏洞检测工具，V1.3
- [**612**星][12m] [Ruby] [thesp0nge/dawnscanner](https://github.com/thesp0nge/dawnscanner) Dawn is a static analysis security scanner for ruby written web applications. It supports Sinatra, Padrino and Ruby on Rails frameworks.
- [**604**星][4m] [Py] [faizann24/xsspy](https://github.com/faizann24/xsspy) Web Application XSS Scanner
- [**569**星][2m] [HTML] [gwillem/magento-malware-scanner](https://github.com/gwillem/magento-malware-scanner) 用于检测 Magento 恶意软件的规则/样本集合
- [**564**星][2m] [Perl] [alisamtechnology/atscan](https://github.com/alisamtechnology/atscan) Advanced dork Search & Mass Exploit Scanner
- [**555**星][5m] [Py] [codingo/vhostscan](https://github.com/codingo/vhostscan) A virtual host scanner that performs reverse lookups, can be used with pivot tools, detect catch-all scenarios, work around wildcards, aliases and dynamic default pages.
- [**542**星][7m] [Go] [marco-lancini/goscan](https://github.com/marco-lancini/goscan) Interactive Network Scanner
- [**536**星][4m] [Py] [dhs-ncats/pshtt](https://github.com/cisagov/pshtt) Scan domains and return data based on HTTPS best practices
- [**526**星][6m] [Py] [grayddq/gscan](https://github.com/grayddq/gscan) 本程序旨在为安全应急响应人员对Linux主机排查时提供便利，实现主机侧Checklist的自动全面化检测，根据检测结果自动数据聚合，进行黑客攻击路径溯源。
- [**481**星][1m] [Py] [fcavallarin/htcap](https://github.com/fcavallarin/htcap) htcap is a web application scanner able to crawl single page application (SPA) recursively by intercepting ajax calls and DOM changes.
- [**475**星][1y] [C] [nanshihui/scan-t](https://github.com/nanshihui/scan-t) a new crawler based on python with more function including Network fingerprint search
- [**399**星][2m] [Py] [boy-hack/w13scan](https://github.com/w-digital-scanner/w13scan) Passive Security Scanner (被动安全扫描器)
- [**397**星][10m] [JS] [eviltik/evilscan](https://github.com/eviltik/evilscan) evilscan：大规模 IP/端口扫描器，Node.js 编写
- [**390**星][10m] [Py] [mitre/multiscanner](https://github.com/mitre/multiscanner) Modular file scanning/analysis framework
- [**386**星][1y] [Py] [grayddq/publicmonitors](https://github.com/grayddq/publicmonitors) 对公网IP列表进行端口服务扫描，发现周期内的端口服务变化情况和弱口令安全风险
- [**385**星][1m] [C] [hasherezade/hollows_hunter](https://github.com/hasherezade/hollows_hunter) Scans all running processes. Recognizes and dumps a variety of potentially malicious implants (replaced/implanted PEs, shellcodes, hooks, in-memory patches).
- [**379**星][13d] [Py] [stamparm/dsss](https://github.com/stamparm/dsss) Damn Small SQLi Scanner
- [**340**星][4m] [Py] [swisskyrepo/wordpresscan](https://github.com/swisskyrepo/wordpresscan) WPScan rewritten in Python + some WPSeku ideas
- [**339**星][12m] [Py] [skavngr/rapidscan](https://github.com/skavngr/rapidscan) 
- [**338**星][1m] [Py] [fgeek/pyfiscan](https://github.com/fgeek/pyfiscan) pyfiscan：Web App 漏洞及版本扫描
- [**335**星][3m] [Java] [portswigger/backslash-powered-scanner](https://github.com/portswigger/backslash-powered-scanner) Finds unknown classes of injection vulnerabilities
- [**330**星][1y] [Py] [flipkart-incubator/rta](https://github.com/flipkart-incubator/rta) Red team Arsenal - An intelligent scanner to detect security vulnerabilities in company's layer 7 assets.
- [**316**星][2m] [HTML] [coinbase/salus](https://github.com/coinbase/salus) Security scanner coordinator
- [**315**星][15d] [C] [royhills/arp-scan](https://github.com/royhills/arp-scan) The ARP Scanner
- [**301**星][10m] [PHP] [steverobbins/magescan](https://github.com/steverobbins/magescan) Scan a Magento site for information
- [**299**星][1m] [PowerShell] [canix1/adaclscanner](https://github.com/canix1/adaclscanner) Repo for ADACLScan.ps1 - Your number one script for ACL's in Active Directory
- [**294**星][1y] [Shell] [cryptolok/ghostinthenet](https://github.com/cryptolok/ghostinthenet) Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**294**星][2m] [Ruby] [m0nad/hellraiser](https://github.com/m0nad/hellraiser) Vulnerability Scanner
- [**294**星][1m] [Shell] [mitchellkrogza/apache-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/apache-ultimate-bad-bot-blocker) Apache Block Bad Bots, (Referer) Spam Referrer Blocker, Vulnerability Scanners, Malware, Adware, Ransomware, Malicious Sites, Wordpress Theme Detectors and Fail2Ban Jail for Repeat Offenders
- [**286**星][4m] [enkomio/taipan](https://github.com/enkomio/Taipan) Web application vulnerability scanner
- [**284**星][1y] [Py] [code-scan/dzscan](https://github.com/code-scan/dzscan) Dzscan
- [**280**星][8m] [Py] [boy-hack/w8fuckcdn](https://github.com/boy-hack/w8fuckcdn) 通过扫描全网绕过CDN获取网站IP地址
- [**278**星][3m] [Py] [shenril/sitadel](https://github.com/shenril/sitadel) Web Application Security Scanner
- [**276**星][2m] [Py] [target/strelka](https://github.com/target/strelka) Real-time, container-based file scanning at enterprise scale
- [**268**星][1y] [PHP] [psecio/parse](https://github.com/psecio/parse) Parse: A Static Security Scanner
- [**262**星][5m] [Py] [abhisharma404/vault_scanner](https://github.com/abhisharma404/vault) swiss army knife for hackers
- [**254**星][3m] [Py] [m4ll0k/konan](https://github.com/m4ll0k/Konan) Konan - Advanced Web Application Dir Scanner
- [**253**星][9m] [jeffzh3ng/insectsawake](https://github.com/jeffzh3ng/insectsawake) Network Vulnerability Scanner
- [**246**星][1m] [Py] [gildasio/h2t](https://github.com/gildasio/h2t) h2t (HTTP Hardening Tool) scans a website and suggests security headers to apply
- [**245**星][2m] [Go] [zmap/zgrab2](https://github.com/zmap/zgrab2) Go Application Layer Scanner
- [**235**星][3m] [PHP] [psecio/versionscan](https://github.com/psecio/versionscan) A PHP version scanner for reporting possible vulnerabilities
- [**233**星][7m] [Go] [gocaio/goca](https://github.com/gocaio/goca) Goca Scanner
- [**217**星][5m] [JS] [pavanw3b/sh00t](https://github.com/pavanw3b/sh00t) Security Testing is not as simple as right click > Scan. It's messy, a tough game. What if you had missed to test just that one thing and had to regret later? Sh00t is a highly customizable, intelligent platform that understands the life of bug hunters and emphasizes on manual security testing.
- [**209**星][3m] [Py] [iojw/socialscan](https://github.com/iojw/socialscan) Check email address and username availability on online platforms
- [**207**星][9m] [Py] [nullarray/dorknet](https://github.com/nullarray/dorknet) Selenium powered Python script to automate searching for vulnerable web apps.
- [**202**星][1y] [Py] [dionach/cmsmap](https://github.com/dionach/cmsmap) CMSmap is a python open source CMS scanner that automates the process of detecting security flaws of the most popular CMSs.
- [**201**星][12m] [PowerShell] [sud0woodo/dcomrade](https://github.com/sud0woodo/dcomrade) Powershell script for enumerating vulnerable DCOM Applications


### <a id="58d8b993ffc34f7ded7f4a0077129eb2"></a>隐私&&Secret&&Privacy扫描


- [**6673**星][10m] [Shell] [awslabs/git-secrets](https://github.com/awslabs/git-secrets) Prevents you from committing secrets and credentials into git repositories
- [**4346**星][7m] [Py] [boxug/trape](https://github.com/jofpin/trape) 学习在互联网上跟踪别人，获取其详细信息，并避免被别人跟踪
- [**3064**星][28d] [Py] [tribler/tribler](https://github.com/tribler/tribler) Privacy enhanced BitTorrent client with P2P content discovery
- [**1102**星][4m] [Vue] [0xbug/hawkeye](https://github.com/0xbug/hawkeye) GitHub 泄露监控系统(GitHub Sensitive Information Leakage Monitor Spider)
- [**935**星][20d] [Py] [mozilla/openwpm](https://github.com/mozilla/OpenWPM) A web privacy measurement framework
- [**884**星][2m] [C#] [elevenpaths/foca](https://github.com/elevenpaths/foca) Tool to find metadata and hidden information in the documents.
- [**822**星][18d] [Py] [al0ne/vxscan](https://github.com/al0ne/vxscan) python3写的综合扫描工具，主要用来存活验证，敏感文件探测(目录扫描/js泄露接口/html注释泄露)，WAF/CDN识别，端口扫描，指纹/服务识别，操作系统识别，POC扫描，SQL注入，绕过CDN，查询旁站等功能，主要用来甲方自测或乙方授权测试，请勿用来搞破坏。
- [**390**星][6m] [Py] [repoog/gitprey](https://github.com/repoog/gitprey) Searching sensitive files and contents in GitHub associated to company name or other key words
- [**356**星][2m] [Py] [hell0w0rld0/github-hunter](https://github.com/hell0w0rld0/github-hunter) This tool is for sensitive information searching on Github - The Fast Version here:
- [**312**星][15d] [HTML] [tanjiti/sec_profile](https://github.com/tanjiti/sec_profile) 爬取secwiki和xuanwu.github.io/sec.today,分析安全信息站点、安全趋势、提取安全工作者账号(twitter,weixin,github等)
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/社交网络/Github](#8d1ae776898748b8249132e822f6c919) |


### <a id="1927ed0a77ff4f176b0b7f7abc551e4a"></a>隐私存储


#### <a id="1af1c4f9dba1db2a4137be9c441778b8"></a>未分类


- [**5029**星][2m] [Shell] [stackexchange/blackbox](https://github.com/stackexchange/blackbox) 文件使用PGP加密后隐藏在Git/Mercurial/Subversion


#### <a id="362dfd9c1f530dd20f922fd4e0faf0e3"></a>隐写


- [**569**星][1m] [Go] [dimitarpetrov/stegify](https://github.com/dimitarpetrov/stegify) Go tool for LSB steganography, capable of hiding any file within an image.
- [**344**星][6m] [Go] [lukechampine/jsteg](https://github.com/lukechampine/jsteg) JPEG steganography
- [**342**星][5m] [Java] [syvaidya/openstego](https://github.com/syvaidya/openstego) OpenStego is a steganography application that provides two functionalities: a) Data Hiding: It can hide any data within a cover file (e.g. images). b) Watermarking: Watermarking files (e.g. images) with an invisible signature. It can be used to detect unauthorized file copying.
- [**274**星][1y] [C] [abeluck/stegdetect](https://github.com/abeluck/stegdetect) UNMAINTAINED. USE AT OWN RISK. Stegdetect is an automated tool for detecting steganographic content in images.
- [**256**星][26d] [Py] [cedricbonhomme/stegano](https://github.com/cedricbonhomme/stegano) Stegano is a pure Python steganography module.






***


## <a id="a76463feb91d09b3d024fae798b92be6"></a>侦察&&信息收集&&子域名发现与枚举&&OSINT


### <a id="05ab1b75266fddafc7195f5b395e4d99"></a>未分类-OSINT


- [**7042**星][28d] [Java] [lionsoul2014/ip2region](https://github.com/lionsoul2014/ip2region) Ip2region is a offline IP location library with accuracy rate of 99.9% and 0.0x millseconds searching performance. DB file is less then 5Mb with all ip address stored. binding for Java,PHP,C,Python,Nodejs,Golang,C#,lua. Binary,B-tree,Memory searching algorithm
- [**6894**星][27d] [greatfire/wiki](https://github.com/greatfire/wiki) 自由浏览
- [**6109**星][9m] [Py] [schollz/howmanypeoplearearound](https://github.com/schollz/howmanypeoplearearound) 检测 Wifi 信号统计你周围的人数
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**2154**星][28d] [C] [texane/stlink](https://github.com/texane/stlink) stm32 discovery line linux programmer
- [**2061**星][16d] [Py] [fortynorthsecurity/eyewitness](https://github.com/FortyNorthSecurity/EyeWitness) 给网站做快照，提供服务器Header信息，识别默认凭证等
- [**1741**星][21d] [Shell] [leebaird/discover](https://github.com/leebaird/discover) 自定义的bash脚本, 用于自动化多个渗透测试任务, 包括: 侦查、扫描、解析、在Metasploit中创建恶意Payload和Listener
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/自动化](#fc8737aef0f59c3952d11749fe582dac) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload生成](#ad92f6b801a18934f1971e2512f5ae4f) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Metasploit/未分类-metasploit](#01be61d5bb9f6f7199208ff0fba86b5d) |
- [**1627**星][28d] [Py] [cea-sec/ivre](https://github.com/cea-sec/ivre) Network recon framework.
- [**1593**星][28d] [Go] [awnumar/memguard](https://github.com/awnumar/memguard) 处理内存中敏感的值，纯Go语言编写。
- [**1591**星][4m] [Py] [mozilla/cipherscan](https://github.com/mozilla/cipherscan) 查找指定目标支持的SSL ciphersuites
- [**1392**星][6m] [Py] [enablesecurity/wafw00f](https://github.com/enablesecurity/wafw00f) 识别保护网站的WAF产品
- [**1309**星][3m] [JS] [lockfale/osint-framework](https://github.com/lockfale/osint-framework) OSINT Framework
- [**1301**星][26d] [CSS] [undeadsec/socialfish](https://github.com/undeadsec/socialfish) 网络钓鱼培训与信息收集
    - 重复区段: [工具/社工(SET)&&钓鱼&&鱼叉攻击/未分类-SET](#ce734598055ad3885d45d0b35d2bf0d7) |
- [**1261**星][1m] [Py] [s0md3v/arjun](https://github.com/s0md3v/Arjun) HTTP parameter discovery suite.
- [**1256**星][2m] [Py] [codingo/reconnoitre](https://github.com/codingo/reconnoitre) A security tool for multithreaded information gathering and service enumeration whilst building directory structures to store results, along with writing out recommendations for further testing.
- [**1253**星][1y] [PowerShell] [dafthack/mailsniper](https://github.com/dafthack/mailsniper) 在Microsoft Exchange环境中搜索邮件中包含的指定内容：密码、insider intel、网络架构信息等
- [**1180**星][15d] [Py] [codingo/nosqlmap](https://github.com/codingo/NoSQLMap) Automated NoSQL database enumeration and web application exploitation tool.
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞利用/漏洞利用](#c83f77f27ccf5f26c8b596979d7151c3) |[工具/数据库&&SQL攻击&&SQL注入/NoSQL/未分类-NoSQL](#af0aaaf233cdff3a88d04556dc5871e0) |
- [**1135**星][10m] [C] [blechschmidt/massdns](https://github.com/blechschmidt/massdns) A high-performance DNS stub resolver for bulk lookups and reconnaissance (subdomain enumeration)
- [**1060**星][2m] [PHP] [tuhinshubhra/red_hawk](https://github.com/tuhinshubhra/red_hawk) 信息收集、漏洞扫描、爬虫多合一
    - 重复区段: [工具/扫描器&&安全扫描&&App扫描&&漏洞扫描/未分类-Scanner](#de63a029bda6a7e429af272f291bb769) |
- [**1041**星][1m] [Rust] [fgribreau/mailchecker](https://github.com/fgribreau/mailchecker) 邮件检测库，跨语言。覆盖33078虚假邮件提供者
- [**944**星][4m] [C] [rbsec/sslscan](https://github.com/rbsec/sslscan) 测试启用SSL/TLS的服务，发现其支持的cipher suites
- [**930**星][2m] [Py] [sundowndev/phoneinfoga](https://github.com/sundowndev/phoneinfoga) Advanced information gathering & OSINT tool for phone numbers
- [**924**星][17d] [OCaml] [airbus-seclab/bincat](https://github.com/airbus-seclab/bincat) 二进制代码静态分析工具。值分析（寄存器、内存）、污点分析、类型重建和传播（propagation）、前向/后向分析
- [**871**星][4m] [derpopo/uabe](https://github.com/derpopo/uabe) Unity Assets Bundle Extractor
- [**851**星][7m] [Py] [s0md3v/recondog](https://github.com/s0md3v/ReconDog) Reconnaissance Swiss Army Knife
- [**760**星][12m] [HTML] [sense-of-security/adrecon](https://github.com/sense-of-security/adrecon) 收集Active Directory信息并生成报告
- [**742**星][3m] [Py] [threatexpress/domainhunter](https://github.com/threatexpress/domainhunter) Checks expired domains for categorization/reputation and Archive.org history to determine good candidates for phishing and C2 domain names
    - 重复区段: [工具/社工(SET)&&钓鱼&&鱼叉攻击/未分类-SET](#ce734598055ad3885d45d0b35d2bf0d7) |
- [**698**星][17d] [Ruby] [intrigueio/intrigue-core](https://github.com/intrigueio/intrigue-core) 外部攻击面发现框架，自动化OSINT
- [**694**星][27d] [Py] [khast3x/h8mail](https://github.com/khast3x/h8mail) Password Breach Hunting and Email OSINT tool, locally or using premium services. Supports chasing down related email
- [**680**星][4m] [Shell] [nahamsec/lazyrecon](https://github.com/nahamsec/lazyrecon) 侦查(reconnaissance)过程自动化脚本, 可自动使用Sublist3r/certspotter获取子域名, 调用nmap/dirsearch等
- [**617**星][5m] [Py] [deibit/cansina](https://github.com/deibit/cansina) cansina：web 内容发现工具。发出各种请求并过滤回复，识别是否存在请求的资源。
- [**579**星][7m] [Py] [ekultek/zeus-scanner](https://github.com/ekultek/zeus-scanner) Advanced reconnaissance utility
- [**537**星][8m] [Py] [m4ll0k/infoga](https://github.com/m4ll0k/infoga) infoga：邮件信息收集工具
- [**483**星][2m] [no-github/digital-privacy](https://github.com/no-github/digital-privacy) 一个关于数字隐私搜集、保护、清理集一体的方案,外加开源信息收集(OSINT)对抗
- [**463**星][3m] [Py] [xillwillx/skiptracer](https://github.com/xillwillx/skiptracer) OSINT python webscaping framework
- [**462**星][14d] [Rust] [kpcyrd/sn0int](https://github.com/kpcyrd/sn0int) Semi-automatic OSINT framework and package manager
- [**417**星][2m] [Py] [superhedgy/attacksurfacemapper](https://github.com/superhedgy/attacksurfacemapper) AttackSurfaceMapper is a tool that aims to automate the reconnaissance process.
- [**404**星][4m] [Shell] [d4rk007/redghost](https://github.com/d4rk007/redghost) Linux post exploitation framework written in bash designed to assist red teams in persistence, reconnaissance, privilege escalation and leaving no trace.
- [**388**星][3m] [Go] [graniet/operative-framework](https://github.com/graniet/operative-framework) operative framework is a OSINT investigation framework, you can interact with multiple targets, execute multiple modules, create links with target, export rapport to PDF file, add note to target or results, interact with RESTFul API, write your own modules.
- [**387**星][12m] [Py] [chrismaddalena/odin](https://github.com/chrismaddalena/odin) Automated network asset, email, and social media profile discovery and cataloguing.
- [**378**星][2m] [ph055a/osint-collection](https://github.com/ph055a/osint-collection) Maintained collection of OSINT related resources. (All Free & Actionable)
- [**362**星][1m] [Py] [dedsecinside/torbot](https://github.com/dedsecinside/torbot) Dark Web OSINT Tool
- [**350**星][11m] [Py] [aancw/belati](https://github.com/aancw/belati) The Traditional Swiss Army Knife for OSINT
- [**350**星][18d] [Py] [depthsecurity/armory](https://github.com/depthsecurity/armory) Armory is a tool meant to take in a lot of external and discovery data from a lot of tools, add it to a database and correlate all of related information.
- [**335**星][1m] [Py] [darryllane/bluto](https://github.com/darryllane/bluto) DNS Recon | Brute Forcer | DNS Zone Transfer | DNS Wild Card Checks | DNS Wild Card Brute Forcer | Email Enumeration | Staff Enumeration | Compromised Account Checking
- [**329**星][11m] [Py] [mdsecactivebreach/linkedint](https://github.com/mdsecactivebreach/linkedint) A LinkedIn scraper for reconnaissance during adversary simulation
- [**320**星][5m] [Go] [nhoya/gosint](https://github.com/nhoya/gosint) OSINT Swiss Army Knife
- [**304**星][4m] [Py] [initstring/linkedin2username](https://github.com/initstring/linkedin2username) Generate username lists for companies on LinkedIn
- [**302**星][1y] [Py] [sharadkumar97/osint-spy](https://github.com/sharadkumar97/osint-spy) Performs OSINT scan on email/domain/ip_address/organization using OSINT-SPY. It can be used by Data Miners, Infosec Researchers, Penetration Testers and cyber crime investigator in order to find deep information about their target. If you want to ask something please feel free to reach out to me at sharad@osint-spy.com
- [**299**星][1y] [Py] [twelvesec/gasmask](https://github.com/twelvesec/gasmask) Information gathering tool - OSINT
- [**296**星][11m] [Py] [r3vn/badkarma](https://github.com/r3vn/badkarma) network reconnaissance toolkit
- [**289**星][6m] [Shell] [eschultze/urlextractor](https://github.com/eschultze/urlextractor) Information gathering & website reconnaissance |
- [**284**星][2m] [JS] [pownjs/pown-recon](https://github.com/pownjs/pown-recon) A powerful target reconnaissance framework powered by graph theory.
- [**279**星][1y] [Shell] [ha71/namechk](https://github.com/ha71/namechk) Osint tool based on namechk.com for checking usernames on more than 100 websites, forums and social networks.
- [**268**星][1y] [Go] [tomsteele/blacksheepwall](https://github.com/tomsteele/blacksheepwall) blacksheepwall is a hostname reconnaissance tool
- [**264**星][2m] [Py] [ekultek/whatbreach](https://github.com/ekultek/whatbreach) OSINT tool to find breached emails, databases, pastes, and relevant information
- [**242**星][2m] [Shell] [solomonsklash/chomp-scan](https://github.com/solomonsklash/chomp-scan) A scripted pipeline of tools to streamline the bug bounty/penetration test reconnaissance phase, so you can focus on chomping bugs.
- [**236**星][13d] [Py] [zephrfish/googd0rker](https://github.com/zephrfish/googd0rker) GoogD0rker is a tool for firing off google dorks against a target domain, it is purely for OSINT against a specific target domain. READ the readme before messaging or tweeting me.
- [**229**星][7m] [JS] [cliqz-oss/local-sheriff](https://github.com/cliqz-oss/local-sheriff) Think of Local sheriff as a recon tool in your browser (WebExtension). While you normally browse the internet, Local Sheriff works in the background to empower you in identifying what data points (PII) are being shared / leaked to which all third-parties.
- [**229**星][1m] [Propeller Spin] [grandideastudio/jtagulator](https://github.com/grandideastudio/jtagulator) Assisted discovery of on-chip debug interfaces
- [**227**星][1m] [Py] [sc1341/instagramosint](https://github.com/sc1341/instagramosint) An Instagram Open Source Intelligence Tool
- [**225**星][1m] [Py] [anon-exploiter/sitebroker](https://github.com/anon-exploiter/sitebroker) A cross-platform python based utility for information gathering and penetration testing automation!
- [**220**星][3m] [Py] [thewhiteh4t/finalrecon](https://github.com/thewhiteh4t/finalrecon) OSINT Tool for All-In-One Web Reconnaissance
- [**220**星][13d] [PowerShell] [tonyphipps/meerkat](https://github.com/tonyphipps/meerkat) A collection of PowerShell modules designed for artifact gathering and reconnaisance of Windows-based endpoints.
- [**219**星][3m] [Py] [eth0izzle/the-endorser](https://github.com/eth0izzle/the-endorser) An OSINT tool that allows you to draw out relationships between people on LinkedIn via endorsements/skills.
- [**218**星][1y] [Shell] [edoverflow/megplus](https://github.com/edoverflow/megplus) Automated reconnaissance wrapper — TomNomNom's meg on steroids. [DEPRECATED]
- [**210**星][4m] [Py] [spiderlabs/hosthunter](https://github.com/spiderlabs/hosthunter) HostHunter a recon tool for discovering hostnames using OSINT techniques.


### <a id="e945721056c78a53003e01c3d2f3b8fe"></a>子域名枚举&&爆破


- [**4008**星][1m] [Py] [aboul3la/sublist3r](https://github.com/aboul3la/sublist3r) Fast subdomains enumeration tool for penetration testers
- [**3147**星][15d] [Py] [laramies/theharvester](https://github.com/laramies/theharvester) E-mails, subdomains and names Harvester - OSINT
- [**2981**星][6m] [Go] [michenriksen/aquatone](https://github.com/michenriksen/aquatone) 子域名枚举工具。除了经典的爆破枚举之外，还利用多种开源工具和在线服务大幅度增加发现子域名的数量。
- [**1750**星][6m] [Py] [lijiejie/subdomainsbrute](https://github.com/lijiejie/subdomainsbrute) 子域名爆破
- [**1686**星][1m] [Go] [subfinder/subfinder](https://github.com/subfinder/subfinder) 使用Passive Sources, Search Engines, Pastebins, Internet Archives等查找子域名
- [**1668**星][7m] [Py] [guelfoweb/knock](https://github.com/guelfoweb/knock) 使用 Wordlist 枚举子域名
    - 重复区段: [工具/wordlist/未分类-wordlist](#af1d71122d601229dc4aa9d08f4e3e15) |
- [**1555**星][14d] [Go] [caffix/amass](https://github.com/caffix/amass) 子域名枚举, 搜索互联网数据源, 使用机器学习猜测子域名. Go语言
- [**1087**星][1m] [Py] [john-kurkowski/tldextract](https://github.com/john-kurkowski/tldextract) Accurately separate the TLD from the registered domain and subdomains of a URL, using the Public Suffix List.
- [**752**星][12d] [Rust] [edu4rdshl/findomain](https://github.com/edu4rdshl/findomain) The fastest and cross-platform subdomain enumerator, don't waste your time.
- [**687**星][4m] [Go] [haccer/subjack](https://github.com/haccer/subjack) 异步多线程扫描子域列表，识别能够被劫持的子域。Go 编写
- [**639**星][1y] [Py] [simplysecurity/simplyemail](https://github.com/SimplySecurity/SimplyEmail) Email recon made fast and easy, with a framework to build on
- [**573**星][2m] [Py] [jonluca/anubis](https://github.com/jonluca/anubis) Subdomain enumeration and information gathering tool
- [**537**星][8m] [Py] [feeicn/esd](https://github.com/feeicn/esd) Enumeration sub domains(枚举子域名)
- [**468**星][1m] [Py] [typeerror/domained](https://github.com/TypeError/domained) Multi Tool Subdomain Enumeration
- [**435**星][1y] [Go] [ice3man543/subover](https://github.com/ice3man543/subover) A Powerful Subdomain Takeover Tool
- [**434**星][5m] [Py] [threezh1/jsfinder](https://github.com/threezh1/jsfinder) JSFinder is a tool for quickly extracting URLs and subdomains from JS files on a website.
- [**425**星][1m] [Py] [nsonaniya2010/subdomainizer](https://github.com/nsonaniya2010/subdomainizer) A tool to find subdomains and interesting things hidden inside, external Javascript files of page, folder, and Github.
- [**422**星][10m] [Py] [appsecco/bugcrowd-levelup-subdomain-enumeration](https://github.com/appsecco/bugcrowd-levelup-subdomain-enumeration) This repository contains all the material from the talk "Esoteric sub-domain enumeration techniques" given at Bugcrowd LevelUp 2017 virtual conference
- [**407**星][2m] [Py] [yanxiu0614/subdomain3](https://github.com/yanxiu0614/subdomain3) subdomain3：简单快速的子域名爆破工具。
- [**327**星][4m] [Py] [chris408/ct-exposer](https://github.com/chris408/ct-exposer) An OSINT tool that discovers sub-domains by searching Certificate Transparency logs
- [**302**星][1y] [Py] [christophetd/censys-subdomain-finder](https://github.com/christophetd/censys-subdomain-finder) 利用搜索引擎 Censys 提供的 certificate transparency 日志, 实现子域名枚举. (Censys: 搜索联网设备信息的搜索引擎)
- [**275**星][7m] [Py] [franccesco/getaltname](https://github.com/franccesco/getaltname) 直接从SSL证书中提取子域名或虚拟域名
- [**254**星][10m] [Py] [appsecco/the-art-of-subdomain-enumeration](https://github.com/appsecco/the-art-of-subdomain-enumeration) This repository contains all the supplement material for the book "The art of sub-domain enumeration"
- [**251**星][5m] [Go] [anshumanbh/tko-subs](https://github.com/anshumanbh/tko-subs) A tool that can help detect and takeover subdomains with dead DNS records
- [**204**星][1m] [Shell] [screetsec/sudomy](https://github.com/screetsec/sudomy) Sudomy is a subdomain enumeration tool, created using a bash script, to analyze domains and collect subdomains in fast and comprehensive way . Report output in HTML or CSV format


### <a id="375a8baa06f24de1b67398c1ac74ed24"></a>信息收集&&侦查&&Recon&&InfoGather


- [**3496**星][15d] [Shell] [drwetter/testssl.sh](https://github.com/drwetter/testssl.sh) 检查服务器任意端口对 TLS/SSL 的支持、协议以及一些加密缺陷，命令行工具
- [**2378**星][15d] [Py] [smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) 自动收集指定目标的信息：IP、域名、主机名、网络子网、ASN、邮件地址、用户名
- [**2168**星][1y] [Py] [datasploit/datasploit](https://github.com/DataSploit/datasploit) 对指定目标执行多种侦查技术：企业、人、电话号码、比特币地址等
- [**1963**星][8m] [JS] [weichiachang/stacks-cli](https://github.com/weichiachang/stacks-cli) Check website stack from the terminal
- [**1873**星][1m] [Py] [j3ssie/osmedeus](https://github.com/j3ssie/osmedeus) Fully automated offensive security framework for reconnaissance and vulnerability scanning
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞扫描&&挖掘&&发现/漏洞扫描/未分类](#0ed7e90d216a8a5be1dafebaf9eaeb5d) |
- [**1629**星][1y] [Py] [evyatarmeged/raccoon](https://github.com/evyatarmeged/raccoon) 高性能的侦查和漏洞扫描工具
    - 重复区段: [工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞扫描&&挖掘&&发现/漏洞扫描/未分类](#0ed7e90d216a8a5be1dafebaf9eaeb5d) |
- [**1420**星][6m] [Py] [oros42/imsi-catcher](https://github.com/oros42/imsi-catcher) This program show you IMSI numbers of cellphones around you.
- [**1271**星][1y] [Go] [evilsocket/xray](https://github.com/evilsocket/xray) 自动化执行一些信息收集、网络映射的初始化工作
- [**619**星][29d] [Py] [tib3rius/autorecon](https://github.com/tib3rius/autorecon) AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
- [**510**星][9m] [Py] [fortynorthsecurity/just-metadata](https://github.com/FortyNorthSecurity/Just-Metadata) Just-Metadata is a tool that gathers and analyzes metadata about IP addresses. It attempts to find relationships between systems within a large dataset.
- [**453**星][19d] [Py] [yassineaboukir/sublert](https://github.com/yassineaboukir/sublert) Sublert is a security and reconnaissance tool which leverages certificate transparency to automatically monitor new subdomains deployed by specific organizations and issued TLS/SSL certificate.
- [**388**星][10m] [Swift] [ibm/mac-ibm-enrollment-app](https://github.com/ibm/mac-ibm-enrollment-app) The Mac@IBM enrollment app makes setting up macOS with Jamf Pro more intuitive for users and easier for IT. The application offers IT admins the ability to gather additional information about their users during setup, allows users to customize their enrollment by selecting apps or bundles of apps to install during setup, and provides users with …
- [**349**星][4m] [C++] [wbenny/pdbex](https://github.com/wbenny/pdbex) pdbex is a utility for reconstructing structures and unions from the PDB into compilable C headers
- [**343**星][27d] [Py] [lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng) Open Source Intelligence gathering tool aimed at reducing the time spent harvesting information from open sources.
- [**283**星][2m] [Py] [govanguard/legion](https://github.com/govanguard/legion) Legion is an open source, easy-to-use, super-extensible and semi-automated network penetration testing tool that aids in discovery, reconnaissance and exploitation of information systems.
- [**269**星][10m] [Py] [LaNMaSteR53/recon-ng](https://bitbucket.org/lanmaster53/recon-ng) 


### <a id="016bb6bd00f1e0f8451f779fe09766db"></a>指纹&&Fingerprinting


- [**8843**星][13d] [JS] [valve/fingerprintjs2](https://github.com/valve/fingerprintjs2) Modern & flexible browser fingerprinting library
- [**3029**星][1m] [JS] [valve/fingerprintjs](https://github.com/valve/fingerprintjs) Anonymous browser fingerprint
- [**1595**星][14d] [JS] [ghacksuserjs/ghacks-user.js](https://github.com/ghacksuserjs/ghacks-user.js) An ongoing comprehensive user.js template for configuring and hardening Firefox privacy, security and anti-fingerprinting
- [**1595**星][9m] [C] [nmikhailov/validity90](https://github.com/nmikhailov/validity90) Reverse engineering of Validity/Synaptics 138a:0090, 138a:0094, 138a:0097, 06cb:0081, 06cb:009a fingerprint readers protocol
- [**918**星][7m] [JS] [song-li/cross_browser](https://github.com/song-li/cross_browser) cross_browser_fingerprinting
- [**783**星][1m] [Py] [salesforce/ja3](https://github.com/salesforce/ja3) SSL/TLS 客户端指纹，用于恶意代码检测
- [**372**星][21d] [Py] [0x4d31/fatt](https://github.com/0x4d31/fatt) FATT /fingerprintAllTheThings - a pyshark based script for extracting network metadata and fingerprints from pcap files and live network traffic
- [**309**星][2m] [Py] [dpwe/audfprint](https://github.com/dpwe/audfprint) Landmark-based audio fingerprinting
- [**305**星][3m] [Py] [salesforce/hassh](https://github.com/salesforce/hassh) HASSH is a network fingerprinting standard which can be used to identify specific Client and Server SSH implementations. The fingerprints can be easily stored, searched and shared in the form of a small MD5 fingerprint.
- [**268**星][1y] [CSS] [w-digital-scanner/w11scan](https://github.com/w-digital-scanner/w11scan) 分布式WEB指纹识别平台 Distributed WEB fingerprint identification platform
- [**240**星][2m] [C] [leebrotherston/tls-fingerprinting](https://github.com/leebrotherston/tls-fingerprinting) TLS Fingerprinting
- [**224**星][2m] [GLSL] [westpointltd/tls_prober](https://github.com/westpointltd/tls_prober) A tool to fingerprint SSL/TLS servers
- [**212**星][1y] [Py] [sensepost/spartan](https://github.com/sensepost/spartan) Frontpage and Sharepoint fingerprinting and attack tool.
- [**200**星][1y] [Erlang] [kudelskisecurity/scannerl](https://github.com/kudelskisecurity/scannerl) scannerl：模块化、分布式指纹识别引擎，在单个主机运行即可扫描数千目标，也可轻松的部署到多台主机


### <a id="6ea9006a5325dd21d246359329a3ede2"></a>收集


- [**3674**星][15d] [jivoi/awesome-osint](https://github.com/jivoi/awesome-osint) OSINT资源收集


### <a id="dc74ad2dd53aa8c8bf3a3097ad1f12b7"></a>社交网络


#### <a id="de93515e77c0ca100bbf92c83f82dc2a"></a>Twitter


- [**2797**星][21d] [Py] [twintproject/twint](https://github.com/twintproject/twint) An advanced Twitter scraping & OSINT tool written in Python that doesn't use Twitter's API, allowing you to scrape a user's followers, following, Tweets and more while evading most API limitations.


#### <a id="8d1ae776898748b8249132e822f6c919"></a>Github


- [**1627**星][22d] [Go] [eth0izzle/shhgit](https://github.com/eth0izzle/shhgit) 监听Github Event API，实时查找Github代码和Gist中的secret和敏感文件
- [**1549**星][1y] [Py] [unkl4b/gitminer](https://github.com/unkl4b/gitminer) Github内容挖掘
- [**1321**星][7m] [Py] [feeicn/gsil](https://github.com/feeicn/gsil) GitHub敏感信息泄露监控，几乎实时监控，发送警告
- [**840**星][7m] [Go] [misecurity/x-patrol](https://github.com/misecurity/x-patrol) github泄露扫描系统
- [**834**星][1m] [JS] [vksrc/github-monitor](https://github.com/vksrc/github-monitor) Github Sensitive Information Leakage Monitor(Github信息泄漏监控系统)
- [**767**星][1m] [Py] [bishopfox/gitgot](https://github.com/bishopfox/gitgot) Semi-automated, feedback-driven tool to rapidly search through troves of public data on GitHub for sensitive secrets.
- [**750**星][3m] [Py] [techgaun/github-dorks](https://github.com/techgaun/github-dorks) 快速搜索Github repo中的敏感信息
- [**602**星][2m] [Py] [hisxo/gitgraber](https://github.com/hisxo/gitgraber) monitor GitHub to search and find sensitive data in real time for different online services such as: Google, Amazon, Paypal, Github, Mailgun, Facebook, Twitter, Heroku, Stripe...
- [**312**星][15d] [HTML] [tanjiti/sec_profile](https://github.com/tanjiti/sec_profile) 爬取secwiki和xuanwu.github.io/sec.today,分析安全信息站点、安全趋势、提取安全工作者账号(twitter,weixin,github等)
    - 重复区段: [工具/扫描器&&安全扫描&&App扫描&&漏洞扫描/隐私&&Secret&&Privacy扫描](#58d8b993ffc34f7ded7f4a0077129eb2) |
- [**290**星][7m] [Py] [s0md3v/zen](https://github.com/s0md3v/zen) 查找Github用户的邮箱地址


#### <a id="6d36e9623aadaf40085ef5af89c8d698"></a>其他


- [**7541**星][30d] [Py] [theyahya/sherlock](https://github.com/sherlock-project/sherlock) Find Usernames Across Social Networks
- [**2504**星][2m] [Py] [greenwolf/social_mapper](https://github.com/Greenwolf/social_mapper) 对多个社交网站的用户Profile图片进行大规模的人脸识别
- [**653**星][1y] [Go] [0x09al/raven](https://github.com/0x09al/raven) raven is a Linkedin information gathering tool that can be used by pentesters to gather information about an organization employees using Linkedin.




### <a id="a695111d8e30d645354c414cb27b7843"></a>DNS


- [**2421**星][4m] [Go] [oj/gobuster](https://github.com/oj/gobuster) Directory/File, DNS and VHost busting tool written in Go
- [**2278**星][30d] [Py] [ab77/netflix-proxy](https://github.com/ab77/netflix-proxy) Smart DNS proxy to watch Netflix
- [**2081**星][19d] [Py] [elceef/dnstwist](https://github.com/elceef/dnstwist) 域名置换引擎，用于检测打字错误，网络钓鱼和企业间谍活动
- [**1885**星][28d] [C++] [powerdns/pdns](https://github.com/powerdns/pdns) PowerDNS
- [**1669**星][3m] [Py] [lgandx/responder](https://github.com/lgandx/responder) Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.
- [**1117**星][7m] [Py] [darkoperator/dnsrecon](https://github.com/darkoperator/dnsrecon) DNS 枚举脚本
- [**1044**星][2m] [Py] [infosec-au/altdns](https://github.com/infosec-au/altdns) Generates permutations, alterations and mutations of subdomains and then resolves them
- [**1039**星][1m] [Go] [nadoo/glider](https://github.com/nadoo/glider) 正向代理，支持若干协议
- [**969**星][6m] [Py] [m57/dnsteal](https://github.com/m57/dnsteal) DNS Exfiltration tool for stealthily sending files over DNS requests.
- [**891**星][18d] [Py] [mschwager/fierce](https://github.com/mschwager/fierce) A DNS reconnaissance tool for locating non-contiguous IP space.
- [**877**星][5m] [Py] [m0rtem/cloudfail](https://github.com/m0rtem/cloudfail) 通过错误配置的DNS和老数据库，发现CloudFlare网络后面的隐藏IP
- [**681**星][1y] [Py] [bugscanteam/dnslog](https://github.com/bugscanteam/dnslog) 监控 DNS 解析记录和 HTTP 访问记录
- [**594**星][7m] [Shell] [cokebar/gfwlist2dnsmasq](https://github.com/cokebar/gfwlist2dnsmasq) A shell script which convert gfwlist into dnsmasq rules. Python version:
- [**558**星][6m] [C] [getdnsapi/stubby](https://github.com/getdnsapi/stubby) Stubby is the name given to a mode of using getdns which enables it to act as a local DNS Privacy stub resolver (using DNS-over-TLS).
- [**457**星][8m] [C] [cofyc/dnscrypt-wrapper](https://github.com/cofyc/dnscrypt-wrapper) This is dnscrypt wrapper (server-side dnscrypt proxy), which helps to add dnscrypt support to any name resolver.
- [**359**星][3m] [JS] [nccgroup/singularity](https://github.com/nccgroup/singularity) A DNS rebinding attack framework.
- [**259**星][11m] [Py] [trycatchhcf/packetwhisper](https://github.com/trycatchhcf/packetwhisper) Stealthily exfiltrate data and defeat attribution using DNS queries and text-based steganography. Avoid the problems associated with typical DNS exfiltration methods. Transfer data between systems without the communicating devices directly connecting to each other or to a common endpoint. No need to control a DNS Name Server.
- [**258**星][2m] [Go] [zmap/zdns](https://github.com/zmap/zdns) 快速DNS查找, 命令行工具
- [**249**星][3m] [C#] [kevin-robertson/inveighzero](https://github.com/kevin-robertson/inveighzero) Windows C# LLMNR/mDNS/NBNS/DNS spoofer/man-in-the-middle tool
- [**243**星][9m] [Go] [erbbysam/dnsgrep](https://github.com/erbbysam/dnsgrep) Quickly Search Large DNS Datasets
- [**237**星][25d] [Py] [mandatoryprogrammer/trusttrees](https://github.com/mandatoryprogrammer/trusttrees) a script to recursively follow all the possible delegation paths for a target domain and graph the relationships between various nameservers along the way.
- [**230**星][1m] [Go] [sensepost/godoh](https://github.com/sensepost/godoh)  A DNS-over-HTTPS Command & Control Proof of Concept 
- [**213**星][1y] [PowerShell] [lukebaggett/dnscat2-powershell](https://github.com/lukebaggett/dnscat2-powershell) A Powershell client for dnscat2, an encrypted DNS command and control tool.


### <a id="18c7c1df2e6ae5e9135dfa2e4eb1d4db"></a>Shodan


- [**1082**星][2m] [Py] [achillean/shodan-python](https://github.com/achillean/shodan-python) The official Python library for Shodan
- [**954**星][4m] [Py] [woj-ciech/kamerka](https://github.com/woj-ciech/kamerka) 利用Shodan构建交互式摄像头地图
- [**831**星][2m] [Py] [649/memcrashed-ddos-exploit](https://github.com/649/memcrashed-ddos-exploit) DDoS attack tool for sending forged UDP packets to vulnerable Memcached servers obtained using Shodan API
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/DDOS](#a0897294e74a0863ea8b83d11994fad6) |
- [**669**星][2m] [jakejarvis/awesome-shodan-queries](https://github.com/jakejarvis/awesome-shodan-queries) 
- [**353**星][1m] [Py] [pielco11/fav-up](https://github.com/pielco11/fav-up) IP lookup from favicon using Shodan
- [**337**星][2m] [Py] [random-robbie/my-shodan-scripts](https://github.com/random-robbie/my-shodan-scripts) Collection of Scripts for shodan searching stuff.
- [**233**星][10m] [Py] [nethunteros/punter](https://github.com/nethunteros/punter) punter：使用 DNSDumpster, WHOIS, Reverse WHOIS 挖掘域名


### <a id="94c01f488096fafc194b9a07f065594c"></a>nmap


- [**3492**星][17d] [C] [nmap/nmap](https://github.com/nmap/nmap) Nmap
- [**2099**星][6m] [Py] [calebmadrigal/trackerjacker](https://github.com/calebmadrigal/trackerjacker) 映射你没连接到的Wifi网络, 类似于NMap, 另外可以追踪设备
- [**1666**星][3m] [Lua] [vulnerscom/nmap-vulners](https://github.com/vulnerscom/nmap-vulners) NSE script based on Vulners.com API
- [**1497**星][2m] [C] [nmap/npcap](https://github.com/nmap/npcap) Nmap Project's packet sniffing library for Windows, based on WinPcap/Libpcap improved with NDIS 6 and LWF.
- [**1237**星][2m] [Lua] [scipag/vulscan](https://github.com/scipag/vulscan) vulscan：Nmap 模块，将 Nmap 转化为高级漏洞扫描器
- [**936**星][4m] [Shell] [trimstray/sandmap](https://github.com/trimstray/sandmap) 使用NMap引擎, 辅助网络和系统侦查(reconnaissance)
- [**887**星][11m] [Py] [rev3rsesecurity/webmap](https://github.com/rev3rsesecurity/webmap) Nmap Web Dashboard and Reporting
- [**822**星][2m] [Py] [x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) brutespray：获取 nmapGNMAP 输出，自动调用 Medusa 使用默认证书爆破服务（brute-forces services）
- [**728**星][4m] [Lua] [cldrn/nmap-nse-scripts](https://github.com/cldrn/nmap-nse-scripts) My collection of nmap NSE scripts
- [**658**星][4m] [Py] [iceyhexman/onlinetools](https://github.com/iceyhexman/onlinetools) 在线cms识别|信息泄露|工控|系统|物联网安全|cms漏洞扫描|nmap端口扫描|子域名获取|待续..
- [**481**星][1y] [XSLT] [honze-net/nmap-bootstrap-xsl](https://github.com/honze-net/nmap-bootstrap-xsl) A Nmap XSL implementation with Bootstrap.
- [**391**星][7m] [Py] [savon-noir/python-libnmap](https://github.com/savon-noir/python-libnmap) libnmap is a python library to run nmap scans, parse and diff scan results. It supports python 2.6 up to 3.4. It's wonderful.
- [**325**星][9m] [Py] [samhaxr/hackbox](https://github.com/samhaxr/hackbox) 集合了某些Hacking工具和技巧的攻击工具
- [**307**星][1y] [Java] [s4n7h0/halcyon](https://github.com/s4n7h0/halcyon) First IDE for Nmap Script (NSE) Development.
- [**282**星][1y] [Ruby] [danmcinerney/pentest-machine](https://github.com/danmcinerney/pentest-machine) Automates some pentest jobs via nmap xml file
- [**257**星][1y] [Java] [danicuestasuarez/nmapgui](https://github.com/danicuestasuarez/nmapgui) Advanced Graphical User Interface for NMap
- [**247**星][1y] [Shell] [m4ll0k/autonse](https://github.com/m4ll0k/autonse) Massive NSE (Nmap Scripting Engine) AutoSploit and AutoScanner
- [**230**星][7m] [Lua] [rvn0xsy/nse_vuln](https://github.com/rvn0xsy/nse_vuln) Nmap扫描、漏洞利用脚本
- [**228**星][5m] [Py] [maaaaz/nmaptocsv](https://github.com/maaaaz/nmaptocsv) A simple python script to convert Nmap output to CSV




***


## <a id="969212c047f97652ceb9c789e4d8dae5"></a>数据库&&SQL攻击&&SQL注入


### <a id="e8d5cfc417b84fa90eff2e02c3231ed1"></a>未分类-Database


- [**950**星][18d] [PowerShell] [netspi/powerupsql](https://github.com/netspi/powerupsql) 攻击SQL服务器的PowerShell工具箱
- [**661**星][3m] [Py] [v3n0m-scanner/v3n0m-scanner](https://github.com/v3n0m-scanner/v3n0m-scanner) Popular Pentesting scanner in Python3.6 for SQLi/XSS/LFI/RFI and other Vulns
- [**638**星][2m] [Py] [quentinhardy/odat](https://github.com/quentinhardy/odat) Oracle Database Attacking Tool
- [**526**星][4m] [Py] [quentinhardy/msdat](https://github.com/quentinhardy/msdat) Microsoft SQL Database Attacking Tool


### <a id="3157bf5ee97c32454d99fd4a9fa3f04a"></a>SQL


#### <a id="1cfe1b2a2c88cd92a414f81605c8d8e7"></a>未分类-SQL


- [**2883**星][1m] [Go] [cookiey/yearning](https://github.com/cookiey/yearning) A most popular sql audit platform for mysql
- [**712**星][1y] [Py] [the-robot/sqliv](https://github.com/the-robot/sqliv) massive SQL injection vulnerability scanner
- [**553**星][1m] [HTML] [netspi/sqlinjectionwiki](https://github.com/netspi/sqlinjectionwiki) A wiki focusing on aggregating and documenting various SQL injection methods
- [**444**星][9m] [Go] [netxfly/x-crack](https://github.com/netxfly/x-crack) Weak password scanner, Support: FTP/SSH/SNMP/MSSQL/MYSQL/PostGreSQL/REDIS/ElasticSearch/MONGODB
- [**439**星][3m] [Go] [stripe/safesql](https://github.com/stripe/safesql) Static analysis tool for Golang that protects against SQL injections
- [**395**星][3m] [C#] [shack2/supersqlinjectionv1](https://github.com/shack2/supersqlinjectionv1) 超级SQL注入工具（SSQLInjection）是一款基于HTTP协议自组包的SQL注入工具,采用C#开发，直接操作TCP会话来进行HTTP交互，支持出现在HTTP协议任意位置的SQL注入，支持各种类型的SQL注入，支持HTTPS模式注入；支持以盲注、错误显示、Union注入等方式来获取数据；支持Access/MySQL/SQLServer/Oracle/PostgreSQL/DB2/SQLite/Informix等数据库；支持手动灵活的进行SQL注入绕过，可自定义进行字符替换等绕过注入防护。本工具为渗透测试人员、信息安全工程师等掌握SQL注入技能的人员设计，需要使用人员对SQL注入有一定了解。
- [**295**星][8m] [JS] [ning1022/sqlinjectionwiki](https://github.com/ning1022/SQLInjectionWiki) 一个专注于聚合和记录各种SQL注入方法的wiki
- [**255**星][7m] [Py] [s0md3v/sqlmate](https://github.com/s0md3v/sqlmate) A friend of SQLmap which will do what you always expected from SQLmap.


#### <a id="0519846509746aa50a04abd3ccf2f1d5"></a>SQL注入


- [**15554**星][16d] [Py] [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) Automatic SQL injection and database takeover tool
- [**592**星][6m] [aleenzz/mysql_sql_bypass_wiki](https://github.com/aleenzz/mysql_sql_bypass_wiki) mysql注入,bypass的一些心得


#### <a id="5a7451cdff13bc6709da7c943dda967f"></a>SQL漏洞






### <a id="ca6f4bd198f3712db7f24383e8544dfd"></a>NoSQL


#### <a id="af0aaaf233cdff3a88d04556dc5871e0"></a>未分类-NoSQL


- [**1180**星][15d] [Py] [codingo/nosqlmap](https://github.com/codingo/NoSQLMap) Automated NoSQL database enumeration and web application exploitation tool.
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |[工具/漏洞&&漏洞管理&&漏洞发现/挖掘&&漏洞开发&&漏洞利用&&Fuzzing/漏洞利用/漏洞利用](#c83f77f27ccf5f26c8b596979d7151c3) |
- [**275**星][1y] [Java] [florent37/android-nosql](https://github.com/florent37/android-nosql) Lightweight, simple structured NoSQL database for Android


#### <a id="54d36c89712652a7064db6179faa7e8c"></a>MongoDB


- [**1069**星][2m] [Py] [stampery/mongoaudit](https://github.com/stampery/mongoaudit) 






***


## <a id="df8a5514775570707cce56bb36ca32c8"></a>审计&&安全审计&&代码审计


### <a id="6a5e7dd060e57d9fdb3fed8635d61bc7"></a>未分类-Audit


- [**6407**星][1m] [Shell] [cisofy/lynis](https://github.com/cisofy/lynis) Security auditing tool for Linux, macOS, and UNIX-based systems. Assists with compliance testing (HIPAA/ISO27001/PCI DSS) and system hardening. Agentless, and installation optional.
- [**1465**星][27d] [Shell] [mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester) Linux privilege escalation auditing tool
- [**967**星][2m] [Py] [nccgroup/scoutsuite](https://github.com/nccgroup/scoutsuite) Multi-Cloud Security Auditing Tool
- [**604**星][6m] [JS] [vincentcox/stacoan](https://github.com/vincentcox/stacoan) StaCoAn is a crossplatform tool which aids developers, bugbounty hunters and ethical hackers performing static code analysis on mobile applications.
    - 重复区段: [工具/移动&&Mobile/未分类-Mobile](#4a64f5e8fdbd531a8c95d94b28c6c2c1) |
- [**271**星][17d] [Py] [lorexxar/cobra-w](https://github.com/lorexxar/cobra-w) Cobra-W -> Cobra-White 白盒源代码审计工具-白帽子版


### <a id="34569a6fdce10845eae5fbb029cd8dfa"></a>代码审计


- [**2041**星][3m] [Py] [whaleshark-team/cobra](https://github.com/WhaleShark-Team/cobra) Source Code Security Audit (源代码安全审计)
- [**807**星][1y] [Py] [utkusen/leviathan](https://github.com/utkusen/leviathan) wide range mass audit toolkit
- [**646**星][1y] [chybeta/code-audit-challenges](https://github.com/chybeta/code-audit-challenges) Code-Audit-Challenges
- [**626**星][8m] [Py] [klen/pylama](https://github.com/klen/pylama) Code audit tool for python.
- [**399**星][4m] [C] [anssi-fr/ad-control-paths](https://github.com/anssi-fr/ad-control-paths) Active Directory Control Paths auditing and graphing tools
- [**355**星][11m] [Py] [enablesecurity/sipvicious](https://github.com/enablesecurity/sipvicious) SIPVicious suite is a set of security tools that can be used to audit SIP based VoIP systems.
- [**293**星][2m] [C#] [ossindex/devaudit](https://github.com/ossindex/devaudit) Open-source, cross-platform, multi-purpose security auditing tool
- [**263**星][14d] [Py] [exodus-privacy/exodus](https://github.com/exodus-privacy/exodus) Platform to audit trackers used by Android application
- [**254**星][1m] [Py] [hubblestack/hubble](https://github.com/hubblestack/hubble) Hubble is a modular, open-source security compliance framework. The project provides on-demand profile-based auditing, real-time security event notifications, alerting, and reporting. HubbleStack is a free and open source project made possible by Adobe.
- [**240**星][4m] [PowerShell] [nccgroup/azucar](https://github.com/nccgroup/azucar) Azure环境安全审计工具
- [**215**星][1y] [C] [meliot/filewatcher](https://github.com/meliot/filewatcher) A simple auditing utility for macOS




***


## <a id="546f4fe70faa2236c0fbc2d486a83391"></a>社工(SET)&&钓鱼&&鱼叉攻击


### <a id="ce734598055ad3885d45d0b35d2bf0d7"></a>未分类-SET


- [**1301**星][26d] [CSS] [undeadsec/socialfish](https://github.com/undeadsec/socialfish) 网络钓鱼培训与信息收集
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |
- [**742**星][3m] [Py] [threatexpress/domainhunter](https://github.com/threatexpress/domainhunter) Checks expired domains for categorization/reputation and Archive.org history to determine good candidates for phishing and C2 domain names
    - 重复区段: [工具/侦察&&信息收集&&子域名发现与枚举&&OSINT/未分类-OSINT](#05ab1b75266fddafc7195f5b395e4d99) |
- [**556**星][2m] [Py] [thewhiteh4t/seeker](https://github.com/thewhiteh4t/seeker) Accurately Locate Smartphones using Social Engineering
- [**305**星][1m] [Py] [raikia/uhoh365](https://github.com/raikia/uhoh365) A script that can see if an email address is valid in Office365 (user/email enumeration). This does not perform any login attempts, is unthrottled, and is incredibly useful for social engineering assessments to find which emails exist and which don't.


### <a id="f30507893511f89b19934e082a54023e"></a>社工


- [**4854**星][2m] [Py] [trustedsec/social-engineer-toolkit](https://github.com/trustedsec/social-engineer-toolkit) The Social-Engineer Toolkit (SET) repository from TrustedSec - All new versions of SET will be deployed here.


### <a id="290e9ae48108d21d6d8b9ea9e74d077d"></a>钓鱼&&Phish


- [**8337**星][17d] [Py] [wifiphisher/wifiphisher](https://github.com/wifiphisher/wifiphisher) 流氓AP框架, 用于RedTeam和Wi-Fi安全测试
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**4161**星][12d] [Go] [gophish/gophish](https://github.com/gophish/gophish) 网络钓鱼工具包
- [**2721**星][1m] [Go] [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2) 独立的MITM攻击工具，用于登录凭证钓鱼，可绕过双因素认证
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**1402**星][8m] [JS] [anttiviljami/browser-autofill-phishing](https://github.com/anttiviljami/browser-autofill-phishing) A simple demo of phishing by abusing the browser autofill feature
- [**1331**星][10m] [HTML] [thelinuxchoice/blackeye](https://github.com/thelinuxchoice/blackeye) The most complete Phishing Tool, with 32 templates +1 customizable
- [**994**星][17d] [Py] [securestate/king-phisher](https://github.com/securestate/king-phisher) Phishing Campaign Toolkit
- [**976**星][1m] [Py] [x0rz/phishing_catcher](https://github.com/x0rz/phishing_catcher) phishing_catcher：使用Certstream 捕获钓鱼域名
- [**861**星][19d] [HTML] [darksecdevelopers/hiddeneye](https://github.com/darksecdevelopers/hiddeneye) Modern Phishing Tool With Advanced Functionality And Multiple Tunnelling Services [ Android-Support-Available ]
- [**858**星][7m] [HTML] [thelinuxchoice/shellphish](https://github.com/thelinuxchoice/shellphish) 针对18个社交媒体的钓鱼工具：Instagram, Facebook, Snapchat, Github, Twitter, Yahoo, Protonmail, Spotify, Netflix, Linkedin, Wordpress, Origin, Steam, Microsoft, InstaFollowers, Gitlab, Pinterest
- [**831**星][4m] [PHP] [raikia/fiercephish](https://github.com/Raikia/FiercePhish) FiercePhish is a full-fledged phishing framework to manage all phishing engagements. It allows you to track separate phishing campaigns, schedule sending of emails, and much more.
- [**828**星][1y] [HTML] [ustayready/credsniper](https://github.com/ustayready/credsniper) CredSniper is a phishing framework written with the Python micro-framework Flask and Jinja2 templating which supports capturing 2FA tokens.
- [**524**星][26d] [Py] [shellphish/driller](https://github.com/shellphish/driller) augmenting AFL with symbolic execution!
- [**348**星][4m] [Py] [tatanus/spf](https://github.com/tatanus/spf) SpeedPhishing Framework
- [**297**星][10m] [Py] [mr-un1k0d3r/catmyphish](https://github.com/Mr-Un1k0d3r/CatMyPhish) Search for categorized domain
- [**265**星][3m] [Go] [muraenateam/muraena](https://github.com/muraenateam/muraena) Muraena is an almost-transparent reverse proxy aimed at automating phishing and post-phishing activities.
- [**240**星][2m] [Py] [atexio/mercure](https://github.com/atexio/mercure) 对员工进行网络钓鱼的培训
- [**228**星][1y] [Jupyter Notebook] [wesleyraptor/streamingphish](https://github.com/wesleyraptor/streamingphish) 使用受监督的机器学习, 从证书透明度(Certificate Transparency)日志中检测钓鱼域名
- [**220**星][3m] [Py] [duo-labs/isthislegit](https://github.com/duo-labs/isthislegit) isthislegit：收集、分析和回复网络钓鱼邮件的框架


### <a id="ab3e6e6526d058e35c7091d8801ebf3a"></a>鱼叉攻击






***


## <a id="04102345243a4bcaec83f703afff6cb3"></a>硬件设备&&USB&树莓派


### <a id="ff462a6d508ef20aa41052b1cc8ad044"></a>未分类-Hardware


- [**2190**星][18d] [Shell] [eliaskotlyar/xiaomi-dafang-hacks](https://github.com/eliaskotlyar/xiaomi-dafang-hacks) 
- [**2009**星][1y] [C] [xoreaxeaxeax/rosenbridge](https://github.com/xoreaxeaxeax/rosenbridge) Hardware backdoors in some x86 CPUs
- [**1932**星][13d] [Go] [ullaakut/cameradar](https://github.com/Ullaakut/cameradar) Cameradar hacks its way into RTSP videosurveillance cameras
- [**1327**星][1y] [Py] [carmaa/inception](https://github.com/carmaa/inception) 利用基于PCI的DMA实现物理内存的操纵与Hacking，可以攻击FireWire，Thunderbolt，ExpressCard，PC Card和任何其他PCI / PCIe硬件接口
- [**1117**星][10m] [JS] [mame82/p4wnp1_aloa](https://github.com/mame82/p4wnp1_aloa) 将 Rapsberry Pi Zero W 转变成灵活的渗透平台
    - 重复区段: [工具/环境配置&&分析系统/未分类-Env](#f5a7a43f964b2c50825f3e2fee5078c8) |
- [**962**星][2m] [C] [olimex/olinuxino](https://github.com/olimex/olinuxino) OLINUXINO is Open Source / Open Hardware, low cost from EUR 24 Linux Industrial grade Single Board Computer capable to operate -25+85C
- [**516**星][3m] [Java] [1998lixin/hardwarecode](https://github.com/1998lixin/hardwarecode) 基于xposed 修改硬件信息


### <a id="48c53d1304b1335d9addf45b959b7d8a"></a>USB


- [**3811**星][17d] [drduh/yubikey-guide](https://github.com/drduh/yubikey-guide) Guide to using YubiKey for GPG and SSH
- [**2643**星][12m] [Py] [mame82/p4wnp1](https://github.com/mame82/p4wnp1) 基于Raspberry Pi Zero 或 Raspberry Pi Zero W 的USB攻击平台, 高度的可定制性
    - 重复区段: [工具/硬件设备&&USB&树莓派/树莓派&&RaspberryPi](#77c39a0ad266ad42ab8157ba4b3d874a) |
- [**2149**星][9m] [C] [conorpp/u2f-zero](https://github.com/conorpp/u2f-zero) U2F USB token optimized for physical security, affordability, and style
- [**1018**星][28d] [C] [solokeys/solo](https://github.com/solokeys/solo) open security key supporting FIDO2 & U2F over USB + NFC
- [**982**星][11m] [C#] [kenvix/usbcopyer](https://github.com/kenvix/usbcopyer) 插上U盘自动按需复制文件 
- [**865**星][2m] [C++] [whid-injector/whid](https://github.com/whid-injector/whid) WiFi HID Injector - An USB Rubberducky / BadUSB On Steroids.
- [**832**星][6m] [Objective-C] [sevenbits/mac-linux-usb-loader](https://github.com/sevenbits/mac-linux-usb-loader) Boot Linux on your Mac, easily
- [**825**星][1m] [C++] [openzwave/open-zwave](https://github.com/openzwave/open-zwave) a C++ library to control Z-Wave Networks via a USB Z-Wave Controller.
- [**744**星][19d] [Py] [snovvcrash/usbrip](https://github.com/snovvcrash/usbrip) Simple CLI forensics tool for tracking USB device artifacts (history of USB events) on GNU/Linux
    - 重复区段: [工具/事件响应&&取证&&内存取证&&数字取证/取证&&Forensics&&数字取证&&内存取证](#1fc5d3621bb13d878f337c8031396484) |
- [**695**星][2m] [C] [nuand/bladerf](https://github.com/nuand/bladerf) bladeRF USB 3.0 Superspeed Software Defined Radio Source Code
- [**596**星][5m] [C] [pelya/android-keyboard-gadget](https://github.com/pelya/android-keyboard-gadget) Convert your Android device into USB keyboard/mouse, control your PC from your Android device remotely, including BIOS/bootloader.
- [**410**星][8m] [Shell] [jsamr/bootiso](https://github.com/jsamr/bootiso) A bash script to securely create a bootable USB device from one ISO file. Just curl it, chmod it and go!
- [**307**星][3m] [Py] [circl/circlean](https://github.com/circl/circlean) USB key cleaner
- [**305**星][3m] [C++] [cedarctic/digispark-scripts](https://github.com/cedarctic/digispark-scripts) USB Rubber Ducky type scripts written for the DigiSpark.
- [**221**星][5m] [ANTLR] [myriadrf/limesdr-usb](https://github.com/myriadrf/limesdr-usb) USB 3.0 version of the LimeSDR board


### <a id="77c39a0ad266ad42ab8157ba4b3d874a"></a>树莓派&&RaspberryPi


- [**2643**星][12m] [Py] [mame82/p4wnp1](https://github.com/mame82/p4wnp1) 基于Raspberry Pi Zero 或 Raspberry Pi Zero W 的USB攻击平台, 高度的可定制性
    - 重复区段: [工具/硬件设备&&USB&树莓派/USB](#48c53d1304b1335d9addf45b959b7d8a) |
- [**1658**星][7m] [Makefile] [raspberrypi/noobs](https://github.com/raspberrypi/noobs) NOOBS (New Out Of Box Software) - An easy Operating System install manager for the Raspberry Pi
- [**1510**星][1m] [C] [raspberrypi/userland](https://github.com/raspberrypi/userland) Source code for ARM side libraries for interfacing to Raspberry Pi GPU.
- [**296**星][6m] [C++] [cyphunk/jtagenum](https://github.com/cyphunk/jtagenum) Given an Arduino compatible microcontroller or Raspberry PI (experimental), JTAGenum scans pins[] for basic JTAG functionality and can be used to enumerate the Instruction Register for undocumented instructions. Props to JTAG scanner and Arduinull which came before JTAGenum and forwhich much of the code and logic is based on. Feel free to branch…
- [**258**星][5m] [Py] [mbro95/portablecellnetwork](https://github.com/mbro95/portablecellnetwork) Utilize a Raspberry Pi and a Nuand BladeRF to generate your own portable local cell network
- [**246**星][4m] [Py] [tipam/pi3d](https://github.com/tipam/pi3d) Simple, yet powerful, 3D Python graphics library for beginners and school children running on the Raspberry Pi.


### <a id="da75af123f2f0f85a4c8ecc08a8aa848"></a>车&&汽车&&Vehicle


- [**1305**星][1m] [jaredthecoder/awesome-vehicle-security](https://github.com/jaredthecoder/awesome-vehicle-security) 
- [**768**星][1y] [C++] [polysync/oscc](https://github.com/polysync/oscc) Open Source Car Control
- [**513**星][7m] [Py] [schutzwerk/canalyzat0r](https://github.com/schutzwerk/canalyzat0r) Security analysis toolkit for proprietary car protocols
- [**261**星][1y] [Shell] [jgamblin/carhackingtools](https://github.com/jgamblin/carhackingtools) Install and Configure Common Car Hacking Tools.
- [**216**星][2m] [Py] [caringcaribou/caringcaribou](https://github.com/caringcaribou/caringcaribou) A friendly car security exploration tool for the CAN bus




***


## <a id="dc89c90b80529c1f62f413288bca89c4"></a>环境配置&&分析系统


### <a id="f5a7a43f964b2c50825f3e2fee5078c8"></a>未分类-Env


- [**1571**星][13d] [HTML] [clong/detectionlab](https://github.com/clong/detectionlab) Vagrant & Packer scripts to build a lab environment complete with security tooling and logging best practices
- [**1371**星][16d] [Go] [crazy-max/windowsspyblocker](https://github.com/crazy-max/windowsspyblocker) 
- [**1294**星][2m] [C] [cisco-talos/pyrebox](https://github.com/cisco-talos/pyrebox) 逆向沙箱，基于QEMU，Python Scriptable
- [**1117**星][10m] [JS] [mame82/p4wnp1_aloa](https://github.com/mame82/p4wnp1_aloa) 将 Rapsberry Pi Zero W 转变成灵活的渗透平台
    - 重复区段: [工具/硬件设备&&USB&树莓派/未分类-Hardware](#ff462a6d508ef20aa41052b1cc8ad044) |
- [**799**星][3m] [redhuntlabs/redhunt-os](https://github.com/redhuntlabs/redhunt-os) Virtual Machine for Adversary Emulation and Threat Hunting
- [**781**星][2m] [sh4hin/androl4b](https://github.com/sh4hin/androl4b) 用于评估Android应用程序，逆向工程和恶意软件分析的虚拟机
    - 重复区段: [工具/移动&&Mobile/Android](#fe88ee8c0df10870b44c2dedcd86d3d3) |
- [**560**星][5m] [Ruby] [sliim/pentest-env](https://github.com/sliim/pentest-env) Pentest environment deployer (kali linux + targets) using vagrant and chef.
- [**210**星][11m] [Shell] [proxycannon/proxycannon-ng](https://github.com/proxycannon/proxycannon-ng) 使用多个云环境构建私人僵尸网络, 用于渗透测试和RedTeaming


### <a id="cf07b04dd2db1deedcf9ea18c05c83e0"></a>Linux-Distro


- [**2830**星][1m] [Py] [trustedsec/ptf](https://github.com/trustedsec/ptf) 创建基于Debian/Ubuntu/ArchLinux的渗透测试环境
- [**2310**星][1m] [security-onion-solutions/security-onion](https://github.com/security-onion-solutions/security-onion) Linux distro for intrusion detection, enterprise security monitoring, and log management
- [**1459**星][13d] [Shell] [blackarch/blackarch](https://github.com/blackarch/blackarch) BlackArch Linux is an Arch Linux-based distribution for penetration testers and security researchers.
- [**342**星][13d] [Shell] [archstrike/archstrike](https://github.com/archstrike/archstrike) An Arch Linux repository for security professionals and enthusiasts. Done the Arch Way and optimized for i686, x86_64, ARMv6, ARMv7 and ARMv8.


### <a id="4709b10a8bb691204c0564a3067a0004"></a>环境自动配置&&自动安装


- [**3058**星][2m] [PowerShell] [fireeye/commando-vm](https://github.com/fireeye/commando-vm) Complete Mandiant Offensive VM (Commando VM), a fully customizable Windows-based pentesting virtual machine distribution. commandovm@fireeye.com
- [**1686**星][18d] [PowerShell] [fireeye/flare-vm](https://github.com/fireeye/flare-vm) 火眼发布用于 Windows 恶意代码分析的虚拟机：FLARE VM




***


## <a id="761a373e2ec1c58c9cd205cd7a03e8a8"></a>靶机&&漏洞环境&&漏洞App


### <a id="3e751670de79d2649ba62b177bd3e4ef"></a>未分类-VulnerableMachine


- [**4986**星][1m] [Shell] [vulhub/vulhub](https://github.com/vulhub/vulhub) Pre-Built Vulnerable Environments Based on Docker-Compose
- [**3680**星][2m] [PHP] [ethicalhack3r/dvwa](https://github.com/ethicalhack3r/DVWA) Damn Vulnerable Web Application (DVWA)
- [**2536**星][25d] [Shell] [medicean/vulapps](https://github.com/medicean/vulapps) 快速搭建各种漏洞环境(Various vulnerability environment)
- [**2382**星][27d] [TSQL] [rapid7/metasploitable3](https://github.com/rapid7/metasploitable3) Metasploitable3 is a VM that is built from the ground up with a large amount of security vulnerabilities.
- [**1522**星][1m] [PHP] [c0ny1/upload-labs](https://github.com/c0ny1/upload-labs) 一个帮你总结所有类型的上传漏洞的靶场
- [**981**星][1m] [C] [hacksysteam/hacksysextremevulnerabledriver](https://github.com/hacksysteam/hacksysextremevulnerabledriver) HackSys Extreme Vulnerable Windows Driver
- [**831**星][27d] [JS] [lirantal/is-website-vulnerable](https://github.com/lirantal/is-website-vulnerable) finds publicly known security vulnerabilities in a website's frontend JavaScript libraries
- [**741**星][1m] [Ruby] [rubysec/ruby-advisory-db](https://github.com/rubysec/ruby-advisory-db) A database of vulnerable Ruby Gems
- [**633**星][2m] [HCL] [rhinosecuritylabs/cloudgoat](https://github.com/rhinosecuritylabs/cloudgoat) CloudGoat is Rhino Security Labs' "Vulnerable by Design" AWS deployment tool
- [**577**星][2m] [HTML] [owasp/railsgoat](https://github.com/owasp/railsgoat) A vulnerable version of Rails that follows the OWASP Top 10
- [**563**星][1m] [C++] [bkerler/exploit_me](https://github.com/bkerler/exploit_me) 带洞的 ARMApp, 可用于漏洞开发练习
- [**517**星][5m] [PHP] [acmesec/dorabox](https://github.com/Acmesec/DoraBox) DoraBox - 基础Web漏洞训练靶场
- [**311**星][28d] [Py] [owasp/owasp-vwad](https://github.com/owasp/owasp-vwad) The OWASP Vulnerable Web Applications Directory Project (VWAD) is a comprehensive and well maintained registry of all known vulnerable web applications currently available.
- [**252**星][2m] [PHP] [incredibleindishell/ssrf_vulnerable_lab](https://github.com/incredibleindishell/ssrf_vulnerable_lab) This Lab contain the sample codes which are vulnerable to Server-Side Request Forgery attack
- [**237**星][2m] [JS] [owasp/dvsa](https://github.com/owasp/dvsa) a Damn Vulnerable Serverless Application
- [**218**星][11m] [C] [stephenbradshaw/vulnserver](https://github.com/stephenbradshaw/vulnserver) Vulnerable server used for learning software exploitation


### <a id="a6a2bb02c730fc1e1f88129d4c2b3d2e"></a>WebApp


- [**2902**星][13d] [JS] [webgoat/webgoat](https://github.com/webgoat/webgoat) 带漏洞WebApp
- [**2556**星][15d] [JS] [bkimminich/juice-shop](https://github.com/bkimminich/juice-shop) OWASP Juice Shop: Probably the most modern and sophisticated insecure web application
- [**459**星][14d] [Py] [stamparm/dsvw](https://github.com/stamparm/dsvw) Damn Small Vulnerable Web
- [**427**星][3m] [Py] [payatu/tiredful-api](https://github.com/payatu/tiredful-api) An intentionally designed broken web application based on REST API.
- [**289**星][1y] [CSS] [appsecco/dvna](https://github.com/appsecco/dvna) Damn Vulnerable NodeJS Application
- [**218**星][5m] [JS] [cr0hn/vulnerable-node](https://github.com/cr0hn/vulnerable-node) A very vulnerable web site written in NodeJS with the purpose of have a project with identified vulnerabilities to test the quality of security analyzers tools tools


### <a id="60b4d03a0cff6efc4b9b998a4a1a79d6"></a>靶机生成


- [**1699**星][13d] [Ruby] [cliffe/secgen](https://github.com/cliffe/secgen) Create randomly insecure VMs
- [**1408**星][5m] [PHP] [s4n7h0/xvwa](https://github.com/s4n7h0/xvwa) XVWA is a badly coded web application written in PHP/MySQL that helps security enthusiasts to learn application security.
- [**305**星][7m] [Ruby] [secgen/secgen](https://github.com/secgen/secgen) Generate vulnerable virtual machines on the fly (current team development is taking place in the cliffe/SecGen fork)


### <a id="383ad9174d3f7399660d36cd6e0b2c00"></a>收集


- [**358**星][4m] [xtiankisutsa/awesome-mobile-ctf](https://github.com/xtiankisutsa/awesome-mobile-ctf) This is a curated list of mobile based CTFs, write-ups and vulnerable apps. Most of them are android based due to the popularity of the platform.
    - 重复区段: [工具/CTF&&HTB/收集](#30c4df38bcd1abaaaac13ffda7d206c6) |


### <a id="aa60e957e4da03301643a7abe4c1938a"></a>MobileApp


- [**645**星][4m] [Java] [dineshshetty/android-insecurebankv2](https://github.com/dineshshetty/android-insecurebankv2) Vulnerable Android application for developers and security enthusiasts to learn about Android insecurities
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
- [**3480**星][7m] [Go] [fanpei91/torsniff](https://github.com/fanpei91/torsniff) torsniff - a sniffer that sniffs torrents from BitTorrent network
- [**3191**星][14d] [Py] [stamparm/maltrail](https://github.com/stamparm/maltrail) 恶意网络流量检测系统
- [**3096**星][25d] [C] [valdikss/goodbyedpi](https://github.com/valdikss/goodbyedpi) GoodbyeDPI—Passive Deep Packet Inspection blocker and Active DPI circumvention utility (for Windows)
- [**2503**星][7m] [C++] [chengr28/pcap_dnsproxy](https://github.com/chengr28/pcap_dnsproxy) Pcap_DNSProxy, a local DNS server based on packet capturing
- [**1877**星][28d] [C] [ntop/ndpi](https://github.com/ntop/ndpi) Open Source Deep Packet Inspection Software Toolkit
- [**1799**星][1m] [C] [merbanan/rtl_433](https://github.com/merbanan/rtl_433) Program to decode traffic from Devices that are broadcasting on 433.9 MHz like temperature sensors
- [**1419**星][2m] [Go] [google/stenographer](https://github.com/google/stenographer) Stenographer is a packet capture solution which aims to quickly spool all packets to disk, then provide simple, fast access to subsets of those packets. Discussion/announcements at stenographer@googlegroups.com
- [**1328**星][2m] [C++] [mfontanini/libtins](https://github.com/mfontanini/libtins) High-level, multiplatform C++ network packet sniffing and crafting library.
- [**1271**星][2m] [C] [traviscross/mtr](https://github.com/traviscross/mtr) Official repository for mtr, a network diagnostic tool
- [**1258**星][1m] [Go] [dreadl0ck/netcap](https://github.com/dreadl0ck/netcap) A framework for secure and scalable network traffic analysis -
- [**1207**星][1y] [Py] [danmcinerney/net-creds](https://github.com/danmcinerney/net-creds) Sniffs sensitive data from interface or pcap
- [**1056**星][6m] [PowerShell] [nytrorst/netripper](https://github.com/nytrorst/netripper) 后渗透工具,针对Windows, 使用API Hooking拦截网络流量和加密相关函数, 可捕获明文和加密前后的内容
- [**1046**星][10m] [C++] [simsong/tcpflow](https://github.com/simsong/tcpflow) TCP/IP packet demultiplexer. Download from:
- [**952**星][2m] [Py] [kiminewt/pyshark](https://github.com/kiminewt/pyshark) Python wrapper for tshark, allowing python packet parsing using wireshark dissectors
- [**945**星][7m] [Py] [fireeye/flare-fakenet-ng](https://github.com/fireeye/flare-fakenet-ng) 下一代动态网络分析工具
- [**853**星][3m] [C] [cisco/joy](https://github.com/cisco/joy) 捕获和分析网络流数据和intraflow数据，用于网络研究、取证和安全监视
- [**820**星][6m] [Go] [40t/go-sniffer](https://github.com/40t/go-sniffer) 
- [**817**星][29d] [C] [zerbea/hcxtools](https://github.com/zerbea/hcxtools) Portable solution for capturing wlan traffic and conversion to hashcat formats (recommended by hashcat) and to John the Ripper formats. hcx: h = hash, c = capture, convert and calculate candidates, x = different hashtypes
- [**800**星][2m] [C] [emmericp/ixy](https://github.com/emmericp/ixy) Simple userspace packet processing for educational purposes
- [**790**星][7m] [Py] [phaethon/kamene](https://github.com/phaethon/kamene) Network packet and pcap file crafting/sniffing/manipulation/visualization security tool. Originally forked from scapy in 2015 and providing python3 compatibility since then.
- [**779**星][2m] [C] [netsniff-ng/netsniff-ng](https://github.com/netsniff-ng/netsniff-ng) A Swiss army knife for your daily Linux network plumbing.
- [**713**星][2m] [Py] [cloudflare/bpftools](https://github.com/cloudflare/bpftools) BPF Tools - packet analyst toolkit
- [**652**星][1m] [Py] [kbandla/dpkt](https://github.com/kbandla/dpkt) fast, simple packet creation / parsing, with definitions for the basic TCP/IP protocols
- [**645**星][1m] [C] [zerbea/hcxdumptool](https://github.com/zerbea/hcxdumptool) Small tool to capture packets from wlan devices.
- [**636**星][1y] [Go] [ga0/netgraph](https://github.com/ga0/netgraph) A cross platform http sniffer with a web UI
- [**509**星][9m] [Perl] [mrash/fwknop](https://github.com/mrash/fwknop) Single Packet Authorization > Port Knocking
- [**505**星][7m] [C++] [kohler/click](https://github.com/kohler/click) The Click modular router: fast modular packet processing and analysis
- [**499**星][1m] [C] [sam-github/libnet](https://github.com/libnet/libnet) A portable framework for low-level network packet construction
- [**458**星][1m] [Py] [netzob/netzob](https://github.com/netzob/netzob)  Protocol Reverse Engineering, Modeling and Fuzzing
- [**451**星][4m] [C] [jarun/keysniffer](https://github.com/jarun/keysniffer) 
- [**440**星][20d] [C#] [malwareinfosec/ekfiddle](https://github.com/malwareinfosec/ekfiddle) A framework based on the Fiddler web debugger to study Exploit Kits, malvertising and malicious traffic in general.
- [**435**星][2m] [C++] [pstavirs/ostinato](https://github.com/pstavirs/ostinato) Packet/Traffic Generator and Analyzer
- [**431**星][2m] [Ruby] [aderyabin/sniffer](https://github.com/aderyabin/sniffer) Log and Analyze Outgoing HTTP Requests
- [**412**星][10m] [C] [jpr5/ngrep](https://github.com/jpr5/ngrep) ngrep is like GNU grep applied to the network layer. It's a PCAP-based tool that allows you to specify an extended regular or hexadecimal expression to match against data payloads of packets. It understands many kinds of protocols, including IPv4/6, TCP, UDP, ICMPv4/6, IGMP and Raw, across a wide variety of interface types, and understands BPF f…
- [**411**星][2m] [C] [desowin/usbpcap](https://github.com/desowin/usbpcap) USB packet capture for Windows
- [**407**星][8m] [Py] [mitrecnd/chopshop](https://github.com/mitrecnd/chopshop) Protocol Analysis/Decoder Framework
- [**387**星][1m] [Rust] [kpcyrd/sniffglue](https://github.com/kpcyrd/sniffglue) Secure multithreaded packet sniffer
- [**382**星][2m] [Go] [alphasoc/flightsim](https://github.com/alphasoc/flightsim) A utility to generate malicious network traffic and evaluate controls
- [**379**星][4m] [PHP] [floedesigntechnologies/phpcs-security-audit](https://github.com/floedesigntechnologies/phpcs-security-audit) phpcs-security-audit is a set of PHP_CodeSniffer rules that finds vulnerabilities and weaknesses related to security in PHP code
- [**375**星][28d] [Py] [idaholab/malcolm](https://github.com/idaholab/malcolm) Malcolm is a powerful, easily deployable network traffic analysis tool suite for full packet capture artifacts (PCAP files) and Zeek logs.
- [**330**星][12m] [Ruby] [packetfu/packetfu](https://github.com/packetfu/packetfu) 数据包篡改工具。Ruby语言编写。
- [**326**星][14d] [TypeScript] [shroudedcode/apk-mitm](https://github.com/shroudedcode/apk-mitm) 
    - 重复区段: [工具/移动&&Mobile/Android](#fe88ee8c0df10870b44c2dedcd86d3d3) |[工具/浏览嗅探&&流量拦截&&流量分析&&中间人/中间人&&MITM](#11c73d3e2f71f3914a3bca35ba90de36) |
- [**303**星][1y] [Py] [tintinweb/scapy-ssl_tls](https://github.com/tintinweb/scapy-ssl_tls) SSL/TLS layers for scapy the interactive packet manipulation tool
- [**292**星][4m] [C] [pulkin/esp8266-injection-example](https://github.com/pulkin/esp8266-injection-example) Example project to demonstrate packet injection / sniffer capabilities of ESP8266 IC.
- [**278**星][23d] [C] [troglobit/nemesis](https://github.com/troglobit/nemesis) 网络数据包构造和注入的命令行工具
- [**273**星][9m] [C] [jiaoxianjun/btle](https://github.com/jiaoxianjun/btle) Bluetooth Low Energy (BLE) packet sniffer and generator for both standard and non standard (raw bit).
- [**254**星][2m] [Go] [sachaos/tcpterm](https://github.com/sachaos/tcpterm) tcpterm is a packet visualizer in TUI.
- [**243**星][7m] [Py] [needmorecowbell/sniff-paste](https://github.com/needmorecowbell/sniff-paste) Pastebin OSINT Harvester
- [**241**星][2m] [C] [nccgroup/sniffle](https://github.com/nccgroup/sniffle) A sniffer for Bluetooth 5 and 4.x LE
- [**218**星][18d] [Py] [ghostop14/sparrow-wifi](https://github.com/ghostop14/sparrow-wifi) Next-Gen GUI-based WiFi and Bluetooth Analyzer for Linux
    - 重复区段: [工具/蓝牙&&Bluetooth](#ceb90405292daed9bb32ac20836c219a) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**213**星][2m] [C] [dns-oarc/dnscap](https://github.com/dns-oarc/dnscap) Network capture utility designed specifically for DNS traffic


### <a id="11c73d3e2f71f3914a3bca35ba90de36"></a>中间人&&MITM


- [**16743**星][18d] [Py] [mitmproxy/mitmproxy](https://github.com/mitmproxy/mitmproxy) An interactive TLS-capable intercepting HTTP proxy for penetration testers and software developers.
    - 重复区段: [工具/通信&&代理&&反向代理&&隧道/未分类-Proxy](#56acb7c49c828d4715dce57410d490d1) |
- [**6294**星][12d] [Go] [bettercap/bettercap](https://github.com/bettercap/bettercap) 新版的bettercap, Go 编写. bettercap 是强大的、模块化、可移植且易于扩展的 MITM 框架, 旧版用 Ruby 编写
- [**2886**星][1y] [Py] [byt3bl33d3r/mitmf](https://github.com/byt3bl33d3r/mitmf) Framework for Man-In-The-Middle attacks
- [**2721**星][1m] [Go] [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2) 独立的MITM攻击工具，用于登录凭证钓鱼，可绕过双因素认证
    - 重复区段: [工具/社工(SET)&&钓鱼&&鱼叉攻击/钓鱼&&Phish](#290e9ae48108d21d6d8b9ea9e74d077d) |
- [**2480**星][15d] [Py] [evilsocket/pwnagotchi](https://github.com/evilsocket/pwnagotchi) (⌐■_■) - Deep Reinforcement Learning instrumenting bettercap for WiFi pwning.
    - 重复区段: [工具/人工智能&&机器学习&&深度学习&&神经网络/未分类-AI](#19dd474da6b715024ff44d27484d528a) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**1258**星][2m] [Go] [unrolled/secure](https://github.com/unrolled/secure) HTTP middleware for Go that facilitates some quick security wins.
- [**1199**星][3m] [C] [droe/sslsplit](https://github.com/droe/sslsplit) 透明SSL/TLS拦截
- [**1184**星][2m] [Py] [jtesta/ssh-mitm](https://github.com/jtesta/ssh-mitm) ssh-mitm：SSH 中间人攻击工具
- [**1085**星][7m] [Ruby] [lionsec/xerosploit](https://github.com/lionsec/xerosploit) Efficient and advanced man in the middle framework
- [**1017**星][3m] [PowerShell] [kevin-robertson/inveigh](https://github.com/kevin-robertson/inveigh) Windows PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer/man-in-the-middle tool
- [**999**星][7m] [Go] [justinas/nosurf](https://github.com/justinas/nosurf) CSRF protection middleware for Go.
- [**983**星][1y] [HTML] [sensepost/mana](https://github.com/sensepost/mana) *DEPRECATED* mana toolkit for wifi rogue AP attacks and MitM
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |
- [**977**星][30d] [Py] [syss-research/seth](https://github.com/syss-research/seth) Perform a MitM attack and extract clear text credentials from RDP connections
- [**568**星][11m] [HTML] [r00t-3xp10it/morpheus](https://github.com/r00t-3xp10it/morpheus) Morpheus - Automating Ettercap TCP/IP (MITM-hijacking Tool)
- [**551**星][8m] [Py] [fox-it/mitm6](https://github.com/fox-it/mitm6) mitm6: 攻击代码
- [**509**星][5m] [JS] [moll/node-mitm](https://github.com/moll/node-mitm) Intercept and mock outgoing Node.js network TCP connections and HTTP requests for testing. Intercepts and gives you a Net.Socket, Http.IncomingMessage and Http.ServerResponse to test and respond with. Super useful when testing code that hits remote servers.
- [**432**星][1y] [JS] [digitalsecurity/btlejuice](https://github.com/digitalsecurity/btlejuice) BtleJuice Bluetooth Smart (LE) Man-in-the-Middle framework
- [**393**星][3m] [Go] [cloudflare/mitmengine](https://github.com/cloudflare/mitmengine) A MITM (monster-in-the-middle) detection tool. Used to build MALCOLM:
- [**382**星][3m] [JS] [joeferner/node-http-mitm-proxy](https://github.com/joeferner/node-http-mitm-proxy) HTTP Man In The Middle (MITM) Proxy
- [**379**星][1y] [JS] [securing/gattacker](https://github.com/securing/gattacker) A Node.js package for BLE (Bluetooth Low Energy) security assessment using Man-in-the-Middle and other attacks
- [**365**星][10m] [Py] [crypt0s/fakedns](https://github.com/crypt0s/fakedns) A regular-expression based python MITM DNS server with support for DNS Rebinding attacks
- [**347**星][17d] [Py] [gosecure/pyrdp](https://github.com/gosecure/pyrdp) RDP man-in-the-middle (mitm) and library for Python 3 with the ability to watch connections live or after the fact
- [**347**星][1y] [Py] [quickbreach/smbetray](https://github.com/quickbreach/smbetray) SMB MiTM tool with a focus on attacking clients through file content swapping, lnk swapping, as well as compromising any data passed over the wire in cleartext.
- [**326**星][14d] [TypeScript] [shroudedcode/apk-mitm](https://github.com/shroudedcode/apk-mitm) 
    - 重复区段: [工具/移动&&Mobile/Android](#fe88ee8c0df10870b44c2dedcd86d3d3) |[工具/浏览嗅探&&流量拦截&&流量分析&&中间人/未分类-Network](#99398a5a8aaf99228829dadff48fb6a7) |
- [**294**星][1y] [Shell] [cryptolok/ghostinthenet](https://github.com/cryptolok/ghostinthenet) Ultimate Network Stealther that makes Linux a Ghost In The Net and protects from MITM/DOS/scan
    - 重复区段: [工具/扫描器&&安全扫描&&App扫描&&漏洞扫描/未分类-Scanner](#de63a029bda6a7e429af272f291bb769) |
- [**225**星][8m] [Py] [ivanvza/arpy](https://github.com/ivanvza/arpy) Mac OSX ARP spoof (MiTM) tool that can also plug into Gource
- [**205**星][3m] [sab0tag3d/mitm-cheatsheet](https://github.com/sab0tag3d/mitm-cheatsheet) All MITM attacks in one place.


### <a id="c09843b4d4190dea0bf9773f8114300a"></a>流量嗅探&&监控


- [**3480**星][7m] [Go] [fanpei91/torsniff](https://github.com/fanpei91/torsniff) 从BitTorrent网络嗅探种子
- [**2950**星][14d] [Lua] [ntop/ntopng](https://github.com/ntop/ntopng) 基于Web的流量监控工具
- [**1328**星][1y] [C] [gamelinux/passivedns](https://github.com/gamelinux/passivedns) A network sniffer that logs all DNS server replies for use in a passive DNS setup
- [**286**星][1m] [Shell] [tehw0lf/airbash](https://github.com/tehw0lf/airbash) airbash: 全自动的WPAPSK握手包捕获脚本, 用于渗透测试


### <a id="dde87061175108fc66b00ef665b1e7d0"></a>pcap数据包


- [**820**星][13d] [C++] [seladb/pcapplusplus](https://github.com/seladb/pcapplusplus) PcapPlusPlus is a multiplatform C++ library for capturing, parsing and crafting of network packets. It is designed to be efficient, powerful and easy to use. It provides C++ wrappers for the most popular packet processing engines such as libpcap, WinPcap, DPDK and PF_RING.
- [**780**星][3m] [Py] [srinivas11789/pcapxray](https://github.com/srinivas11789/pcapxray) A Network Forensics Tool
- [**459**星][30d] [C#] [chmorgan/sharppcap](https://github.com/chmorgan/sharppcap) Official repository - Fully managed, cross platform (Windows, Mac, Linux) .NET library for capturing packets
- [**210**星][12m] [Py] [mateuszk87/pcapviz](https://github.com/mateuszk87/pcapviz) Visualize network topologies and collect graph statistics based on pcap files
- [**209**星][7m] [JS] [dirtbags/pcapdb](https://github.com/dirtbags/pcapdb) 分布式、搜索优化的网络数据包捕获系统
- [**206**星][4m] [Py] [pynetwork/pypcap](https://github.com/pynetwork/pypcap) python libpcap module, forked from code.google.com/p/pypcap, now actively maintained


### <a id="1692d675f0fc7d190e0a33315f4abae8"></a>劫持&&TCP/HTTP/流量劫持




### <a id="3c28b67524f117ed555daed9cc99e35e"></a>协议分析&&流量分析


- [**1401**星][1m] [Go] [skydive-project/skydive](https://github.com/skydive-project/skydive) An open source real-time network topology and protocols analyzer




***


## <a id="c49aef477cf3397f97f8b72185c3d100"></a>密码&&凭证


### <a id="20bf2e2fefd6de7aadbf0774f4921824"></a>未分类-Password


- [**4772**星][1m] [Py] [alessandroz/lazagne](https://github.com/alessandroz/lazagne) Credentials recovery project
- [**1441**星][1y] [Py] [d4vinci/cr3dov3r](https://github.com/d4vinci/cr3dov3r) Know the dangers of credential reuse attacks.
- [**1025**星][1y] [PowerShell] [danmcinerney/icebreaker](https://github.com/danmcinerney/icebreaker) Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
- [**891**星][16d] [C] [cossacklabs/themis](https://github.com/cossacklabs/themis) themis：用于存储或通信的加密库，可用于Swift, ObjC, Android, С++, JS, Python, Ruby, PHP, Go。
- [**514**星][2m] [Py] [unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) Firefox Decrypt is a tool to extract passwords from Mozilla (Firefox/Thunderbird/Seabird) profiles
- [**492**星][2m] [Py] [byt3bl33d3r/sprayingtoolkit](https://github.com/byt3bl33d3r/sprayingtoolkit) Scripts to make password spraying attacks against Lync/S4B & OWA a lot quicker, less painful and more efficient
- [**483**星][1y] [JS] [emilbayes/secure-password](https://github.com/emilbayes/secure-password) Making Password storage safer for all
- [**442**星][1y] [Go] [ncsa/ssh-auditor](https://github.com/ncsa/ssh-auditor) 扫描网络中的弱SSH密码
- [**385**星][11m] [Shell] [mthbernardes/sshlooter](https://github.com/mthbernardes/sshlooter) Script to steal passwords from ssh.
- [**347**星][3m] [Py] [davidtavarez/pwndb](https://github.com/davidtavarez/pwndb) Search for leaked credentials
- [**295**星][5m] [C#] [raikia/credninja](https://github.com/raikia/credninja) A multithreaded tool designed to identify if credentials are valid, invalid, or local admin valid credentials within a network at-scale via SMB, plus now with a user hunter
- [**284**星][6m] [Shell] [greenwolf/spray](https://github.com/Greenwolf/Spray) A Password Spraying tool for Active Directory Credentials by Jacob Wilkin(Greenwolf)
- [**272**星][2m] [JS] [kspearrin/ff-password-exporter](https://github.com/kspearrin/ff-password-exporter) Easily export your passwords from Firefox.
- [**267**星][1m] [Py] [xfreed0m/rdpassspray](https://github.com/xfreed0m/rdpassspray) Python3 tool to perform password spraying using RDP
- [**255**星][5m] [C] [rub-syssec/omen](https://github.com/rub-syssec/omen) Ordered Markov ENumerator - Password Guesser
- [**210**星][3m] [Ruby] [bdmac/strong_password](https://github.com/bdmac/strong_password) Entropy-based password strength checking for Ruby and Rails.


### <a id="86dc226ae8a71db10e4136f4b82ccd06"></a>密码


- [**6832**星][17d] [C] [hashcat/hashcat](https://github.com/hashcat/hashcat) 世界上最快最先进的密码恢复工具
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/后渗透/未分类-post-exp](#12abc279c69d1fcf10692b9cb89bcdf7) |
- [**5149**星][12m] [JS] [samyk/poisontap](https://github.com/samyk/poisontap) Exploits locked/password protected computers over USB, drops persistent WebSocket-based backdoor, exposes internal router, and siphons cookies using Raspberry Pi Zero & Node.js.
- [**3083**星][13d] [C] [magnumripper/johntheripper](https://github.com/magnumripper/johntheripper) This is the official repo for John the Ripper, "Jumbo" version. The "bleeding-jumbo" branch is based on 1.9.0-Jumbo-1 which was released on May 14, 2019. An import of the "core" version of john this jumbo was based on (or newer) is found in the "master" branch (CVS:
- [**2536**星][1m] [C] [huntergregal/mimipenguin](https://github.com/huntergregal/mimipenguin) dump 当前Linux用户的登录密码
- [**1124**星][7m] [Py] [mebus/cupp](https://github.com/mebus/cupp) Common User Passwords Profiler (CUPP)
- [**859**星][4m] [Go] [fireeye/gocrack](https://github.com/fireeye/gocrack) 火眼开源的密码破解工具，可以跨多个 GPU 服务器执行任务
- [**843**星][2m] [Go] [ukhomeoffice/repo-security-scanner](https://github.com/ukhomeoffice/repo-security-scanner) CLI tool that finds secrets accidentally committed to a git repo, eg passwords, private keys
- [**628**星][1y] [Java] [faizann24/wifi-bruteforcer-fsecurify](https://github.com/faizann24/wifi-bruteforcer-fsecurify) Android app，无需 Root 即可爆破 Wifi 密码
- [**585**星][1y] [Py] [brannondorsey/passgan](https://github.com/brannondorsey/passgan) A Deep Learning Approach for Password Guessing (
- [**578**星][6m] [C] [hashcat/hashcat-utils](https://github.com/hashcat/hashcat-utils) Small utilities that are useful in advanced password cracking
- [**574**星][3m] [Py] [thewhiteh4t/pwnedornot](https://github.com/thewhiteh4t/pwnedornot) OSINT Tool for Finding Passwords of Compromised Email Addresses
- [**482**星][1y] [PowerShell] [dafthack/domainpasswordspray](https://github.com/dafthack/domainpasswordspray) DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS!
- [**404**星][1y] [C++] [vah13/extracttvpasswords](https://github.com/vah13/extracttvpasswords) tool to extract passwords from TeamViewer memory using Frida
- [**344**星][7m] [Py] [iphelix/pack](https://github.com/iphelix/pack) PACK (Password Analysis and Cracking Kit)
- [**318**星][2m] [JS] [auth0/repo-supervisor](https://github.com/auth0/repo-supervisor) Serverless工具，在pull请求中扫描源码，搜索密码及其他秘密
- [**318**星][1m] [CSS] [guyoung/captfencoder](https://github.com/guyoung/captfencoder) CaptfEncoder是一款跨平台网络安全工具套件，提供网络安全相关编码转换、古典密码、密码学、特殊编码等工具，并聚合各类在线工具。




***


## <a id="d5e869a870d6e2c14911de2bc527a6ef"></a>古老的&&有新的替代版本的


- [**1593**星][3m] [Py] [knownsec/pocsuite](https://github.com/knownsec/pocsuite) This project has stopped to maintenance, please to
- [**1510**星][1y] [dripcap/dripcap](https://github.com/dripcap/dripcap) 
- [**845**星][1y] [Py] [kgretzky/evilginx](https://github.com/kgretzky/evilginx) PLEASE USE NEW VERSION:


***


## <a id="983f763457e9599b885b13ea49682130"></a>Windows


- [**8590**星][3m] [C] [gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz) A little tool to play with Windows security
- [**2084**星][1m] [Py] [trustedsec/unicorn](https://github.com/trustedsec/unicorn) 通过PowerShell降级攻击, 直接将Shellcode注入到内存


***


## <a id="bad06ceb38098c26b1b8b46104f98d25"></a>webshell


### <a id="e08366dcf7aa021c6973d9e2a8944dff"></a>收集


- [**21409**星][14d] [PHP] [danielmiessler/seclists](https://github.com/danielmiessler/seclists) 多种类型资源收集：用户名、密码、URL、敏感数据类型、Fuzzing  Payload、WebShell等
    - 重复区段: [工具/wordlist/收集](#3202d8212db5699ea5e6021833bf3fa2) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload收集](#b5d99a78ddb383c208aae474fc2cb002) |
- [**5033**星][1m] [PHP] [tennc/webshell](https://github.com/tennc/webshell) webshell收集


### <a id="faa91844951d2c29b7b571c6e8a3eb54"></a>未分类-webshell


- [**1739**星][2m] [Py] [epinna/weevely3](https://github.com/epinna/weevely3) Weaponized web shell
- [**956**星][1m] [Py] [yzddmr6/webshell-venom](https://github.com/yzddmr6/webshell-venom) 免杀webshell无限生成工具(利用随机异或无限免杀D盾)
- [**474**星][7m] [ASP] [landgrey/webshell-detect-bypass](https://github.com/landgrey/webshell-detect-bypass) 绕过专业工具检测的Webshell研究文章和免杀的Webshell
- [**421**星][1y] [Py] [shmilylty/cheetah](https://github.com/shmilylty/cheetah) a very fast brute force webshell password tool
- [**411**星][1y] [PHP] [ysrc/webshell-sample](https://github.com/ysrc/webshell-sample) 收集自网络各处的 webshell 样本，用于测试 webshell 扫描器检测率。
- [**366**星][5m] [PHP] [blackarch/webshells](https://github.com/blackarch/webshells) Various webshells. We accept pull requests for additions to this collection.
- [**351**星][7m] [PHP] [s0md3v/nano](https://github.com/s0md3v/nano) PHP Webshell家族
- [**305**星][8m] [Py] [wangyihang/webshell-sniper](https://github.com/wangyihang/webshell-sniper) webshell管理器，命令行工具
- [**282**星][1y] [JS] [chrisallenlane/novahot](https://github.com/chrisallenlane/novahot) Webshell框架，实现了基于Json的API，可与任何语言编写的后门（默认支持PHP/Ruby/Python）进行通信。
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/后渗透/未分类-post-exp](#12abc279c69d1fcf10692b9cb89bcdf7) |
- [**243**星][8m] [Py] [antoniococo/sharpyshell](https://github.com/antoniococo/sharpyshell) ASP.NET webshell，小型，混淆，针对C# Web App
- [**207**星][6m] [PHP] [samdark/yii2-webshell](https://github.com/samdark/yii2-webshell) Web shell allows to run yii console commands using a browser




***


## <a id="43b0310ac54c147a62c545a2b0f4bce2"></a>辅助周边


### <a id="569887799ee0148230cc5d7bf98e96d0"></a>未分类


- [**25893**星][12d] [Py] [certbot/certbot](https://github.com/certbot/certbot) Certbot is EFF's tool to obtain certs from Let's Encrypt and (optionally) auto-enable HTTPS on your server. It can also act as a client for any other CA that uses the ACME protocol.
- [**7594**星][17d] [JS] [gchq/cyberchef](https://github.com/gchq/cyberchef) The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis
- [**4838**星][2m] [Rust] [sharkdp/hexyl](https://github.com/sharkdp/hexyl) 命令行中查看hex
- [**4230**星][14d] [JS] [cure53/dompurify](https://github.com/cure53/dompurify) DOMPurify - a DOM-only, super-fast, uber-tolerant XSS sanitizer for HTML, MathML and SVG. DOMPurify works with a secure default, but offers a lot of configurability and hooks. Demo:
- [**3166**星][6m] [HTML] [leizongmin/js-xss](https://github.com/leizongmin/js-xss) Sanitize untrusted HTML (to prevent XSS) with a configuration specified by a Whitelist
- [**3078**星][2m] [Shell] [trimstray/htrace.sh](https://github.com/trimstray/htrace.sh) My simple Swiss Army knife for http/https troubleshooting and profiling.
- [**949**星][8m] [Go] [maliceio/malice](https://github.com/maliceio/malice) 开源版的VirusTotal
- [**500**星][17d] [Py] [certtools/intelmq](https://github.com/certtools/intelmq) IntelMQ is a solution for IT security teams for collecting and processing security feeds using a message queuing protocol.
- [**464**星][4m] [JS] [ehrishirajsharma/swiftnessx](https://github.com/ehrishirajsharma/swiftnessx) A cross-platform note-taking & target-tracking app for penetration testers.


### <a id="86d5daccb4ed597e85a0ec9c87f3c66f"></a>TLS&&SSL&&HTTPS


- [**4292**星][5m] [Py] [diafygi/acme-tiny](https://github.com/diafygi/acme-tiny) A tiny script to issue and renew TLS certs from Let's Encrypt
- [**1663**星][2m] [HTML] [chromium/badssl.com](https://github.com/chromium/badssl.com) 
- [**1177**星][2m] [Go] [jsha/minica](https://github.com/jsha/minica) minica is a small, simple CA intended for use in situations where the CA operator also operates each host where a certificate will be used.
- [**1126**星][19d] [Go] [smallstep/certificates](https://github.com/smallstep/certificates) 私有的证书颁发机构（X.509和SSH）和ACME服务器，用于安全的自动证书管理，因此您可以在SSH和SSO处使用TLS
- [**507**星][14d] [Java] [rub-nds/tls-attacker](https://github.com/rub-nds/tls-attacker) TLS-Attacker is a Java-based framework for analyzing TLS libraries. It is developed by the Ruhr University Bochum (




***


## <a id="e1fc1d87056438f82268742dc2ba08f5"></a>事件响应&&取证&&内存取证&&数字取证


### <a id="65f1e9dc3e08dff9fcda9d2ee245764e"></a>未分类-Forensics




### <a id="d0f59814394c5823210aa04a8fcd1220"></a>事件响应&&IncidentResponse


- [**3054**星][14d] [meirwah/awesome-incident-response](https://github.com/meirwah/awesome-incident-response) A curated list of tools for incident response
- [**1801**星][4m] [bypass007/emergency-response-notes](https://github.com/bypass007/emergency-response-notes) 应急响应实战笔记，一个安全工程师的自我修养。
- [**1310**星][3m] [HTML] [thehive-project/thehive](https://github.com/thehive-project/thehive) TheHive: a Scalable, Open Source and Free Security Incident Response Platform
- [**1132**星][10m] [Py] [certsocietegenerale/fir](https://github.com/certsocietegenerale/fir) Fast Incident Response
- [**988**星][9m] [Go] [gencebay/httplive](https://github.com/gencebay/httplive) HTTP Request & Response Service, Mock HTTP
- [**965**星][1m] [JS] [monzo/response](https://github.com/monzo/response) Monzo's real-time incident response and reporting tool
- [**764**星][16d] [microsoft/msrc-security-research](https://github.com/microsoft/msrc-security-research) Security Research from the Microsoft Security Response Center (MSRC)
- [**744**星][10m] [PowerShell] [davehull/kansa](https://github.com/davehull/kansa) A Powershell incident response framework
- [**710**星][2m] [HTML] [pagerduty/incident-response-docs](https://github.com/pagerduty/incident-response-docs) PagerDuty's Incident Response Documentation.
- [**634**星][9m] [Roff] [palantir/windows-event-forwarding](https://github.com/palantir/windows-event-forwarding) 使用 Windows 事件转发实现网络事件监测和防御
- [**627**星][21d] [Kotlin] [chuckerteam/chucker](https://github.com/chuckerteam/chucker) simplifies the inspection of HTTP(S) requests/responses, and Throwables fired by your Android App
- [**579**星][9m] [Go] [nytimes/gziphandler](https://github.com/nytimes/gziphandler) Go middleware to gzip HTTP responses
- [**535**星][5m] [Py] [owasp/qrljacking](https://github.com/owasp/qrljacking) 一个简单的能够进行会话劫持的社会工程攻击向量，影响所有使用“使用 QR 码登录”作为安全登录方式的应用程序。（ Quick Response CodeLogin Jacking）
- [**459**星][6m] [palantir/osquery-configuration](https://github.com/palantir/osquery-configuration) 使用 osquery 做事件检测和响应
- [**452**星][28d] [Py] [controlscanmdr/cyphon](https://github.com/controlscanmdr/cyphon) 事件管理和响应平台
- [**286**星][1m] [Py] [alexandreborges/malwoverview](https://github.com/alexandreborges/malwoverview) Malwoverview.py is a first response tool to perform an initial and quick triage in a directory containing malware samples, specific malware sample, suspect URL and domains. Additionally, it allows to download and send samples to main online sandboxes.
- [**251**星][1m] [C#] [orlikoski/cylr](https://github.com/orlikoski/CyLR) CyLR - Live Response Collection Tool
- [**204**星][2m] [PowerShell] [wiredpulse/posh-r2](https://github.com/wiredpulse/posh-r2) PowerShell - Rapid Response... For the incident responder in you!


### <a id="1fc5d3621bb13d878f337c8031396484"></a>取证&&Forensics&&数字取证&&内存取证


- [**3315**星][2m] [Py] [google/grr](https://github.com/google/grr) GRR Rapid Response: remote live forensics for incident response
- [**1486**星][9m] [Py] [google/rekall](https://github.com/google/rekall) Rekall Memory Forensic Framework
- [**1465**星][18d] [C] [sleuthkit/sleuthkit](https://github.com/sleuthkit/sleuthkit) The Sleuth Kit® (TSK) is a library and collection of command line digital forensics tools that allow you to investigate volume and file system data. The library can be incorporated into larger digital forensics tools and the command line tools can be directly used to find evidence.
- [**1200**星][27d] [Py] [google/timesketch](https://github.com/google/timesketch) Collaborative forensic timeline analysis
- [**1152**星][2m] [Go] [mozilla/mig](https://github.com/mozilla/mig) mig：分布式实时数字取证和研究平台
- [**953**星][1m] [Rich Text Format] [decalage2/oletools](https://github.com/decalage2/oletools) oletools - python tools to analyze MS OLE2 files (Structured Storage, Compound File Binary Format) and MS Office documents, for malware analysis, forensics and debugging.
- [**940**星][17d] [C++] [hasherezade/pe-sieve](https://github.com/hasherezade/pe-sieve) Scans a given process. Recognizes and dumps a variety of potentially malicious implants (replaced/injected PEs, shellcodes, hooks, in-memory patches).
- [**909**星][2m] [Py] [ondyari/faceforensics](https://github.com/ondyari/faceforensics) Github of the FaceForensics dataset
- [**826**星][12d] [Java] [sleuthkit/autopsy](https://github.com/sleuthkit/autopsy) Autopsy® is a digital forensics platform and graphical interface to The Sleuth Kit® and other digital forensics tools. It can be used by law enforcement, military, and corporate examiners to investigate what happened on a computer. You can even use it to recover photos from your camera's memory card.
- [**817**星][21d] [cugu/awesome-forensics](https://github.com/cugu/awesome-forensics) A curated list of awesome forensic analysis tools and resources
- [**802**星][14d] [Py] [yampelo/beagle](https://github.com/yampelo/beagle) Beagle is an incident response and digital forensics tool which transforms security logs and data into graphs.
- [**744**星][19d] [Py] [snovvcrash/usbrip](https://github.com/snovvcrash/usbrip) Simple CLI forensics tool for tracking USB device artifacts (history of USB events) on GNU/Linux
    - 重复区段: [工具/硬件设备&&USB&树莓派/USB](#48c53d1304b1335d9addf45b959b7d8a) |
- [**419**星][2m] [Py] [obsidianforensics/hindsight](https://github.com/obsidianforensics/hindsight) Internet history forensics for Google Chrome/Chromium
- [**400**星][14d] [Py] [forensicartifacts/artifacts](https://github.com/forensicartifacts/artifacts) Digital Forensics Artifact Repository
- [**391**星][10m] [Go] [mozilla/masche](https://github.com/mozilla/masche) MIG Memory Forensic library
- [**321**星][10m] [Py] [alessandroz/lazagneforensic](https://github.com/alessandroz/lazagneforensic) Windows passwords decryption from dump files
- [**317**星][3m] [HTML] [intezer/linux-explorer](https://github.com/intezer/linux-explorer) linux-explorer: 针对Linux 系统的现场取证工具箱. Web 界面, 简单易用
- [**311**星][8m] [Py] [n0fate/chainbreaker](https://github.com/n0fate/chainbreaker) Mac OS X Keychain Forensic Tool
- [**301**星][2m] [Py] [google/turbinia](https://github.com/google/turbinia) Automation and Scaling of Digital Forensics Tools
- [**296**星][24d] [Shell] [vitaly-kamluk/bitscout](https://github.com/vitaly-kamluk/bitscout) bitscout：远程数据取证工具
- [**268**星][12d] [Perl] [owasp/o-saft](https://github.com/owasp/o-saft) O-Saft - OWASP SSL advanced forensic tool
- [**255**星][6m] [Batchfile] [diogo-fernan/ir-rescue](https://github.com/diogo-fernan/ir-rescue) A Windows Batch script and a Unix Bash script to comprehensively collect host forensic data during incident response.
- [**250**星][21d] [Py] [google/docker-explorer](https://github.com/google/docker-explorer) A tool to help forensicate offline docker acquisitions
- [**248**星][12m] [C++] [comaeio/swishdbgext](https://github.com/comaeio/SwishDbgExt) Incident Response & Digital Forensics Debugging Extension
- [**243**星][11m] [Py] [crowdstrike/forensics](https://github.com/crowdstrike/forensics) Scripts and code referenced in CrowdStrike blog posts
- [**241**星][1m] [Py] [orlikoski/cdqr](https://github.com/orlikoski/CDQR) The Cold Disk Quick Response (CDQR) tool is a fast and easy to use forensic artifact parsing tool that works on disk images, mounted drives and extracted artifacts from Windows, Linux, MacOS, and Android devices
- [**227**星][30d] [C] [elfmaster/libelfmaster](https://github.com/elfmaster/libelfmaster) Secure ELF parsing/loading library for forensics reconstruction of malware, and robust reverse engineering tools
- [**217**星][2m] [Py] [crowdstrike/automactc](https://github.com/crowdstrike/automactc) AutoMacTC: Automated Mac Forensic Triage Collector


### <a id="4d2a33083a894d6e6ef01b360929f30a"></a>Volatility


- [**3199**星][2m] [Py] [volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility) An advanced memory forensics framework
- [**308**星][7m] [Py] [jasonstrimpel/volatility-trading](https://github.com/jasonstrimpel/volatility-trading) A complete set of volatility estimators based on Euan Sinclair's Volatility Trading
- [**224**星][2m] [Py] [volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles) Volatility profiles for Linux and Mac OS X
- [**219**星][1m] [Py] [volatilityfoundation/community](https://github.com/volatilityfoundation/community) Volatility plugins developed and maintained by the community




***


## <a id="a2df15c7819a024c2f5c4a7489285597"></a>密罐&&Honeypot


### <a id="2af349669891f54649a577b357aa81a6"></a>未分类-Honeypot


- [**1784**星][1m] [Py] [threatstream/mhn](https://github.com/pwnlandia/mhn) 蜜罐网络
- [**1259**星][21d] [C] [dtag-dev-sec/tpotce](https://github.com/dtag-dev-sec/tpotce) tpotce：创建多蜜罐平台T-Pot ISO 镜像
- [**1201**星][24d] [Go] [hacklcx/hfish](https://github.com/hacklcx/hfish) 扩展企业安全测试主动诱导型开源蜜罐框架系统，记录黑客攻击手段
- [**400**星][3m] [Py] [nsmfoo/antivmdetection](https://github.com/nsmfoo/antivmdetection) Script to create templates to use with VirtualBox to make vm detection harder
- [**356**星][2m] [Py] [p1r06u3/opencanary_web](https://github.com/p1r06u3/opencanary_web) The web management platform of honeypot
- [**325**星][1y] [JS] [shmakov/honeypot](https://github.com/shmakov/honeypot) Low interaction honeypot that displays real time attacks
- [**303**星][1m] [Py] [hatching/vmcloak](https://github.com/hatching/vmcloak) Automated Virtual Machine Generation and Cloaking for Cuckoo Sandbox.
- [**271**星][1y] [Py] [gbafana25/esp8266_honeypot](https://github.com/gbafana25/esp8266_honeypot) THE ESP8266 HONEYPOT: A PROJECT TO TRAP SCRIPT KIDDIES EVERYWHRE!!
- [**229**星][1y] [Shell] [aplura/tango](https://github.com/aplura/tango) Honeypot Intelligence with Splunk
- [**227**星][9m] [Py] [honeynet/beeswarm](https://github.com/honeynet/beeswarm) Honeypot deployment made easy
- [**219**星][1m] [Py] [jamesturk/django-honeypot](https://github.com/jamesturk/django-honeypot) 


### <a id="d20acdc34ca7c084eb52ca1c14f71957"></a>密罐


- [**735**星][1m] [Py] [buffer/thug](https://github.com/buffer/thug) Python low-interaction honeyclient
- [**687**星][4m] [Py] [mushorg/conpot](https://github.com/mushorg/conpot) ICS/SCADA honeypot
- [**668**星][6m] [Go] [honeytrap/honeytrap](https://github.com/honeytrap/honeytrap) 高级蜜罐框架, 可以运行/监控/管理蜜罐. Go语言编写
- [**574**星][2m] [Py] [thinkst/opencanary](https://github.com/thinkst/opencanary) Modular and decentralised honeypot
- [**396**星][2m] [Py] [mushorg/glastopf](https://github.com/mushorg/glastopf) Web Application Honeypot
- [**379**星][3m] [Py] [foospidy/honeypy](https://github.com/foospidy/honeypy) A low to medium interaction honeypot.
- [**371**星][1m] [Py] [dinotools/dionaea](https://github.com/dinotools/dionaea) Home of the dionaea honeypot
- [**224**星][1m] [Py] [johnnykv/heralding](https://github.com/johnnykv/heralding) Credentials catching honeypot
- [**215**星][1m] [Py] [mushorg/snare](https://github.com/mushorg/snare) Super Next generation Advanced Reactive honEypot


### <a id="efde8c850d8d09e7c94aa65a1ab92acf"></a>收集


- [**3708**星][1m] [Py] [paralax/awesome-honeypots](https://github.com/paralax/awesome-honeypots) an awesome list of honeypot resources


### <a id="c8f749888134d57b5fb32382c78ef2d1"></a>SSH&&Telnet


- [**2906**星][18d] [Py] [cowrie/cowrie](https://github.com/cowrie/cowrie) cowrie：中型/交互型 SSH/Telnet 蜜罐，
- [**272**星][27d] [C] [droberson/ssh-honeypot](https://github.com/droberson/ssh-honeypot) Fake sshd that logs ip addresses, usernames, and passwords.


### <a id="356be393f6fb9215c14799e5cd723fca"></a>TCP&&UDP




### <a id="577fc2158ab223b65442fb0fd4eb8c3e"></a>HTTP&&Web


- [**433**星][1y] [Py] [0x4d31/honeylambda](https://github.com/0x4d31/honeylambda) honeyλ - a simple, serverless application designed to create and monitor fake HTTP endpoints (i.e. URL honeytokens) automatically, on top of AWS Lambda and Amazon API Gateway


### <a id="35c6098cbdc5202bf7f60979a76a5691"></a>ActiveDirectory




### <a id="7ac08f6ae5c88efe2cd5b47a4d391e7e"></a>SMTP




### <a id="8c58c819e0ba0442ae90d8555876d465"></a>打印机




### <a id="1a6b81fd9550736d681d6d0e99ae69e3"></a>Elasticsearch




### <a id="57356b67511a9dc7497b64b007047ee7"></a>ADB




### <a id="c5b6762b3dc783a11d72dea648755435"></a>蓝牙&&Bluetooth 


- [**1261**星][1m] [Py] [virtualabs/btlejack](https://github.com/virtualabs/btlejack) Bluetooth Low Energy Swiss-army knife
- [**1120**星][9m] [evilsocket/bleah](https://github.com/evilsocket/bleah) 低功耗蓝牙扫描器
- [**865**星][3m] [Java] [googlearchive/android-bluetoothlegatt](https://github.com/googlearchive/android-BluetoothLeGatt) Migrated:
- [**292**星][11m] [JS] [jeija/bluefluff](https://github.com/jeija/bluefluff) Reverse Engineering Furby Connect's Bluetooth Protocol and Update Format


### <a id="2a77601ce72f944679b8c5650d50148d"></a>其他类型


#### <a id="1d0819697e6bc533f564383d0b98b386"></a>Wordpress








***


## <a id="f56806b5b229bdf6c118f5fb1092e141"></a>威胁情报


### <a id="8fd1f0cfde78168c88fc448af9c6f20f"></a>未分类-ThreatIntelligence


- [**2390**星][13d] [PHP] [misp/misp](https://github.com/misp/misp) MISP (core software) - Open Source Threat Intelligence and Sharing Platform (formely known as Malware Information Sharing Platform)
- [**1836**星][3m] [YARA] [yara-rules/rules](https://github.com/yara-rules/rules) Repository of yara rules
- [**1246**星][15d] [Shell] [firehol/blocklist-ipsets](https://github.com/firehol/blocklist-ipsets) ipsets dynamically updated with firehol's update-ipsets.sh script
- [**826**星][19d] [YARA] [neo23x0/signature-base](https://github.com/neo23x0/signature-base) Signature base for my scanner tools
- [**824**星][27d] [JS] [opencti-platform/opencti](https://github.com/opencti-platform/opencti) Open Cyber Threat Intelligence Platform
- [**786**星][17d] [Py] [yeti-platform/yeti](https://github.com/yeti-platform/yeti) yeti：情报威胁管理平台
- [**715**星][24d] [C++] [facebook/threatexchange](https://github.com/facebook/threatexchange) Share threat information with vetted partners
- [**704**星][2m] [Go] [activecm/rita](https://github.com/activecm/rita) Real Intelligence Threat Analytics
- [**505**星][6m] [Py] [te-k/harpoon](https://github.com/te-k/harpoon) CLI tool for open source and threat intelligence
- [**444**星][4m] [PHP] [kasperskylab/klara](https://github.com/kasperskylab/klara) Kaspersky's GReAT KLara
- [**411**星][1m] [mitre/cti](https://github.com/mitre/cti) Cyber Threat Intelligence Repository expressed in STIX 2.0
- [**407**星][3m] [Scala] [thehive-project/cortex](https://github.com/TheHive-Project/Cortex) Cortex: a Powerful Observable Analysis and Active Response Engine
- [**374**星][7m] [Py] [hurricanelabs/machinae](https://github.com/hurricanelabs/machinae) Machinae Security Intelligence Collector
- [**290**星][6m] [YARA] [supportintelligence/icewater](https://github.com/supportintelligence/icewater) 16,432 Free Yara rules created by
- [**253**星][2m] [Py] [diogo-fernan/malsub](https://github.com/diogo-fernan/malsub) A Python RESTful API framework for online malware analysis and threat intelligence services.
- [**234**星][2m] [Py] [cylance/cybot](https://github.com/cylance/CyBot) Open Source Threat Intelligence Chat Bot
- [**231**星][1m] [Py] [anouarbensaad/vulnx](https://github.com/anouarbensaad/vulnx) An Intelligent Bot Auto Shell Injector that detect vulnerabilities in multiple types of CMS
- [**217**星][2m] [Py] [inquest/threatingestor](https://github.com/inquest/threatingestor) Extract and aggregate threat intelligence.
- [**208**星][18d] [Py] [inquest/omnibus](https://github.com/inquest/omnibus) The OSINT Omnibus (beta release)
- [**201**星][3m] [Py] [yelp/threat_intel](https://github.com/yelp/threat_intel) Threat Intelligence APIs


### <a id="91dc39dc492ee8ef573e1199117bc191"></a>收集


- [**3117**星][5m] [hslatman/awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence) A curated list of Awesome Threat Intelligence resources
- [**1459**星][14d] [YARA] [cybermonitor/apt_cybercriminal_campagin_collections](https://github.com/cybermonitor/apt_cybercriminal_campagin_collections) APT & CyberCriminal Campaign Collection


### <a id="3e10f389acfbd56b79f52ab4765e11bf"></a>IOC


#### <a id="c94be209c558a65c5e281a36667fc27a"></a>未分类


- [**1408**星][1m] [Py] [neo23x0/loki](https://github.com/neo23x0/loki) Loki - Simple IOC and Incident Response Scanner
- [**208**星][4m] [Shell] [neo23x0/fenrir](https://github.com/neo23x0/fenrir) Simple Bash IOC Scanner


#### <a id="20a019435f1c5cc75e574294c01f3fee"></a>IOC集合


- [**405**星][8m] [Shell] [sroberts/awesome-iocs](https://github.com/sroberts/awesome-iocs) A collection of sources of indicators of compromise.


#### <a id="1b1aa1dfcff3054bc20674230ee52cfe"></a>IOC提取


- [**212**星][23d] [Py] [inquest/python-iocextract](https://github.com/inquest/python-iocextract) IoC提取器


#### <a id="9bcb156b2e3b7800c42d5461c0062c02"></a>IOC获取


- [**652**星][13d] [Py] [blackorbird/apt_report](https://github.com/blackorbird/apt_report) Interesting apt report collection and some special ioc express
- [**626**星][28d] [YARA] [eset/malware-ioc](https://github.com/eset/malware-ioc) Indicators of Compromises (IOC) of our various investigations
- [**418**星][1y] [JS] [ciscocsirt/gosint](https://github.com/ciscocsirt/gosint) 收集、处理、索引高质量IOC的框架
- [**303**星][1y] [Py] [fsecurelabs/win_driver_plugin](https://github.com/FSecureLABS/win_driver_plugin) A tool to help when dealing with Windows IOCTL codes or reversing Windows drivers.
- [**257**星][2m] [PHP] [pan-unit42/iocs](https://github.com/pan-unit42/iocs) Indicators from Unit 42 Public Reports






***


## <a id="946d766c6a0fb23b480ff59d4029ec71"></a>防护&&Defense


### <a id="7a277f8b0e75533e0b50d93c902fb351"></a>未分类-Defense


- [**630**星][5m] [Py] [binarydefense/artillery](https://github.com/binarydefense/artillery) The Artillery Project is an open-source blue team tool designed to protect Linux and Windows operating systems through multiple methods.


### <a id="784ea32a3f4edde1cd424b58b17e7269"></a>WAF


- [**3248**星][2m] [C] [nbs-system/naxsi](https://github.com/nbs-system/naxsi) NAXSI is an open-source, high performance, low rules maintenance WAF for NGINX
- [**3125**星][17d] [C++] [spiderlabs/modsecurity](https://github.com/spiderlabs/modsecurity) ModSecurity is an open source, cross platform web application firewall (WAF) engine for Apache, IIS and Nginx that is developed by Trustwave's SpiderLabs. It has a robust event-based programming language which provides protection from a range of attacks against web applications and allows for HTTP traffic monitoring, logging and real-time analys…
- [**617**星][2m] [Py] [3xp10it/xwaf](https://github.com/3xp10it/xwaf) waf 自动爆破(绕过)工具
- [**600**星][3m] [Lua] [jx-sec/jxwaf](https://github.com/jx-sec/jxwaf) JXWAF(锦衣盾)是一款基于openresty(nginx+lua)开发的web应用防火墙
- [**599**星][1y] [Lua] [unixhot/waf](https://github.com/unixhot/waf) 使用Nginx+Lua实现的WAF（版本v1.0）
- [**543**星][7m] [Py] [s0md3v/blazy](https://github.com/s0md3v/Blazy) Blazy is a modern login bruteforcer which also tests for CSRF, Clickjacking, Cloudflare and WAF .
- [**500**星][1m] [Go] [janusec/janusec](https://github.com/janusec/janusec) Janusec Application Gateway, a Golang based application security solution which provides WAF (Web Application Firewall), CC attack defense, unified web administration portal, private key protection, web routing and scalable load balancing.
- [**462**星][7m] [Java] [chengdedeng/waf](https://github.com/chengdedeng/waf) 
- [**436**星][2m] [PHP] [akaunting/firewall](https://github.com/akaunting/firewall) Web Application Firewall (WAF) package for Laravel
- [**424**星][8m] [Py] [aws-samples/aws-waf-sample](https://github.com/aws-samples/aws-waf-sample) This repository contains example scripts and sets of rules for the AWS WAF service. Please be aware that the applicability of these examples to specific workloads may vary.
- [**406**星][1m] [C#] [jbe2277/waf](https://github.com/jbe2277/waf) Win Application Framework (WAF) is a lightweight Framework that helps you to create well structured XAML Applications.
- [**401**星][7m] [Py] [awslabs/aws-waf-security-automations](https://github.com/awslabs/aws-waf-security-automations) This solution automatically deploys a single web access control list (web ACL) with a set of AWS WAF rules designed to filter common web-based attacks.
- [**401**星][10m] [C] [titansec/openwaf](https://github.com/titansec/openwaf) Web security protection system based on openresty
- [**243**星][1y] [Py] [warflop/cloudbunny](https://github.com/warflop/cloudbunny) CloudBunny is a tool to capture the real IP of the server that uses a WAF as a proxy or protection. In this tool we used three search engines to search domain information: Shodan, Censys and Zoomeye.
- [**207**星][6m] [C] [coolervoid/raptor_waf](https://github.com/coolervoid/raptor_waf) Raptor - WAF - Web application firewall using DFA [ Current version ] - Beta


### <a id="ce6532938f729d4c9d66a5c75d1676d3"></a>防火墙&&FireWall


- [**4162**星][2m] [Py] [evilsocket/opensnitch](https://github.com/evilsocket/opensnitch) opensnitch：Little Snitch 应用程序防火墙的 GNU/Linux 版本。（Little Snitch：Mac操作系统的应用程序防火墙，能防止应用程序在你不知道的情况下自动访问网络）
- [**3186**星][1m] [Objective-C] [objective-see/lulu](https://github.com/objective-see/lulu) LuLu is the free macOS firewall
- [**1515**星][12d] [Java] [ukanth/afwall](https://github.com/ukanth/afwall) AFWall+ (Android Firewall +) - iptables based firewall for Android
- [**1031**星][9m] [Shell] [firehol/firehol](https://github.com/firehol/firehol) A firewall for humans...
- [**817**星][4m] [trimstray/iptables-essentials](https://github.com/trimstray/iptables-essentials) Iptables Essentials: Common Firewall Rules and Commands.
- [**545**星][6m] [Go] [sysdream/chashell](https://github.com/sysdream/chashell) Chashell is a Go reverse shell that communicates over DNS. It can be used to bypass firewalls or tightly restricted networks.
- [**449**星][5m] [Shell] [vincentcox/bypass-firewalls-by-dns-history](https://github.com/vincentcox/bypass-firewalls-by-dns-history) Firewall bypass script based on DNS history records. This script will search for DNS A history records and check if the server replies for that domain. Handy for bugbounty hunters.
- [**232**星][4m] [Shell] [essandess/macos-fortress](https://github.com/essandess/macos-fortress) Firewall and Privatizing Proxy for Trackers, Attackers, Malware, Adware, and Spammers with Anti-Virus On-Demand and On-Access Scanning (PF, squid, privoxy, hphosts, dshield, emergingthreats, hostsfile, PAC file, clamav)
- [**220**星][1y] [Go] [maksadbek/tcpovericmp](https://github.com/maksadbek/tcpovericmp) TCP implementation over ICMP protocol to bypass firewalls


### <a id="ff3e0b52a1477704b5f6a94ccf784b9a"></a>IDS&&IPS


- [**2874**星][27d] [Zeek] [zeek/zeek](https://github.com/zeek/zeek) Zeek is a powerful network analysis framework that is much different from the typical IDS you may know.
- [**2798**星][1m] [C] [ossec/ossec-hids](https://github.com/ossec/ossec-hids) ossec-hids：入侵检测系统
- [**1589**星][1m] [Go] [ysrc/yulong-hids](https://github.com/ysrc/yulong-hids) 一款由 YSRC 开源的主机入侵检测系统
- [**1252**星][1m] [C] [oisf/suricata](https://github.com/OISF/suricata) a network IDS, IPS and NSM engine
- [**524**星][19d] [Py] [0kee-team/watchad](https://github.com/0kee-team/watchad) AD Security Intrusion Detection System
- [**507**星][4m] [C] [decaf-project/decaf](https://github.com/decaf-project/DECAF) DECAF (short for Dynamic Executable Code Analysis Framework) is a binary analysis platform based on QEMU. This is also the home of the DroidScope dynamic Android malware analysis platform. DroidScope is now an extension to DECAF.
- [**489**星][7m] [Shell] [stamusnetworks/selks](https://github.com/stamusnetworks/selks) A Suricata based IDS/IPS distro
- [**369**星][6m] [jnusimba/androidsecnotes](https://github.com/jnusimba/androidsecnotes) some learning notes about Android Security
- [**278**星][13d] [C] [ebwi11/agentsmith-hids](https://github.com/EBWi11/AgentSmith-HIDS) Low performance loss and by LKM technology HIDS tool, from E_Bwill.
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
- [**382**星][3m] [Ruby] [digininja/cewl](https://github.com/digininja/cewl) CeWL is a Custom Word List Generator
- [**328**星][4m] [Py] [initstring/passphrase-wordlist](https://github.com/initstring/passphrase-wordlist) Passphrase wordlist and hashcat rules for offline cracking of long, complex passwords
- [**251**星][1y] [Py] [berzerk0/bewgor](https://github.com/berzerk0/bewgor) Bull's Eye Wordlist Generator - Does your password rely on predictable patterns of accessible info?


### <a id="3202d8212db5699ea5e6021833bf3fa2"></a>收集


- [**21409**星][14d] [PHP] [danielmiessler/seclists](https://github.com/danielmiessler/seclists) 多种类型资源收集：用户名、密码、URL、敏感数据类型、Fuzzing  Payload、WebShell等
    - 重复区段: [工具/webshell/收集](#e08366dcf7aa021c6973d9e2a8944dff) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/Payload&&远控&&RAT/Payload收集](#b5d99a78ddb383c208aae474fc2cb002) |
- [**5955**星][6m] [berzerk0/probable-wordlists](https://github.com/berzerk0/probable-wordlists) Version 2 is live! Wordlists sorted by probability originally created for password generation and testing - make sure your passwords aren't popular!


### <a id="f2c76d99a0b1fda124d210bd1bbc8f3f"></a>Wordlist生成






***


## <a id="96171a80e158b8752595329dd42e8bcf"></a>泄漏&&Breach&&Leak


- [**1358**星][5m] [gitguardian/apisecuritybestpractices](https://github.com/gitguardian/apisecuritybestpractices) Resources to help you keep secrets (API keys, database credentials, certificates, ...) out of source code and remediate the issue in case of a leaked API key. Made available by GitGuardian.
- [**885**星][21d] [Py] [woj-ciech/leaklooker](https://github.com/woj-ciech/leaklooker) Find open databases - Powered by Binaryedge.io


***


## <a id="de81f9dd79c219c876c1313cd97852ce"></a>破解&&Crack&&爆破&&BruteForce


- [**3217**星][18d] [C] [vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra) 网络登录破解，支持多种服务
- [**1885**星][1m] [Py] [lanjelot/patator](https://github.com/lanjelot/patator) Patator is a multi-purpose brute-forcer, with a modular design and a flexible usage.
- [**1042**星][3m] [Py] [landgrey/pydictor](https://github.com/landgrey/pydictor) A powerful and useful hacker dictionary builder for a brute-force attack
- [**875**星][2m] [Py] [trustedsec/hate_crack](https://github.com/trustedsec/hate_crack) hate_crack: 使用HashCat 的自动哈希破解工具
- [**789**星][6m] [C] [brendan-rius/c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker) C 语言编写的 JWT 爆破工具
- [**780**星][10m] [Py] [mak-/parameth](https://github.com/mak-/parameth) 在文件中(例如PHP 文件)暴力搜索GET 和 POST 请求的参数
- [**748**星][4m] [Py] [s0md3v/hash-buster](https://github.com/s0md3v/Hash-Buster) Crack hashes in seconds.
- [**679**星][7m] [Shell] [1n3/brutex](https://github.com/1n3/brutex) Automatically brute force all services running on a target.
- [**625**星][2m] [JS] [animir/node-rate-limiter-flexible](https://github.com/animir/node-rate-limiter-flexible) Node.js rate limit requests by key and protection from DDoS and Brute-Force attacks in process Memory, Redis, MongoDb, Memcached, MySQL, PostgreSQL, Cluster or PM
- [**619**星][4m] [C#] [shack2/snetcracker](https://github.com/shack2/snetcracker) 超级弱口令检查工具是一款Windows平台的弱口令审计工具，支持批量多线程检查，可快速发现弱密码、弱口令账号，密码支持和用户名结合进行检查，大大提高成功率，支持自定义服务端口和字典。
- [**606**星][1y] [C] [nfc-tools/mfoc](https://github.com/nfc-tools/mfoc) Mifare Classic Offline Cracker
- [**551**星][5m] [PHP] [s3inlc/hashtopolis](https://github.com/s3inlc/hashtopolis) Hashcat wrapper, 用于跨平台分布式Hash破解
- [**546**星][1y] [CSS] [hashview/hashview](https://github.com/hashview/hashview) 密码破解和分析工具
- [**516**星][3m] [C] [nmap/ncrack](https://github.com/nmap/ncrack) Ncrack network authentication tool
- [**507**星][1m] [Py] [pure-l0g1c/instagram](https://github.com/pure-l0g1c/instagram) Bruteforce attack for Instagram
- [**499**星][3m] [duyetdev/bruteforce-database](https://github.com/duyetdev/bruteforce-database) Bruteforce database
- [**487**星][1y] [C] [mikeryan/crackle](https://github.com/mikeryan/crackle) Crack and decrypt BLE encryption
- [**437**星][1y] [C] [ryancdotorg/brainflayer](https://github.com/ryancdotorg/brainflayer) A proof-of-concept cracker for cryptocurrency brainwallets and other low entropy key alogrithms.
- [**435**星][5m] [JS] [coalfire-research/npk](https://github.com/coalfire-research/npk) A mostly-serverless distributed hash cracking platform
- [**380**星][25d] [Py] [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) jwt_tool：测试，调整和破解JSON Web Token 的工具包
- [**351**星][2m] [Py] [denyhosts/denyhosts](https://github.com/denyhosts/denyhosts) Automated host blocking from SSH brute force attacks
- [**307**星][10m] [C] [e-ago/bitcracker](https://github.com/e-ago/bitcracker) bitcracker：BitLocker密码破解器
- [**287**星][11m] [Shell] [cyb0r9/socialbox](https://github.com/Cyb0r9/SocialBox) SocialBox is a Bruteforce Attack Framework [ Facebook , Gmail , Instagram ,Twitter ] , Coded By Belahsan Ouerghi
- [**265**星][11m] [C] [jmk-foofus/medusa](https://github.com/jmk-foofus/medusa) Medusa is a speedy, parallel, and modular, login brute-forcer.
- [**256**星][17d] [Shell] [wuseman/emagnet](https://github.com/wuseman/emagnet) Emagnet is a tool for find leaked databases with 97.1% accurate to grab mail + password together from pastebin leaks. Support for brute forcing spotify accounts, instagram accounts, ssh servers, microsoft rdp clients and gmail accounts
- [**250**星][1y] [Py] [avramit/instahack](https://github.com/avramit/instahack) Instagram bruteforce tool
- [**246**星][6m] [Go] [ropnop/kerbrute](https://github.com/ropnop/kerbrute) A tool to perform Kerberos pre-auth bruteforcing
- [**245**星][11m] [Shell] [thelinuxchoice/instainsane](https://github.com/thelinuxchoice/instainsane) Multi-threaded Instagram Brute Forcer (100 attemps at once)
- [**225**星][2m] [Py] [evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) 修改NTLMv1/NTLMv1-ESS/MSCHAPv1 Hask, 使其可以在hashcat中用DES模式14000破解
- [**220**星][6m] [Py] [blark/aiodnsbrute](https://github.com/blark/aiodnsbrute) Python 3.5+ DNS asynchronous brute force utility
- [**220**星][11m] [Py] [chris408/known_hosts-hashcat](https://github.com/chris408/known_hosts-hashcat) A guide and tool for cracking ssh known_hosts files with hashcat
- [**215**星][7m] [Py] [paradoxis/stegcracker](https://github.com/paradoxis/stegcracker) Steganography brute-force utility to uncover hidden data inside files
- [**209**星][1m] [C] [hyc/fcrackzip](https://github.com/hyc/fcrackzip) A braindead program for cracking encrypted ZIP archives. Forked from
- [**203**星][3m] [Py] [isaacdelly/plutus](https://github.com/isaacdelly/plutus) An automated bitcoin wallet collider that brute forces random wallet addresses


***


## <a id="13d067316e9894cc40fe55178ee40f24"></a>OSCP


- [**1710**星][20d] [olivierlaflamme/cheatsheet-god](https://github.com/olivierlaflamme/cheatsheet-god) Penetration Testing Biggest Reference Bank - OSCP / PTP & PTX Cheatsheet
    - 重复区段: [工具/收集&&集合/混合型收集](#664ff1dbdafefd7d856c88112948a65b) |
- [**756**星][1m] [HTML] [rewardone/oscprepo](https://github.com/rewardone/oscprepo) A list of commands, scripts, resources, and more that I have gathered and attempted to consolidate for use as OSCP (and more) study material. Commands in 'Usefulcommands' Keepnote. Bookmarks and reading material in 'BookmarkList' Keepnote. Reconscan in scripts folder.
- [**667**星][8m] [XSLT] [adon90/pentest_compilation](https://github.com/adon90/pentest_compilation) Compilation of commands, tips and scripts that helped me throughout Vulnhub, Hackthebox, OSCP and real scenarios
    - 重复区段: [工具/收集&&集合/未分类](#e97d183e67fa3f530e7d0e7e8c33ee62) |
- [**375**星][10m] [Py] [rustyshackleford221/oscp-prep](https://github.com/rustyshackleford221/oscp-prep) A comprehensive guide/material for anyone looking to get into infosec or take the OSCP exam
- [**360**星][8m] [PowerShell] [ferreirasc/oscp](https://github.com/ferreirasc/oscp) oscp study
- [**289**星][14d] [PowerShell] [mantvydasb/redteam-tactics-and-techniques](https://github.com/mantvydasb/RedTeam-Tactics-and-Techniques) Red Teaming Tactics and Techniques
- [**222**星][7m] [0x4d31/awesome-oscp](https://github.com/0x4d31/awesome-oscp) A curated list of awesome OSCP resources
- [**210**星][1y] [foobarto/redteam-notebook](https://github.com/foobarto/redteam-notebook) Collection of commands, tips and tricks and references I found useful during preparation for OSCP exam.


***


## <a id="249c9d207ed6743e412c8c8bcd8a2927"></a>MitreATT&CK


- [**2595**星][12d] [PowerShell] [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) Small and highly portable detection tests based on MITRE's ATT&CK.
- [**1308**星][14d] [Py] [mitre/caldera](https://github.com/mitre/caldera) 自动化 adversary emulation 系统
- [**557**星][5m] [HTML] [nshalabi/attack-tools](https://github.com/nshalabi/attack-tools) Utilities for MITRE™ ATT&CK
- [**454**星][2m] [Py] [olafhartong/threathunting](https://github.com/olafhartong/threathunting) A Splunk app mapped to MITRE ATT&CK to guide your threat hunts
- [**450**星][12m] [bfuzzy/auditd-attack](https://github.com/bfuzzy/auditd-attack) A Linux Auditd rule set mapped to MITRE's Attack Framework
- [**325**星][5m] [teoseller/osquery-attck](https://github.com/teoseller/osquery-attck) Mapping the MITRE ATT&CK Matrix with Osquery
- [**312**星][10m] [PowerShell] [cyb3rward0g/invoke-attackapi](https://github.com/cyb3rward0g/invoke-attackapi) A PowerShell script to interact with the MITRE ATT&CK Framework via its own API
- [**307**星][29d] [Py] [atc-project/atomic-threat-coverage](https://github.com/atc-project/atomic-threat-coverage) Actionable analytics designed to combat threats based on MITRE's ATT&CK.


***


## <a id="76df273beb09f6732b37a6420649179c"></a>浏览器&&browser


- [**4591**星][2m] [JS] [beefproject/beef](https://github.com/beefproject/beef) The Browser Exploitation Framework Project
- [**960**星][8m] [Py] [selwin/python-user-agents](https://github.com/selwin/python-user-agents) A Python library that provides an easy way to identify devices like mobile phones, tablets and their capabilities by parsing (browser) user agent strings.
- [**852**星][3m] [escapingbug/awesome-browser-exploit](https://github.com/escapingbug/awesome-browser-exploit) awesome list of browser exploitation tutorials
- [**450**星][30d] [Py] [globaleaks/tor2web](https://github.com/globaleaks/tor2web) Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
- [**446**星][2m] [m1ghtym0/browser-pwn](https://github.com/m1ghtym0/browser-pwn) An updated collection of resources targeting browser-exploitation.
- [**408**星][2m] [Pascal] [felipedaragon/sandcat](https://github.com/felipedaragon/sandcat) 为渗透测试和开发者准备的轻量级浏览器, 基于Chromium和Lua
- [**290**星][2m] [xsleaks/xsleaks](https://github.com/xsleaks/xsleaks) A collection of browser-based side channel attack vectors.
- [**215**星][2m] [Py] [icsec/airpwn-ng](https://github.com/icsec/airpwn-ng) force the target's browser to do what we want 
- [**212**星][1y] [C#] [djhohnstein/sharpweb](https://github.com/djhohnstein/sharpweb) .NET 2.0 CLR project to retrieve saved browser credentials from Google Chrome, Mozilla Firefox and Microsoft Internet Explorer/Edge.


***


## <a id="ceb90405292daed9bb32ac20836c219a"></a>蓝牙&&Bluetooth


- [**218**星][18d] [Py] [ghostop14/sparrow-wifi](https://github.com/ghostop14/sparrow-wifi) Next-Gen GUI-based WiFi and Bluetooth Analyzer for Linux
    - 重复区段: [工具/浏览嗅探&&流量拦截&&流量分析&&中间人/未分类-Network](#99398a5a8aaf99228829dadff48fb6a7) |[工具/渗透&&offensive&&渗透框架&&后渗透框架/无线&&WiFi&&AP&&802.11/未分类-WiFi](#d4efda1853b2cb0909727188116a2a8c) |


***


## <a id="7d5d2d22121ed8456f0c79098f5012bb"></a>REST_API&&RESTFUL 


- [**1220**星][8m] [Py] [flipkart-incubator/astra](https://github.com/flipkart-incubator/astra) 自动化的REST API安全测试脚本


***


## <a id="8cb1c42a29fa3e8825a0f8fca780c481"></a>恶意代码&&Malware&&APT


- [**2013**星][1m] [C++] [lordnoteworthy/al-khaser](https://github.com/lordnoteworthy/al-khaser) Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.
    - 重复区段: [工具/渗透&&offensive&&渗透框架&&后渗透框架/未分类-Pentest](#2e40f2f1df5d7f93a7de47bf49c24a0e) |
- [**859**星][2m] [aptnotes/data](https://github.com/aptnotes/data) APTnotes data


# 贡献
内容为系统自动导出, 有任何问题请提issue