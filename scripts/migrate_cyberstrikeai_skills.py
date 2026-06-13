#!/usr/bin/env python3
"""Migrate CyberStrikeAI's 21 skills to OpenSquilla's PERSONAL skills layer.

Source : /Users/zlpc/data/zspace/hack/CyberStrikeAI/skills/<name>/SKILL.md
Target : /Users/zlpc/.agents/skills/<name>/SKILL.md

For each skill, we keep the markdown body verbatim and translate the YAML
frontmatter into the OpenSquilla schema (per loader contract):

  - Required: name
  - Recommended: description, triggers, provenance, metadata.opensquilla
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

SRC_ROOT = Path("/Users/zlpc/data/zspace/hack/CyberStrikeAI/skills")
DST_ROOT = Path("/Users/zlpc/.agents/skills")
UPSTREAM = "https://github.com/CyberStrikeAI/CyberStrikeAI"


@dataclass(frozen=True)
class SkillMeta:
    name: str
    risk: str  # low | medium | high
    triggers: tuple[str, ...]
    bins: tuple[str, ...]
    capabilities: tuple[str, ...]
    # brew formulas mapped from bin name (bin -> brew formula)
    install_brew: tuple[tuple[str, str], ...] = ()  # (formula, bin)
    install_pip: tuple[str, ...] = ()  # pip module name


# Capability vocabulary is approximate; the loader doesn't enforce a strict
# enum, but we mirror the common ones.
NET = "network"
SHELL = "shell"
FS_R = "filesystem-read"
FS_W = "filesystem-write"
HTTP_O = "network.http"  # outbound
SKILL = "skill"
# We keep it tight: skills that primarily invoke CLIs get shell+network.


SKILLS: tuple[SkillMeta, ...] = (
    SkillMeta(
        name="sql-injection-testing",
        risk="medium",
        triggers=("SQL注入", "SQLi", "sql injection", "联合查询", "盲注", "sqli"),
        bins=("sqlmap", "nuclei"),
        capabilities=(SHELL, NET, FS_R),
        install_brew=(("sqlmap", "sqlmap"), ("nuclei", "nuclei")),
    ),
    SkillMeta(
        name="xss-testing",
        risk="medium",
        triggers=("XSS", "跨站脚本", "跨站", "xss", "反射型", "存储型", "DOM型"),
        bins=("dalfox", "xsser", "nuclei"),
        capabilities=(SHELL, NET, FS_R),
        install_brew=(("dalfox", "dalfox"), ("xsser", "xsser"), ("nuclei", "nuclei")),
    ),
    SkillMeta(
        name="csrf-testing",
        risk="medium",
        triggers=("CSRF", "跨站请求伪造", "csrf", "token", "SameSite"),
        bins=("nuclei",),
        capabilities=(SHELL, NET, FS_R),
        install_brew=(("nuclei", "nuclei"),),
    ),
    SkillMeta(
        name="ssrf-testing",
        risk="medium",
        triggers=("SSRF", "服务端请求伪造", "ssrf", "内网探测", "gopherus", "SSRFmap"),
        bins=("nuclei", "ffuf"),
        capabilities=(SHELL, NET, FS_R),
        install_brew=(("nuclei", "nuclei"), ("ffuf", "ffuf")),
    ),
    SkillMeta(
        name="command-injection-testing",
        risk="high",
        triggers=("命令注入", "RCE", "命令执行", "commix", "反弹shell", "cmdi"),
        bins=("commix", "nuclei"),
        capabilities=(SHELL, NET, FS_R),
        install_brew=(("commix", "commix"), ("nuclei", "nuclei")),
    ),
    SkillMeta(
        name="xxe-testing",
        risk="medium",
        triggers=("XXE", "外部实体", "xxe", "XML注入", "XXEinjector"),
        bins=("nuclei",),
        capabilities=(SHELL, NET, FS_R),
        install_brew=(("nuclei", "nuclei"),),
    ),
    SkillMeta(
        name="ldap-injection-testing",
        risk="medium",
        triggers=("LDAP注入", "LDAPi", "ldap injection", "ldapsearch"),
        bins=("nuclei",),
        capabilities=(SHELL, NET, FS_R),
        install_brew=(("nuclei", "nuclei"),),
    ),
    SkillMeta(
        name="xpath-injection-testing",
        risk="medium",
        triggers=("XPath注入", "XPathi", "xpath", "xml注入"),
        bins=("nuclei",),
        capabilities=(SHELL, NET, FS_R),
        install_brew=(("nuclei", "nuclei"),),
    ),
    SkillMeta(
        name="deserialization-testing",
        risk="high",
        triggers=("反序列化", "ysoserial", "pickle", "漏洞利用链", "gadget chain"),
        bins=("ysoserial", "nuclei"),
        capabilities=(SHELL, NET, FS_R),
        install_brew=(("nuclei", "nuclei"),),
    ),
    SkillMeta(
        name="idor-testing",
        risk="medium",
        triggers=("IDOR", "越权", "水平越权", "垂直越权", "未授权访问"),
        bins=("ffuf", "nuclei"),
        capabilities=(SHELL, NET, FS_R),
        install_brew=(("ffuf", "ffuf"), ("nuclei", "nuclei")),
    ),
    SkillMeta(
        name="file-upload-testing",
        risk="high",
        triggers=("文件上传", "绕过", "getshell", "蚁剑", "冰蝎", "webshell"),
        bins=("nuclei", "ffuf"),
        capabilities=(SHELL, NET, FS_W),
        install_brew=(("nuclei", "nuclei"), ("ffuf", "ffuf")),
    ),
    SkillMeta(
        name="business-logic-testing",
        risk="medium",
        triggers=("业务逻辑", "越权", "支付绕过", "优惠券", "race condition"),
        bins=("nuclei", "ffuf"),
        capabilities=(SHELL, NET, FS_R),
        install_brew=(("nuclei", "nuclei"), ("ffuf", "ffuf")),
    ),
    SkillMeta(
        name="api-security-testing",
        risk="medium",
        triggers=("API安全", "接口安全", "BOLA", "BOPLA", "REST安全", "graphql"),
        bins=("nuclei", "ffuf", "httpx", "jwt_tool"),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_brew=(("nuclei", "nuclei"), ("ffuf", "ffuf"), ("httpx", "httpx")),
        install_pip=("jwt_tool",),
    ),
    SkillMeta(
        name="network-penetration-testing",
        risk="medium",
        triggers=("渗透测试", "端口扫描", "内网", "横向移动", "nmap", "pentest"),
        bins=("nmap", "masscan", "rustscan", "arp-scan", "nbtscan"),
        capabilities=(SHELL, NET, FS_R),
        install_brew=(
            ("nmap", "nmap"),
            ("masscan", "masscan"),
            ("rustscan", "rustscan"),
            ("arp-scan", "arp-scan"),
            ("nbtscan", "nbtscan"),
        ),
    ),
    SkillMeta(
        name="container-security-testing",
        risk="low",
        triggers=("容器安全", "镜像扫描", "CIS", "trivy", "kube-bench", "kubernetes"),
        bins=("trivy", "kube-bench", "kube-hunter", "docker-bench-security", "falco"),
        capabilities=(SHELL, NET, FS_R),
        install_brew=(
            ("trivy", "trivy"),
            ("kube-bench", "kube-bench"),
            ("kube-hunter", "kube-hunter"),
            ("falco", "falco"),
        ),
    ),
    SkillMeta(
        name="cloud-security-audit",
        risk="low",
        triggers=("云安全", "AWS审计", "阿里云", "IAM审计", "S3桶", "prowler", "scout"),
        bins=("prowler", "scout", "checkov", "terrascan"),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_brew=(
            ("checkov", "checkov"),
            ("terrascan", "terrascan"),
        ),
        install_pip=("prowler", "scout-suite"),
    ),
    SkillMeta(
        name="secure-code-review",
        risk="low",
        triggers=("代码审计", "SAST", "白盒", "源码审计", "code review"),
        bins=("semgrep", "bandit"),
        capabilities=(SHELL, FS_R),
        install_brew=(("semgrep", "semgrep"),),
        install_pip=("bandit",),
    ),
    SkillMeta(
        name="security-automation",
        risk="low",
        triggers=("安全自动化", "CI/CD扫描", "自动化漏扫", "SOAR"),
        bins=("nuclei", "nmap"),
        capabilities=(SHELL, NET, FS_R),
        install_brew=(("nuclei", "nuclei"), ("nmap", "nmap")),
    ),
    SkillMeta(
        name="security-awareness-training",
        risk="low",
        triggers=("安全意识", "培训", "钓鱼演练", "social engineering"),
        bins=(),
        capabilities=(SKILL,),
    ),
    SkillMeta(
        name="incident-response",
        risk="low",
        triggers=("应急响应", "IR", "取证", "溯源", "事件复盘", "incident"),
        bins=("volatility", "volatility3", "exiftool", "binwalk"),
        capabilities=(SHELL, FS_R),
        install_brew=(("volatility", "volatility"), ("exiftool", "exiftool"), ("binwalk", "binwalk")),
        install_pip=("volatility3",),
    ),
    SkillMeta(
        name="mobile-app-security-testing",
        risk="medium",
        triggers=("移动安全", "Android", "iOS", "apk", "逆向", "frida"),
        bins=("apktool", "jadx", "mobsf"),
        capabilities=(SHELL, FS_R),
        install_brew=(("apktool", "apktool"), ("jadx", "jadx")),
        install_pip=("mobsf",),
    ),
)


def split_frontmatter(text: str) -> tuple[dict, str]:
    """Parse a simple `--- key: val ---` block, return (dict, body)."""
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end < 0:
        return {}, text
    header = text[3:end].strip()
    body = text[end + 4 :].lstrip("\n")
    fm: dict = {}
    for line in header.splitlines():
        m = re.match(r"^(\w[\w-]*)\s*:\s*(.*)$", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        fm[key] = val.strip('"').strip("'")
    return fm, body


def yaml_escape(s: str) -> str:
    """Quote a value if it contains YAML-special chars."""
    if re.search(r"[:#\n\"']", s):
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def render_frontmatter(meta: SkillMeta, description: str) -> str:
    """Render the OpenSquilla-style frontmatter for one skill."""
    lines: list[str] = ["---"]
    lines.append(f"name: {meta.name}")
    lines.append(f"description: {yaml_escape(description)}")
    lines.append("always: false")
    lines.append("triggers:")
    for t in meta.triggers:
        lines.append(f"  - {yaml_escape(t)}")
    lines.append("provenance:")
    lines.append("  origin: cyberstrikeai-ported")
    lines.append("  license: Apache-2.0")
    lines.append(f"  upstream_url: {UPSTREAM}")
    lines.append("  maintained_by: zlpc")
    lines.append("metadata:")
    lines.append("  opensquilla:")
    lines.append(f"    risk: {meta.risk}")
    if meta.capabilities:
        lines.append("    capabilities:")
        for c in meta.capabilities:
            lines.append(f"      - {c}")
    if meta.bins:
        lines.append("    requires:")
        lines.append("      bins:")
        for b in meta.bins:
            lines.append(f"        - {b}")
    if meta.install_brew or meta.install_pip:
        lines.append("    install:")
        for formula, bin_name in meta.install_brew:
            lines.append(f"      - kind: brew")
            lines.append(f"        id: {formula}")
            lines.append(f"        formula: {formula}")
            lines.append(f"        bins:")
            lines.append(f"          - {bin_name}")
        for mod in meta.install_pip:
            lines.append(f"      - kind: uv")
            lines.append(f"        module: {mod}")
            lines.append(f"        bins:")
            lines.append(f"          - {mod}")
    lines.append("---")
    return "\n".join(lines) + "\n"


def main() -> None:
    DST_ROOT.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    skipped: list[str] = []
    for meta in SKILLS:
        src = SRC_ROOT / meta.name / "SKILL.md"
        if not src.exists():
            skipped.append(meta.name)
            continue
        dst_dir = DST_ROOT / meta.name
        dst_dir.mkdir(parents=True, exist_ok=True)
        text = src.read_text(encoding="utf-8")
        fm, body = split_frontmatter(text)
        description = fm.get("description") or meta.name
        new_text = render_frontmatter(meta, description) + "\n" + body
        (dst_dir / "SKILL.md").write_text(new_text, encoding="utf-8")
        # Sidecar README with attribution
        (dst_dir / "ATTRIBUTION.md").write_text(
            f"# Attribution — {meta.name}\n\n"
            f"Ported from [CyberStrikeAI]({UPSTREAM}) on 2026-06-04.\n"
            f"Original frontmatter `version` dropped (not in OpenSquilla schema).\n"
            f"Original description preserved verbatim. Body copied verbatim.\n",
            encoding="utf-8",
        )
        written.append(meta.name)
    print(f"OK  wrote  {len(written):>2}  skills -> {DST_ROOT}")
    for n in written:
        print(f"     + {n}")
    if skipped:
        print(f"WARN skipped {len(skipped)}: {skipped}")


if __name__ == "__main__":
    main()
