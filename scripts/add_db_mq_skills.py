#!/usr/bin/env python3
"""Add 5 DB / MQ client skills (R3 P0).

Skills: mongosh, redis-cli, elasticsearch-tools, rabbitmqadmin, kafkacat

These are official client CLIs for the canonical data services used
in modern stacks. They are thin wrappers — the actual skill value is
the trigger recognition + the operator's "run mongosh with X" prompt
context, not anything fancy. The actual auth-test logic is in W4
(penetration) where vector_class='db' / 'mgmt' routes here.

Risk: ALL 5 are HIGH because they CAN authenticate against misconfigured
services (default creds / no auth). MANDATORY ROE.aggressive gate for any
test connection. ROEEvidence is not extended this round (deferred to R4);
the agent reads the full ROE document when deciding.
"""
from __future__ import annotations
import re, sys
from dataclasses import dataclass
from pathlib import Path

DST_ROOT = Path.home() / ".opensquilla" / "skills"
ATTRIBUTION_DATE = "2026-06-10"
NET = "network"; SHELL = "shell"; FS_R = "filesystem-read"; HTTP_O = "network.http"


@dataclass(frozen=True)
class SkillMeta:
    name: str; risk: str; triggers: tuple; bins: tuple
    capabilities: tuple = ()
    install_brew: tuple = (); install_go: tuple = (); install_pip: tuple = (); install_apt: tuple = ()
    description: str = ""; upstream_url: str = ""


# 5 entries: name -> (triggers, install_brew, install_apt, install_pip, upstream, default_usage)
DB_MQ_SKILLS: tuple = (
    SkillMeta(
        name="mongosh", risk="high",
        triggers=("mongosh","mongodb","MongoDB","Mongo 认证","Mongo 暴露","NoSQL"),
        bins=("mongosh",), capabilities=(SHELL, NET, FS_R),
        install_brew=(("mongosh","mongosh"),),
        install_apt=(("mongodb-mongosh","mongosh"),),
        description=(
            "Official MongoDB shell (replaces legacy mongo). Default usage: "
            "`mongosh mongodb://target:27017/admin --eval 'db.runCommand({ping:1})'` "
            "for unauthenticated banner; `--eval 'show dbs'` for unauth DB enum. "
            "For default-creds brute, gate by ROE.aggressive. Risk: HIGH — any "
            "write operation (insert/update/drop) is destructive."
        ),
        upstream_url="https://github.com/mongodb-js/mongosh",
    ),
    SkillMeta(
        name="redis-cli", risk="high",
        triggers=("redis-cli","redis","Redis 暴露","Redis 默认认证","缓存枚举"),
        bins=("redis-cli",), capabilities=(SHELL, NET, FS_R),
        install_brew=(("redis","redis-cli"),),
        install_apt=(("redis-tools","redis-cli"),),
        description=(
            "Official Redis CLI. Default usage: `redis-cli -h target ping` "
            "to confirm unauthenticated access; `INFO` to dump server info; "
            "`KEYS *` to enumerate keys (⚠️ destructive on prod). "
            "Risk: HIGH — Redis allows arbitrary commands once authenticated; "
            "even unauth ping confirms exposure."
        ),
        upstream_url="https://github.com/redis/redis",
    ),
    SkillMeta(
        name="elasticsearch-tools", risk="high",
        triggers=("elasticsearch-tools","elasticdump","elasticsearch","ES 暴露","ES 默认凭据"),
        bins=("elasticdump","elasticsearch-tools",), capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_brew=(("elasticdump","elasticdump"),),
        install_pip=("elasticdump",),
        description=(
            "Elasticsearch dump/restore + cluster introspection via the "
            "`elasticdump` package. Default usage: "
            "`elasticdump --input=http://target:9200 --output=/tmp/es.json --type=data` "
            "to dump if cluster has no auth. For `_cat/indices?pretty` curl probes "
            "(cluster info), gate by ROE.aggressive. Risk: HIGH — full data exfil "
            "on unauth clusters."
        ),
        upstream_url="https://github.com/elasticsearch-dump/elasticsearch-dump",
    ),
    SkillMeta(
        name="rabbitmqadmin", risk="high",
        triggers=("rabbitmqadmin","rabbitmq","RabbitMQ 暴露","AMQP","MQ 认证"),
        bins=("rabbitmqadmin",), capabilities=(SHELL, NET, FS_R),
        install_brew=(("rabbitmqadmin","rabbitmqadmin"),),
        install_pip=("rabbitmqadmin",),
        description=(
            "Official RabbitMQ management CLI. Default usage: "
            "`rabbitmqadmin -H target -P 15672 list queues` (port 15672 is "
            "the management UI HTTP API). Gate by ROE.aggressive; unauth "
            "exposure dumps message counts, consumer groups, vhost config. "
            "Risk: HIGH — exposes business message metadata."
        ),
        upstream_url="https://github.com/rabbitmq/rabbitmq-management",
    ),
    SkillMeta(
        name="kafkacat", risk="high",
        triggers=("kafkacat","kcat","kafka","Kafka 暴露","Kafka 认证"),
        bins=("kafkacat","kcat"), capabilities=(SHELL, NET, FS_R),
        install_brew=(("kafkacat","kafkacat"),),
        install_apt=(("kafkacat","kafkacat"),),
        description=(
            "Apache Kafka consumer/producer CLI (`kcat` on newer systems). "
            "Default usage: `kafkacat -b target:9092 -L` to list brokers / "
            "topics metadata (often works without auth on misconfigured "
            "clusters); `-C -t <topic>` to consume messages. Gate by "
            "ROE.aggressive. Risk: HIGH — full message stream access."
        ),
        upstream_url="https://github.com/edenhill/kafkacat",
    ),
)


def yaml_escape(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"' if re.search(r"[:#\n\"']", s) else s


def render_frontmatter(m: SkillMeta) -> str:
    L = ["---", f"name: {m.name}", f"description: {yaml_escape(m.description)}", "always: false", "triggers:"]
    for t in m.triggers: L.append(f"  - {yaml_escape(t)}")
    L.append("provenance:"); L.append("  origin: recon-coverage-gap-fix-r3-2026-06-10"); L.append("  license: per-tool")
    if m.upstream_url: L.append(f"  upstream_url: {m.upstream_url}")
    L.append("  maintained_by: zlpc")
    L.append("metadata:"); L.append("  opensquilla:"); L.append(f"    risk: {m.risk}")
    if m.capabilities:
        L.append("    capabilities:")
        for c in m.capabilities: L.append(f"      - {c}")
    if m.bins:
        L.append("    requires:"); L.append("      bins:")
        for b in m.bins: L.append(f"        - {b}")
    if m.install_brew or m.install_go or m.install_pip or m.install_apt:
        L.append("    install:")
        for f, b in m.install_brew:
            L += ["      - kind: brew", f"        id: {f}", f"        formula: {f}", "        bins:", f"          - {b}"]
        for p in m.install_go:
            bn = p.rsplit("/", 1)[-1]
            L += ["      - kind: go", f"        path: {p}", "        bins:", f"          - {bn}"]
        for mod in m.install_pip:
            L += ["      - kind: uv", f"        module: {mod}", "        bins:", f"          - {mod}"]
        for pkg, bn in m.install_apt:
            L += ["      - kind: apt", f"        package: {pkg}", "        bins:", f"          - {bn}"]
    L.append("---"); return "\n".join(L) + "\n"


def render_body(m: SkillMeta) -> str:
    return (f"\n# {m.name}\n\n{m.description}\n\n"
            f"**Triggers**: {', '.join(repr(t) for t in m.triggers)}\n\n"
            f"**Bins**: {', '.join(m.bins) or '(none)'}\n\n"
            f"**Risk**: {m.risk}\n\n"
            f"**Capabilities**: {', '.join(m.capabilities) or '(none)'}\n\n"
            f"Added by `scripts/add_db_mq_skills.py` on {ATTRIBUTION_DATE} (R3 P0 S16). "
            f"All 5 are gated by ROE.aggressive for any write/credential action.\n")


def render_attribution(m: SkillMeta) -> str:
    return (f"# Attribution — {m.name}\n\nAdded {ATTRIBUTION_DATE} (R3 P0).\n\n"
            f"- **Triggers**: {', '.join(repr(t) for t in m.triggers)}\n"
            f"- **Bins**: {', '.join(m.bins)}\n- **Upstream**: {m.upstream_url}\n"
            f"- **Risk**: {m.risk} (ROE.aggressive gate)\n- **Maintainer**: zlpc\n")


def write_skill(m: SkillMeta) -> Path:
    d = DST_ROOT / m.name; d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(render_frontmatter(m) + render_body(m), encoding="utf-8")
    (d / "ATTRIBUTION.md").write_text(render_attribution(m), encoding="utf-8"); return d


def main() -> int:
    DST_ROOT.mkdir(parents=True, exist_ok=True); n = 0
    for m in DB_MQ_SKILLS: d = write_skill(m); print(f"     + {m.name} -> {d}"); n += 1
    print(f"OK  wrote {n}  db-mq skills -> {DST_ROOT}"); return 0


if __name__ == "__main__":
    sys.exit(main())