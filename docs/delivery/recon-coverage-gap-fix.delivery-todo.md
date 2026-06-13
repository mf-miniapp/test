# Delivery Todo: recon 资产搜集 / Web 分析覆盖面修复 (R1 B 方案 + R3 P0+P1 合并包)

## 0. Requirement Log
| Req ID | Captured At | Source | Description | Round | Status | Origin File |
| --- | --- | --- | --- | --- | --- | --- |
| R1 | 2026-06-10 | user: "你的资产搜集和web分析作的并不好" | recon 端口扫描必须真正覆盖 1-65535,目录路径必须字典爆破,漏洞类型必须覆盖 SQLi/SSRF/LFI/XXE/SSTI/IDOR | 1 | completed | — |
| R2 | 2026-06-10 | user: "B 补 skill (3 个注册脚本 + 7 个 bin)" | 走 B 方案:端口/目录/漏洞扫描 7 bin 全部注册;raft-medium 字典;nuclei 排除 | 1 | completed | — |
| R3 | 2026-06-10 | user: 30 项侦查 + 11 阶段攻击链 → AskUserQuestion "P0 + P1 合并包" | 补齐 11 项核心缺口:5 P0 + 6 P1 | 2 | in-progress | — |
| R4 | 2026-06-10 | user: "加 W0.6 (Recommended)" | 新增 W0.6 资源检查站 wave | 2 | in-progress | — |
| R5 | 2026-06-10 | user: "两者都要:W1 探测 + W4 认证" | DB/MQ 两阶段 | 2 | in-progress | — |

## 0. Round Log
| Round | Theme | Captured At | Closed At | Validation | Worktree Δ | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | R1 全端口 + 字典爆破 + 漏洞扫描 skill 补齐 (8 bins) | 2026-06-10 | 2026-06-10 (uncommitted) | `ls ~/.opensquilla/skills/ \| wc -l` == 40, 264 passed | 5 files (3 add_*, fetch_wordlists, README) + 4 uncommitted (evidence, waves, tests, turn_runner) | completed |
| 2 | R3 11 项缺口 (P0 + P1) + W0.6 资源检查站 + DB/MQ 两阶段 (本轮) | 2026-06-10 | — | TBD | TBD | in-progress |

## 1. Metadata
| Field | Value |
| --- | --- |
| Topic | recon 资产搜集 / Web 分析覆盖面修复 (R1 B 方案 + R3 P0+P1 合并包) |
| Derived From | [recon-coverage-gap-fix.delivery-solution.md](./recon-coverage-gap-fix.delivery-solution.md) |
| Active Req IDs | R3, R4, R5 (R1/R2 已 completed) |
| Execution Gate | ready-for-execution |
| Execution Mode | serial(Round 2: 13 T 串行) → parallel-ready(Round 3: 4 threads) → serial(Round 4 合闸) |
| Thread Budget | 4 |
| Last Updated | 2026-06-10 |

## 2. Todo Rows
| Todo ID | Solution ID | Task | Implementation Notes | Validation | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | S1 | scripts/add_port_scan_skills.py: 注册 naabu + nmap | 沿用 add_subdomain_enum_skills.py schema | python scripts/add_port_scan_skills.py && ls ~/.opensquilla/skills/{naabu,nmap}/ | completed |
| T2 | S2 | scripts/add_dir_bust_skills.py: 注册 ffuf + feroxbuster + gobuster | 三者均 Go | python scripts/add_dir_bust_skills.py && ls ~/.opensquilla/skills/{ffuf,feroxbuster,gobuster}/ | completed |
| T3 | S3 | scripts/add_vuln_scan_skills.py: 注册 sqlmap + nikto + dalfox | sqlmap pip,nikto brew/apt,dalfox go | python scripts/add_vuln_scan_skills.py && ls ~/.opensquilla/skills/{sqlmap,nikto,dalfox}/ | completed |
| T4 | S4 | scripts/fetch_wordlists.py: fetch raft-medium-directories.txt + sqlmap 模板 + sha256 校验 | 从 SecLists GitHub release 抓 | python scripts/fetch_wordlists.py && ls ~/.opensquilla/wordlists/ | completed |
| T5 | S5 | recon SOUL.md 工具清单 append-only 追加 5 bins | 写到运行时 ~/.opensquilla/agents/recon/SOUL.md | grep -E "naabu\|nmap\|ffuf\|feroxbuster\|gobuster" ~/.opensquilla/agents/recon/SOUL.md | completed |
| T6 | S6 | penetration SOUL.md 工具清单按 vector_class 分流 | SQLi→sqlmap, XSS→dalfox, 手工 SSRF/SSTI/LFI/XXE/IDOR | grep -E "sqlmap\|dalfox\|nikto\|ssrf\|ssti\|lfi\|xxe\|idor" ~/.opensquilla/agents/penetration/SOUL.md | completed |
| T7 | S7 | attack-surface-enumeration SOUL.md priority_top_n 强制依赖端口全开 + 目录爆破证据 | 改 ~/.opensquilla/agents/attack-surface-enumeration/SOUL.md | test_priority_top_n_requires_port_dir_evidence | completed |
| T8 | S8 | evidence.py: ReconEvidence 加 scan_profile / port_scan_complete / dir_bust_evidence 字段 | Optional / 兜底默认 | test_recon_evidence_has_scan_profile | completed |
| T9 | S9 | waves.py: 加 W1.5c expand scan wave(条件触发) | deps=(W1,), specialist=recon | test_w1_5c_expand_scan_registered | completed |
| T10 | S10 | tests/test_recon_coverage.py: SOUL↔Skill 描述一致性测试 | 读取 recon SOUL.md + 列举 skill 目录 | pytest tests/test_recon_coverage.py -v | completed |
| T11 | S11 | tests/test_attack_dispatch.py: W1.5c + scan_profile 测试 | 验证 step 上限 65536 + W1.5c | pytest tests/test_attack_dispatch.py -v | completed |
| T12 | S12 | README.md "安全工具"段加 7 bin | 不动其他段 | grep -E "naabu\|nmap\|ffuf\|feroxbuster\|gobuster\|sqlmap\|nikto\|dalfox" README.md | completed |
| T13 | — | R1 8 bin smoke test: which / --version | 哪个缺就 brew/apt/go install 哪个 | for b in naabu nmap ffuf feroxbuster gobuster sqlmap nikto dalfox; do which $b; done | completed |
| **T14** | S13 | scripts/add_cloud_assets_skills.py: 注册 s3scanner + cloud_enum | pip install s3scanner;git clone cloud_enum | python scripts/add_cloud_assets_skills.py && ls ~/.opensquilla/skills/{s3scanner,cloud_enum}/ | completed |
| **T15** | S14 | scripts/add_devops_skills.py: 注册 jenkins-cli + gitrob | jenkins-cli 走 brew + nmap NSE;gitrob 走 go install | python scripts/add_devops_skills.py && ls ~/.opensquilla/skills/{jenkins-cli,gitrob}/ | completed |
| **T16** | S15 | scripts/add_monitoring_skills.py: 注册 grafana-fingerprinter + prometheus-fingerprinter | 走 nmap NSE + monitoring-paths 字典 | python scripts/add_monitoring_skills.py && ls ~/.opensquilla/skills/{grafana-fingerprinter,prometheus-fingerprinter}/ | completed |
| **T17** | S16 | scripts/add_db_mq_skills.py: 注册 mongosh + redis-cli + elasticsearch-tools + rabbitmqadmin + kafkacat | mongosh 走 tarball,redis-cli 走 brew,ES-tools 走 pip,rabbitmqadmin 走 pip,kafkacat 走 brew | python scripts/add_db_mq_skills.py && ls 5 目录 | completed |
| **T18** | S18 | scripts/add_whois_asn_skills.py: 注册 whois + asnmap | whois 走 pip;asnmap 走 go install | python scripts/add_whois_asn_skills.py && ls 2 目录 | completed |
| **T19** | S19 | scripts/add_waf_cdn_skills.py: 注册 cdncheck + wafw00f | cdncheck 走 go install;wafw00f 走 pip | python scripts/add_waf_cdn_skills.py && ls 2 目录 | completed |
| **T20** | S20 | scripts/add_ssl_tls_skills.py: 注册 tlsx + sslyze | tlsx 走 go install;sslyze 走 pip | python scripts/add_ssl_tls_skills.py && ls 2 目录 | completed |
| **T21** | S21 | scripts/add_secret_scan_skills.py: 注册 gitleaks + trufflehog | 都走 go install,scope 1000 commits / 50MB | python scripts/add_secret_scan_skills.py && ls 2 目录 | completed |
| **T22** | S22 | fetch_wordlists.py 增量: devops-paths + monitoring-paths + cloud-buckets-prefixes + db-ports | 4 字典自维护 + sha256 校验 | python scripts/fetch_wordlists.py && ls ~/.opensquilla/wordlists/ \| wc -l == 5 | completed |
| **T23** | S23 | dnsx SOUL.md 扩: DNS 区域传输 + DMARC/SPF/DKIM TXT | append 到 ~/.opensquilla/skills/dnsx/SKILL.md 触发器 | grep -E "axfr\|dmarc\|spf" ~/.opensquilla/skills/dnsx/SKILL.md | completed |
| **T24** | S25 | recon SOUL.md 工具清单 append-only 19 新 bin + ServiceEntry.service 精度段 + nmap NSE 触发段 | append 到既有 R1 工具清单后 | grep -E "s3scanner\|jenkins-cli\|mongosh\|asnmap\|cdncheck\|gitleaks" ~/.opensquilla/agents/recon/SOUL.md | completed |
| **T25** | S26 | penetration SOUL.md vector_class 分流表加 'db' + 'mgmt' 两行 (mongosh/redis-cli/ES-tools + jenkins-cli/grafana-fp) | append 到 R1 漏洞类型矩阵后 | grep -E "mongosh\|redis-cli\|jenkins-cli\|grafana" ~/.opensquilla/agents/penetration/SOUL.md | completed |
| **T26** | S27 | attack-surface-enumeration SOUL.md priority_top_n 排序: DB/MQ 开放端口 + 管理面板发现 = P0 入口 | 改 ~/.opensquilla/agents/attack-surface-enumeration/SOUL.md | test_priority_top_n_db_mgmt_p0 | completed |
| **T27** | S17 S24 | evidence.py: PrivescEvidence.current_access 升级 7 类键 + ResourceEntry + ResourceEvidence schema + EVIDENCE_SCHEMAS 注册 | 兜底默认 + extra=forbid 兼容 | pytest tests/test_attack_dispatch.py -v | completed |
| **T28** | S24 | waves.py: W0.6 wave 注册 + W1/W4 deps 追加 | 不破坏 W0-W8 拓扑 | test_w0_6_resource_checkpoint_registered | completed |
| **T29** | S28 | tests/test_recon_coverage.py 增量 19 bin 断言 | 读取 recon SOUL.md, 19 bin 名都在 ~/.opensquilla/skills/ | pytest tests/test_recon_coverage.py -v | completed |
| **T30** | S29 | README.md "安全工具"段追加 19 bin | 不动其他段 | grep -E "s3scanner\|cloud_enum\|mongosh\|tlsx\|gitleaks" README.md | completed |
| **T31** | — | 19 bin smoke test: which / --version 全跑一遍 | 缺不阻塞 round, 标 partial (4/19 OK: redis-cli, whois, wafw00f, tlsx; 15 MISS) | for b in 19 bin; do which $b; done | completed (partial: 4/19 OK) |

## 3. Execution Loop Rules
1. **Round 2 (Serial Foundation)**: T14 → T15 → T16 → T17 → T18 → T19 → T20 → T21 → T22 → T23 → T24 → T25 → T26 (13 个 T 串行, 写同一个 ~/.opensquilla/skills/ 需要顺序 IO)
2. **Round 3 (Parallel 4-Thread)**:
   - **Thread A**: T27 → T28 (evidence.py + waves.py 源码)
   - **Thread B**: T29 (test_recon_coverage.py 增量)
   - **Thread C**: T30 (README.md 增量)
   - **Thread D**: T31 (smoke test)
3. **Round 4 (Merge Gate)**: 全量回归 + final-review → decision=close
4. 任何线程发现共享文件冲突 → 立刻退回串行
5. 每个 T 完成后立即把 normalized todo 的 Status 从 `pending` 改为 `completed` 再开始下一个 T

## 4. Current Execution Snapshot
| Field | Value |
| --- | --- |
| Active Todo | T14 (R3 Round 2 in-progress) |
| Active Req IDs | R3, R4, R5 |
| Active Threads | serial |
| Approval Status | confirmed (用户已说"开干,一步到位") |
| Last Verified By | none (R3 Round 2 未开始) |
| Step Review | pending |
| Global Audit | R1 passed, R3 pending |
| Remaining Before Stop | 18 个 todo (T14-T31) 全部待完成 |

## 5. Parallel Threads Plan

| Thread | Scope | Candidate Todos | Parallel Safety | Current Status |
| --- | --- | --- | --- | --- |
| Thread A | evidence.py + waves.py 源码改动 | T27 T28 | high (与 B/C/D 无文件竞争) | idle |
| Thread B | tests/test_recon_coverage.py 增量 | T29 | high (追加既有测试文件) | idle |
| Thread C | README.md 增量 | T30 | high (与 A/B/D 无竞争) | idle |
| Thread D | 19 bin smoke test | T31 | high (与 A/B/C 无竞争) | idle |

**Round 2 串行地基 (pre-parallel)**: T14-T26 — 8 个 add_*_skills.py + 1 个 fetch_wordlists.py 增量 + 1 个 dnsx SOUL 扩 + 3 个 specialist SOUL 增量 (单线程串行, 因为写同一个 ~/.opensquilla/skills/ + 既有 R1/R2 约定串行)。

**Round 3 并行启用条件**:
1. Round 2 全部 13 个 T 状态都是 `completed`
2. `ls ~/.opensquilla/skills/ | wc -l` == 59
3. `ls ~/.opensquilla/wordlists/ | wc -l` == 5
4. `~/.opensquilla/skills/dnsx/SKILL.md` 含 'axfr' / 'dmarc' / 'spf' 触发器
5. 4 个线程无文件竞争

**Merge gate (Round 4 串行)**: 全量回归 + final-review。

## 6. Todo Cards (R3 增量 T14-T31)

### T14. scripts/add_cloud_assets_skills.py
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 2) |
| Scope | scripts/add_cloud_assets_skills.py + ~/.opensquilla/skills/{s3scanner,cloud_enum}/ |
| Current Slice | 2 个 SkillMeta + render_frontmatter + write_skill |
| Definition of Done | 脚本可独立运行 + 落盘 2 个 SKILL.md/ATTRIBUTION.md + 幂等 |
| Required Validation | `python scripts/add_cloud_assets_skills.py` + `ls ~/.opensquilla/skills/s3scanner ~/.opensquilla/skills/cloud_enum` |
| Step Review Focus | s3scanner 走 `pip install s3scanner`;cloud_enum 走 `git clone https://github.com/initstring/cloud_enum` (Python) |
| Remaining Gap | none |

### T15. scripts/add_devops_skills.py
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 2) |
| Scope | scripts/add_devops_skills.py + ~/.opensquilla/skills/{jenkins-cli,gitrob}/ |
| Current Slice | 2 个 SkillMeta + render_frontmatter + write_skill |
| Definition of Done | 脚本可独立运行 + 落盘 2 个 SKILL.md/ATTRIBUTION.md + 幂等 |
| Required Validation | `python scripts/add_devops_skills.py` + `ls ~/.opensquilla/skills/jenkins-cli ~/.opensquilla/skills/gitrob` |
| Step Review Focus | jenkins-cli 走 `brew install jenkins` + `nmap NSE jenkins-info`;gitrob 走 `go install github.com/michenriksen/gitrob@latest` |
| Remaining Gap | none |

### T16. scripts/add_monitoring_skills.py
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 2) |
| Scope | scripts/add_monitoring_skills.py + ~/.opensquilla/skills/{grafana-fingerprinter,prometheus-fingerprinter}/ |
| Current Slice | 2 个 SkillMeta + render_frontmatter + write_skill |
| Definition of Done | 脚本可独立运行 + 落盘 2 个 SKILL.md/ATTRIBUTION.md + 幂等 |
| Required Validation | `python scripts/add_monitoring_skills.py` + `ls ~/.opensquilla/skills/grafana-fingerprinter ~/.opensquilla/skills/prometheus-fingerprinter` |
| Step Review Focus | grafana-fp 走 ffuf + monitoring-paths 字典;prometheus-fp 走 nmap NSE `prometheus-info` + /metrics 端点 |
| Remaining Gap | none |

### T17. scripts/add_db_mq_skills.py
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 2) |
| Scope | scripts/add_db_mq_skills.py + ~/.opensquilla/skills/{mongosh,redis-cli,elasticsearch-tools,rabbitmqadmin,kafkacat}/ |
| Current Slice | 5 个 SkillMeta + render_frontmatter + write_skill |
| Definition of Done | 脚本可独立运行 + 落盘 5 个 SKILL.md/ATTRIBUTION.md + 幂等 |
| Required Validation | `python scripts/add_db_mq_skills.py` + ls 5 目录 |
| Step Review Focus | mongosh 走 tarball;redis-cli 走 `brew install redis`;ES-tools 走 `pip install elasticsearch`;rabbitmqadmin 走 `pip install pika`;kafkacat 走 `brew install kcat` |
| Remaining Gap | macOS 没有 mongosh brew 包 → 走官网 tarball + PATH 注入脚本 |

### T18. scripts/add_whois_asn_skills.py
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 2) |
| Scope | scripts/add_whois_asn_skills.py + ~/.opensquilla/skills/{whois,asnmap}/ |
| Current Slice | 2 个 SkillMeta + render_frontmatter + write_skill |
| Definition of Done | 脚本可独立运行 + 落盘 2 个 SKILL.md/ATTRIBUTION.md + 幂等 |
| Required Validation | `python scripts/add_whois_asn_skills.py` + ls 2 目录 |
| Step Review Focus | whois 走 `pip install python-whois`;asnmap 走 `go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest` |
| Remaining Gap | none |

### T19. scripts/add_waf_cdn_skills.py
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 2) |
| Scope | scripts/add_waf_cdn_skills.py + ~/.opensquilla/skills/{cdncheck,wafw00f}/ |
| Current Slice | 2 个 SkillMeta + render_frontmatter + write_skill |
| Definition of Done | 脚本可独立运行 + 落盘 2 个 SKILL.md/ATTRIBUTION.md + 幂等 |
| Required Validation | `python scripts/add_waf_cdn_skills.py` + ls 2 目录 |
| Step Review Focus | cdncheck 走 `go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest`;wafw00f 走 `pip install wafw00f` |
| Remaining Gap | none |

### T20. scripts/add_ssl_tls_skills.py
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 2) |
| Scope | scripts/add_ssl_tls_skills.py + ~/.opensquilla/skills/{tlsx,sslyze}/ |
| Current Slice | 2 个 SkillMeta + render_frontmatter + write_skill |
| Definition of Done | 脚本可独立运行 + 落盘 2 个 SKILL.md/ATTRIBUTION.md + 幂等 |
| Required Validation | `python scripts/add_ssl_tls_skills.py` + ls 2 目录 |
| Step Review Focus | tlsx 走 `go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest`;sslyze 走 `pip install sslyze` |
| Remaining Gap | none |

### T21. scripts/add_secret_scan_skills.py
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 2) |
| Scope | scripts/add_secret_scan_skills.py + ~/.opensquilla/skills/{gitleaks,trufflehog}/ |
| Current Slice | 2 个 SkillMeta + render_frontmatter + write_skill |
| Definition of Done | 脚本可独立运行 + 落盘 2 个 SKILL.md/ATTRIBUTION.md + 幂等 |
| Required Validation | `python scripts/add_secret_scan_skills.py` + ls 2 目录 |
| Step Review Focus | gitleaks 走 `go install github.com/gitleaks/gitleaks/v8@latest`;trufflehog 走 `go install github.com/trufflesecurity/trufflehog/v3@latest` |
| Remaining Gap | 大仓库扫描超时 → 默认 scope 1000 commits / 50MB |

### T22. fetch_wordlists.py 增量
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 2) |
| Scope | scripts/fetch_wordlists.py + ~/.opensquilla/wordlists/ |
| Current Slice | 4 个新字典 fetch + sha256 校验 + 落盘 |
| Definition of Done | 跑通 + 4 字典存在 + sha256 一致 |
| Required Validation | `python scripts/fetch_wordlists.py` + `ls -lh ~/.opensquilla/wordlists/` 含 5 文件 |
| Step Review Focus | devops-paths 自维护 1500 行;monitoring-paths 自维护 2000 行;cloud-buckets-prefixes 自维护 300 行;db-ports 自维护 10 行 |
| Remaining Gap | none |

### T23. dnsx SOUL.md 扩
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 2) |
| Scope | ~/.opensquilla/skills/dnsx/SKILL.md |
| Current Slice | 在 triggers 段 append 三行: 'axfr' / 'dmarc' / 'spf' |
| Definition of Done | dnsx SKILL.md 触发器含三关键词 |
| Required Validation | `grep -E 'axfr\|dmarc\|spf' ~/.opensquilla/skills/dnsx/SKILL.md` |
| Step Review Focus | 不破坏 dnsx 既有触发器;append-only |
| Remaining Gap | none |

### T24. recon SOUL.md 工具清单增量
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 2) |
| Scope | ~/.opensquilla/agents/recon/SOUL.md |
| Current Slice | 19 个新 bin append 到 R1/R2 工具清单后 + "ServiceEntry.service 精度" 段 + "nmap NSE 触发" 段 |
| Definition of Done | grep 19 个 bin 全在 |
| Required Validation | `grep -E 's3scanner\|jenkins-cli\|mongosh\|asnmap\|cdncheck\|gitleaks' ~/.opensquilla/agents/recon/SOUL.md` |
| Step Review Focus | append-only, 不动既有 R1/R2 段 |
| Remaining Gap | none |

### T25. penetration SOUL.md vector_class 分流增量
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 2) |
| Scope | ~/.opensquilla/agents/penetration/SOUL.md |
| Current Slice | vector_class 路由表加 'db' + 'mgmt' 两行 + 漏洞类型矩阵加对应行 |
| Definition of Done | grep 4 关键词全在 |
| Required Validation | `grep -E 'mongosh\|redis-cli\|jenkins-cli\|grafana' ~/.opensquilla/agents/penetration/SOUL.md` |
| Step Review Focus | append-only, 'db' 行明确 mongosh + redis-cli + ES-tools + rabbitmqadmin + kafkacat;'mgmt' 行明确 jenkins-cli + grafana-fp + prometheus-fp + kibana + jira |
| Remaining Gap | none |

### T26. attack-surface-enumeration SOUL.md priority_top_n P0 入口
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | serial (Round 2) |
| Scope | ~/.opensquilla/agents/attack-surface-enumeration/SOUL.md |
| Current Slice | 在 §51 complete 判据段加一行: "DB/MQ 开放端口 + 管理面板发现 = P0 入口" |
| Definition of Done | SOUL.md 含此约束 + test 通过 |
| Required Validation | test_priority_top_n_db_mgmt_p0 |
| Step Review Focus | 不破坏 schema-v1 顶层结构 |
| Remaining Gap | none |

### T27. evidence.py: PrivescEvidence + ResourceEntry + ResourceEvidence
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | Thread A (Round 3 并行) |
| Scope | src/opensquilla/attack_dispatch/evidence.py |
| Current Slice | (a) PrivescEvidence.current_access 7 类键 (os/net/proc/cron/env/creds/suid); (b) ResourceEntry Pydantic 子模型; (c) ResourceEvidence schema; (d) EVIDENCE_SCHEMAS 注册 "resource-v1" |
| Definition of Done | 字段全在 + 兜底默认 + extra=forbid 兼容 + 既有测试通过 |
| Required Validation | pytest tests/test_attack_dispatch.py -v |
| Step Review Focus | PrivescEvidence.current_access 改 dict 不破坏既有 schema 验证 |
| Remaining Gap | none |

### T28. waves.py: W0.6 注册 + W1/W4 deps 追加
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | Thread A (Round 3 并行) |
| Scope | src/opensquilla/attack_dispatch/waves.py |
| Current Slice | (a) W0.6 wave 注册: deps=("W0",), static_fanout 3 specialist, evidence_schema="resource-v1"; (b) W1 deps 改 ("W0", "W0.6"); (c) W4 deps 改 ("W2", "W3", "W0.6"); (d) DRILL_IN_SLOTS 不动 |
| Definition of Done | W0.6 可读 + W1/W4 deps 含 W0.6 + 单测过 |
| Required Validation | test_w0_6_resource_checkpoint_registered |
| Step Review Focus | 不破坏 W0-W8 拓扑 |
| Remaining Gap | none |

### T29. tests/test_recon_coverage.py 增量
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | Thread B (Round 3 并行) |
| Scope | tests/test_recon_coverage.py (追加段落) |
| Current Slice | 新增 test_recon_soul_r3_19_bins_registered: 读取 recon SOUL.md, 提取 19 个 bin 名, 断言 ~/.opensquilla/skills/<name>/ 存在 |
| Definition of Done | 全绿 |
| Required Validation | pytest tests/test_recon_coverage.py -v |
| Step Review Focus | 容错:SOUL.md 不存在时 skip;容错:bin 名取 R1+R3 合并集合 |
| Remaining Gap | none |

### T30. README.md "安全工具"段追加
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | Thread C (Round 3 并行) |
| Scope | README.md |
| Current Slice | 找 "安全工具" / "Security Tools" 段, 追加一行 "R3 增量 19 个 bin" |
| Definition of Done | README.md 含 grep 19 个工具名 |
| Required Validation | `grep -E 's3scanner\|cloud_enum\|mongosh\|tlsx\|gitleaks' README.md` |
| Step Review Focus | 不破坏现有 README 结构;不动 SECURITY.md |
| Remaining Gap | none |

### T31. 19 bin smoke test
| Field | Value |
| --- | --- |
| Status | pending |
| Thread | Thread D (Round 3 并行) |
| Scope | 一次性 shell 验证 |
| Current Slice | for b in 19 bin; do which $b; done |
| Definition of Done | 至少 14/19 bin 拿得到;缺哪个补哪个 |
| Required Validation | bash 一行命令输出非空 |
| Step Review Focus | 缺 bin 不阻塞 round, 降级 partial 标 |
| Remaining Gap | mongosh 在 macOS 需 tarball 手动装 |

## 7. Round Order
1. **R1 (Round 1, completed)**: T1 → T2 → ... → T13 (8 bins + 字典 + payload + 3 SOUL + evidence + waves + tests + README + smoke)
2. **R3 (Round 2 串行地基, in-progress)**: T14 → T15 → ... → T26 (8 add_*_skills.py + 1 fetch 增量 + 1 dnsx SOUL 扩 + 3 SOUL 增量)
3. **R3 (Round 3 并行, idle)**: Thread A T27-T28 + Thread B T29 + Thread C T30 + Thread D T31
4. **R3 (Round 4 合闸, idle)**: 全量回归 + final-review → decision=close

## 8. Validation Rules
- 每改一个文件就 grep 确认 import / 命名一致
- 每个 T 完成即跑对应单测, 不堆到 Round 4
- 任何新加 Pydantic 字段必须 Optional / 兜底默认
- 任何新加 Wave 必须不破坏既有 W0-W8 deps 拓扑 (含 W0.5 + W1.5 + W1.5c)
- Round 4 合闸必须全绿才能 final-review

## 9. Risks / Watchpoints
- **R3-R1**: 19 bin 装失败 (brew/apt/go install/pip 任一不可用) → 单 bin 失败不阻塞整个 round, T31 标 partial
- **R3-R2**: mongosh / redis-cli 在 macOS 没有 brew 包 → mongosh 走 tarball + PATH 注入; 真不行降级到 "nmap NSE 探测" 路径
- **R3-R3**: W0.6 资源检查跑得太慢 (扫 59 个 skill + which 19+ bin) → 加 timeout = 30s, 缺失项标 unknown
- **R3-R4**: PrivescEvidence.current_access 升级 7 类键可能让旧 LLM 不写满 → 兜底默认 {}, 不强制 required
- **R3-R5**: 5 个 P0 skill (mongosh/redis-cli/ES-tools/wafw00f/sslyze) 涉及"主动认证测试" → 严格 ROE.aggressive gate (本轮不扩 ROEEvidence, 默认 false)
- **R3-R6**: gitleaks / trufflehog 扫描大仓库会超时 → 默认 scope 1000 commits / 50MB
- **R3-R7**: 19 bin 全装上后 ~/.opensquilla/skills/ 共 59 个 skill → 单测遍历慢 → conftest.py 加 marker `slow` 跳过
- **R3-R8**: W0.6 跑在 W0 之后, W1 之前 — 若 W0 ROE 没产生, W0.6 跳过 (fail-open)
- **R3-R9**: T29 SOUL↔Skill 一致性测试如果过不了 → 反映 SOUL.md 描述溢出, 需先降级 SOUL 再让测试过
- **R3-R10**: 本轮 13 个 T 串行, 8 个 add_*_skills.py 落同一个 ~/.opensquilla/skills/, 任一脚本幂等失败会阻塞后续 → 沿用 R1/R2 的 idempotent 写法

## 10. Termination Checklist
- [ ] R3 全部 17 个 S 状态 `completed`
- [ ] Round 2 全部 13 个 T 状态 `completed` (T14-T26)
- [ ] Round 3 全部 4 线程状态 `completed` (T27-T31)
- [ ] Round 4 smoke test + 全量回归全绿
- [ ] ~/.opensquilla/skills/ 共 59 个 skill (40 R1 + 19 R3)
- [ ] ~/.opensquilla/wordlists/ 共 5 个字典
- [ ] ~/.opensquilla/agents/{recon,penetration,attack-surface-enumeration}/SOUL.md 含 19 个新 bin 描述
- [ ] ~/.opensquilla/skills/dnsx/SKILL.md 含 axfr / dmarc / spf 触发器
- [ ] tests/test_recon_coverage.py / test_attack_dispatch.py / test_engine 全绿
- [ ] README.md "安全工具"段含 19 个新 bin
- [ ] W0.6 wave 注册, deps=(W0,), EVIDENCE_SCHEMAS 含 "resource-v1"
- [ ] PrivescEvidence.current_access 7 类键 schema 验证通过
- [ ] 规范化 todo 全部 `completed`
- [ ] delivery-state.json current_status=complete + final_audit_status=passed