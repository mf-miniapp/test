# Engagement Plan: 51ifind.com (同花顺 iFinD)

---

## 1. 范围摘要 (Scope Summary)

### 1.1 目标确认
| 字段 | 值 |
|------|------|
| **主域名** | 51ifind.com |
| **WWW 域名** | www.51ifind.com (301 redirect from 51ifind.com) |
| **IP 地址** | 121.52.252.15 (主), 121.201.70.245 (webcache), 120.132.86.105 (ltsq15) |
| **端口** | 80/tcp (open), 443/tcp (open); 其余 (22,8080,8443,3000,9090,3306,5432,6379,445,139) filtered/closed |
| **ASN** | 阿里云 (121.52.252.0/24 段归属) |
| **DNS** | NS3.MYHEXIN.COM / NS4.MYHEXIN.COM (MyHexin 域名解析服务) |
| **注册商** | 22net, Inc. |
| **创建日期** | 2010-08-18 |
| **到期日期** | 2031-08-18 |
| **SSL 证书** | 主机名不匹配 (通过 CDN/LB 托管) |

### 1.2 已知子域
| 子域 | IP | 状态 |
|------|-----|------|
| www.51ifind.com | 121.52.252.15 | ✅ 已解析, HTTP 200 |
| 51ifind.com | 121.52.252.15 | ✅ 301→www |
| ftupass.51ifind.com | 121.52.252.15 | ✅ HTTP 404 (有 Stargate/CDN 后端) |
| webcache.51ifind.com | 121.201.70.245 | ✅ 已解析 |
| ltsq15.51ifind.com | 120.132.86.105 | ✅ 已解析 |
| api.51ifind.com | — | ❌ 未解析 (连接超时) |
| app.51ifind.com | — | ❌ 未解析 (连接超时) |
| dev.51ifind.com | — | ❌ 未解析 (连接超时) |
| staging.51ifind.com | — | ❌ 未解析 (连接超时) |
| test.51ifind.com | — | ❌ 未解析 (连接超时) |

### 1.3 关键子域 (推测)
- **ftupass.51ifind.com** — FTP 登录/认证服务 (Stargate 网关, 有 RSA pubkey 端点 /pubkey/default.js)
- **webcache.51ifind.com** — 缓存代理 (121.201.70.245)
- **ltsq15.51ifind.com** — 未知服务 (120.132.86.105)
- 潜在子域需 W1 recon 阶段用 subfinder/dnsenum/fierce 批量枚举

---

## 2. 阶段路线图 (Phase Roadmap)

```
Phase 0 (本阶段): Engagement Planning ✅
  ├─ 目标确认 / 范围定义 / ROE
  └─ 工具 + 参数表 + 成功/退出标准

Phase 1 (并行三路): W1 Evidence Collection
  ├─ W1A: recon (子域枚举 / 端口扫描 / 技术指纹 / CDN 探测)
  ├─ W1B: intel-collection (WHOIS 回溯 / ASN 关联 / 历史 DNS / SSL 证书链)
  └─ W1C: attack-surface-enumeration (爬虫 / API 端点发现 / 中间件探测)

Phase 2: Vuln Enumeration
  └─ 对 W1 产出进行漏洞扫描 (Nuclei / AWVS / Nessus 等)

Phase 3: Exploitation
  └─ 利用链构建 (API → 认证 → 数据提取)

Phase 4: Lateral Movement
  └─ 子域 → webcache → ftupass → ltsq15

Phase 5: Impact Proof
  └─ 数据泄露证明 + 报告
```

---

## 3. 工具 + 参数表 (Tools & Parameters)

### Phase 1A: Recon
| 工具 | 用途 | 参数 |
|------|------|------|
| subfinder | 子域枚举 | `-d 51ifind.com -all -o recon/subdomains.txt` |
| amass | 子域枚举 (OSINT) | `amass enum -d 51ifind.com -o recon/amass.txt` |
| masscan + nmap | 端口扫描 | `nmap -Pn -sV -sC -O -oA recon/ports 121.52.252.0/24` |
| whatweb | 技术指纹 | `whatweb -a 3 https://www.51ifind.com` |
| wappalyzer (via ff) | Web 技术栈 | ff 加载页面 → 导出指纹 |
| httprobe | 活跃子域验证 | `cat recon/subdomains.txt | httprobe -c 100` |
| certspotter/crt.sh | SSL 证书枚举 | `https://crt.sh/?q=51ifind.com` |

### Phase 1B: Intel
| 工具 | 用途 | 参数 |
|------|------|------|
| whois + whoisxmlapi | WHOIS 回溯 | 查注册人/邮箱/历史 |
| asnlookup (bgp.he.net) | ASN 关联 | 查 121.52.0.0/16 段 |
| shodan | Shodan 数据 | `shodan search "51ifind.com"` |
| waybackurls | 历史 URL | `waybackurls 51ifind.com` |
| securitytrails | DNS 历史 | API 查历史解析记录 |

### Phase 1C: Attack Surface
| 工具 | 用途 | 参数 |
|------|------|------|
| katana/gobuster | 目录/文件爆破 | `gobuster dir -u https://www.51ifind.com -w /usr/share/wordlists/dirb/common.txt` |
| arjun | API 端点发现 | `arjun -u https://www.51ifind.com/ -m GET` |
| nuclei | 模板化漏洞扫描 | `nuclei -l recon/targets.txt -t templates/` |
| postman/insomnia | API 手动探索 | 导入页面 JS 中的端点 |
| curl/har2curl | 抓包分析 | 浏览器 HAR 导出 → 分析 API 调用 |

---

## 4. 技术栈与基础设施特征 (已确认)

| 组件 | 版本/特征 | 来源 |
|------|-----------|------|
| **API 网关** | Kong 0.14.1 | `Via: kong/0.14.1` |
| **反向代理** | OpenResty | `Server: openresty` |
| **后端** | Apache 2.4.66 (Unix) | `/api/` 返回的 Server 头 |
| **CDN** | 同花顺自建 CDN (cachemd*.10jqka.com.cn, SQUID) | Via 头 |
| **CDN/静态** | s.thsi.cn (thsi.cn 二级域) | JS/CSS 资源路径 |
| **FTP 认证** | Stargate 网关 | ftupass.51ifind.com 返回 Server: Stargate |
| **前端框架** | jQuery 3.5.0 | 页面 JS 引用 |
| **加密库** | RSA public key (ftupass), encrypt.js (thsi.cn) | 前端 JS |
| **验证码** | thsi.cn captcha v1.4 | captcha.min.js |
| **Analytics** | Baidu Tongji (hm.baidu.com) | h.js |
| **Microsoft 365** | MS=ms43176830 (TXT 记录) | DNS TXT |
| **后端语言** | Java (ifind-java-company-bff-web-container) | JS CDN 路径 |
| **数据库服务** | 未知 (推测 MySQL/Oracle, 金融数据) | 页面描述 |
| **SSL** | 通配符/CDN 托管证书 | 证书不匹配 51ifind.com |

---

## 5. 攻击面范围 (Attack Surface)

### 5.1 Web 端口
- **80/tcp** — HTTP (301 → 443)
- **443/tcp** — HTTPS (主入口, Kong API Gateway)

### 5.2 API 端点 (推测)
- `/api/` — Kong 代理, 返回 Apache/2.4.66
- `/api/v1/` — Kong 代理, 返回 Apache/2.4.66
- `/api/health` — 404 (Kong 代理存在)
- `/actuator/health` — 404 (Spring Boot 可能)
- `ftupass.51ifind.com/pubkey/default.js` — RSA 公钥端点
- `s.thsi.cn` 静态资源 — 多个 JS/CSS 端点

### 5.3 云服务
- **阿里云** — 主 IP 段归属
- **Microsoft 365** — MS 验证记录
- **百度统计** — 跟踪脚本
- **thsi.cn CDN** — 自建内容分发

### 5.4 认证系统
- ftupass.51ifind.com — FTP 认证
- 前端 RSA 加密 → thsi.cn encrypt.js
- Captcha 系统 (thsi.cn v1.4)

---

## 6. 初步 ROE (Rules of Engagement)

### 6.1 Success Unit (成功判定)
```
[CRITICAL] 通过 API 端点获取 ≥3 条真实金融数据记录
[HIGH]     发现并利用 ftupass.51ifind.com 认证缺陷, 获取有效 token
[HIGH]     webcache.51ifind.com (121.201.70.245) 存在 SSRF 或信息泄露
[MEDIUM]   发现 ≥2 个未授权 API 端点
[MEDIUM]   ltsq15.51ifind.com (120.132.86.105) 存在可探测服务
[LOW]      子域接管 (subdomain takeover) — 如已解析但未使用的 CNAME 指向已删除资源
```

### 6.2 Scope Boundaries (范围边界)
| 项目 | 值 |
|------|-----|
| **In-Scope** | *.51ifind.com, 121.52.252.0/24, webcache.51ifind.com IP, ltsq15.51ifind.com IP |
| **Out-of-Scope** | 生产数据库直接写入/删除, 凌晨 2:00-6:00 (CST) 高峰操作, 对 www.51ifind.com 并发 >50 的扫描 |
| **Rate Limit** | 单 IP 每分钟 ≤60 请求, 扫描窗口 2 小时/子域 |
| **Data Limit** | 单次 API 请求 ≤1000 条记录 |

### 6.3 紧急联系点
- 同花顺 (10jqka.com.cn) 运维团队 (通过 cachemd*.10jqka.com.cn CDN)
- 注册邮箱: abuse@22.cn (域名注册商)

---

## 7. W1 三路并行 Specialist 聚焦方向

### W1A: recon (子域/端口/指纹)
**聚焦**:
1. 用 subfinder + amass + massdns 批量枚举 *.51ifind.com 子域
2. masscan + nmap 扫描 121.52.252.0/24 段, 重点探测 80, 443, 8080, 8443, 3000
3. 对 webcache.51ifind.com (121.201.70.245) 和 ltsq15.51ifind.com (120.132.86.105) 做完整端口/服务指纹扫描
4. crt.sh + certspotter 查所有 SSL 证书包含的子域
5. 识别 CDN 边界 (同花顺 CDN vs 阿里云 vs 其他)

### W1B: intel-collection (WHOIS/ASN/历史)
**聚焦**:
1. WHOIS 完整信息 (注册人/邮箱/电话/地址) — 需查 whois.22.cn
2. ASN 回溯: 121.52.0.0/16 段归属的 ASN 及同 ASN 下的其他域名
3. Shodan/Hackertarget 搜索 51ifind.com 历史资产
4. Wayback Machine 回溯 51ifind.com 历史 URL (waybackurls)
5. SecurityTrails API 查 DNS 历史记录 (A/CNAME/MX/TXT 变更)
6. Microsoft 365 租户探测 (MS=ms43176830)

### W1C: attack-surface-enumeration (API/目录/中间件)
**聚焦**:
1. Gobuster/Ffuf 目录爆破: https://www.51ifind.com + https://ftupass.51ifind.com
2. Arjun/Paramspider API 端点发现: 分析页面 JS 中的 API 调用
3. 浏览器抓包 (HAR 导出): 分析页面加载时的真实 API 请求
4. Kong API Gateway 特性探测 (/kong/status, /api/v1, /service/xxx)
5. Apache 2.4.66 已知漏洞 (CVE-2021-41773, CVE-2021-42013 路径穿越)
6. Stargate FTP 网关探测 (ftupass 的认证/授权缺陷)

---

## 8. 成功/退出标准

| 条件 | 判定 |
|------|------|
| **成功** | W1A+B+C 完成, 产出 ≥10 个活跃子域, ≥3 个 API 端点, ≥1 个可利用漏洞 |
| **退出** | W1 产出 < 3 个有效资产, 或扫描超时 4 小时 |
| **继续** | 发现任何子域接管或 API 未授权访问 |
