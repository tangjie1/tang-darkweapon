<div align="center">

# 唐门 · 暗之器

**网络安全可视化工具集 · 黑客风格 GUI · Python + PyQt6**

[![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python)](https://www.python.org/)
[![PyQt6](https://img.shields.io/badge/PyQt-6-green?logo=qt)](https://pypi.org/project/PyQt6/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?logo=windows)](https://www.microsoft.com/windows)

</div>

---

## 📖 简介

**唐门-暗之器** 是一款面向安全研究人员的可视化工具集，提供 FOFA 资产测绘爬取与 Nuclei 漏洞扫描的一体化图形界面，采用黑客风格深色 UI 设计。

> ⚠️ **免责声明**：本工具仅供安全研究和**授权**渗透测试使用，请遵守相关法律法规。对未授权目标进行测试属于违法行为，后果自负。

---

## ✨ 功能特性

### 🔍 FOFA 爬取模块
| 功能 | 说明 |
|------|------|
| FOFA 搜索 | 支持完整 FOFA 语法，自动 Base64 编码 |
| 分页爬取 | 可设置起止页，一键获取总页数 |
| 反爬间隔 | 可配置随机延迟（默认 3~6s），避免封 IP |
| 实时展示 | 表格实时显示 Host / IP / Port / 协议 / 标题 |
| 存活探测 | HTTP 探测每个 Host 可达性，颜色标注 |
| 结果导出 | 支持 `.txt` / `.csv` 格式导出 |
| Cookie 管理 | 独立配置弹窗，支持 Cookie 有效性验证 |

### ⚡ Nuclei 扫描模块
| 功能 | 说明 |
|------|------|
| 可视化配置 | 模板路径、输出目录、代理等图形化配置 |
| 模板树形浏览 | 异步加载模板目录，支持搜索/勾选/右键编辑 |
| 实时输出 | 扫描结果实时彩色展示，按严重级别分色 |
| 漏洞统计 | 自动统计真实漏洞数量（排除 INFO 级别信息） |
| FOFA 联动 | 一键将 FOFA 结果发送至 Nuclei 批量扫描 |
| 目标管理 | 支持手动输入 / txt 文件批量导入 |
| 结果导出 | 扫描结果导出为 `.txt` / `.jsonl` |

---

## 🚀 快速开始

### 环境要求
- Python 3.9+
- Windows（已测试）/ Linux（理论支持）
- [Nuclei](https://github.com/projectdiscovery/nuclei)（Nuclei 模块需要）
- [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)（Nuclei 模块需要）

### 安装

```bash
# 克隆仓库
git clone https://github.com/tangjie1/tang-darkweapon.git
cd tang-darkweapon

# 安装依赖
pip install -r requirements.txt
```

或双击 `安装依赖.bat`

### 配置

```bash
# 复制配置模板
copy config\settings.json.example config\settings.json
```

然后编辑 `config/settings.json`，填入：
- `fofa_cookie`：你的 FOFA Cookie（浏览器 DevTools → Application → Cookies 复制）
- `nuclei_exe`：nuclei 可执行文件的完整路径
- `nuclei_template_dir`：nuclei-templates 目录路径

### 启动

```bash
python main.py
```

或双击 `启动.bat`

---

## 📁 目录结构

```
唐门-暗之器/
├── main.py                  # 主程序入口 + 主窗口
├── requirements.txt         # Python 依赖
├── 启动.bat                 # Windows 一键启动
├── 安装依赖.bat             # Windows 一键安装依赖
│
├── fofa-scan/               # FOFA 爬取模块
│   ├── gui.py               # FofaScanTab UI
│   ├── spider.py            # FofaSpider 爬虫核心
│   └── config_manager.py   # 配置管理
│
├── nuclei-scan/             # Nuclei 扫描模块
│   ├── nuclei_tab.py        # NucleiTab UI
│   └── nuclei_runner.py     # NucleiRunner（QThread 执行器）
│
├── config/
│   └── settings.json.example  # 配置模板（复制为 settings.json 后填写）
│
├── output/                  # 扫描/爬取结果（已 .gitignore）
├── logs/                    # 运行日志（已 .gitignore）
└── resources/               # 静态资源
```

---

## 🔒 安全说明

`config/settings.json` 包含你的 FOFA Cookie 等敏感信息，**已被 `.gitignore` 排除，不会上传至 GitHub**。

如不小心提交了敏感信息，请立即：
1. 登录 FOFA 使旧 Cookie 失效
2. 从 git 历史中彻底删除（`git filter-branch` 或 `BFG Repo-Cleaner`）

---

## 📦 依赖

| 库 | 用途 |
|----|------|
| PyQt6 | GUI 框架 |
| requests | HTTP 请求 |
| lxml | HTML 解析 |

---

## 📝 更新日志

### v1.1.0（2026-04-01）
- ✅ Nuclei 可视化扫描模块完成
- ✅ FOFA → Nuclei 联动（批量/单条发送）
- ✅ 实时输出按严重级别分色显示
- ✅ 漏洞统计排除 INFO 信息级别

### v1.0.0（2026-03-31）
- ✅ FOFA 爬取模块完成
- ✅ 黑客风格 GUI 界面
- ✅ Cookie 管理与有效性验证

---

## 📄 License

MIT License — 详见 [LICENSE](LICENSE)
