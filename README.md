<div align="center">

# 👋 Hi, I'm vvsq.

**专注逆向工程 (Reverse Engineering) 与样本分析 (Malware Analysis)**

[![Blog](https://img.shields.io/badge/Blog-vvsq.github.io-blue?style=flat-square&logo=github)](https://vvsq.github.io/)
[![CTF](https://img.shields.io/badge/Focus-Reverse%20%26%20Pwn-red?style=flat-square)](#)
[![Status](https://img.shields.io/badge/Status-Looking%20for%20Intern-green?style=flat-square)](#)

</div>

---

### 🧑‍💻 关于我 (About Me)

你好！我是 **vvsq**，一名网络安全学习者。

目前主要热衷于**二进制安全**方向，有半年的逆向 CTF 经验。熟悉 PE 结构、ctf逆向算法、反调试与花指令去除、智能体辅助逆向。

**我的目标**是。

- ✍️ 日常记录：在博客中分享 CTF Reverse 踩坑实录与样本分析笔记。
- 🎯 长期目标：尽量减少依赖 AI 智能体进行逆向分析复杂恶意样本，逐步积累经验。

### 🛡️ 技能树 (Tech Stack)

- **语言基础**：C/C++（熟悉）、Python（看得懂）、x86/x64 汇编。
- **逆向工具**：IDA Pro、x64dbg、WinDbg等
- **安全技能**：PE 文件结构解析、简单壳脱壳、动/静态调试、花指令与简单混淆对抗、基础漏洞分析。

---

### 📝 博客介绍 (About This Blog)

这是我的个人技术博客，基于 Astro 框架与 Firefly 主题搭建的纯静态站点，部署在 GitHub Pages。

**🌐 线上地址：<https://vvsq.github.io/>**

博客主要用于沉淀我的技术思考，主要内容方向包括：
- **CTF Reverse**：各种加密算法、混淆逻辑与反调试技巧的分析。
- **样本分析**：真实木马样本的行为分析与特征提取。
- **PE 结构与底层**：Windows 系统机制与底层逆向。
- **渗透测试**：拓展网安的知识面。
- **其他学习经验**：不只是安全方向，计算机领域还有很多有意思的东西等我发掘。

---

### 🛠️ 博客构建 (Development)

> 如果你也对这本站的技术实现感兴趣，以下是一些基础信息：

| 组成 | 说明 |
| --- | --- |
| 框架 | Astro (静态输出) + Svelte + Tailwind CSS |
| 搜索 | Pagefind |
| 部署 | GitHub Actions 自动构建至 GitHub Pages |

**本地运行：**

```bash
# 环境要求：Node.js ≥ 22.23、pnpm ≥ 11
pnpm install     # 安装依赖
pnpm dev         # 本地预览 http://localhost:4321
pnpm build       # 生产构建