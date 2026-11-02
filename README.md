# vvsq 的博客

个人博客站点。基于 [Astro](https://astro.build) 构建的纯静态站点，主题为 [Firefly](https://github.com/CuteLeaf/Firefly)。

🌐 **线上地址：<https://vvsq.github.io/>**

## 技术栈

| 组成 | 说明 |
| --- | --- |
| 框架 | Astro（静态输出，无后端服务） |
| 交互 | Svelte 岛屿组件 |
| 样式 | Tailwind CSS |
| 搜索 | Pagefind（构建期生成索引） |
| 部署 | GitHub Pages + GitHub Actions |

## 目录结构

```
src/
├── config/      # 站点、个人资料、导航、评论等配置
├── content/     # 文章（posts）、动态（dynamic）、项目（projects）
├── components/  # UI 组件
├── layouts/     # 页面布局
├── pages/       # 路由
├── plugins/     # Markdown / HTML 处理插件
└── utils/       # 工具函数
public/          # 原样输出的静态资源
scripts/         # 构建期辅助脚本（图标、LQIP、字体子集等）
```

## 本地开发

环境要求：Node.js ≥ 22.23、pnpm ≥ 11。

```bash
pnpm install     # 安装依赖
pnpm dev         # 本地预览 http://localhost:4321
pnpm build       # 生产构建，输出到 dist/
pnpm preview     # 预览构建产物
```

代码检查与格式化：

```bash
pnpm check       # Astro 诊断
pnpm type-check  # TypeScript 类型检查
pnpm lint        # Biome 检查
pnpm format      # Biome 格式化
```

## 写文章

```bash
pnpm new-post    # 交互式创建新文章
pnpm new-d       # 创建一条动态
```

文章放在 `src/content/posts/`，使用 Markdown 或 MDX，元信息写在 frontmatter 里。

## 部署

推送到 `main` 分支后，`.github/workflows/deploy.yml` 会自动安装依赖、构建并发布到 GitHub Pages，无需服务器，也无需备案。

首次部署需在仓库 **Settings → Pages → Build and deployment → Source** 选择 **GitHub Actions**。

站点域名不需要写死在代码里：工作流会根据仓库名自动推导 `site` 与 `base`。如果之后绑定自定义域名，在 **Settings → Secrets and variables → Actions → Variables** 里新增 `SITE_URL=https://你的域名` 即可。

## 致谢

主题来自 [CuteLeaf/Firefly](https://github.com/CuteLeaf/Firefly)，遵循 [MIT License](./LICENSE)。
