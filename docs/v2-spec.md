# ClaudeGuard v2.0 重构规范（用户提示词存档，权威标准）

> 2026-10-02 由用户下达。本文与其后 AGENTS.md 冲突时，以本文为准；
> `DESIGN (1).md` 自 v2 起降级为参考资料（色板可作起点）。

## 你的角色与任务

资深设计工程师（design engineer），ClaudeGuard v2.0 重构：egui 界面整体替换为 Tauri 2 + Web 前端。
"换壳保心脏"——UI 层全部重写，守卫核心原封不动。视觉与动效唯一标准 = Emil Kowalski 设计工程哲学 + Apple 流体界面原则。

## 项目背景

- 仓库 `C:\Users\daha\Desktop\ClaudeGuard`（github.com/daha1216/ClaudeGuard），v1.3.3，Rust + eframe/egui 0.36。
- 功能（v2 必须原样保留，一行逻辑都不改）：校验系统代理 127.0.0.1:7890 → CONNECT 握手 → 出口 IP 必须为用户设定值（ipinfo 主判据，ipify 备用，TCP 观察兜底）；不合规 → 杀 claude 进程 + 防火墙隔离。托盘常驻、开机自启、首次运行向导。
- 后端模块 checks/guard/install/update 已解耦——原样复用，只允许在外围加薄 IPC 绑定（Tauri commands + events）。
- v1 纪律延续：AGENTS.md 是宪法；CI 红线 = fmt + clippy -D warnings + test 全绿；行为锁测试在新 UI 层重建等价物。
- 分发沿用 Inno Setup Per-user 安装器，v2 更新它而不是换方案。

## 设计标准（最高优先级）

### 排版
- 系统字体栈 system-ui + font-optical-sizing: auto，不引入自定义字体（除非有明确理由）。
- 字距随字号变化：大标题 letter-spacing -0.02em，正文≈0，小字微正。禁止全站固定字距。
- 行高与字号反向：标题紧 ~1.05，正文松 ~1.5。
- 层级用 字重+字号+行高 组合；v2 必须用真实字重 500/600（v1 egui 做不到，这是 v2 存在的理由）。

### 材质与深度
- 标题栏/浮层/抽屉半透明材质：backdrop-filter: blur(20px) saturate(180%) + 半透明底 + 1px 亮色顶边。
- 大面积表面比小元素更"厚"：更强 blur + 更深阴影。禁止浅色透明叠浅色透明。
- 模态配 scrim 压暗；非阻塞并行面板只半透明+位移，不加 scrim。
- 阴影柔和分层，不用生硬 offset 硬阴影。

### 动效：先决策再写代码
顺序：该不该动（频率）→ 目的（空间一致性/状态指示/反馈/防跳变，"酷"不算）→ 曲线 → 时长 → 如何被打断。
守卫面板低频工具，宁可克制：状态数据每几秒刷新时不要整块动画，只动指示灯/数字/状态色；打开主窗口（偶发）标准动画；首次向导（一次性）可加 delight；键盘操作永不动画。

### 曲线与时长（硬值，写进 tokens）
```css
--ease-out: cubic-bezier(0.23, 1, 0.32, 1);    /* 入场/交互反馈 */
--ease-in-out: cubic-bezier(0.77, 0, 0.175, 1); /* 屏内移动 */
--ease-drawer: cubic-bezier(0.32, 0.72, 0, 1);  /* 抽屉/面板 */
```
- 禁止 ease-in 用于 UI；禁止 transition: all，永远写明属性。
- 时长：按钮按压 100-160ms；浮层/tooltip 125-200ms；下拉 150-250ms；模态/抽屉 200-500ms；常规 ≤300ms。
- 按压 :active { transform: scale(0.97) }，pointer-down 即反馈。
- 入场永远从 scale(0.95)+opacity:0 开始，禁止 scale(0)。
- 浮层 transform-origin 锚定触发元素；模态居中。进出同路径同锚点。
- 可拖拽元素用弹簧 { type:'spring', bounce:0, duration:0.4 }（临界阻尼）；甩动/惯性才 bounce 0.2；拖拽结束速度交接（velocity handoff）；中断从当前呈现值续动。
- 列表批量入场 stagger 30-80ms；只动画 transform 和 opacity；预设动画交给 CSS/WAAPI。
- 交叉淡入淡出发涩时 filter: blur(2px)（≤20px）遮瑕。

### 无障碍
- prefers-reduced-motion: reduce → 位移/弹簧改短 cross-fade，保留辅助理解的 opacity/颜色变化。
- prefers-reduced-transparency: reduce → 毛玻璃实底化。
- hover 动效包在 @media (hover:hover) and (pointer:fine) 里。

## 技术方向
- Tauri 2.x + WebView2（系统预装，不打包运行时）。Rust 侧三件事：现有核心模块、#[tauri::command] 薄绑定、守卫状态事件推送（emit 不轮询）。
- 前端栈自选给理由：小工具优先 Vanilla TS 或轻框架；若用 React 动效用 Motion 且 x/y 简写不走硬件加速——用完整 transform 字符串。CSS-first，依赖最小化。
- 无边框 decorations:false + 自绘标题栏（data-tauri-drag-region）+ 最小化/最大化/关闭走 Tauri window API（保证 Snap Layout 等系统行为正常）。
- 图标全部内联 SVG，禁止字体字形/emoji（v1 豆腐块教训）。
- 插件：托盘 tray-icon、自启 autostart、单实例 single-instance。更新暂沿用 Inno Setup 覆盖安装，不引入 updater 签名体系（除非同意）。
- 200% DPI：v1 AppliedDPI hack 不再需要，但要实测高 DPI 布局。

## v2 硬指标（验收逐项检查）
1. 守卫行为与 v1 完全一致（判定/杀进程/防火墙隔离既有测试全绿）。
2. 真实字重 500/600、可控字距、柔和阴影、毛玻璃材质、弹簧动画全部成立。
3. 所有图标内联 SVG 无缺字形。
4. 启动到可交互 ≤1.5s；常驻内存 ≤300MB。
5. 守卫状态变化到界面更新 ≤1s。
6. 200% DPI 与 reduced-motion 实测无破版。
7. Inno Setup Per-user 安装器装/跑/卸 E2E 三连过。

## 交付节奏（三阶段，每阶段结束停下等验收）
- P0 骨架对齐：Tauri 壳跑通，IPC 命令+事件全量接好。列 v1 每个页面/交互对等清单逐项打钩。行为锁测试重建，CI 绿。视觉可朴素。
- P1 视觉与动效：tokens → 排版 → 材质 → 动效。主页先出 2-3 风格变体对比定稿再铺开。每个动画过收尾审查（transition:all / scale(0) / ease-in / popover 居中缩放 / >300ms / 键盘带动画——有则必改）。
- P2 打包发布：安装器更新、E2E、截图验收（视觉模型看图挑错，含 200% DPI 与 reduced-motion），版本 2.0.0。

## 红线（违反 = 返工）
1. 守卫判定逻辑、阈值、杀进程、防火墙行为一概不改。
2. 后端核心模块不改内部实现，只许加 IPC 绑定层。
3. 不引入 Electron 或重依赖；前端依赖最小。
4. DESIGN (1).md 与本提示词冲突以本提示词为准。
5. 未经确认不删除/绕过/弱化行为锁测试与 CI 红线。
6. 每阶段交付必须可运行可演示，不留半成品。

## 技能调度
- 设计写 UI：emil-design-eng + apple-design 常驻标准。
- 每个从零动画用 animate；收尾 review-animations；全库动效审计 improve-animations；找该不该加动效 find-animation-opportunities（本工具低频，预期结论"大部分不加"）。
