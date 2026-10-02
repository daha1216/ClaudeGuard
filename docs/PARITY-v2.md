# ClaudeGuard v1→v2 对等清单（PARITY）

> 由源码通读自动提取（app.rs 1258 行、wizard.rs、widgets.rs、theme.rs、main.rs 全文 + 核心模块接口）。
> P0 重写 UI 时逐项打钩；每项右侧 `[ ]` 复制到 docs/PARITY-status.md 跟踪。
> 本文是"v1 是什么样"的唯一权威；与代码不符以代码为准并更新本文。

## 0. 三个关键发现（影响对等语义）

1. **向导第 1 页端口/IP 不落盘（v1 bug）**：wizard 页 1 只改 GuardApp.ed_port/ed_ip 编辑缓冲，"继续"和 finish_wizard() 都不写 Config（finish 只设 first_run=false 再 save）。配置真正写入只在主屏设置卡同名 TextEdit 的 lost_focus/Enter。
   **v2 决策：修复**——向导页 1 "继续"时即校验并写回 Config（first_run 保持 true 到页 2 完成才置 false）。
2. **Config.launch_on_pass 是死配置**：全仓库只在 config.rs 出现（默认 true），UI/逻辑从未读。启动 Claude 只发生在"启动 Claude"按钮（Purpose::Launch）。
   **v2 决策：保持现状**（字段+设置开关保留，不实现自动启动；向用户披露，等指示）。
3. **约定出口为空 = 宁可错杀**：默认 allowed_ips=[] 且 egress_region=""，一旦查到任何出口即 mismatch → 熔断。config.rs 注释明确此设计。
   **v2 决策：保留语义**（新装用户首次向导前如果监测线程已查到出口会立刻熔断——与 v1 相同）。
   **v2.6 变更**：required_ip 单值 → allowed_ips 列表（命中任一即过）+ egress_region 地区规则（ISO alpha-2，无固定 IP 用户按国家放行；IP 与地区任一命中即通过）。旧配置 load 时自动迁移并落盘。地区模式下拿不到地区数据（ipinfo 失败、仅 ipify 出 IP）不熔断——防误杀。

## 1. 窗口

- 单窗口，Screen {Wizard, Main} 同窗切换（first_run ? Wizard : Main）。标题 "Claude 守护器"；自绘标题栏左同文本。`[P0]`
- 初始 [420, target_h]，min [400, 420]；target_h = 工作区逻辑高-8 clamp(420,620)，回退整屏-56，再回退 620；CG_WIN_H 覆盖。v2=Tauri 逻辑像素自动处理，保留 min。`[P0]`
- 关闭：close_to_tray=true → 阻止关闭+隐藏（× 时 log"窗口已收进托盘，守护仍在运行"）；false → 真退出。托盘"退出"=真退出（不释放防火墙）。`[P0]`
- --tray：启动即隐藏。`[P0]`
- 最大化：标题栏按钮/双击切换；最大化时禁用边缘缩放。`[P0]`
- 边缘缩放：八向，边带宽 6 逻辑 px，顶边让出标题按钮区 138px。`[P0]`
- compact 模式：内容高 <400 触发紧凑排版。`[P1]`

## 2. 主屏（自上而下）

- **hero**：环+主副标题。busy→(Spin,"正在检查…","正在核对代理和出口 IP")；tripped→(Fail,"已暂停 Claude","{reason}·切回节点后自动恢复"，reason 空则"出口 IP 与约定不一致")；passed→(Pass,"一切正常","出口 {ip} {desc 前18字}")；未过→(Fail,"没有通过检查",plain_reason(reason))；无结果→(Idle,"准备中","马上开始第一次检查")。环 150px r52 stroke9；Pass 绿满环+矢量勾；Fail 红满环+矢量感叹号；Spin 3 段蓝弧转速 2.6rad/s；Idle 3 灰点。`[P0 状态/文案 | P1 动效]`
- **横幅**（白卡+状态色发丝线+色点）：①notice 绿"完成"（"已保存"/"安装完成，桌面已建快捷方式"/"安装失败：{e}"，4 秒消失）②非管理员 橙"需要管理员权限"/"自动断网要用管理员权限。请关掉这个窗口，用桌面的 ClaudeGuard 快捷方式重新打开。"③tripped 红"Claude 已被暂停"/"出口 IP 和约定不一致：已结束 Claude 的进程，并断开了它的网络。切回正确节点后会自动恢复。"④last 未过且 egress_ip 无 橙"暂时没法确认网络"/"刚才的检查没有成功，可能是网络没通。确认代理软件开着，再点重新检查。"（优先级即此序）`[P0]`
- **CTA 胶囊**（44 高满圆，宽 min(avail-28,320)）：tripped→"我已切回节点，重新检查"；busy/无结果→"正在检查，稍候…"禁用灰；passed 未 tripped→"启动 Claude"；否则→"重新检查"（未过不给启动入口）。次级"重新检查"链接仅 last_ok 时显示。`[P0]`
- **检查详情卡**（默认收起）：header"检查详情"+右侧状态字（"全部通过"绿/"有问题"/"检查中"/"还没检查"）；展开三行："代理已开启"/"代理能连通"/"出口 IP 正确" + 右侧 StepResult.text（Skip 固定"未检测"），圆点绿/红/灰；无结果"还没有结果，稍等片刻…"。`[P0]`
- **设置卡**（默认收起）：组"检测"：代理端口｜"代理软件的端口，常见是 7890"｜1-65535，err"端口要填 1-65535"；约定的出口 IP｜"只认这些出口，别的都会拦"｜**v2.6 列表编辑器**（每行一个 IPv4，×删除，底部"添加 IP"追加，err"要写成 4 段数字，如 203.0.113.10"；清空且无地区时拒绝保存："至少留一个 IP，或先选一个出口地区"）；出口地区｜"没有固定 IP 时按国家放行"｜下拉 12 项（不限/美国/日本/新加坡/香港/台湾/韩国/英国/德国/法国/加拿大/澳大利亚）；检查间隔｜"每隔几秒复查一次（秒）"｜5-3600，err"范围 5-3600 秒"/"填数字"。组"发现出口不对时"：停掉 Claude｜"立刻结束 Claude 的所有进程"；断开它的网络｜"用防火墙拦住 Claude 联网，恢复后自动解除"。组"通用"：关窗后驻留托盘｜"守护继续在后台运行"；开机自启｜"开机后自动在托盘里默默守护"（未安装时禁用+"安装之后才能开启"；变化即 set_autostart）。字段失焦/回车写回；写回成功 notice"已保存"。`[P0]`
- **软件更新组**（UpdState）：Idle"从 GitHub 看看有没有新版本"+链接"检查更新"；UpToDate"已经是最新版本了"；Checking"正在向 GitHub 查询"+"正在检查…"；Available"有新版本，下载完会自动重启"+"下载 v{ver} 并更新"；Downloading"正在下载新版本"+"{pct}%"+进度条(6 高蓝填充)；Restarting"下载完成，马上重启"+"即将重启…"；Failed"上次没成功，可以再试"+链接"重试"+错误行。`[P0]`
- **运行日志卡**（默认收起）：末尾 30 条，11px monospace。`[P0]`
- **底栏**：`ClaudeGuard v{版本}` · "打开数据文件夹"（explorer 打开 %APPDATA%\ClaudeGuard）·（未安装）"安装到电脑"。`[P0]`

## 3. 向导（3 页，圆点指示）

- 页 0："欢迎使用"/"Claude 守护器"双 24px 标题；卡"它做三件事"：「替你把关｜打开 Claude 前，先确认网络走的是约定的出口」「一直在守护｜常驻后台，每隔几秒复查一次，不用你操心」「不对就刹车｜一旦出口不对，立刻停掉 Claude 并断开它的联网」；胶囊"继续"。`[P0]`
- 页 1："两个关键数字"(21)+"不知道的话，保持默认就好"；卡：代理端口/"代理软件的端口，常见是 7890"；约定的出口 IP/"可填多个，用逗号分隔；从这些出口走才允许用 Claude"（**v2.6 多 IP**，placeholder "203.0.113.10, 198.51.100.7"）；出口地区下拉（**v2.6**，同设置卡 12 项，"没有固定 IP 时按国家放行"）；每帧校验 err"端口需为 1-65535 的数字"/"要写成 4 段数字，如 203.0.113.10"；"继续"需端口合法且（至少一个 IP 或选了地区）；"上一步"。**v2 修复：继续时写回 Config**。`[P0]`
- 页 2："最后一步"(21)+"要把它装进这台电脑吗？"；两选项卡：A"安装到这台电脑（推荐）"/"放进程序列表，桌面建快捷方式，随时可卸载"→do_install+finish；B"直接用，不安装"/"这次打开就当便携版用，不影响功能"→finish；"上一步"。finish=first_run=false+save+回主屏。`[P0]`
- 监测线程在向导期间照跑（空 IP 熔断语义见 §0-3）。`[P0]`

## 4. 托盘

tooltip "Claude 守护器"；菜单：显示主窗口｜立即检测｜解除隔离｜退出；左键=显示+聚焦；Recheck→Manual 检查；Release→firewall_release（log"已手动解除防火墙隔离"/"没有可解除的隔离规则"）+tripped=None；Quit→真退出。`[P0]`

## 5. 后台逻辑（逐条对等）

- Shared：cfg/last/tripped(Mutex)+busy/hide_req/stop(AtomicBool)+loglines(环形 200)。log=guard::log_line+内存。`[P0]`
- run_check（busy.swap 防重入）：
  1. run_checks → last=Some；log "result: passed={} reason={}"（空 reason 显示 "-"）
  2. 熔断条件（v2.6 起用 checks::match_egress）：`pass = ip ∈ allowed_ips 或 country == egress_region`；`mismatch = 拿到出口信息(ip 或地区) 且两条都不满足`；!passed && mismatch：已 tripped→只再 kill_claude()（killed>0 log"持续异常：再次结束 {n} 个 Claude 进程"）；未→guard::trip(reason)→log"已熔断：结束 {n} 个进程，新增防火墙规则 {n} 条"→tripped=Some。**egress_ip/egress_country 全 None（网络失败含 TCP 回退失败）不熔断；地区模式下拿不到地区（country=None）也不熔断——防误杀**。
  3. passed 且已 tripped→firewall_release（log"检测通过：已解除防火墙隔离"）→tripped=None（每次通过都查）。
  4. purpose==Launch：passed→resolve_app_id→launch_claude，成功 log"校验通过，已启动 Claude"且 close_to_tray 时 hide_req=true（自动收托盘）；失败 log"启动 Claude 失败（shell:AppsFolder）"；未过 log"校验未通过，已阻止启动"。
- Purpose {Monitor, Manual, Launch}；手动检查=每次新线程。
- 监测线程：启动 1s 后首轮；循环 300ms tick；到点且 !busy→run_check(Monitor)；next=now+interval.clamp(5,3600)（实时读 cfg）。
- 启动恢复：firewall_active()→tripped=Some(default)+log"检测到已有 ClaudeGuard 防火墙规则（沿用隔离状态）"。
- UpdState 机：见 §2 更新组；Checking→check_latest→is_newer?→exe_asset→Available{ver,url,size}/Failed("新版本没有附带 exe 文件")/UpToDate/Failed(e)；下载 Downloading{done,total}→Ok→Restarting→apply_update(true)→Ok exit(0)；无自动检查。
- v2 换 Tauri 事件推送替代每帧轮询：guard://status{outcome,tripped,checking}、guard://log{line}、guard://update、guard://config。语义不变。`[P0]`

## 6. CLI 入口（main.rs）

--check（JSON 到 stdout，exit 0/2）；--install（exit 0/2）；--uninstall（恒 0）；--update-selftest（打印 current/latest/is_newer/asset/download/SWAP OK）；--tray（隐藏启动）；无 flag 正常 GUI；未知忽略。CG_SMOKE_SETTINGS/CG_WIN_H 测试钩子（v2 需重建等价物或废弃并记录）。`[P0]`

## 7. plain_reason 映射（JS 侧实现）

reason 含"系统代理"→"电脑还没开系统代理：打开代理软件里的「系统代理」开关"；含"端口"/"握手"/"CONNECT"→"连不上代理端口：看看代理软件是不是开着"；含"出口"/"IP"→"出口 IP 和约定不一致"；空→"没有通过检查"；其他→原样。`[P0]`

## 8. 核心接口（UI 层引用，v2 IPC 直接调）

- checks::run_checks(&Config, impl FnMut(String)) -> CheckOutcome{proxy,port,egress:StepResult{state:Pass|Fail|Skip,text},passed,reason,egress_ip,egress_desc,egress_country}
- checks::match_egress(&Config, Option<&str> ip, Option<&str> country) -> (bool pass, bool mismatch)（v2.6 熔断判定单一真源）
- Config 15 字段（serde snake_case+default）：proxy_host/proxy_port/allowed_ips/egress_region/required_ip(legacy 只读)/connect_target/app_id/check_interval_secs/kill_on_fail/quarantine_on_fail/launch_on_pass/close_to_tray/auto_start_with_system/first_run；load() 自动迁移并落盘；save()
- guard::{log_line, kill_claude, is_claude_proc, claude_running, firewall_quarantine, firewall_release, firewall_active, is_admin, launch_claude(app_id), resolve_app_id(fallback), find_claude_dir, trip(&Config,&str)->TripResult{killed,firewall_rules,quarantined}, FW_RULE_OUT/IN}
- update::{current_version, is_newer, check_latest(&Config)->Result<Release>, Release{tag_name,assets}, Asset{name,size,browser_download_url}, Release::exe_asset, download(&Config,url,size,progress), apply_update(&Path,bool), cleanup_old}
- install::{install_dir, installed_exe, is_installed, install()->Result<PathBuf,String>, set_autostart(bool)->bool, uninstall}
- tcp_table::{established_connections, listener_pid}

## 9. P1 参考

v1 色板（作 P1 起点）：BG #F5F5F7｜CARD #FFF｜SEP #D6D6D6｜TXT #1D1D1F｜TXT2 #707070｜BLUE #0071E3｜BLUE_H #007DF0｜LINK #0066CC｜GREEN #03AA49｜GREEN_DEEP #03873A｜RED #E4002B｜ORANGE #ED6300｜MIST #E2E2E5｜CLOSE_RED #C42B1C；标题栏钮 hover #E9E9EC；输入 hover 描边 #87878A。字号阶梯见 v1 清单（24/21/17/15/14/13/12/11）。部件：胶囊 h44 满圆、toggle 50x30 r15、卡 r28 stroke1、hairline 1px。

## 附：v2 已知偏差决策（P0 向用户披露）

- 修复 §0-1 向导不落盘 bug（唯一行为变更，方向为更安全）。
- §0-2 launch_on_pass 维持死配置现状。
- v1.3.3 起 Inno 安装在 Program Files 时 is_installed()=false → 设置卡"开机自启"被禁用（v1 同款现状）；v2 P0 先保持，P2 随 Inno 一起修（如安装器直接写 Run 键）。
- do_install（"安装到电脑"）在 v2 保留入口（复用 install.rs），Inno 已装环境下 is_installed=false 仍会显示——P2 一并处理。
