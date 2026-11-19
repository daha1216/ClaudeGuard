//! Native Win32 system tray icon (`Shell_NotifyIconW` + `CreatePopupMenu`) with zero external crates.
//!
//! Runs a lightweight hidden Win32 message loop on a dedicated thread so the GPUI
//! windows can be completely destroyed (`window.remove_window()`, dropping DirectX
//! SwapChain & GPU VRAM to 0) while keeping the tray icon responsive in <25ms.

use crate::theme::{HeroTone, layout};
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

/// Logical screen rectangle (`x, y, width, height`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LogicalRect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

/// Tray events emitted from the Win32 tray thread to the GPUI app controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayEvent {
    ToggleHud,
    OpenConsole,
    RecheckNow,
    TogglePause,
    SweepOrphans,
    SafeExit,
    QuitGuiOnly,
}

/// Tray icon visual status tone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayTone {
    Healthy,
    Tripped,
    Warn,
}

impl From<HeroTone> for TrayTone {
    fn from(value: HeroTone) -> Self {
        match value {
            HeroTone::Healthy => Self::Healthy,
            HeroTone::Tripped => Self::Tripped,
            HeroTone::DisarmedOrPaused => Self::Warn,
        }
    }
}

/// Lock-free-feeling Waker-backed event queue bridging the Win32 tray thread to GPUI's foreground executor.
#[derive(Clone, Default)]
pub struct TrayChannel {
    inner: Arc<Mutex<TrayChannelState>>,
}

#[derive(Default)]
struct TrayChannelState {
    queue: VecDeque<TrayEvent>,
    waker: Option<Waker>,
    closed: bool,
}

impl TrayChannel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn send(&self, event: TrayEvent) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.queue.push_back(event);
            if let Some(waker) = guard.waker.take() {
                waker.wake();
            }
        }
    }

    pub fn close(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.closed = true;
            if let Some(waker) = guard.waker.take() {
                waker.wake();
            }
        }
    }

    pub fn recv_async(&self) -> TrayNextFuture {
        TrayNextFuture {
            inner: self.inner.clone(),
        }
    }
}

pub struct TrayNextFuture {
    inner: Arc<Mutex<TrayChannelState>>,
}

impl Future for TrayNextFuture {
    type Output = Option<TrayEvent>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.inner.lock().expect("tray channel lock");
        if let Some(ev) = guard.queue.pop_front() {
            Poll::Ready(Some(ev))
        } else if guard.closed {
            Poll::Ready(None)
        } else {
            guard.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// Computes bottom-right HUD bounds anchored just above the Windows taskbar work area.
pub fn compute_hud_bounds(work_area: LogicalRect) -> LogicalRect {
    let margin = 10.0_f32;
    let width = layout::HUD_WIDTH.min((work_area.width - margin * 2.0).max(320.0));
    let height = layout::HUD_HEIGHT.min((work_area.height - margin * 2.0).max(360.0));
    let x = work_area.x + (work_area.width - width - margin).max(0.0);
    let y = work_area.y + (work_area.height - height - margin).max(0.0);
    LogicalRect {
        x,
        y,
        width,
        height,
    }
}

#[cfg(windows)]
mod win_impl {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    use std::thread::JoinHandle;
    use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
    use windows::Win32::Graphics::Gdi::{CreateBitmap, DeleteObject};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::Shell::{
        NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_ERROR, NIIF_INFO, NIM_ADD, NIM_DELETE,
        NIM_MODIFY, NIN_SELECT, NOTIFYICONDATAW, Shell_NotifyIconW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreateIconIndirect, CreatePopupMenu, CreateWindowExW, DefWindowProcW,
        DestroyIcon, DestroyMenu, DispatchMessageW, GetCursorPos, GetMessageW, GetWindowLongPtrW,
        HICON, ICONINFO, MF_SEPARATOR, MF_STRING, MSG, PostMessageW, PostQuitMessage,
        RegisterClassW, RegisterWindowMessageW, SPI_GETWORKAREA, SetForegroundWindow,
        SetWindowLongPtrW, SystemParametersInfoW, TPM_BOTTOMALIGN, TPM_LEFTALIGN, TPM_RETURNCMD,
        TPM_RIGHTBUTTON, TrackPopupMenuEx, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_COMMAND,
        WM_CONTEXTMENU, WM_DESTROY, WM_LBUTTONUP, WM_RBUTTONUP, WM_USER, WNDCLASSW,
    };
    use windows::core::{PCWSTR, w};

    const WM_TRAY_CALLBACK: u32 = WM_APP + 101;
    const WM_TRAY_SYNC: u32 = WM_USER + 102;
    const WM_TRAY_BALLOON: u32 = WM_USER + 103;
    const TRAY_ICON_ID: u32 = 1;

    const CMD_OPEN_CONSOLE: u32 = 1001;
    const CMD_TOGGLE_HUD: u32 = 1002;
    const CMD_RECHECK: u32 = 1003;
    const CMD_TOGGLE_PAUSE: u32 = 1004;
    const CMD_SWEEP_ORPHANS: u32 = 1005;
    const CMD_SAFE_EXIT: u32 = 1006;
    const CMD_QUIT_GUI: u32 = 1007;

    struct TraySharedState {
        channel: TrayChannel,
        tone: AtomicU8,
        paused: AtomicBool,
        tooltip: Mutex<String>,
        pending_balloon: Mutex<Option<(String, String, bool)>>,
        taskbar_created_msg: u32,
        hwnd: Mutex<Option<isize>>,
    }

    pub struct TrayHandle {
        shared: Arc<TraySharedState>,
        thread: Option<JoinHandle<()>>,
    }

    impl TrayHandle {
        pub fn start(channel: TrayChannel) -> Result<Self, String> {
            let shared = Arc::new(TraySharedState {
                channel,
                tone: AtomicU8::new(0),
                paused: AtomicBool::new(false),
                tooltip: Mutex::new("ClaudeGuard v4 · 守护中".to_string()),
                pending_balloon: Mutex::new(None),
                taskbar_created_msg: unsafe { RegisterWindowMessageW(w!("TaskbarCreated")) },
                hwnd: Mutex::new(None),
            });

            let thread_shared = shared.clone();
            let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
            let thread = std::thread::Builder::new()
                .name("cg-tray-win32".into())
                .spawn(move || run_tray_loop(thread_shared, ready_tx))
                .map_err(|e| format!("启动托盘线程失败：{e}"))?;

            match ready_rx.recv() {
                Ok(Ok(())) => Ok(Self {
                    shared,
                    thread: Some(thread),
                }),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(format!("托盘线程初始化异常：{e}")),
            }
        }

        pub fn set_status(&self, tone: TrayTone, paused: bool, tooltip: &str) {
            let code = match tone {
                TrayTone::Healthy => 0,
                TrayTone::Warn => 1,
                TrayTone::Tripped => 2,
            };
            self.shared.tone.store(code, Ordering::Relaxed);
            self.shared.paused.store(paused, Ordering::Relaxed);
            if let Ok(mut guard) = self.shared.tooltip.lock() {
                *guard = tooltip.to_string();
            }
            if let Ok(guard) = self.shared.hwnd.lock()
                && let Some(raw) = *guard
            {
                let hwnd = HWND(raw as *mut _);
                let _ = unsafe { PostMessageW(hwnd, WM_TRAY_SYNC, WPARAM(0), LPARAM(0)) };
            }
        }

        /// Surfaces a native Windows Action Center notification in interactive Session 1.
        pub fn show_balloon(&self, title: &str, body: &str, is_error: bool) {
            if let Ok(mut guard) = self.shared.pending_balloon.lock() {
                *guard = Some((title.to_string(), body.to_string(), is_error));
            }
            if let Ok(guard) = self.shared.hwnd.lock()
                && let Some(raw) = *guard
            {
                let hwnd = HWND(raw as *mut _);
                let _ = unsafe { PostMessageW(hwnd, WM_TRAY_BALLOON, WPARAM(0), LPARAM(0)) };
            }
        }

        pub fn shutdown(&mut self) {
            if let Ok(guard) = self.shared.hwnd.lock()
                && let Some(raw) = *guard
            {
                let hwnd = HWND(raw as *mut _);
                let _ = unsafe { PostMessageW(hwnd, WM_DESTROY, WPARAM(0), LPARAM(0)) };
            }
            if let Some(handle) = self.thread.take() {
                let _ = handle.join();
            }
        }
    }

    impl Drop for TrayHandle {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    struct WindowContext {
        shared: Arc<TraySharedState>,
        icon_healthy: HICON,
        icon_warn: HICON,
        icon_tripped: HICON,
    }

    impl WindowContext {
        fn current_icon(&self) -> HICON {
            match self.shared.tone.load(Ordering::Relaxed) {
                2 => self.icon_tripped,
                1 => self.icon_warn,
                _ => self.icon_healthy,
            }
        }
    }

    impl Drop for WindowContext {
        fn drop(&mut self) {
            unsafe {
                let _ = DestroyIcon(self.icon_healthy);
                let _ = DestroyIcon(self.icon_warn);
                let _ = DestroyIcon(self.icon_tripped);
            }
        }
    }

    fn run_tray_loop(
        shared: Arc<TraySharedState>,
        ready_tx: std::sync::mpsc::Sender<Result<(), String>>,
    ) {
        let hinstance = HINSTANCE::from(unsafe { GetModuleHandleW(None) }.unwrap_or_default());
        let class_name = w!("ClaudeGuardV4TrayWindow");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(tray_wnd_proc),
            hInstance: hinstance,
            lpszClassName: class_name,
            ..Default::default()
        };
        unsafe { RegisterClassW(&wc) };

        let hwnd = match unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                class_name,
                w!("ClaudeGuardV4Tray"),
                WINDOW_STYLE(0),
                0,
                0,
                0,
                0,
                None,
                None,
                hinstance,
                None,
            )
        } {
            Ok(h) => h,
            Err(err) => {
                let _ = ready_tx.send(Err(format!("CreateWindowExW 托盘窗口失败：{err}")));
                return;
            }
        };

        let ctx = Box::new(WindowContext {
            shared: shared.clone(),
            icon_healthy: create_badge_icon(0x10, 0xB9, 0x81),
            icon_warn: create_badge_icon(0xF5, 0x9E, 0x0B),
            icon_tripped: create_badge_icon(0xEF, 0x44, 0x44),
        });
        let ctx_ptr = Box::into_raw(ctx);
        unsafe {
            SetWindowLongPtrW(
                hwnd,
                windows::Win32::UI::WindowsAndMessaging::GWLP_USERDATA,
                ctx_ptr as isize,
            );
        }
        if let Ok(mut guard) = shared.hwnd.lock() {
            *guard = Some(hwnd.0 as isize);
        }

        let ctx_ref = unsafe { &*ctx_ptr };
        let _ = add_or_update_tray_icon(hwnd, ctx_ref, true);
        let _ = ready_tx.send(Ok(()));

        let mut msg = MSG::default();
        while unsafe { GetMessageW(&mut msg, None, 0, 0) }.as_bool() {
            let _ = unsafe { DispatchMessageW(&msg) };
        }

        let _ = remove_tray_icon(hwnd);
        if let Ok(mut guard) = shared.hwnd.lock() {
            *guard = None;
        }
        unsafe {
            SetWindowLongPtrW(
                hwnd,
                windows::Win32::UI::WindowsAndMessaging::GWLP_USERDATA,
                0,
            );
            drop(Box::from_raw(ctx_ptr));
        }
        shared.channel.close();
    }

    unsafe extern "system" fn tray_wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        let ptr = unsafe {
            GetWindowLongPtrW(hwnd, windows::Win32::UI::WindowsAndMessaging::GWLP_USERDATA)
        } as *const WindowContext;
        if ptr.is_null() {
            return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) };
        }
        let ctx = unsafe { &*ptr };

        if ctx.shared.taskbar_created_msg != 0 && msg == ctx.shared.taskbar_created_msg {
            let _ = add_or_update_tray_icon(hwnd, ctx, true);
            return LRESULT(0);
        }

        match msg {
            WM_TRAY_SYNC => {
                let _ = add_or_update_tray_icon(hwnd, ctx, false);
                LRESULT(0)
            }
            WM_TRAY_BALLOON => {
                if let Ok(mut guard) = ctx.shared.pending_balloon.lock()
                    && let Some((title, body, is_error)) = guard.take()
                {
                    let _ = show_tray_balloon(hwnd, &title, &body, is_error);
                }
                LRESULT(0)
            }
            WM_TRAY_CALLBACK => {
                let event_code = (lparam.0 as u32) & 0xFFFF;
                if event_code == WM_LBUTTONUP || event_code == NIN_SELECT {
                    ctx.shared.channel.send(TrayEvent::ToggleHud);
                } else if event_code == WM_RBUTTONUP || event_code == WM_CONTEXTMENU {
                    show_context_menu(hwnd, ctx);
                }
                LRESULT(0)
            }
            WM_COMMAND => {
                let cmd = (wparam.0 as u32) & 0xFFFF;
                dispatch_menu_cmd(cmd, &ctx.shared.channel);
                LRESULT(0)
            }
            WM_DESTROY => {
                let _ = remove_tray_icon(hwnd);
                unsafe { PostQuitMessage(0) };
                LRESULT(0)
            }
            _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
        }
    }

    fn dispatch_menu_cmd(cmd: u32, channel: &TrayChannel) {
        match cmd {
            CMD_OPEN_CONSOLE => channel.send(TrayEvent::OpenConsole),
            CMD_TOGGLE_HUD => channel.send(TrayEvent::ToggleHud),
            CMD_RECHECK => channel.send(TrayEvent::RecheckNow),
            CMD_TOGGLE_PAUSE => channel.send(TrayEvent::TogglePause),
            CMD_SWEEP_ORPHANS => channel.send(TrayEvent::SweepOrphans),
            CMD_SAFE_EXIT => channel.send(TrayEvent::SafeExit),
            CMD_QUIT_GUI => channel.send(TrayEvent::QuitGuiOnly),
            _ => {}
        }
    }

    fn show_context_menu(hwnd: HWND, ctx: &WindowContext) {
        let Ok(menu) = (unsafe { CreatePopupMenu() }) else {
            return;
        };
        let paused = ctx.shared.paused.load(Ordering::Relaxed);
        let pause_text = if paused {
            w!("恢复守护检测")
        } else {
            w!("暂停保护 30 分钟")
        };

        unsafe {
            let _ = AppendMenuW(
                menu,
                MF_STRING,
                CMD_OPEN_CONSOLE as usize,
                w!("打开主控制台"),
            );
            let _ = AppendMenuW(
                menu,
                MF_STRING,
                CMD_TOGGLE_HUD as usize,
                w!("显示 / 隐藏快捷 HUD"),
            );
            let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
            let _ = AppendMenuW(menu, MF_STRING, CMD_RECHECK as usize, w!("立即重检出口"));
            let _ = AppendMenuW(menu, MF_STRING, CMD_TOGGLE_PAUSE as usize, pause_text);
            let _ = AppendMenuW(
                menu,
                MF_STRING,
                CMD_SWEEP_ORPHANS as usize,
                w!("一键清孤儿进程"),
            );
            let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
            let _ = AppendMenuW(menu, MF_STRING, CMD_QUIT_GUI as usize, w!("仅退出托盘界面"));
            let _ = AppendMenuW(
                menu,
                MF_STRING,
                CMD_SAFE_EXIT as usize,
                w!("安全撤防并退出"),
            );

            let mut pt = POINT::default();
            let _ = GetCursorPos(&mut pt);
            let _ = SetForegroundWindow(hwnd);
            let selected = TrackPopupMenuEx(
                menu,
                (TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RETURNCMD | TPM_RIGHTBUTTON).0,
                pt.x,
                pt.y,
                hwnd,
                None,
            );
            let _ = DestroyMenu(menu);
            if selected.0 > 0 {
                dispatch_menu_cmd(selected.0 as u32, &ctx.shared.channel);
            }
        }
    }

    fn add_or_update_tray_icon(hwnd: HWND, ctx: &WindowContext, add: bool) -> bool {
        let mut nid = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: TRAY_ICON_ID,
            uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
            uCallbackMessage: WM_TRAY_CALLBACK,
            hIcon: ctx.current_icon(),
            ..Default::default()
        };

        let tip_text = ctx
            .shared
            .tooltip
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|_| "ClaudeGuard v4".to_string());
        let utf16: Vec<u16> = tip_text.encode_utf16().take(127).collect();
        for (idx, code) in utf16.into_iter().enumerate() {
            nid.szTip[idx] = code;
        }

        let cmd = if add { NIM_ADD } else { NIM_MODIFY };
        unsafe { Shell_NotifyIconW(cmd, &nid) }.as_bool()
    }

    fn show_tray_balloon(hwnd: HWND, title: &str, body: &str, is_error: bool) -> bool {
        let mut nid = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: TRAY_ICON_ID,
            uFlags: NIF_INFO,
            dwInfoFlags: if is_error { NIIF_ERROR } else { NIIF_INFO },
            ..Default::default()
        };
        for (idx, code) in title.encode_utf16().take(63).enumerate() {
            nid.szInfoTitle[idx] = code;
        }
        for (idx, code) in body.encode_utf16().take(255).enumerate() {
            nid.szInfo[idx] = code;
        }
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) }.as_bool()
    }

    fn remove_tray_icon(hwnd: HWND) -> bool {
        let nid = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: TRAY_ICON_ID,
            ..Default::default()
        };
        unsafe { Shell_NotifyIconW(NIM_DELETE, &nid) }.as_bool()
    }

    /// Generates a crisp 32x32 ARGB shield/ring tray icon with zero external `.ico` files.
    fn create_badge_icon(r: u8, g: u8, b: u8) -> HICON {
        const SIZE: i32 = 32;
        let mut pixels = vec![0u32; (SIZE * SIZE) as usize];
        let cx = 15.5_f32;
        let cy = 15.5_f32;

        for y in 0..SIZE {
            for x in 0..SIZE {
                let dx = x as f32 - cx;
                let dy = y as f32 - cy;
                let dist = (dx * dx + dy * dy).sqrt();
                let (ar, ag, ab, alpha) = if (9.0..=13.0).contains(&dist) {
                    (r, g, b, 255u8)
                } else if dist < 9.0 {
                    // Inner dark emerald/slate core with glowing center dot
                    if dist <= 4.2 {
                        (r, g, b, 255u8)
                    } else {
                        (18u8, 24u8, 36u8, 240u8)
                    }
                } else if dist <= 14.2 {
                    (r, g, b, 120u8)
                } else {
                    (0u8, 0u8, 0u8, 0u8)
                };
                // Win32 BGRA in little-endian u32: 0xAARRGGBB
                let argb = (u32::from(alpha) << 24)
                    | (u32::from(ar) << 16)
                    | (u32::from(ag) << 8)
                    | u32::from(ab);
                pixels[(y * SIZE + x) as usize] = argb;
            }
        }

        let mask_bits = vec![0u8; (SIZE * SIZE / 8) as usize];
        unsafe {
            let hbm_color = CreateBitmap(SIZE, SIZE, 1, 32, Some(pixels.as_ptr() as *const _));
            let hbm_mask = CreateBitmap(SIZE, SIZE, 1, 1, Some(mask_bits.as_ptr() as *const _));
            let info = ICONINFO {
                fIcon: true.into(),
                xHotspot: 0,
                yHotspot: 0,
                hbmMask: hbm_mask,
                hbmColor: hbm_color,
            };
            let hicon = CreateIconIndirect(&info).unwrap_or_default();
            let _ = DeleteObject(hbm_color);
            let _ = DeleteObject(hbm_mask);
            hicon
        }
    }

    /// Queries the primary monitor work area in logical pixels using DPI scaling.
    pub fn primary_work_area_logical(scale_factor: f32) -> LogicalRect {
        let mut rect = RECT::default();
        let ok = unsafe {
            SystemParametersInfoW(
                SPI_GETWORKAREA,
                0,
                Some(&mut rect as *mut RECT as *mut _),
                Default::default(),
            )
        }
        .is_ok();
        let scale = if scale_factor > 0.1 {
            scale_factor
        } else {
            let sys_dpi = unsafe { windows::Win32::UI::HiDpi::GetDpiForSystem() };
            if sys_dpi >= 96 {
                (sys_dpi as f32 / 96.0).max(1.0)
            } else {
                1.0
            }
        };
        if ok {
            LogicalRect {
                x: rect.left as f32 / scale,
                y: rect.top as f32 / scale,
                width: (rect.right - rect.left) as f32 / scale,
                height: (rect.bottom - rect.top) as f32 / scale,
            }
        } else {
            LogicalRect {
                x: 0.0,
                y: 0.0,
                width: 1920.0 / scale,
                height: 1040.0 / scale,
            }
        }
    }

    /// Applies Windows 11 native DWM rounded corners (`DWMWCP_ROUND`) and subtle border color
    /// to a GPUI window owned by the current process. Safely no-ops on Windows 10.
    pub fn apply_win11_round_corners(window_title: &str, border_rgb: u32) {
        use windows::Win32::Graphics::Dwm::{
            DWMWA_BORDER_COLOR, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND, DwmSetWindowAttribute,
        };
        use windows::Win32::UI::WindowsAndMessaging::{FindWindowExW, GetWindowThreadProcessId};

        let mut utf16: Vec<u16> = window_title.encode_utf16().collect();
        utf16.push(0);
        let self_pid = std::process::id();
        let mut prev = HWND::default();

        loop {
            let Ok(hwnd) = (unsafe {
                FindWindowExW(
                    HWND::default(),
                    prev,
                    PCWSTR::null(),
                    PCWSTR(utf16.as_ptr()),
                )
            }) else {
                break;
            };
            if hwnd.0.is_null() {
                break;
            }
            let mut pid = 0u32;
            unsafe {
                GetWindowThreadProcessId(hwnd, Some(&mut pid));
            }
            if pid == self_pid {
                let corner_pref = DWMWCP_ROUND;
                let r = (border_rgb >> 16) & 0xFF;
                let g = (border_rgb >> 8) & 0xFF;
                let b = border_rgb & 0xFF;
                let colorref: u32 = r | (g << 8) | (b << 16);
                unsafe {
                    let _ = DwmSetWindowAttribute(
                        hwnd,
                        DWMWA_WINDOW_CORNER_PREFERENCE,
                        &corner_pref as *const _ as *const _,
                        std::mem::size_of_val(&corner_pref) as u32,
                    );
                    let _ = DwmSetWindowAttribute(
                        hwnd,
                        DWMWA_BORDER_COLOR,
                        &colorref as *const _ as *const _,
                        std::mem::size_of_val(&colorref) as u32,
                    );
                }
                break;
            }
            prev = hwnd;
        }
    }
    /// Signals an already-running ClaudeGuard v4 tray window if present.
    /// - In normal mode (`!is_demo`), wakes the existing instance (`ToggleHud` or `OpenConsole`)
    ///   and returns `true` so the caller can exit cleanly without spawning duplicate tray icons.
    /// - In `--demo` mode, asks any lingering tray instance to quit (`CMD_QUIT_GUI`) so demo runs
    ///   never accumulate stale background processes, then returns `false` to continue startup.
    pub fn signal_existing_tray_instance(
        is_demo: bool,
        start_hud: bool,
        start_in_tray: bool,
    ) -> bool {
        use windows::Win32::UI::WindowsAndMessaging::FindWindowW;

        let Ok(hwnd) =
            (unsafe { FindWindowW(w!("ClaudeGuardV4TrayWindow"), w!("ClaudeGuardV4Tray")) })
        else {
            return false;
        };
        if hwnd.0.is_null() {
            return false;
        }

        if is_demo {
            let _ =
                unsafe { PostMessageW(hwnd, WM_COMMAND, WPARAM(CMD_QUIT_GUI as usize), LPARAM(0)) };
            std::thread::sleep(std::time::Duration::from_millis(80));
            return false;
        }

        if start_hud {
            let _ = unsafe {
                PostMessageW(hwnd, WM_COMMAND, WPARAM(CMD_TOGGLE_HUD as usize), LPARAM(0))
            };
        } else if !start_in_tray {
            let _ = unsafe {
                PostMessageW(
                    hwnd,
                    WM_COMMAND,
                    WPARAM(CMD_OPEN_CONSOLE as usize),
                    LPARAM(0),
                )
            };
        }
        true
    }
}

#[cfg(not(windows))]
mod win_impl {
    use super::*;

    pub struct TrayHandle;

    impl TrayHandle {
        pub fn start(_channel: TrayChannel) -> Result<Self, String> {
            Ok(Self)
        }

        pub fn set_status(&self, _tone: TrayTone, _paused: bool, _tooltip: &str) {}

        pub fn show_balloon(&self, _title: &str, _body: &str, _is_error: bool) {}

        pub fn shutdown(&mut self) {}
    }

    pub fn primary_work_area_logical(_scale_factor: f32) -> LogicalRect {
        LogicalRect {
            x: 0.0,
            y: 0.0,
            width: 1920.0,
            height: 1040.0,
        }
    }

    pub fn apply_win11_round_corners(_window_title: &str, _border_rgb: u32) {}

    pub fn signal_existing_tray_instance(
        _is_demo: bool,
        _start_hud: bool,
        _start_in_tray: bool,
    ) -> bool {
        false
    }
}

pub use win_impl::{
    TrayHandle, apply_win11_round_corners, primary_work_area_logical, signal_existing_tray_instance,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hud_bounds_anchor_bottom_right_above_taskbar() {
        let work_area = LogicalRect {
            x: 0.0,
            y: 0.0,
            width: 1920.0,
            height: 1032.0,
        };
        let hud = compute_hud_bounds(work_area);
        assert_eq!(hud.width, layout::HUD_WIDTH);
        assert_eq!(hud.height, layout::HUD_HEIGHT);
        assert_eq!(hud.x, 1920.0 - layout::HUD_WIDTH - 10.0);
        assert_eq!(hud.y, 1032.0 - layout::HUD_HEIGHT - 10.0);
    }

    #[test]
    fn hud_bounds_fit_1080p_at_200_percent_dpi() {
        // 1920x1080 physical @ 200% DPI with 48px physical taskbar => 960x516 logical work area.
        let work_area = LogicalRect {
            x: 0.0,
            y: 0.0,
            width: 960.0,
            height: 516.0,
        };
        let hud = compute_hud_bounds(work_area);
        let expected_h = layout::HUD_HEIGHT.min(516.0 - 20.0);
        assert_eq!(hud.width, layout::HUD_WIDTH);
        assert_eq!(hud.height, expected_h);
        assert_eq!(hud.x, 960.0 - layout::HUD_WIDTH - 10.0);
        assert_eq!(hud.y, 516.0 - expected_h - 10.0);
        assert!(hud.x + hud.width <= work_area.width);
        assert!(hud.y + hud.height <= work_area.height);
    }

    #[test]
    fn tray_channel_delivers_events_in_fifo_order() {
        let ch = TrayChannel::new();
        ch.send(TrayEvent::ToggleHud);
        ch.send(TrayEvent::OpenConsole);
        let guard = ch.inner.lock().unwrap();
        assert_eq!(guard.queue.len(), 2);
        assert_eq!(guard.queue[0], TrayEvent::ToggleHud);
        assert_eq!(guard.queue[1], TrayEvent::OpenConsole);
    }
}
