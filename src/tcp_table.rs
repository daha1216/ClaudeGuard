//! Win32 GetExtendedTcpTable: 枚举 ESTABLISHED TCP 连接（IPv4）。
//! 用手动字节解析，避免结构体布局问题。

pub struct TcpConn {
    pub local_port: u16,
    pub remote_addr: String,
    pub state: u32,
    pub pid: u32,
}

/// MIB_TCP_STATE_ESTAB
const TCP_STATE_ESTAB: u32 = 5;

/// 返回所有 IPv4 ESTABLISHED 连接
pub fn established_connections() -> Vec<TcpConn> {
    table_rows()
        .into_iter()
        .filter(|r| r.state == TCP_STATE_ESTAB)
        .collect()
}

/// 监听端口的进程 PID（任意 state=LISTEN 的行；LISTEN=2）
pub fn listener_pid(port: u16) -> u32 {
    for r in table_rows() {
        // LISTEN 行 remote 全 0；本地端口在网络序低 16 位
        if r.state == 2 && r.local_port == port {
            return r.pid;
        }
    }
    0
}

fn table_rows() -> Vec<TcpConn> {
    #[cfg(windows)]
    unsafe {
        use windows::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL,
        };

        let af_inet: u32 = 2; // AF_INET
        let mut size: u32 = 0;
        let _ = GetExtendedTcpTable(None, &mut size, false, af_inet, TCP_TABLE_OWNER_PID_ALL, 0);
        if size == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            &mut size,
            false,
            af_inet,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if ret != 0 {
            return Vec::new();
        }
        let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let row_size = 24usize; // 6 × u32
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let off = 4 + i * row_size;
            if off + row_size > buf.len() {
                break;
            }
            let u32_at = |k: usize| -> u32 {
                u32::from_le_bytes([
                    buf[off + k],
                    buf[off + k + 1],
                    buf[off + k + 2],
                    buf[off + k + 3],
                ])
            };
            let state = u32_at(0);
            // 本地端口在偏移 8（网络序低 16 位）；对端地址在偏移 12；PID 在偏移 20
            let lp = u32_at(8) & 0xffff;
            let remote_addr = format!(
                "{}.{}.{}.{}",
                buf[off + 12],
                buf[off + 13],
                buf[off + 14],
                buf[off + 15]
            );
            let pid = u32_at(20);
            let local_port = (((lp & 0xff) << 8) | ((lp >> 8) & 0xff)) as u16;
            out.push(TcpConn {
                local_port,
                remote_addr,
                state,
                pid,
            });
        }
        out
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}
