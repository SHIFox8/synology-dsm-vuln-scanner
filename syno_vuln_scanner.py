#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Synology DSM Vulnerability Scanner (detection-only)
====================================================

SVRForum 게시글(https://svrforum.com/nas/3232929)에서 다룬 두 취약점을
안전하게 탐지하기 위한 보안 연구자용 스캐너입니다.

  1) Synology-SA-24:20  (CVE-2024-10441, CVSS 9.8, CISA KEV 등재)
     - system plugin daemon 비인증 RCE — 실제 랜섬웨어 공격에 악용됨
  2) Synology-SA-26:13  (CVE-2026-13684 / CVE-2026-13639, CVSS 9.8)
     - SCGI 컴포넌트 / 로그인 로직 비인증 RCE (2026-09-18 공개)

탐지 방식 (익스플로잇 없음 · 파괴적 행위 없음):
  - 인증 없이: /webman/global.js, 로그인 페이지, SYNO.API.Info 쿼리로
    DSM 빌드/브랜치 지문 수집 → 공식 어드바이저리 고정 버전과 비교
  - 자격증명 제공 시(선택): SYNO.API.Auth 로그인 후
    SYNO.Core.System.Info 로 정확한 빌드+Update 레벨 확인, 설치 패키지 열람
  - 빌드 번호만으로는 Update 레벨을 알 수 없으므로(같은 브랜치에서
    빌드가 유지됨), Update 미확인 대상은 "검증 필요"로 보수적으로 표기

윤리/법적 고지:
  본 도구는 소유하거나 명시적 사전 동의를 받은 시스템에만 사용하십시오.
  실행 시 --authorize 플래그가 요구됩니다.

Python 3.9+ / 표준 라이브러리만 사용 (외부 의존성 없음).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# 콘솔 색상 (Windows ANSI 활성화 포함)
# ---------------------------------------------------------------------------

def _enable_ansi() -> None:
    if os.name == "nt":
        os.system("")
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


_enable_ansi()


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"

    @classmethod
    def disable(cls) -> None:
        for name in dir(cls):
            if name.isupper():
                setattr(cls, name, "")


# ---------------------------------------------------------------------------
# 어드바이저리 데이터 (공식 Synology 어드바이저리 기준 고정 버전)
# ---------------------------------------------------------------------------

ADVISORIES: list[dict] = [
    {
        "id": "Synology-SA-24:20",
        "cves": ["CVE-2024-10441", "CVE-2024-50629", "CVE-2024-10445"],
        "severity": "Critical (9.8)",
        "summary": (
            "system plugin daemon 비인증 RCE (CVE-2024-10441). "
            "PWN2OWN 2024에서 발표되었으며 CISA KEV 등재, 실제 랜섬웨어 캠페인에 악용 중. "
            "CVE-2024-50629(webapi 파일 읽기, 5.3), CVE-2024-10445(update 기능 MITM 파일 쓰기, 4.3) 동반."
        ),
        "reference": "https://www.synology.com/en-global/security/advisory/Synology_SA_24_20",
        # branch -> (base_build, min_update)  ※ 이상이면 안전
        "fixed": {
            "7.2.2": (72806, 1),
            "7.2.1": (69057, 6),
            "7.2": (64570, 4),
            "7.1.1": (42962, 7),
            "6.2.4": (25556, 8),
        },
        "note": "7.3/7.4 브랜치는 본 어드바이저리 영향 범위 밖(해당 없음).",
    },
    {
        "id": "Synology-SA-26:13",
        "cves": [
            "CVE-2026-13684", "CVE-2026-13639", "CVE-2026-13673",
            "CVE-2026-6205", "CVE-2026-13635", "CVE-2026-13623",
            "CVE-2026-13666", "CVE-2026-13683",
        ],
        "severity": "Critical (9.8) x2",
        "summary": (
            "SCGI 컴포넌트 출력 인코딩 결함(CVE-2026-13684) 및 로그인 로직 엔트로피 부족"
            "(CVE-2026-13639) — 모두 비인증 원격 코드 실행/원격 접근 가능(CVSS 9.8). "
            "LDAP/Upload/Auth/Theme/Sharing/EventScheduler API 결함 동반. 2026-09-18 공개."
        ),
        "reference": "https://www.synology.com/en-global/security/advisory/Synology_SA_26_13",
        "fixed": {
            "7.4": (90075, 0),
            "7.3.2": (86009, 4),
            "7.2.2": (72806, 9),
            "7.2.1": (69057, 12),
        },
        "note": "7.2.0 및 이전 브랜치(7.3.0/7.3.1 포함)에는 패치 미제공 — 지원 종료(EOL). "
                "인터넷 노출을 제거하고 내부망으로 격리해야 함.",
    },
]

# 빌드 번호 -> DSM 브랜치 (알려진 빌드 기준)
BUILD_TO_BRANCH = {
    90075: "7.4",
    86009: "7.3.2",
    72806: "7.2.2",
    69057: "7.2.1",
    64570: "7.2",
    42962: "7.1.1",
    25556: "6.2.4",
}

# 상태 코드 정의
ST_PATCHED = "PATCHED"
ST_VULN = "VULNERABLE"
ST_VERIFY = "VERIFY_NEEDED"       # 브랜치는 영향권, Update 레벨 미확인
ST_EOL = "EOL_NO_PATCH"           # 이 브랜치는 패치가 존재하지 않음
ST_NOT_AFFECTED = "NOT_AFFECTED"  # 어드바이저리 영향 범위 밖
ST_UNKNOWN = "UNKNOWN_VERSION"    # 버전 자체를 못 알아냄
ST_ERROR = "UNREACHABLE"          # 접속 실패 / DSM 아님

STATUS_LABEL = {
    ST_PATCHED: "패치됨 (안전)",
    ST_VULN: "취약 — 즉시 패치 필요",
    ST_VERIFY: "검증 필요 (Update 미확인)",
    ST_EOL: "패치 미제공 (EOL) — 격리 필요",
    ST_NOT_AFFECTED: "영향 범위 밖",
    ST_UNKNOWN: "버전 미확인",
    ST_ERROR: "접속 불가 / DSM 아님",
}

STATUS_COLOR = {
    ST_PATCHED: C.GREEN,
    ST_VULN: C.RED + C.BOLD,
    ST_VERIFY: C.YELLOW,
    ST_EOL: C.RED,
    ST_NOT_AFFECTED: C.CYAN,
    ST_UNKNOWN: C.MAGENTA,
    ST_ERROR: C.DIM,
}


# ---------------------------------------------------------------------------
# HTTP 헬퍼
# ---------------------------------------------------------------------------

def make_opener(verify_tls: bool, timeout: float) -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPRedirectHandler(),
    )


class Http:
    """지문 수집에 쓰는 최소한의 GET/POST 클라이언트 (읽기 전용 요청만)."""

    def __init__(self, opener, timeout: float, delay: float = 0.0):
        self.opener = opener
        self.timeout = timeout
        self.delay = delay

    def _req(self, url: str, data: bytes | None, headers: dict) -> tuple[int, str, dict]:
        if self.delay:
            time.sleep(self.delay)
        req = urllib.request.Request(url, data=data, headers=headers, method="GET" if data is None else "POST")
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                body = resp.read(512 * 1024).decode("utf-8", "replace")
                return resp.status, body, dict(resp.headers)
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read(256 * 1024).decode("utf-8", "replace")
            except Exception:
                pass
            return e.code, body, dict(e.headers or {})
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError):
            return 0, "", {}

    def get(self, url: str) -> tuple[int, str, dict]:
        headers = {
            "User-Agent": "SynoVulnScanner/1.0 (detection-only; authorized research)",
            "Accept": "*/*",
            "Accept-Language": "ko,en;q=0.5",
        }
        return self._req(url, None, headers)

    def post_form(self, url: str, params: dict) -> tuple[int, str, dict]:
        data = urllib.parse.urlencode(params).encode()
        headers = {
            "User-Agent": "SynoVulnScanner/1.0 (detection-only; authorized research)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        return self._req(url, data, headers)


# ---------------------------------------------------------------------------
# 지문 수집 (비인증)
# ---------------------------------------------------------------------------

RE_VERSION_VAR = re.compile(r'SYNO\.SDS\.(?:Product)?Version\s*=\s*["\']?(\d+\.\d+(?:\.\d+)?)')
RE_BUILD_VAR = re.compile(r'SYNO\.SDS\.Build(?:Number)?\s*=\s*["\']?(\d{5,6})')
RE_ANY_BUILD = re.compile(r"[?&;]v=(\d{5,6})(?:[^\d]|$)")
RE_DSM_TITLE = re.compile(r"Synology|DiskStation|SYNO\.SDS", re.I)

INTERESTING_API_PREFIXES = (
    "SYNO.Photo", "SYNO.PhotoStation", "SYNO.SurveillanceStation",
    "SYNO.AudioStation", "SYNO.VideoStation", "SYNO.Office",
    "SYNO.SDS.Application", "SYNO.Virtualization.API",
    "SYNO.ActiveBackup", "SYNO.Backup",
)


def looks_like_dsm(status: int, body: str, headers: dict) -> bool:
    if not body:
        return False
    if "SYNO.SDS" in body or "DiskStation" in body or "Synology" in body:
        return True
    if status == 200 and body.strip().lower() in ("pong", '"pong"'):
        return True
    return False


def fingerprint(base: str, http: Http) -> dict:
    """base: 'https://host:5001' — 비인증으로 DSM 지문 수집."""
    fp: dict = {
        "is_dsm": False,
        "version": None,      # "7.2.2" 형태
        "build": None,        # 72806
        "update": None,       # 인증 없이는 대부분 모름
        "exposed_login": False,
        "apis": [],           # 설치된 패키지/API 공격면
        "auth_path": "auth.cgi",
        "entry_path": "entry.cgi",
    }

    # 1) 루트 → /webman/ 리다이렉트 확인 + ping.cgi 응답
    st, body, _ = http.get(base + "/webman/ping.cgi")
    hint = looks_like_dsm(st, body, {})
    if st == 0:
        return fp

    # 2) global.js: 버전/빌드 변수
    st_g, body_g, _ = http.get(base + "/webman/global.js")
    if body_g:
        hint = hint or RE_DSM_TITLE.search(body_g) is not None
        m = RE_VERSION_VAR.search(body_g)
        if m:
            fp["version"] = m.group(1)
        m = RE_BUILD_VAR.search(body_g)
        if m:
            fp["build"] = int(m.group(1))
    if fp["version"] or fp["build"]:
        fp["is_dsm"] = True

    # 3) 로그인 페이지 (노출 확인 + 자산 버전 폴백)
    st_l, body_l, _ = http.get(base + "/webman/index.cgi")
    if body_l and RE_DSM_TITLE.search(body_l):
        fp["is_dsm"] = True
        fp["exposed_login"] = st_l == 200
        if fp["build"] is None:
            m = RE_ANY_BUILD.search(body_l)
            if m:
                fp["build"] = int(m.group(1))
        if fp["version"] is None:
            m = RE_VERSION_VAR.search(body_l)
            if m:
                fp["version"] = m.group(1)

    fp["is_dsm"] = fp["is_dsm"] or hint

    # 4) SYNO.API.Info 쿼리: 설치된 API(공격면) 열람 — 인증 불필요
    q = ("api=SYNO.API.Info&method=query&version=1&query="
         "SYNO.API.Auth,SYNO.Photo,SYNO.PhotoStation,SYNO.SurveillanceStation,"
         "SYNO.AudioStation,SYNO.VideoStation,SYNO.Office,SYNO.Virtualization.API,"
         "SYNO.ActiveBackup,SYNO.Backup,SYNO.Core.Package.Server")
    st_q, body_q, _ = http.get(base + "/webapi/query.cgi?" + q)
    if body_q:
        try:
            data = json.loads(body_q)
            if isinstance(data, dict) and data.get("success"):
                apis = data.get("data") or {}
                for name, info in apis.items():
                    if not isinstance(info, dict):
                        continue
                    if any(name.startswith(p) for p in INTERESTING_API_PREFIXES):
                        entry = name
                        if info.get("path"):
                            entry = f"{name} ({info['path']})"
                        fp["apis"].append(entry)
                    if name == "SYNO.API.Auth" and info.get("path"):
                        fp["auth_path"] = info["path"]
                    if name.startswith("SYNO.Core") and info.get("path"):
                        fp["entry_path"] = info["path"]
        except (json.JSONDecodeError, ValueError):
            pass

    return fp


# ---------------------------------------------------------------------------
# 버전 비교 로직
# ---------------------------------------------------------------------------

def parse_update_from_version_string(vs: str) -> int | None:
    m = re.search(r"[Uu]pdate\s+(\d+)", vs)
    if m:
        return int(m.group(1))
    m = re.search(r"-(\d{5,6})-(\d+)$", vs)
    if m:
        return int(m.group(2))
    return None


def assess(advisory: dict, version: str | None, build: int | None,
           update: int | None) -> tuple[str, str]:
    """(상태, 근거 설명) 반환."""
    fixed = advisory["fixed"]
    branch = version if version in fixed else BUILD_TO_BRANCH.get(build or -1)

    if version is None and build is None:
        return ST_UNKNOWN, "DSM 버전/빌드를 확인하지 못했습니다."

    # 버전 문자열이 테이블에 없으면 알려진 빌드 맵으로 브랜치 추정
    if branch is None and version:
        branch = version

    if branch is None:
        return ST_UNKNOWN, f"빌드 {build} 를 알려진 DSM 브랜치로 매핑하지 못했습니다."

    if branch not in fixed:
        # 이 어드바이저리에서 이 브랜치는 고정 버전이 존재하지 않는가?
        if advisory["id"] == "Synology-SA-26:13":
            # 7.3.0/7.3.1 은 7.3.2-86009-4 로의 업그레이드 경로가 존재한다.
            if branch.startswith("7.3"):
                return ST_VULN, (
                    f"브랜치 {branch} 는 SA-26:13 영향권이며 7.3.2-86009-4 이상으로 업그레이드해야 합니다."
                )
            return ST_EOL, (
                f"브랜치 {branch} 는 SA-26:13 패치 대상(7.4/7.3.2/7.2.2/7.2.1)이 아니어서 "
                "업데이트가 제공되지 않습니다. 인터넷 노출 제거가 유일한 완화책입니다."
            )
        return ST_NOT_AFFECTED, f"브랜치 {branch} 는 본 어드바이저리 영향 범위에 없습니다."

    base_build, min_update = fixed[branch]

    if update is not None:
        if build is not None and build > base_build:
            return ST_PATCHED, f"빌드 {build} > 고정 기준 빌드 {base_build}"
        if build == base_build and update >= min_update:
            return ST_PATCHED, f"{branch} Update {update} ≥ 고정 기준 Update {min_update}"
        return ST_VULN, f"{branch} Update {update} < 고정 기준 {base_build}-Update{min_update}"

    # Update 레벨 미확인
    if build is not None and build > base_build:
        return ST_PATCHED, f"빌드 {build} > 고정 기준 빌드 {base_build} (Update 불필요)"
    if build is not None and build < base_build:
        return ST_VULN, f"빌드 {build} < 고정 기준 빌드 {base_build}"
    return ST_VERIFY, (
        f"브랜치 {branch}(빌드 {build})는 영향권입니다. 안전하려면 "
        f"{base_build} Update {min_update} 이상이어야 하며 Update 레벨을 인증 검증으로 확인하십시오."
    )


# ---------------------------------------------------------------------------
# 인증 기반 심층 검증 (선택, 읽기 전용 API만)
# ---------------------------------------------------------------------------

AUTH_SESSION_NAME = "SynoVulnScanner"


def deep_check(base: str, http: Http, fp: dict, account: str, passwd: str) -> dict:
    """로그인 → 정확한 버전/Update + 설치 패키지 확인 → 로그아웃. 읽기 전용."""
    result = {"authenticated": False, "exact_version": None, "packages": []}
    auth_url = base.rstrip("/") + "/webapi/" + fp["auth_path"].lstrip("/")
    entry_url = base.rstrip("/") + "/webapi/" + fp["entry_path"].lstrip("/")

    st, body, _ = http.post_form(auth_url, {
        "api": "SYNO.API.Auth", "method": "login", "version": "6",
        "account": account, "passwd": passwd,
        "session": AUTH_SESSION_NAME, "format": "sid",
    })
    sid = None
    try:
        data = json.loads(body)
        if data.get("success"):
            sid = (data.get("data") or {}).get("sid")
    except (json.JSONDecodeError, ValueError):
        pass
    if not sid:
        result["auth_error"] = "로그인 실패 (자격증명 확인 또는 2단계 인증 여부 확인)"
        return result

    result["authenticated"] = True
    try:
        # 정확한 시스템 버전: SYNO.Core.System.Info getinfo
        params = {
            "api": "SYNO.Core.System.Info", "method": "getinfo",
            "version": "1", "session": AUTH_SESSION_NAME, "_sid": sid,
        }
        st, body, _ = http.get(entry_url + "?" + urllib.parse.urlencode(params))
        if body:
            try:
                data = json.loads(body).get("data") or {}
                ver = data.get("version") or data.get("fullversion") or ""
                if ver:
                    result["exact_version"] = str(ver)
            except (json.JSONDecodeError, ValueError):
                pass

        # 설치 패키지 (Synology Photos 등 공격면 확인) — 알려진 API 후보 순회
        for api, method, ver in (
            ("SYNO.Core.Package.Server", "list", "1"),
            ("SYNO.Core.Package", "list", "1"),
            ("SYNO.Core.Package.Installed", "list", "1"),
        ):
            params = {
                "api": api, "method": method, "version": ver,
                "additional": '["version"]',
                "session": AUTH_SESSION_NAME, "_sid": sid,
            }
            st, body, _ = http.get(entry_url + "?" + urllib.parse.urlencode(params))
            try:
                data = json.loads(body)
                if data.get("success") and isinstance(data.get("data"), (list, dict)):
                    items = data["data"]
                    if isinstance(items, dict):
                        items = items.get("packages") or items.get("list") or []
                    pkgs = []
                    for it in items:
                        if isinstance(it, dict) and it.get("id") or it.get("package"):
                            pkgs.append({
                                "id": it.get("id") or it.get("package") or "",
                                "name": it.get("name", ""),
                                "version": it.get("version", ""),
                            })
                    if pkgs:
                        result["packages"] = pkgs
                        break
            except (json.JSONDecodeError, ValueError):
                continue
    finally:
        # 항상 로그아웃
        try:
            http.post_form(auth_url, {
                "api": "SYNO.API.Auth", "method": "logout", "version": "6",
                "session": AUTH_SESSION_NAME, "_sid": sid,
            })
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# 타깃 확장
# ---------------------------------------------------------------------------

def parse_target(s: str) -> tuple[str, int | None, str | None]:
    """단일 타깃 → (host, port|None, scheme|None)."""
    s = s.strip().rstrip("/")
    if "://" in s:
        p = urllib.parse.urlparse(s)
        return p.hostname or "", p.port, p.scheme
    if "/" in s:
        s = s.split("/")[0]
    if ":" in s:
        host, _, port = s.rpartition(":")
        try:
            return host, int(port), None
        except ValueError:
            return s, None, None
    return s, None, None


def expand_targets(raw: str) -> list[str]:
    """host | URL | CIDR | 파일목록 → 타깃 문자열 리스트."""
    out: list[str] = []
    raw = raw.strip()
    if os.path.isfile(raw):
        with open(raw, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    out.extend(expand_targets(line))
        return out
    try:
        net = ipaddress.ip_network(raw, strict=False)
        if net.num_addresses == 1:
            out.append(str(net.network_address))
        elif net.num_addresses <= 65536:
            out.extend(str(h) for h in net.hosts())
        else:
            fail(f"네트워크가 너무 큽니다 (>65536 주소): {raw}")
        return out
    except ValueError:
        out.append(raw)
        return out


# ---------------------------------------------------------------------------
# 스캔 단위 실행
# ---------------------------------------------------------------------------

def probe_base(host: str, port: int | None, scheme: str | None,
               http: Http) -> str | None:
    """DSM이 응답하는 base URL을 찾음. 기본 5000/5001(그리고 80/443) 순차 시도."""
    candidates: list[str] = []
    if scheme and port:
        candidates.append(f"{scheme}://{host}:{port}")
    elif scheme:
        candidates.append(f"{scheme}://{host}" + (f":{port}" if port else ""))
    elif port:
        candidates.append(f"{'https' if port in (443, 5001) else 'http'}://{host}:{port}")
    else:
        candidates += [
            f"https://{host}:5001", f"http://{host}:5000",
            f"https://{host}", f"http://{host}",
        ]
    for base in candidates:
        st, body, _ = http.get(base + "/webman/ping.cgi")
        if st == 0:
            continue
        if looks_like_dsm(st, body, {}) or "webman" in body.lower():
            return base
        # ping이 막혀도 로그인 페이지가 응답하면 DSM으로 간주
        st2, body2, _ = http.get(base + "/webman/index.cgi")
        if st2 and RE_DSM_TITLE.search(body2 or ""):
            return base
    return None


def scan_target(target: str, args, opener) -> dict:
    host, port, scheme = parse_target(target)
    http = Http(opener, args.timeout, args.delay)
    rec: dict = {
        "target": target, "host": host, "base": None,
        "is_dsm": False, "version": None, "build": None, "update": None,
        "exposed_login": None, "packages": [],
        "findings": [], "error": None,
    }

    base = probe_base(host, port, scheme, http)
    if not base:
        rec["error"] = "DSM 응답 없음 (5000/5001/80/443 시도)"
        return rec
    rec["base"] = base

    fp = fingerprint(base, http)
    if not fp["is_dsm"]:
        rec["error"] = "DSM 지문 아님 (다른 웹서비스로 추정)"
        return rec

    rec["is_dsm"] = True
    rec["version"] = fp["version"]
    rec["build"] = fp["build"]
    rec["exposed_login"] = fp["exposed_login"]

    # 인증 심층 검증 (정확한 Update 레벨 + 패키지)
    exact_version = None
    if args.login and args.password:
        dc = deep_check(base, http, fp, args.login, args.password)
        if dc.get("authenticated"):
            exact_version = dc.get("exact_version")
            rec["packages"] = dc.get("packages", [])
            rec["_exact"] = exact_version
            if exact_version:
                m = re.search(r"(\d+\.\d+(?:\.\d+)?)[^\d]*(\d{5,6})", exact_version)
                if m:
                    rec["version"] = m.group(1)
                    rec["build"] = int(m.group(2))
                rec["update"] = parse_update_from_version_string(exact_version)
        else:
            rec["auth_note"] = dc.get("auth_error", "인증 실패")

    # 어드바이저리별 판정
    for adv in ADVISORIES:
        status, reason = assess(adv, rec["version"], rec["build"], rec["update"])
        rec["findings"].append({
            "advisory": adv["id"],
            "cves": adv["cves"],
            "severity": adv["severity"],
            "status": status,
            "status_label": STATUS_LABEL[status],
            "reason": reason,
            "fixed_versions": {k: f"{k}-{v[0]}" + (f" Update {v[1]}" if v[1] else "")
                               for k, v in adv["fixed"].items()},
            "reference": adv["reference"],
        })
    return rec


# ---------------------------------------------------------------------------
# 출력
# ---------------------------------------------------------------------------

def print_record(rec: dict) -> None:
    print(f"\n{C.BOLD}▶ {rec['target']}{C.RESET}  {C.DIM}({rec.get('base') or '-'}){C.RESET}")
    if rec.get("error"):
        print(f"   {C.DIM}— {rec['error']}{C.RESET}")
        return
    ver = rec.get("version") or "?"
    build = rec.get("build") or "?"
    upd = f" Update {rec['update']}" if rec.get("update") is not None else ""
    print(f"   DSM {C.BOLD}{ver} (build {build}){upd}{C.RESET}"
          + (f"   {C.DIM}정확값: {rec.get('_exact')}{C.RESET}" if rec.get("_exact") else ""))
    if rec.get("exposed_login") is True:
        print(f"   {C.YELLOW}⚠ 로그인 페이지가 네트워크에 노출됨{C.RESET}")
    for note in (rec.get("auth_note"),):
        if note:
            print(f"   {C.DIM}· {note}{C.RESET}")
    if rec.get("packages"):
        names = ", ".join(p["id"] for p in rec["packages"][:12])
        print(f"   {C.DIM}설치 패키지: {names}{' …' if len(rec['packages']) > 12 else ''}{C.RESET}")
    for f in rec["findings"]:
        col = STATUS_COLOR.get(f["status"], "")
        print(f"   [{f['advisory']}] {col}{C.BOLD}{f['status_label']}{C.RESET}  "
              f"{C.DIM}{', '.join(f['cves'][:2])}{' …' if len(f['cves']) > 2 else ''}{C.RESET}")
        print(f"      └ {f['reason']}")


def print_summary(records: list[dict]) -> None:
    counts: dict[str, int] = {}
    for r in records:
        if r.get("error"):
            counts[ST_ERROR] = counts.get(ST_ERROR, 0) + 1
            continue
        for f in r["findings"]:
            counts[f["status"]] = counts.get(f["status"], 0) + 1
    print(f"\n{C.BOLD}════ 요약 ════{C.RESET}")
    for st, label in STATUS_LABEL.items():
        if counts.get(st):
            print(f"  {STATUS_COLOR.get(st, '')}{label}: {counts[st]}{C.RESET}")
    worst = max(counts.get(k, 0) for k in (ST_VULN, ST_EOL, ST_VERIFY))
    if worst:
        print(f"\n  {C.RED}조치: 영향 대상은 공식 어드바이저리의 고정 버전 이상으로 즉시 업데이트하세요.{C.RESET}")
        print(f"  {C.RED}패치 미제공(EOL) 장비는 DSM 인터넷 접근을 완전히 차단하세요.{C.RESET}")


def save_json(records: list[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)


def save_csv(records: list[dict], path: str) -> None:
    cols = ["target", "host", "base", "version", "build", "update",
            "exposed_login", "sa2420", "sa2613", "packages", "error"]
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in records:
            fnd = {f["advisory"]: f["status"] for f in r.get("findings", [])}
            w.writerow([
                r.get("target"), r.get("host"), r.get("base"),
                r.get("version"), r.get("build"), r.get("update"),
                r.get("exposed_login"),
                fnd.get("Synology-SA-24:20", ""), fnd.get("Synology-SA-26:13", ""),
                ";".join(p["id"] for p in r.get("packages", [])),
                r.get("error") or "",
            ])


def print_advisories() -> None:
    for adv in ADVISORIES:
        print(f"\n{C.BOLD}{adv['id']}  [{adv['severity']}]{C.RESET}")
        print(f"  CVE: {', '.join(adv['cves'])}")
        print(f"  {adv['summary']}")
        print(f"  고정 버전(이상): " + ", ".join(
            f"{k}-{v[0]}" + (f" Update {v[1]}" if v[1] else "") for k, v in adv["fixed"].items()))
        print(f"  참고: {adv['reference']}")
        if adv.get("note"):
            print(f"  ※ {adv['note']}")


def fail(msg: str) -> None:
    print(f"{C.RED}[오류] {msg}{C.RESET}", file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# 메인
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        prog="syno_vuln_scanner",
        description="Synology DSM 취약점 탐지 스캐너 (SA-24:20 / SA-26:13) — 탐지 전용, 익스플로잇 없음",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "예시:\n"
            "  python syno_vuln_scanner.py --authorize 192.168.1.10\n"
            "  python syno_vuln_scanner.py --authorize -t targets.txt --json report.json --csv report.csv\n"
            "  python syno_vuln_scanner.py --authorize 10.0.0.0/24 --threads 16\n"
            "  python syno_vuln_scanner.py --authorize 192.168.1.10 --login admin --password '***'\n"
            "  python syno_vuln_scanner.py --list-advisories\n"
        ),
    )
    ap.add_argument("target", nargs="?", help="호스트, URL, CIDR 또는 대상 파일 경로")
    ap.add_argument("-t", "--targets", help="대상 목록 파일 (한 줄에 하나)")
    ap.add_argument("--port", type=int, help="DSM 포트 강제 지정 (기본: 5000/5001/80/443 자동)")
    ap.add_argument("--scheme", choices=["http", "https"], help="스킴 강제 지정")
    ap.add_argument("--threads", type=int, default=8, help="동시 스캔 수 (기본: 8)")
    ap.add_argument("--timeout", type=float, default=8.0, help="요청 타임아웃 초 (기본: 8)")
    ap.add_argument("--delay", type=float, default=0.0, help="요청 간 지연 초 (rate limit)")
    ap.add_argument("--verify-tls", action="store_true", help="TLS 인증서 검증 (기본: 자가서명 허용)")
    ap.add_argument("--login", help="(선택) 인증 심층 검증용 계정 — 읽기 전용 API만 호출")
    ap.add_argument("--password", help="(선택) 인증 심층 검증용 비밀번호")
    ap.add_argument("--json", help="JSON 리포트 저장 경로")
    ap.add_argument("--csv", help="CSV 리포트 저장 경로")
    ap.add_argument("--no-color", action="store_true", help="색상 출력 비활성화")
    ap.add_argument("--quiet", action="store_true", help="요약만 출력")
    ap.add_argument("--list-advisories", action="store_true", help="탐지 대상 어드바이저리 표 출력")
    ap.add_argument("--authorize", action="store_true",
                    help="내가 이 시스템의 소유자이거나 명시적 테스트 동의를 받았음을 확인")

    args = ap.parse_args()

    if args.no_color:
        C.disable()

    if args.list_advisories:
        print_advisories()
        return 0

    if not args.authorize:
        print(f"{C.YELLOW}{C.BOLD}[사전 동의 필요]{C.RESET}")
        print("본 도구는 소유하거나 명시적 사전 동의를 받은 시스템에만 사용할 수 있습니다.")
        print("실행하려면 --authorize 플래그를 붙이십시오.")
        return 1

    raw_targets: list[str] = []
    if args.target:
        raw_targets.extend(expand_targets(args.target))
    if args.targets:
        raw_targets.extend(expand_targets(args.targets))
    if not raw_targets:
        ap.print_help()
        return 2
    # 중복 제거, 순서 유지
    seen, targets = set(), []
    for t in raw_targets:
        if t not in seen:
            seen.add(t)
            targets.append(t)

    opener = make_opener(args.verify_tls, args.timeout)

    print(f"{C.BOLD}Synology DSM 취약점 탐지 스캐너{C.RESET} — 탐지 대상: "
          f"SA-24:20(CVE-2024-10441), SA-26:13(CVE-2026-13684/13639)")
    print(f"대상 {len(targets)}개 · 스레드 {args.threads} · 탐지 전용(읽기 요청만)\n")

    records: list[dict] = []
    lock_print = args.threads <= 1

    def run(t: str) -> dict:
        rec = scan_target(t, args, opener)
        if lock_print:
            print_record(rec)
        return rec

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        for rec in ex.map(run, targets):
            records.append(rec)
            if not lock_print:
                print_record(rec)

    print_summary(records)

    if args.json:
        save_json(records, args.json)
        print(f"\n{C.CYAN}JSON 리포트 저장: {args.json}{C.RESET}")
    if args.csv:
        save_csv(records, args.csv)
        print(f"{C.CYAN}CSV 리포트 저장: {args.csv}{C.RESET}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
