# Synology DSM 취약점 탐지 스캐너

SVRForum 게시글 [시놀로지 랜섬 취약점 CVE-2024-10441 / Synology-SA-24:20](https://svrforum.com/nas/3232929)에서 다룬
두 개의 시놀로지 취약점을 **안전하게(읽기 전용, 익스플로잇 없이)** 탐지하는
보안 연구자용 스캐너입니다.

## 탐지 대상 취약점

### 1. Synology-SA-24:20 — CVE-2024-10441 (Critical, CVSS 9.8)

- system plugin daemon의 출력 인코딩 결함 → **비인증 원격 코드 실행**
- PWN2OWN 2024에서 발표, CISA KEV 등재, **실제 랜섬웨어 캠페인에 악용 중**
- 동반: CVE-2024-50629(webapi 파일 읽기, 5.3), CVE-2024-10445(업데이트 기능 MITM 파일 쓰기, 4.3)
- 안전 최소 버전 (이상으로 업데이트 필요):

| DSM 브랜치 | 취약 범위 | 안전한 최소 패치 |
|---|---|---|
| 7.2.2 | 7.2.2-72806 미만 Update | **7.2.2-72806 Update 1** |
| 7.2.1 | Update 6 미만 | **7.2.1-69057 Update 6** |
| 7.2 | Update 4 미만 | **7.2-64570 Update 4** |
| 7.1.1 | Update 7 미만 | **7.1.1-42962 Update 7** |
| 6.2.4 | Update 8 미만 | **6.2.4-25556 Update 8** |
| BeeStation OS | 1.1-65374 미만 | **1.1-65374** |

### 2. Synology-SA-26:13 — CVE-2026-13684 / CVE-2026-13639 (Critical, CVSS 9.8 x2)

- SCGI 컴포넌트 출력 인코딩 결함(CVE-2026-13684) + 로그인 로직 엔트로피 부족(CVE-2026-13639)
- **비인증 원격 코드 실행 / 원격 접근 가능**. 2026-09-18 공개, 완화책 없음(패치만 가능)
- 동반: LDAP API 권한 결함(8.8), Upload API 경로 조작(8.1), Auth/Theme/Sharing/EventScheduler API 결함
- 안전 최소 버전:

| DSM 브랜치 | 안전한 최소 패치 |
|---|---|
| 7.4 | **7.4-90075** |
| 7.3 | **7.3.2-86009-4** (7.3.0/7.3.1은 이 버전으로 업그레이드) |
| 7.2.2 | **7.2.2-72806-9** |
| 7.2.1 | **7.2.1-69057-12** |

⚠️ **7.2.0 및 이전 브랜치(7.1.x, 6.2.x 등)에는 패치가 제공되지 않습니다(지원 종료).**
해당 장비는 스캐너가 `EOL_NO_PATCH`로 표기하며, **DSM의 인터넷 접근을 완전히 차단**해야 합니다.

## 탐지 방식 (익스플로잇 없음)

이 스캐너는 시스템을 건드리지 않습니다. 대상 장비에 대해 다음 **읽기 전용 GET 요청**만 수행합니다.

1. **DSM 식별**: `/webman/ping.cgi`, `/webman/index.cgi`, `/webman/global.js`
2. **버전 지문**: `global.js`의 `SYNO.SDS.Version` / `SYNO.SDS.BuildNumber` 변수,
   실패 시 로그인 페이지 자산의 `?v=빌드번호` 파라미터
3. **공격면 열람**: `SYNO.API.Info` 쿼리(인증 불필요)로 Synology Photos·Surveillance Station 등
   설치된 API 목록 확인
4. **판정**: 얻어낸 빌드/브랜치를 위 표(공식 고정 버전)와 비교

### 중요한 한계 — Update 레벨

같은 브랜치 내에서는 빌드 번호가 유지되기 때문에(예: 7.2.2는 Update 0~9까지 모두 빌드 72806),
**인증 없이는 Update 레벨을 알 수 없습니다.** 이 경우 스캐너는 `검증 필요 (VERIFY_NEEDED)`로
보수적으로 표기합니다. 확정하려면 관리자 자격증명으로 심층 검증을 실행하십시오.

- 심층 검증(`--login/--password`)은 `SYNO.API.Auth` 로그인 → `SYNO.Core.System.Info`로
  정확한 `빌드 + Update N` 확인 → `SYNO.Core.Package.Server`로 설치 패키지 열람 → 로그아웃,
  즉 **읽기 전용 API만 호출**합니다.

## 설치 및 사용

요구사항: Python 3.9+ (표준 라이브러리만 사용, 의존성 없음)

```bash
# 사전 동의 플래그(--authorize)가 반드시 필요합니다
python syno_vuln_scanner.py --authorize 192.168.1.10

# 서브넷 전체 (자동으로 호스트 목록 확장)
python syno_vuln_scanner.py --authorize 192.168.1.0/24 --threads 16

# 대상 파일 (한 줄에 하나, 주석 # 지원)
python syno_vuln_scanner.py --authorize -t targets.txt --json report.json --csv report.csv

# 포트/스킴 강제 지정 (기본: 5000/5001/80/443 자동 탐색)
python syno_vuln_scanner.py --authorize nas.example.local --port 5001 --scheme https

# 심층 검증: Update 레벨 확정 + 설치 패키지 확인 (읽기 전용 API만)
python syno_vuln_scanner.py --authorize 192.168.1.10 --login admin --password '비밀번호'

# 탐지 대상 어드바이저리 표만 출력
python syno_vuln_scanner.py --list-advisories
```

### 주요 옵션

| 옵션 | 설명 |
|---|---|
| `--authorize` | 소유자/사전 동의 확인 (필수) |
| `-t/--targets FILE` | 대상 목록 파일 |
| `--port`, `--scheme` | 포트/스킴 강제 |
| `--threads N` | 동시 스캔 수 (기본 8) |
| `--delay SEC` | 요청 간 지연 (rate limit) |
| `--timeout SEC` | 요청 타임아웃 (기본 8) |
| `--login`, `--password` | 심층 검증 자격증명 (선택) |
| `--json`, `--csv` | 리포트 저장 |
| `--no-color`, `--quiet` | 출력 제어 |

### 판정 코드

| 상태 | 의미 |
|---|---|
| `패치됨 (안전)` | 고정 버전 이상으로 확인됨 |
| `취약 — 즉시 패치 필요` | 고정 버전 미달 확정, 또는 업그레이드 경로 존재(7.3.x) |
| `검증 필요 (Update 미확인)` | 브랜치는 영향권, Update 레벨 미확인 → `--login`으로 확정 |
| `패치 미제공 (EOL) — 격리 필요` | 이 브랜치는 업데이트가 나오지 않음 → 인터넷 차단 |
| `영향 범위 밖` | 해당 어드바이저리의 영향을 받지 않는 브랜치 |
| `접속 불가 / DSM 아님` | DSM 식별 실패 |

## 테스트

실제 장비 없이 로컬 목서버로 전체 탐지 경로를 검증할 수 있습니다:

```bash
python test_mock_dsm.py 5000 7.2.2 72806 3        # DSM 7.2.2 Update 3 흉내
python syno_vuln_scanner.py --authorize 127.0.0.1:5000 --login admin --password test1234
```

## 취약점 발견 시 조치 요약

1. **지원 중인 장비**: 위 표의 고정 버전 이상으로 즉시 업데이트
   (수동 패치: https://archive.synology.com/download/Os/DSM 에서 .pat 다운로드)
2. **지원 종료(EOL) 장비**: DSM 인터넷 접근 완전 차단 (포트포워딩/QuickConnect 해제, 방화벽/VPN 뒤로 이동)
3. **침해 의심 시**: DSM 로그 센터에서 외부 로그인 기록·비정상 `webapi/` 요청 확인,
   계정 목록에 미인식 계정이 없는지 점검, 최근 수정된 웹 파일 존재 여부 확인

## 윤리 / 법적 고지

본 도구는 **자신이 소유하거나 명시적 사전 동의(승인된 모의침투 범위)를 받은 시스템에만** 사용하십시오.
무단 스캔은 법적 처벌 대상이 될 수 있습니다. 이를 강제하기 위해 실행 시 `--authorize` 플래그가 필요합니다.
스캐너는 탐지 전용이며 어떠한 익스플로잇 코드도 포함하지 않습니다.

## 참고 자료

- 게시글: https://svrforum.com/nas/3232929
- SA-24:20: https://www.synology.com/en-global/security/advisory/Synology_SA_24_20
- SA-26:13: https://www.synology.com/en-global/security/advisory/Synology_SA_26_13
- DSM 수동 업데이트: https://archive.synology.com/download/Os/DSM
