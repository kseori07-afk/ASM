# 프로젝트명: ASM툴 개발 및 구현 
## 요구사항 
- 서비스 포트 스캔, 서비스 식별, OS 추정, 제로데이 취약점에 대한 PoC 구현
- 취약점이 있는 시스템을 구축하여 해당 ASM이 제대로 동작하는지 시연

1. 아래 취약점을 포함한 서버를 구축 (도커 기반)
    * Log4Shell (CVE-2021-44228)
    * SambaCry (CVE-2017-7494)
    * SSH User Enumeration (CVE-2018-15473)
2. 만든 ASM 툴로 해당 서버를 스캔하여, CVE가 발견됨을 증명
3. ASM 툴이 발견한 CVE에 대해 조치하는 방법을 사용자에게 제공 


## 설계 방향 요약
* 파이썬 + Subfinder, Naabu, Nmap + Nuclei + 데이터베이스 
* 서브도메인 탐색, 포트 탐색, OS 추정까지 단계는 타겟 도메인이나 IP 입력 받아 수행 
* Nuclei를 이용한 취약점 탐색의 경우 타겟 도메인과 사용할 템플릿을 결정해서 제공

## 필요 기술
* 사용 언어: Python 3.11 버전 (권장), 외부 도구 제어(subprocess) 및 데이터 처리
* 서브도메인 수집: Subfinder 
* 포트/OS 스캔: Naabu, Nmap (고속 포트 스캔 및 상세 서비스 식별)
* 취약점 스캔: Nuclei
* 데이터베이스: SQLite3
* 시연용 타겟 시스템: 도커

## 프로그램 실행 흐름

### Default Scanning(서브 도메인 찾기, 포트 스캔, OS 서비스 식별)
1. 대상 입력: 사용자로부터 타겟 도메인 또는 IP 대역을 입력받음
2. 서브도메인 탐색: Subfinder를 호출해 활성화된 서브도메인을 찾기
3. 포트 탐색: Naabu를 통해 열려 있는 서비스 포트를 찾기
4. 서비스/OS 식별: Nmap의 -O, -sV 옵션 등을 결합하여 서비스 버전과 OS 정보를 찾기
5. DB 저장: 결과(JSON/CSV)를 파서로 정규화하여 DB에 적재
6. 결과 출력: 실시간으로 발견된 자산 현황과 취약점 통계를 대시보드(혹은 터미널)에 출력

사용자 입력(도메인 또는 IP)
    ↓
Subfinder 
    ↓
발견된 Subdomain 저장
    ↓
각 호스트에 대해 Naabu
    ↓
열린 포트 발견
    ↓
열린 포트에 대해 Nmap 서비스/OS 분석
    ↓
DB 저장
    ↓
결과 출력 or 시각화


### CVE Scanning(취약점 탐지)
1. 대상 입력: 사용자로부터 타겟 도메인 입력받음. 템플릿 선택 기능은 고려중이므로 일단 보류.
2. 취약점 탐지: Nuclei를 실행하여 알려진 취약점 및 설정 오류를 탐지
3. DB 저장: 결과(JSON/CSV)를 파서로 정규화하여 DB에 적재
4. 결과 리포트 출력: 실시간으로 발견된 취약점을 대시보드(혹은 터미널)에 출력

사용자 입력(도메인 또는 IP)
    ↓
Nuclei / Nmap NSE 등으로 취약점 탐지
    ↓
DB 저장
    ↓
결과 출력 or 시각화

## 현재 구현 상태
### 구현 완료된 작업
* Default Scanning의 기본 기능 구현 완료
  - Subfinder 서브도메인 탐색, Naabu 포트 스캔, Nmap 서비스/OS 식별, 결과 파싱 및 DB 저장이 동작함
* CVE Scanning의 기본 기능 구현 완료
  - Nuclei 실행 및 취약점 탐지 파이프라인이 구성되어 있음

### 남은 작업
* Nuclei의 한계로 인해 서버의 실제 취약점을 탐지하지 못함 
  - Log4Shell / SambaCry / SSH User Enumeration 취약점 보유 서버 만들고 탐지 성공시켜야함 
  - 필요한 경우 Nuclei 템플릿 추가, Nmap NSE 보완, 또는 커스텀 취약점 검증 로직 도입 검토

## **프로젝트 디렉터리 구조**
ASM/
├── main.py                 # 프로그램 통합 실행 포인트
|
├── project_context.md      # 프로젝트 설명 문서
|
├── requirements.txt        # 필요한 파이썬 라이브러리 목록
|
├── scanner/                # 스캔 도구 모음
│   ├── subfinder_scan.py             # Subfinder (서브도메인 수집)
│   ├── naabu_scan.py                 # Naabu (포트 스캔 수행)
│   ├── nmap_scan.py                  # NMap (서비스 버전 및 OS 탐지 수행)
│   ├── nuclei_scan.py                # Nuclei (취약점 탐지 수행)
│   └── parser.py                     # 각 도구 실행 결과(JSON/XML/Text 등) 파싱 및 정규화
│
├── controller/                       # 전체 ASM 실행 흐름 제어
│   └── workflow.py                   # 스캔 순서 제어 및 결과 처리
|
├── modules/                # [필요시 추가] 외부 도구 및 헬퍼
│   └── utils.py            # 공통 유틸리티 (로깅, 파일 처리 등)
|
├── templates/               # neclei가 쓰는 템플릿 저장 공간 
│   └── CVE-2021-44228.yaml
│
├── database/               # DB 저장 및 조회 기능
│   ├── schema.sql          # DB 테이블 설계 문문
│   └── db_manager.py       # SQLite CRUD 동작 
|
└── data/                   # 결과 파일 및 DB 파일 저장소
    ├── json/               # JSON 형태 결과 저장
    ├── logs/               # 실행 로그 저장
    ├── reports/            # 최종 리포트(html/txt 등) 저장
    └── results.db          # SQLite 데이터베이스

## 핵심 모듈 
### ASM Controller
* 모든 스캔 도구를 제어하는 역할 
* Python subprocess 기반
* subprocess 실행, 결과 수집, JSON 파싱, 다음 단계 전달 등의 역할 수행
* 주요 기능 
    스캔 순서 관리
    외부 도구 실행
    JSON/XML 파싱
    결과 통합
    실패 대응
    실시간 로깅 

### Subfinder
* 도메인의 서브도메인 탐색 역할, 가장 중요한 기능 
* 예시 입력: example.com
* 예시 출력: 
    api.example.com
    admin.example.com
    dev.example.com

### Naabu 
* 열려있는 포트 탐색
* 예시 입력: api.example.com
* 예시 출력: 
    80/tcp
    443/tcp
    22/tcp

### Nmap Module
* 서비스, OS 세부 정보 등의 식별
* 예시 출력: 
    Apache 2.4.49
    OpenSSH 7.2
    Ubuntu Linux

### Nuclei
* 취약점 탐지 역할
    CVE
    Misconfiguration
    Default Credential
    Exposed Admin Panel 등 
* 예시 출력:
    CVE-2021-41773
    Severity: HIGH

### 데이터 저장 (SQLite)
* Scan history 이용, 결과 비교, 발표용 재현성 등을 위해 데이터 저장 
| Field         | 설명      |
| ------------- | ------- |
| id            | scan id |
| target        | 대상      |
| subdomain     | 발견 자산   |
| port          | 포트      |
| service       | 서비스     |
| os            | OS      |
| vulnerability | 취약점     |
| severity      | 위험도     |
| timestamp     | 시간      |



