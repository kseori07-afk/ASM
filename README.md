# ASM
## 지원 모드

- **기본 스캔**: 서브도메인 검색(`Subfinder`) → 포트 스캔(`Naabu`) → 서비스/OS 탐지(`Nmap`)
- **CVE 스캔**: 취약점 스캔(`Nuclei`)

## Docker 설정

이 프로젝트에는 다른 머신에서 쉽게 실행할 수 있도록 Docker 구성이 포함되어 있습니다.

`docker build + docker run` = 이미지를 직접 빌드한 후 실행

1. Docker 이미지 빌드
프로젝트 루트 위치(ASM/)에서 이미지를 한 번 빌드합니다.
```bash
docker build -t asm-tool .
```

2. 컨테이너 실행
새 컨테이너에서 도구를 시작하고 로컬 `data/` 폴더를 마운트하여 결과를 저장합니다.
```bash
docker run --rm -it -v %cd%/data:/app/data asm-tool
```

Windows에서 PowerShell을 사용하는 경우 다음 명령을 사용합니다.
```powershell
docker run --rm -it -v ${PWD}/data:/app/data asm-tool
```
이 명령은 컨테이너를 시작하고 `python main.py`를 실행하며 스캔 데이터를 호스트에 저장합니다.

## Notes

- 컨테이너는 Python 3.11, Nmap, `subfinder`, `naabu`, `nuclei`를 자동으로 설치합니다.
- 도구를 대화형으로 실행하려면 `docker run --rm -it ...` 명령을 사용하십시오.
- 스캔 결과는 `data/json/` 디렉터리에 저장됩니다.
- 스캔 기록은 SQLite 데이터베이스의 `data/results.db` 파일에도 저장됩니다.
