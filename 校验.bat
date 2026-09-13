chcp 65001 >nul
@echo off
rem ===== CNVD portable package self-check + smoke test =====
rem == CNVD 便携包环境自检 + 冒烟测试（乱码不影响功能）==
cd /d "%~dp0"
set PY=python
%PY% --version >nul 2>&1
if errorlevel 1 (
  echo [1] Python .............. FAIL  - python not found. Install Python 3.8+ with "Add to PATH".
  echo     [1] Python ............ FAIL  未找到 python，请安装 Python 3.8+ 并勾选 Add to PATH
  echo     ^(若用 py 启动器，把本 bat 里的 python 替换为 py^)
  pause & exit /b 1
)
echo [1] Python .............. OK
for /f "delims=" %%v in ('%PY% --version 2^>^&1') do echo      %%v

%PY% tools\scripts\cnvd_recon.py --help >nul 2>&1
if errorlevel 1 ( echo [2] recon script ........ FAIL & pause & exit /b 1 )
echo [2] recon script ........ OK

%PY% tools\scripts\cnvd_check.py --help >nul 2>&1
if errorlevel 1 ( echo [3] check script ........ FAIL & pause & exit /b 1 )
echo [3] check script ........ OK

%PY% tools\scripts\verify_newfe_A.py --help >nul 2>&1
if errorlevel 1 ( echo [3a] verify_newfe_A ...... FAIL & pause & exit /b 1 )
echo [3a] verify_newfe_A ...... OK

%PY% tools\scripts\verify_newfe_B.py --help >nul 2>&1
if errorlevel 1 ( echo [3b] verify_newfe_B ...... FAIL & pause & exit /b 1 )
echo [3b] verify_newfe_B ...... OK

%PY% tools\scripts\verify_rtsp2.py --help >nul 2>&1
if errorlevel 1 ( echo [3c] verify_rtsp2 ......... FAIL & pause & exit /b 1 )
echo [3c] verify_rtsp2 ......... OK

%PY% tools\scripts\probe_newfe_A_bodies.py --help >nul 2>&1
if errorlevel 1 ( echo [3d] probe_bodies ......... FAIL & pause & exit /b 1 )
echo [3d] probe_bodies ......... OK

%PY% -c "import json;d=json.load(open('api_keys.json',encoding='utf-8'));chs=d.get('channels',[]);enabled=[c for c in chs if c.get('enabled')];assert enabled;print('[4a] channels field ...... OK, found',len(enabled),'enabled channel(s)');import sys;sys.exit(3 if any(c.get('key','')=='REPLACE_ME' for c in enabled) else 0)"
if errorlevel 3 (
  echo [4b] key values .......... TODO  - still placeholders. Fill your own FOFA key per README step 1.5
  echo     [4b] key ............. TODO  还是占位符，请按 README 第 1.5 步填入自己的 FOFA key
  echo     ^(填入后重新双击本脚本复检；通道实测将跳过^)
  goto :done
)
if errorlevel 1 ( echo [4] api_keys.json ....... FAIL - broken or missing fields & pause & exit /b 1 )
echo [4b] key values .......... OK

echo [5] FOFA channel test .... sending one small query (size=1)...
%PY% tools\scripts\cnvd_recon.py --query "title=\"NVR\"" --size 1 --out nul 2>&1 | findstr /i "返回 失败 无结果"

:done
echo.
echo ====== Self-check done. All OK ==^> start per README-移植说明.md ======
pause
