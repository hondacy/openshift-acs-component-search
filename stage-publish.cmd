@echo off
setlocal

rem Build, test, and stage-publish acs-component-search to the npm registry,
rem then open the staged-packages page in a browser on success.
rem
rem Usage:
rem   stage-publish.cmd            Build, test, stage publish current version
rem   stage-publish.cmd patch      Bump patch version first (also: minor ^| major)
rem
rem Any failing step aborts with a non-zero exit code and the browser is NOT opened.

set "STAGE_URL=https://www.npmjs.com/settings/devsops/staged-packages"

rem Run from the directory this script lives in, regardless of the caller's CWD.
cd /d "%~dp0"

if not "%~1"=="" (
  echo [1/4] Bumping version: %~1
  call npm version %~1 --no-git-tag-version || exit /b 1
) else (
  echo [1/4] Skipping version bump ^(pass patch^|minor^|major to bump^)
)

echo [2/4] Building (npm install)...
call npm install --no-audit --no-fund || exit /b 1

echo [3/4] Testing...
call npm test || exit /b 1

echo [4/4] Stage publishing...
call npm stage publish || exit /b 1

echo Stage publish succeeded. Opening %STAGE_URL%
start "" "%STAGE_URL%"

endlocal
