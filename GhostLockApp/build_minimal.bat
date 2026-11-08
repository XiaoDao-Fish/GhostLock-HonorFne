@echo off
chcp 65001 >nul
setlocal
echo ============================================================
echo   GhostLock HonorFne - 最小命令行构建（无需 Android Studio）
echo ============================================================
echo.

REM ---- 定位目录 ----
REM 本脚本位于 GhostLockApp\ 下，父目录即 GhostLock-HonorFne-main
set "APP_DIR=%~dp0"
set "ROOT_DIR=%APP_DIR%..\"

REM ---- 1) JDK 17 ----
set "JAVA_HOME=%ROOT_DIR%jdk-17.0.12"
if not exist "%JAVA_HOME%\bin\java.exe" (
  echo [错误] 找不到 JDK：%JAVA_HOME%
  echo        请确认 jdk-17.0.12 已解压到 GhostLock-HonorFne-main\ 下。
  pause & exit /b 1
)
echo [OK] JAVA_HOME = %JAVA_HOME%
"%JAVA_HOME%\bin\java.exe" -version
echo.

REM ---- 2) cmdline-tools ----
set "CMDLINE=%ROOT_DIR%cmdline-tools\bin"
if not exist "%CMDLINE%\sdkmanager.bat" (
  echo [错误] 找不到 sdkmanager：%CMDLINE%
  echo        请确认 cmdline-tools 已解压到 GhostLock-HonorFne-main\cmdline-tools\。
  pause & exit /b 1
)

REM ---- 3) SDK 组件安装目录 ----
set "ANDROID_SDK=%ROOT_DIR%android-sdk"

REM ---- 4) 补齐 gradle-wrapper.jar（Android Studio 才会自动生成，这里手动拉）----
set "WRAPPER_JAR=%APP_DIR%gradle\wrapper\gradle-wrapper.jar"
if not exist "%WRAPPER_JAR%" (
  echo [准备] 未找到 gradle-wrapper.jar，用 PowerShell 下载（约 60KB，需联网）...
  powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/gradle/gradle/v8.7.0/gradle/wrapper/gradle-wrapper.jar' -OutFile '%WRAPPER_JAR%'"
  if not exist "%WRAPPER_JAR%" (
    echo [失败] 下载 gradle-wrapper.jar 失败。
    echo        请手动下载并放到：%WRAPPER_JAR%
    echo        链接：https://raw.githubusercontent.com/gradle/gradle/v8.7.0/gradle/wrapper/gradle-wrapper.jar
    pause & exit /b 1
  )
  echo [OK] gradle-wrapper.jar 已就绪。
)
echo.

REM ---- 5) 安装必要 SDK 组件（缺失才装）----
set "NEED_INSTALL=0"
if not exist "%ANDROID_SDK%\platform-tools\adb.exe" set NEED_INSTALL=1
if not exist "%ANDROID_SDK%\platforms\android-34" set NEED_INSTALL=1
if not exist "%ANDROID_SDK%\build-tools\34.0.0" set NEED_INSTALL=1

if "%NEED_INSTALL%"=="1" (
  echo [1/3] 安装 SDK 组件（platform-tools / android-34 / build-tools 34.0.0）...
  echo        首次会联网从 Google 下载，请耐心等待。
  "%CMDLINE%\sdkmanager.bat" --sdk_root="%ANDROID_SDK%" --accept-licenses "platform-tools" "platforms;android-34" "build-tools;34.0.0"
  if errorlevel 1 (
    echo [失败] SDK 组件安装出错，请检查网络/代理后重试。
    pause & exit /b 1
  )
) else (
  echo [1/3] SDK 组件已就绪，跳过安装。
)
echo.

REM ---- 6) 本会话 PATH（不污染系统环境变量）----
set "PATH=%JAVA_HOME%\bin;%ANDROID_SDK%\platform-tools;%CMDLINE%;%PATH%"

REM ---- 7) 构建 debug APK ----
echo [2/3] 用 Gradle 构建 debug APK（首次会下载 Gradle 8.7 与依赖，已配阿里云镜像）...
echo.
call "%APP_DIR%gradlew.bat" assembleDebug
if errorlevel 1 (
  echo [失败] 构建出错，请查看上面的日志。
  pause & exit /b 1
)
echo.

REM ---- 8) 安装到已连接设备 ----
echo [3/3] 构建完成，尝试安装到已连接设备...
set "APK=%APP_DIR%app\build\outputs\apk\debug\app-debug.apk"
if not exist "%APK%" (
  echo [错误] 未找到生成的 APK：%APK%
  pause & exit /b 1
)
adb install -r "%APK%"
if errorlevel 1 (
  echo [提示] adb install 失败（设备未连接或未授权）。请手动安装：
  echo        %APK%
) else (
  echo [完成] 已安装到设备，去桌面打开 GhostLock 即可。
)
echo.
pause
