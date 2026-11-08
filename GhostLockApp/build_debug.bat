@echo off
chcp 65001 >nul
echo ============================================================
echo   GhostLock HonorFne - 一键构建 Debug APK（Windows）
echo ============================================================
echo.

REM 0) 检查 Java
where java >nul 2>nul
if errorlevel 1 (
  echo [错误] 没找到 java。请先安装 Android Studio（自带 JDK 17）并重启终端，
  echo        或在系统环境变量里配置 JAVA_HOME 指向 JDK 17 的目录。
  echo        下载：https://developer.android.com/studio
  pause
  exit /b 1
)
echo [OK] 已找到 java：
java -version
echo.

REM 1) 构建 debug APK
echo [1/2] 正在用 Gradle 构建 debug APK ...
echo       （首次构建会联网下载 Gradle 8.7 与依赖，请耐心等待几分钟）
echo.
call gradlew.bat assembleDebug
if errorlevel 1 (
  echo.
  echo [失败] 构建出错。请查看上面的日志。常见原因：
  echo   - Android SDK 未安装 / 未配置 ANDROID_HOME
  echo   - 未安装 "Android SDK Platform 34" 或 Build-Tools 34.x
  echo   - 公司网络/代理拦截了 Gradle / Maven 下载
  pause
  exit /b 1
)

REM 2) 安装到已连接设备（可选）
echo.
echo [2/2] 构建完成，尝试安装到已连接设备 ...
set "APK=app\build\outputs\apk\debug\app-debug.apk"
if not exist "%APK%" (
  echo [错误] 没找到生成的 APK：%APK%
  pause
  exit /b 1
)
where adb >nul 2>nul
if errorlevel 1 (
  echo [提示] 没找到 adb（Android SDK platform-tools）。请手动安装该 APK：
  echo        %APK%
  pause
  exit /b 0
)
adb install -r "%APK%"
if errorlevel 1 (
  echo [提示] adb install 失败，可能设备未连接或未授权。请手动安装：
  echo        %APK%
) else (
  echo [完成] 已安装到设备，去桌面打开 GhostLock 即可。
)
echo.
pause
