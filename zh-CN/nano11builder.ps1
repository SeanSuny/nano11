# 检查执行策略是否为 Restricted（禁止脚本运行）
if ((Get-ExecutionPolicy) -eq 'Restricted') {
    Write-Host "您当前的 PowerShell 执行策略设置为 Restricted，这会阻止脚本运行。是否要将其更改为 RemoteSigned？(yes/no)"
    $response = Read-Host
    if ($response -eq 'yes') {
        Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Confirm:$false
    } else {
        Write-Host "不更改执行策略则无法运行脚本，正在退出..."
        exit
    }
}

# 检查并以管理员身份运行脚本（如果需要）
$adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$adminGroup = $adminSID.Translate([System.Security.Principal.NTAccount])
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
if (! $myWindowsPrincipal.IsInRole($adminRole))
{
    Write-Host "将以管理员身份在新窗口中重新启动 nano11 镜像创建器，您可以关闭此窗口。"
    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
    $newProcess.Arguments = $myInvocation.MyCommand.Definition;
    $newProcess.Verb = "runas";
    [System.Diagnostics.Process]::Start($newProcess);
    exit
}

# 开始记录日志
Start-Transcript -Path "$PSScriptRoot\nano11.log"
# 询问用户是否继续
Write-Host "欢迎使用 nano11 构建工具!"
Write-Host "此脚本可生成高度精简的 Windows 11 镜像。由于其缺乏可维护性（无法添加语言、更新或功能），它不适合常规使用。nano11 不是完整的 Windows 11 替代品，而是用于快速测试或开发工具，可能在虚拟机环境中使用。"
Write-Host "是否要继续？(y/n)"
$input = Read-Host

if ($input -eq 'y') {
    Write-Host "开始执行..."
Start-Sleep -Seconds 3
Clear-Host

# 创建临时目录
$mainOSDrive = $env:SystemDrive
New-Item -ItemType Directory -Force -Path "$mainOSDrive\nano11\sources"

# 获取 Windows 安装源路径
$DriveLetter = Read-Host "请输入 Windows 11 镜像的驱动器盘符"
$DriveLetter = $DriveLetter + ":"

# 检查并转换 install.esd（如果存在）
if ((Test-Path "$DriveLetter\sources\boot.wim") -eq $false -or (Test-Path "$DriveLetter\sources\install.wim") -eq $false) {
    if ((Test-Path "$DriveLetter\sources\install.esd") -eq $true) {
        Write-Host "找到 install.esd，正在转换为 install.wim..."
        &  'dism' "/Get-WimInfo" "/wimfile:$DriveLetter\sources\install.esd"
        $index = Read-Host "请输入镜像索引号"
        Write-Host '正在将 install.esd 转换为 install.wim，请稍候...'
        & 'DISM' /Export-Image /SourceImageFile:"$DriveLetter\sources\install.esd" /SourceIndex:$index /DestinationImageFile:"$mainOSDrive\nano11\sources\install.wim" /Compress:max /CheckIntegrity
    } else {
        Write-Host "在指定驱动器盘符中找不到 Windows 安装文件，正在退出..."
        exit
    }
}

# 复制 Windows 镜像
Write-Host "正在复制 Windows 镜像..."
Copy-Item -Path "$DriveLetter\*" -Destination "$mainOSDrive\nano11" -Recurse -Force > null
Remove-Item "$mainOSDrive\nano11\sources\install.esd" -ErrorAction SilentlyContinue

# 获取镜像信息并挂载
Write-Host "获取镜像信息:"
&  'dism' "/Get-WimInfo" "/wimfile:$mainOSDrive\nano11\sources\install.wim"
$index = Read-Host "请输入镜像索引号"
Write-Host "正在挂载 Windows 镜像，请稍候..."
$wimFilePath = "$($env:SystemDrive)\nano11\sources\install.wim"
& takeown "/F" $wimFilePath 
& icacls $wimFilePath "/grant" "$($adminGroup.Value):(F)"
try {
    Set-ItemProperty -Path $wimFilePath -Name IsReadOnly -Value $false -ErrorAction Stop
} catch {
    #  忽略错误
}
New-Item -ItemType Directory -Force -Path "$mainOSDrive\scratchdir"
& dism "/mount-image" "/imagefile:$($env:SystemDrive)\nano11\sources\install.wim" "/index:$index" "/mountdir:$($env:SystemDrive)\scratchdir"

# --- 主动获取 install.wim 的所有目标文件夹的所有权 ---
$scratchDir = "$($env:SystemDrive)\scratchdir"
$foldersToOwn = @( "$scratchDir\Windows\System32\DriverStore\FileRepository", "$scratchDir\Windows\Fonts", "$scratchDir\Windows\Web", "$scratchDir\Windows\Help", "$scratchDir\Windows\Cursors", "$scratchDir\Program Files (x86)\Microsoft", "$scratchDir\Program Files\WindowsApps", "$scratchDir\Windows\System32\Microsoft-Edge-Webview", "$scratchDir\Windows\System32\Recovery", "$scratchDir\Windows\WinSxS", "$scratchDir\Windows\assembly", "$scratchDir\ProgramData\Microsoft\Windows Defender", "$scratchDir\Windows\System32\InputMethod", "$scratchDir\Windows\Speech", "$scratchDir\Windows\Temp" )
$filesToOwn = @( "$scratchDir\Windows\System32\OneDriveSetup.exe" )
foreach ($folder in $foldersToOwn) { if (Test-Path $folder) { Write-Host "正在获取文件夹所有权: $folder"; & takeown.exe /F $folder /R /D Y ; & icacls.exe $folder /grant "$($adminGroup.Value):(F)" /T /C  } }
foreach ($file in $filesToOwn) { if (Test-Path $file) { Write-Host "正在获取文件所有权: $file"; & takeown.exe /F $file /D Y ; & icacls.exe $file /grant "$($adminGroup.Value):(F)" /C  } }

# 获取系统默认语言
$imageIntl = & dism /Get-Intl "/Image:$scratchDir"
$languageLine = $imageIntl -split '\n' | Where-Object { $_ -match 'Default system UI language : ([a-zA-Z]{2}-[a-zA-Z]{2})' }
if ($languageLine) { $languageCode = $Matches[1]; Write-Host "默认系统界面语言代码: $languageCode" } else { Write-Host "未找到默认系统界面语言代码。" }

# 获取系统架构
$imageInfo = & 'dism' '/Get-WimInfo' "/wimFile:$wimFilePath" "/index:$index"
$lines = $imageInfo -split '\r?\n'
foreach ($line in $lines) { if ($line -like '*Architecture : *') { $architecture = $line -replace 'Architecture : ',''; if ($architecture -eq 'x64') { $architecture = 'amd64' }; Write-Host "系统架构: $architecture"; break } }
if (-not $architecture) { Write-Host "未找到系统架构信息。" }

# 移除预装应用 (AppX)
Write-Host "正在移除预装的 AppX 包 (臃肿软件)..."
$packagesToRemove = Get-AppxProvisionedPackage -Path $scratchDir | Where-Object { $_.PackageName -like '*Zune*' -or $_.PackageName -like '*Bing*' -or $_.PackageName -like '*Clipchamp*' -or $_.PackageName -like '*Gaming*' -or $_.PackageName -like '*People*' -or $_.PackageName -like '*PowerAutomate*' -or $_.PackageName -like '*Teams*' -or $_.PackageName -like '*Todos*' -or $_.PackageName -like '*YourPhone*' -or $_.PackageName -like '*SoundRecorder*' -or $_.PackageName -like '*Solitaire*' -or $_.PackageName -like '*FeedbackHub*' -or $_.PackageName -like '*Maps*' -or $_.PackageName -like '*OfficeHub*' -or $_.PackageName -like '*Help*' -or $_.PackageName -like '*Family*' -or $_.PackageName -like '*Alarms*' -or $_.PackageName -like '*CommunicationsApps*' -or $_.PackageName -like '*Copilot*' -or $_.PackageName -like '*CompatibilityEnhancements*' -or $_.PackageName -like '*AV1VideoExtension*' -or $_.PackageName -like '*AVCEncoderVideoExtension*' -or $_.PackageName -like '*HEIFImageExtension*' -or $_.PackageName -like '*HEVCVideoExtension*' -or $_.PackageName -like '*MicrosoftStickyNotes*' -or $_.PackageName -like '*OutlookForWindows*' -or $_.PackageName -like '*RawImageExtension*' -or $_.PackageName -like '*SecHealthUI*' -or $_.PackageName -like '*VP9VideoExtensions*' -or $_.PackageName -like '*WebpImageExtension*' -or $_.PackageName -like '*DevHome*' -or $_.PackageName -like '*Photos*' -or $_.PackageName -like '*Camera*' -or $_.PackageName -like '*QuickAssist*' -or $_.PackageName -like '*CoreAI*'  -or $_.PackageName -like '*PeopleExperienceHost*' -or $_.PackageName -like '*PinningConfirmationDialog*' -or $_.PackageName -like '*SecureAssessmentBrowser*' -or $_.PackageName -like '*Paint*' -or $_.PackageName -like '*Notepad*'  }
foreach ($package in $packagesToRemove) { write-host "正在移除: $($package.DisplayName)"; Remove-AppxProvisionedPackage -Path $scratchDir -PackageName $package.PackageName }

# 清理残留文件
Write-Host "尝试移除残留的 WindowsApps 文件夹..."
foreach ($package in $packagesToRemove) { $folderPath = Join-Path "$scratchDir\Program Files\WindowsApps" $package.PackageName; if (Test-Path $folderPath) { Write-Host "正在删除文件夹: $($package.PackageName)"; Remove-Item $folderPath -Recurse -Force -ErrorAction SilentlyContinue } }

Write-Host "系统应用移除完成！现在开始移除系统功能包..."
Start-Sleep -Seconds 1
Clear-Host

# 移除系统功能包
$scratchDir = "$($env:SystemDrive)\scratchdir"
$packagePatterns = @(
    # --- 旧版组件和可选应用 ---
    "Microsoft-Windows-InternetExplorer-Optional-Package~",
    "Microsoft-Windows-MediaPlayer-Package~",
    "Microsoft-Windows-WordPad-FoD-Package~",
    "Microsoft-Windows-StepsRecorder-Package~",
    "Microsoft-Windows-MSPaint-FoD-Package~",
    "Microsoft-Windows-SnippingTool-FoD-Package~",
    "Microsoft-Windows-TabletPCMath-Package~",
    "Microsoft-Windows-Xps-Xps-Viewer-Opt-Package~",
    "Microsoft-Windows-PowerShell-ISE-FOD-Package~",
    "OpenSSH-Client-Package~",

    # --- 语言和输入功能（仅保留主语言）---
    "Microsoft-Windows-LanguageFeatures-Handwriting-$languageCode-Package~",
    "Microsoft-Windows-LanguageFeatures-OCR-$languageCode-Package~",
    "Microsoft-Windows-LanguageFeatures-Speech-$languageCode-Package~",
    "Microsoft-Windows-LanguageFeatures-TextToSpeech-$languageCode-Package~",
    "*IME-ja-jp*",
    "*IME-ko-kr*",
    # "*IME-zh-cn*", # 【修改】已注释，防止删除中文输入法
    "*IME-zh-tw*",

    # --- 核心操作系统功能（破坏性移除）---
    "Windows-Defender-Client-Package~",
    "Microsoft-Windows-Search-Engine-Client-Package~",
    "Microsoft-Windows-Kernel-LA57-FoD-Package~",

    # --- 安全与身份（会破坏功能）---
    "Microsoft-Windows-Hello-Face-Package~",
    "Microsoft-Windows-Hello-BioEnrollment-Package~",
    "Microsoft-Windows-BitLocker-DriveEncryption-FVE-Package~",
    "Microsoft-Windows-TPM-WMI-Provider-Package~",

    # --- 辅助工具 ---
    "Microsoft-Windows-Narrator-App-Package~",
    "Microsoft-Windows-Magnifier-App-Package~",

    # --- 其他功能 ---
    "Microsoft-Windows-Printing-PMCPPC-FoD-Package~",
    "Microsoft-Windows-WebcamExperience-Package~",
    "Microsoft-Media-MPEG2-Decoder-Package~",
    "Microsoft-Windows-Wallpaper-Content-Extended-FoD-Package~"
)

$allPackages = & dism /image:$scratchDir /Get-Packages /Format:Table
$allPackages = $allPackages -split "`n" | Select-Object -Skip 1

foreach ($packagePattern in $packagePatterns) {
    # 筛选要移除的功能包
    $packagesToRemove = $allPackages | Where-Object { $_ -like "$packagePattern*" }

    foreach ($package in $packagesToRemove) {
        # 提取功能包标识
        $packageIdentity = ($package -split "\s+")[0]

        Write-Host "正在移除 $packageIdentity..."
        & dism /image:$scratchDir /Remove-Package /PackageName:$packageIdentity 
    }
}

# 移除预编译的 .NET 程序集
Write-Host "正在移除预编译的 .NET 程序集 (本机映像)..."
Remove-Item -Path "$scratchDir\Windows\assembly\NativeImages_*" -Recurse -Force -ErrorAction SilentlyContinue

# 手动删除文件
Write-Host "正在进行彻底的手动文件删除..."
$winDir = "$scratchDir\Windows"

# 精简驱动程序存储
Write-Host "正在精简驱动程序存储...（移除非必要的驱动程序）"
$driverRepo = Join-Path -Path $winDir -ChildPath "System32\DriverStore\FileRepository"
$patternsToRemove = @(
    'prn*',        # 打印机驱动程序 (e.g., prnms001.inf, prnge001.inf)
    'scan*',       # 扫描仪驱动程序
    'mfd*',        # 多功能设备驱动程序
    'wscsmd.inf*', # 智能卡读卡器
    'tapdrv*',     # 磁带驱动器
    'rdpbus.inf*', # 远程桌面虚拟总线
    'tdibth.inf*'  # 蓝牙个人区域网络
)

# 获取所有驱动程序包并删除匹配模式的驱动程序包
Get-ChildItem -Path $driverRepo -Directory | ForEach-Object {
    $driverFolder = $_.Name
    foreach ($pattern in $patternsToRemove) {
        if ($driverFolder -like $pattern) {
            Write-Host "正在移除非必要驱动程序包: $driverFolder"
            Remove-Item -Path $_.FullName -Recurse -Force
            break # 找到匹配项后移动到下一个文件夹
        }
    }
}

# 精简字体文件
$fontsPath = Join-Path -Path $winDir -ChildPath "Fonts"
# 【修改】 在排除列表(Exclude)里添加了中文相关字体，并删除了后面主动删除亚洲字体的命令
if (Test-Path $fontsPath) { Get-ChildItem -Path $fontsPath -Exclude "segoe*.*", "tahoma*.*", "marlett.ttf", "8541oem.fon", "segui*.*", "consol*.*", "lucon*.*", "calibri*.*", "arial*.*", "times*.*", "cou*.*", "8*.*", "msyh*", "msjh*", "simsun*", "mingli*" | Remove-Item -Recurse -Force }

# 移除其他组件
Remove-Item -Path (Join-Path -Path $winDir -ChildPath "Speech\Engines\TTS") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$scratchDir\ProgramData\Microsoft\Windows Defender\Definition Updates" -Recurse -Force -ErrorAction SilentlyContinue
# 【修改】 删除了 Remove-Item InputMethod\CHS 的命令
Remove-Item -Path "$scratchDir\Windows\System32\InputMethod\CHT" -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path "$scratchDir\Windows\System32\InputMethod\JPN" -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path "$scratchDir\Windows\System32\InputMethod\KOR" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$scratchDir\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path -Path $winDir -ChildPath "Web") -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path (Join-Path -Path $winDir -ChildPath "Help") -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path (Join-Path -Path $winDir -ChildPath "Cursors") -Recurse -Force -ErrorAction SilentlyContinue

# 移除 Edge, WinRE 和 OneDrive
Write-Host "正在移除 Edge、WinRE 和 OneDrive..."
Remove-Item -Path "$scratchDir\Program Files (x86)\Microsoft\Edge*" -Recurse -Force
if ($architecture -eq 'amd64') { $folderPath = Get-ChildItem -Path "$scratchDir\Windows\WinSxS" -Filter "amd64_microsoft-edge-webview_31bf3856ad364e35*" -Directory | Select-Object -ExpandProperty FullName }
if ($folderPath) { Remove-Item -Path $folderPath -Recurse -Force  }
Remove-Item -Path "$scratchDir\Windows\System32\Microsoft-Edge-Webview" -Recurse -Force
Remove-Item -Path "$scratchDir\Windows\System32\Recovery\winre.wim" -Recurse -Force
New-Item -Path "$scratchDir\Windows\System32\Recovery\winre.wim" -ItemType File -Force
Remove-Item -Path "$scratchDir\Windows\System32\OneDriveSetup.exe" -Force
& 'dism' "/image:$scratchDir" '/Cleanup-Image' '/StartComponentCleanup' '/ResetBase'

# 处理 WinSxS 文件夹
Write-Host "正在获取 WinSxS 文件夹所有权，请稍候..."
& 'takeown' '/f' "$mainOSDrive\scratchdir\Windows\WinSxS" '/r'
& 'icacls' "$mainOSDrive\scratchdir\Windows\WinSxS" '/grant' "$($adminGroup.Value):(F)" '/T' '/C'
Write-host "完成!"

# 创建精简版 WinSxS
$folderPath = Join-Path -Path $mainOSDrive -ChildPath "\scratchdir\Windows\WinSxS_edit"
$sourceDirectory = "$mainOSDrive\scratchdir\Windows\WinSxS"
$destinationDirectory = "$mainOSDrive\scratchdir\Windows\WinSxS_edit"
New-Item -Path $folderPath -ItemType Directory
# 根据架构复制必要文件
if ($architecture -eq "amd64") {
    $dirsToCopy = @(
        "x86_microsoft.windows.common-controls_6595b64144ccf1df_*",
        "x86_microsoft.windows.gdiplus_6595b64144ccf1df_*",
        "x86_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*",
        "x86_microsoft.windows.isolationautomation_6595b64144ccf1df_*",
        "x86_microsoft-windows-s..ngstack-onecorebase_31bf3856ad364e35_*",
        "x86_microsoft-windows-s..stack-termsrv-extra_31bf3856ad364e35_*",
        "x86_microsoft-windows-servicingstack_31bf3856ad364e35_*",
        "x86_microsoft-windows-servicingstack-inetsrv_*",
        "x86_microsoft-windows-servicingstack-onecore_*",
        "amd64_microsoft.vc80.crt_1fc8b3b9a1e18e3b_*",
        "amd64_microsoft.vc90.crt_1fc8b3b9a1e18e3b_*",
        "amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*",
        "amd64_microsoft.windows.common-controls_6595b64144ccf1df_*",
        "amd64_microsoft.windows.gdiplus_6595b64144ccf1df_*",
        "amd64_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*",
        "amd64_microsoft.windows.isolationautomation_6595b64144ccf1df_*",
        "amd64_microsoft-windows-s..stack-inetsrv-extra_31bf3856ad364e35_*",
        "amd64_microsoft-windows-s..stack-msg.resources_31bf3856ad364e35_*",
        "amd64_microsoft-windows-s..stack-termsrv-extra_31bf3856ad364e35_*",
        "amd64_microsoft-windows-servicingstack_31bf3856ad364e35_*",
        "amd64_microsoft-windows-servicingstack-inetsrv_31bf3856ad364e35_*",
        "amd64_microsoft-windows-servicingstack-msg_31bf3856ad364e35_*",
        "amd64_microsoft-windows-servicingstack-onecore_31bf3856ad364e35_*",
        "Catalogs",
        "FileMaps",
        "Fusion",
        "InstallTemp",
        "Manifests",
        "x86_microsoft.vc80.crt_1fc8b3b9a1e18e3b_*",
        "x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b_*",
        "x86_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*",
        "x86_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*"
    )
    # 复制每个目录
    foreach ($dir in $dirsToCopy) {
        $sourceDirs = Get-ChildItem -Path $sourceDirectory -Filter $dir -Directory
        foreach ($sourceDir in $sourceDirs) {
            $destDir = Join-Path -Path $destinationDirectory -ChildPath $sourceDir.Name
            Write-Host "Copying $sourceDir.FullName to $destDir"
            Copy-Item -Path $sourceDir.FullName -Destination $destDir -Recurse -Force
        }
    }
}
elseif ($architecture -eq "arm64") {
    $dirsToCopy = @(
        "arm64_microsoft-windows-servicingstack-onecore_31bf3856ad364e35_*",
        "Catalogs"
        "FileMaps"
        "Fusion"
        "InstallTemp"
        "Manifests"
        "SettingsManifests"
        "Temp"
        "x86_microsoft.vc80.crt_1fc8b3b9a1e18e3b_*"
        "x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b_*"
        "x86_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*"
        "x86_microsoft.windows.common-controls_6595b64144ccf1df_*"
        "x86_microsoft.windows.gdiplus_6595b64144ccf1df_*"
        "x86_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*"
        "x86_microsoft.windows.isolationautomation_6595b64144ccf1df_*"
        "arm_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*"
        "arm_microsoft.windows.common-controls_6595b64144ccf1df_*"
        "arm_microsoft.windows.gdiplus_6595b64144ccf1df_*"
        "arm_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*"
        "arm_microsoft.windows.isolationautomation_6595b64144ccf1df_*"
        "arm64_microsoft.vc80.crt_1fc8b3b9a1e18e3b_*"
        "arm64_microsoft.vc90.crt_1fc8b3b9a1e18e3b_*"
        "arm64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_*"
        "arm64_microsoft.windows.common-controls_6595b64144ccf1df_*"
        "arm64_microsoft.windows.gdiplus_6595b64144ccf1df_*"
        "arm64_microsoft.windows.i..utomation.proxystub_6595b64144ccf1df_*"
        "arm64_microsoft.windows.isolationautomation_6595b64144ccf1df_*"
        "arm64_microsoft-windows-servicing-adm_31bf3856ad364e35_*"
        "arm64_microsoft-windows-servicingcommon_31bf3856ad364e35_*"
        "arm64_microsoft-windows-servicing-onecore-uapi_31bf3856ad364e35_*"
        "arm64_microsoft-windows-servicingstack_31bf3856ad364e35_*"
        "arm64_microsoft-windows-servicingstack-inetsrv_31bf3856ad364e35_*"
        "arm64_microsoft-windows-servicingstack-msg_31bf3856ad364e35_*"
    )
}
foreach ($dir in $dirsToCopy) {
        $sourceDirs = Get-ChildItem -Path $sourceDirectory -Filter $dir -Directory
        foreach ($sourceDir in $sourceDirs) {
            $destDir = Join-Path -Path $destinationDirectory -ChildPath $sourceDir.Name
            Write-Host "正在复制 $sourceDir.FullName 到 $destDir"
            Copy-Item -Path $sourceDir.FullName -Destination $destDir -Recurse -Force
        }
    }

# 替换 WinSxS 文件夹
Write-Host "正在删除原 WinSxS，请稍候..."
        Remove-Item -Path $mainOSDrive\scratchdir\Windows\WinSxS -Recurse -Force

Rename-Item -Path $mainOSDrive\scratchdir\Windows\WinSxS_edit -NewName $mainOSDrive\scratchdir\Windows\WinSxS
Write-Host "完成!"

# 加载注册表配置单元进行修改
reg load HKLM\zCOMPONENTS $ScratchDisk\scratchdir\Windows\System32\config\COMPONENTS | Out-Null
reg load HKLM\zDEFAULT $ScratchDisk\scratchdir\Windows\System32\config\default | Out-Null
reg load HKLM\zNTUSER $ScratchDisk\scratchdir\Users\Default\ntuser.dat | Out-Null
reg load HKLM\zSOFTWARE $ScratchDisk\scratchdir\Windows\System32\config\SOFTWARE | Out-Null
reg load HKLM\zSYSTEM $ScratchDisk\scratchdir\Windows\System32\config\SYSTEM | Out-Null
# 绕过系统要求
Write-Host "正在绕过系统要求（在系统镜像上）:"
& 'reg' 'add' 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV1' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV2' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV1' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV2' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassCPUCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassRAMCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassSecureBootCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassStorageCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassTPMCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\MoSetup' '/v' 'AllowUpgradesWithUnsupportedTPMOrCPU' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
# 禁用推广应用
Write-Host "正在禁用推广应用:"
& 'reg' 'add' 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'OemPreInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'PreInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SilentInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' '/v' 'DisableWindowsConsumerFeatures' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'ContentDeliveryAllowed' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start' '/v' 'ConfigureStartPins' '/t' 'REG_SZ' '/d' '{"pinnedList": [{}]}' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'ContentDeliveryAllowed' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'ContentDeliveryAllowed' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'FeatureManagementEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'OemPreInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'PreInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'PreInstalledAppsEverEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SilentInstalledAppsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SoftLandingEnabled' '/t' 'REG_DWORD' '/d' '0' '/f'| Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContentEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-310093Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-338388Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-338389Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-338393Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-353694Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContent-353696Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SubscribedContentEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' '/v' 'SystemPaneSuggestionsEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\PushToInstall' '/v' 'DisablePushToInstall' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\MRT' '/v' 'DontOfferThroughWUAU' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'delete' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions' '/f' | Out-Null
& 'reg' 'delete' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' '/v' 'DisableConsumerAccountStateContent' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' '/v' 'DisableCloudOptimizedContent' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Write-Host "在 OOBE 中启用本地账户:"
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' '/v' 'BypassNRO' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Copy-Item -Path "$PSScriptRoot\autounattend.xml" -Destination "$ScratchDisk\scratchdir\Windows\System32\Sysprep\autounattend.xml" -Force | Out-Null
Write-Host "禁用保留存储:"
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' '/v' 'ShippedWithReserves' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
Write-Host "禁用BitLocker设备加密"
& 'reg' 'add' 'HKLM\zSYSTEM\ControlSet001\Control\BitLocker' '/v' 'PreventDeviceEncryption' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Write-Host "禁用聊天图标:"
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' '/v' 'ChatIcon' '/t' 'REG_DWORD' '/d' '3' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' '/v' 'TaskbarMn' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
Write-Host "移除 Edge 相关注册表项"
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge" /f | Out-Null
reg delete "HKEY_LOCAL_MACHINE\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update" /f | Out-Null
Write-Host "禁用 OneDrive 文件夹备份"
& 'reg' 'add' "HKLM\zSOFTWARE\Policies\Microsoft\Windows\OneDrive" '/v' 'DisableFileSyncNGSC' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Write-Host "禁用数据收集:"
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' '/v' 'Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Privacy' '/v' 'TailoredExperiencesWithDiagnosticDataEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' '/v' 'HasAccepted' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Input\TIPC' '/v' 'Enabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' '/v' 'RestrictImplicitInkCollection' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' '/v' 'RestrictImplicitTextCollection' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization\TrainedDataStore' '/v' 'HarvestContacts' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Software\Microsoft\Personalization\Settings' '/v' 'AcceptedPrivacyPolicy' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection' '/v' 'AllowTelemetry' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\ControlSet001\Services\dmwappushservice' '/v' 'Start' '/t' 'REG_DWORD' '/d' '4' '/f' | Out-Null
Write-Host "阻止安装 DevHome 和 Outlook:"
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate' '/v' 'workCompleted' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate' '/v' 'workCompleted' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'delete' 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate' '/f' | Out-Null
& 'reg' 'delete' 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate' '/f' | Out-Null
Write-Host "禁用 Copilot"
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' '/v' 'TurnOffWindowsCopilot' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Edge' '/v' 'HubsSidebarEnabled' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer' '/v' 'DisableSearchBoxSuggestions' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Write-Host "阻止安装 Teams:"
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Teams' '/v' 'DisableInstallation' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Write-Host "阻止安装 New Outlook":
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Mail' '/v' 'PreventRun' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
$tasksPath = "C:\scratchdir\Windows\System32\Tasks"

Write-Host "移除预设任务计划配置文件..."

# 应用程序兼容性评定器
Remove-Item -Path "$tasksPath\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" -Force -ErrorAction SilentlyContinue

# 客户体验改善计划（删除整个文件夹及其中的所有任务）
Remove-Item -Path "$tasksPath\Microsoft\Windows\Customer Experience Improvement Program" -Recurse -Force -ErrorAction SilentlyContinue

# 程序数据更新器
Remove-Item -Path "$tasksPath\Microsoft\Windows\Application Experience\ProgramDataUpdater" -Force -ErrorAction SilentlyContinue

# 磁盘检查代理
Remove-Item -Path "$tasksPath\Microsoft\Windows\Chkdsk\Proxy" -Force -ErrorAction SilentlyContinue

# Windows 错误报告（队列报告）
Remove-Item -Path "$tasksPath\Microsoft\Windows\Windows Error Reporting\QueueReporting" -Force -ErrorAction SilentlyContinue

Write-Host "任务文件已删除。"
Write-Host "禁用 Windows 更新..."
& 'reg' 'add' "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" '/v' 'StopWUPostOOBE1' '/t' 'REG_SZ' '/d' 'net stop wuauserv' '/f'
& 'reg' 'add' "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" '/v' 'StopWUPostOOBE2' '/t' 'REG_SZ' '/d' 'sc stop wuauserv' '/f'
& 'reg' 'add' "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" '/v' 'StopWUPostOOBE3' '/t' 'REG_SZ' '/d' 'sc config wuauserv start= disabled' '/f'
& 'reg' 'add' "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" '/v' 'DisbaleWUPostOOBE1' '/t' 'REG_SZ' '/d' 'reg add HKLM\SYSTEM\CurrentControlSet\Services\wuauserv /v Start /t REG_DWORD /d 4 /f' '/f'
& 'reg' 'add' "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" '/v' 'DisbaleWUPostOOBE2' '/t' 'REG_SZ' '/d' 'reg add HKLM\SYSTEM\ControlSet001\Services\wuauserv /v Start /t REG_DWORD /d 4 /f' '/f'
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' '/v' 'DoNotConnectToWindowsUpdateInternetLocations' '/t' 'REG_DWORD' '/d' '1' '/f'
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' '/v' 'DisableWindowsUpdateAccess' '/t' 'REG_DWORD' '/d' '1' '/f'
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' '/v' 'WUServer' '/t' 'REG_SZ' '/d' 'localhost' '/f'
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' '/v' 'WUStatusServer' '/t' 'REG_SZ' '/d' 'localhost' '/f'
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' '/v' 'UpdateServiceUrlAlternate' '/t' 'REG_SZ' '/d' 'localhost' '/f'
& 'reg' 'add' 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' '/v' 'UseWUServer' '/t' 'REG_DWORD' '/d' '1' '/f'
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' '/v' 'DisableOnline' '/t' 'REG_DWORD' '/d' '1' '/f'
& 'reg' 'add' 'HKLM\zSYSTEM\ControlSet001\Services\wuauserv' '/v' 'Start' '/t' 'REG_DWORD' '/d' '4' '/f'
& 'reg' 'delete' 'HKLM\zSYSTEM\ControlSet001\Services\WaaSMedicSVC' '/f'
& 'reg' 'delete' 'HKLM\zSYSTEM\ControlSet001\Services\UsoSvc' '/f'
& 'reg' 'add' 'HKEY_LOCAL_MACHINE\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' '/v' 'NoAutoUpdate' '/t' 'REG_DWORD' '/d' '1' '/f'
Write-Host "禁用 Windows Defender"
$servicePaths = @(
    "WinDefend",
    "WdNisSvc",
    "WdNisDrv",
    "WdFilter",
    "Sense"
)

foreach ($path in $servicePaths) {
    Set-ItemProperty -Path "HKLM:\zSYSTEM\ControlSet001\Services\$path" -Name "Start" -Value 4
}
& 'reg' 'add' 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' '/v' 'SettingsPageVisibility' '/t' 'REG_SZ' '/d' 'hide:virus;windowsupdate' '/f' 
Write-Host "优化完成!"
Write-Host "卸载注册表..."
reg unload HKLM\zCOMPONENTS >null
reg unload HKLM\zDEFAULT >null
reg unload HKLM\zNTUSER >null
reg unload HKLM\zSOFTWARE
reg unload HKLM\zSYSTEM >null

Write-Host "加载注册表配置单元以移除服务..."
reg load HKLM\zSYSTEM "$scratchDir\Windows\System32\config\SYSTEM" | Out-Null
$servicesToRemove = @(
    'Spooler',
    'PrintNotify',
    'Fax',
    'RemoteRegistry',
    'diagsvc',
    'WerSvc',
    'PcaSvc',
    #'DPS',
    # 'Audiosrv', # 关键提示：移除此项很可能是导致启动失败的原因。
    # 'AudioEndpointBuilder', # 关键提示：Audiosrv的依赖项。
    'MapsBroker',
    'WalletService',
    'BthAvctpSvc',
    'BluetoothUserService',
    # 'WbioSrvc', # 风险：可能导致登录屏幕挂起。
    'wuauserv',
    'UsoSvc',
    'WaaSMedicSvc'
)
foreach ($service in $servicesToRemove) { Write-Host "正在移除服务: $service"; & 'reg' 'delete' "HKLM\zSYSTEM\ControlSet001\Services\$service" /f | Out-Null }
reg unload HKLM\zSYSTEM

Write-Host "清理并卸载 install.wim..."
& 'dism' "/image:$scratchDir" '/Cleanup-Image' '/StartComponentCleanup' '/ResetBase'
& 'dism' '/unmount-image' "/mountdir:$scratchDir" '/commit'
& 'dism' '/Export-Image' "/SourceImageFile:$mainOSDrive\nano11\sources\install.wim" "/SourceIndex:$index" "/DestinationImageFile:$mainOSDrive\nano11\sources\install2.wim" '/compress:max'
Remove-Item -Path "$mainOSDrive\nano11\sources\install.wim" -Force
Rename-Item -Path "$mainOSDrive\nano11\sources\install2.wim" -NewName "install.wim"

Write-Host "精简 boot.wim..."
$bootWimPath = "$($env:SystemDrive)\nano11\sources\boot.wim"
Write-Host "获取 $bootWimPath 的所有权..."
& takeown "/F" $bootWimPath
& icacls $bootWimPath "/grant" "$($adminGroup.Value):(F)"
try {
    Set-ItemProperty -Path $bootWimPath -Name IsReadOnly -Value $false -ErrorAction Stop
} catch {
}
Write-Host "从 boot.wim 导出修改后安装镜像（索引2）..."
$newBootWimPath = "$($env:SystemDrive)\nano11\sources\boot_new.wim"
$finalBootWimPath = "$($env:SystemDrive)\nano11\sources\boot_final.wim"
& 'dism' '/Export-Image' "/SourceImageFile:$bootWimPath" '/SourceIndex:2' "/DestinationImageFile:$newBootWimPath"
& 'dism' '/mount-image' "/imagefile:$newbootWimPath" '/index:1' "/mountdir:$scratchDir"
reg load HKLM\zDEFAULT $ScratchDisk\scratchdir\Windows\System32\config\default | Out-Null
reg load HKLM\zNTUSER $ScratchDisk\scratchdir\Users\Default\ntuser.dat | Out-Null
reg load HKLM\zSOFTWARE $ScratchDisk\scratchdir\Windows\System32\config\SOFTWARE | Out-Null
reg load HKLM\zSYSTEM $ScratchDisk\scratchdir\Windows\System32\config\SYSTEM | Out-Null
Write-Host "绕过系统要求（在安装镜像上）:"
& 'reg' 'add' 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV1' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV2' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV1' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' '/v' 'SV2' '/t' 'REG_DWORD' '/d' '0' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassCPUCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassRAMCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassSecureBootCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassStorageCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\LabConfig' '/v' 'BypassTPMCheck' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
& 'reg' 'add' 'HKLM\zSYSTEM\Setup\MoSetup' '/v' 'AllowUpgradesWithUnsupportedTPMOrCPU' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Write-Host "禁用 BitLocker 设备加密"
& 'reg' 'add' 'HKLM\zSYSTEM\ControlSet001\Control\BitLocker' '/v' 'PreventDeviceEncryption' '/t' 'REG_DWORD' '/d' '1' '/f' | Out-Null
Write-Host "优化完成!"
Write-Host "卸载注册表..."
reg unload HKLM\zNTUSER
reg unload HKLM\zDEFAULT
reg unload HKLM\zSOFTWARE
reg unload HKLM\zSYSTEM >null
Start-Sleep -Seconds 10
& 'dism' '/unmount-image' "/mountdir:$scratchDir" '/commit'
& takeown "/F" $bootWimPath
& icacls $bootWimPath "/grant" "$($adminGroup.Value):(F)"
Remove-Item -Path $bootWimPath -Force
& 'dism' '/Export-Image' "/SourceImageFile:$newBootWimPath" '/SourceIndex:1' "/DestinationImageFile:$finalBootWimPath" '/compress:max'
Remove-Item -Path $newBootWimPath -Force
Rename-Item -Path $finalBootWimPath -NewName "boot.wim"

Clear-Host
Write-Host "将最终镜像导出为高压缩 ESD 格式..."
& dism /Export-Image /SourceImageFile:"$mainOSdrive\nano11\sources\install.wim" /SourceIndex:1 /DestinationImageFile:"$mainOSdrive\nano11\sources\install.esd" /Compress:recovery
Remove-Item "$mainOSdrive\nano11\sources\install.wim"  2>&1

Write-Host "正在对安装文件夹根目录进行最终清理..."
$isoRoot = "$mainOSDrive\nano11"
$keepList = @("boot", "efi", "sources", "bootmgr", "bootmgr.efi", "setup.exe", "autounattend.xml")
Get-ChildItem -Path $isoRoot | Where-Object { $_.Name -notin $keepList } | ForEach-Object {
    Write-Host "从 ISO 根目录移除非必要文件/文件夹: $($_.Name)"
    Remove-Item -Path $_.FullName -Recurse -Force
}

Write-Host "创建可启动 ISO 镜像..."
$OSCDIMG = "$PSScriptRoot\oscdimg.exe"
if (-not (Test-Path $OSCDIMG)) { $url = "https://msdl.microsoft.com/download/symbols/oscdimg.exe/3D44737265000/oscdimg.exe"; Invoke-WebRequest -Uri $url -OutFile $OSCDIMG }
& "$OSCDIMG" '-m' '-o' '-u2' '-udfver102' "-bootdata:2#p0,e,b$mainOSdrive\nano11\boot\etfsboot.com#pEF,e,b$mainOSdrive\nano11\efi\microsoft\boot\efisys.bin" "$mainOSdrive\nano11" "$PSScriptRoot\nano11.iso"

Write-Host "创建完成! 您的 ISO 文件名为 nano11.iso"
Read-Host "按 Enter 键执行清理并退出。"
& 'dism' '/unmount-image' "/mountdir:$scratchDir" '/discard'
Remove-Item -Path "$mainOSdrive\nano11" -Recurse -Force
Remove-Item -Path "$mainOSdrive\scratchdir" -Recurse -Force
Stop-Transcript
exit
}
else {
    Write-Host "您选择不继续，脚本现在将退出。"
    exit
}