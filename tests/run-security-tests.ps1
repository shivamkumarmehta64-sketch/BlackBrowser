$ErrorActionPreference = "Stop"
$csc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) {
    throw ".NET 4.8 csc.exe not found at $csc"
}

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $outExe = Join-Path $PSScriptRoot "SecurityRegressionTests.exe"
    & $csc /nologo /platform:x64 /main:BlackBrowserTests.SecurityRegressionTests `
        /reference:System.IO.Compression.FileSystem.dll `
        /reference:System.IO.Compression.dll `
        /reference:Microsoft.Web.WebView2.Core.dll `
        /reference:Microsoft.Web.WebView2.WinForms.dll `
        /reference:System.Security.dll `
        /reference:System.Web.Extensions.dll `
        /out:$outExe `
        "tests\SecurityRegressionTests.cs" `
        "src\UpdateManager.cs" `
        "src\Program.cs" `
        "src\PasswordManager.cs" `
        "src\BrowserForm.cs" `
        "src\BrowserForm.Features.cs" `
        "src\AdShieldEngine.cs" `
        "src\BloomFilter.cs" `
        "src\BookmarksManager.cs" `
        "src\BrowserThemeControls.cs" `
        "src\ChromePainter.cs" `
        "src\CookieManager.cs" `
        "src\CustomDialsManager.cs" `
        "src\DefaultBrowserManager.cs" `
        "src\DownloadsManager.cs" `
        "src\ExtensionManager.cs" `
        "src\EyeCareOverlay.cs" `
        "src\GlassButton.cs" `
        "src\HistoryManager.cs" `
        "src\InternalUrlRouter.cs" `
        "src\LegalPagesManager.cs" `
        "src\LruTabManager.cs" `
        "src\MemoryTrimmer.cs" `
        "src\PrefixTrie.cs" `
        "src\QrCodeForm.cs" `
        "src\SessionManager.cs" `
        "src\SettingsForm.cs" `
        "src\SettingsStore.cs" `
        "src\SpeedDialPage.cs" `
        "src\SplashForm.cs"

    if ($LASTEXITCODE -ne 0) { throw "Failed to compile SecurityRegressionTests.exe" }

    & $outExe
    $testExit = $LASTEXITCODE
    Remove-Item -Force -ErrorAction SilentlyContinue $outExe
    if ($testExit -ne 0) { exit $testExit }
}
finally {
    Pop-Location
}
