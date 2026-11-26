#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

if [[ $(/usr/bin/uname -s) != Darwin || $(/usr/bin/uname -m) != arm64 ]]; then
    printf '%s\n' '请在 Apple Silicon Mac 的原生 arm64 环境中构建。' >&2
    exit 1
fi
if ! /usr/bin/xcrun --find swiftc >/dev/null 2>&1; then
    printf '%s\n' '请先安装 Xcode 或运行 xcode-select --install 安装 Command Line Tools。' >&2
    exit 1
fi

mkdir -p build
temporary=$(/usr/bin/mktemp -d "$PWD/build/staging.XXXXXXXX")
trap '/bin/rm -rf -- "$temporary"' EXIT
app="$temporary/WireGuard Control.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp Info.plist "$app/Contents/Info.plist"
cp Resources/AppIcon.icns "$app/Contents/Resources/AppIcon.icns"
/usr/bin/plutil -lint "$app/Contents/Info.plist"
/usr/bin/xcrun swiftc -swift-version 5 -warnings-as-errors -O \
    -module-cache-path "$PWD/build/ModuleCache" \
    -target arm64-apple-macos13.0 -sdk "$(/usr/bin/xcrun --sdk macosx --show-sdk-path)" \
    Sources/*.swift -o "$app/Contents/MacOS/WireGuardControl"
/usr/bin/codesign --force --options runtime --sign - "$app"
/usr/bin/codesign --verify --strict "$app"

destination="$PWD/build/WireGuard Control.app"
/bin/rm -rf -- "$destination"
/bin/mv "$app" "$destination"
/bin/rm -f "$PWD/build/WireGuard-Control-arm64.zip"
/usr/bin/ditto -c -k --norsrc --keepParent "$destination" "$PWD/build/WireGuard-Control-arm64.zip"
printf '构建完成\n%s\n' "$PWD/build/WireGuard-Control-arm64.zip"
