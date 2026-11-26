#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build
temporary=$(/usr/bin/mktemp -d "$PWD/build/test.XXXXXXXX")
trap '/bin/rm -rf -- "$temporary"' EXIT
/usr/bin/xcrun swiftc -swift-version 5 -warnings-as-errors \
    -module-cache-path "$PWD/build/ModuleCache" \
    -target arm64-apple-macos13.0 -sdk "$(/usr/bin/xcrun --sdk macosx --show-sdk-path)" \
    Sources/TunnelConfig.swift Sources/TunnelClient.swift Sources/PrivilegedScripts.swift \
    Sources/AuthorizationSession.swift Sources/SessionScripts.swift Sources/SessionToolkit.swift \
    Sources/ConnectionProfile.swift Sources/WebsiteRules.swift Sources/WebsiteProxyConfig.swift \
    Sources/NetworkDiagnosis.swift \
    Tests/Checks.swift -o "$temporary/checks"
"$temporary/checks"
