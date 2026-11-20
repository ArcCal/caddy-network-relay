#!/usr/bin/env bash
set -euo pipefail
source_root=$1
history=$2
out=$3
mkdir -p "$out"
for product in tun; do
    case "$product" in nf) model=NetworkRelayNF ;; tun) model=NetworkRelayTun ;; esac
    parent="$source_root/network-relay-$product"
    cargo build --locked --release --manifest-path "$parent/Core/Cargo.toml" --lib
    modules="$out/modules-$product"
    mkdir -p "$modules"
    cp "$parent/App/Sources/${model}Bridge/include/${model}Bridge.h" "$modules/"
    cat > "$modules/module.modulemap" <<MAP
module ${model}Bridge {
    header "${model}Bridge.h"
    export *
}
MAP
    app="$parent/App/Sources/$model"
    swift=(xcrun swiftc -parse-as-library -swift-version 5 -O -target arm64-apple-macos27.0)
    "${swift[@]}" -whole-module-optimization -emit-object -emit-module -module-name "${model}Model" \
        -emit-module-path "$modules/${model}Model.swiftmodule" "$parent/App/Sources/${model}Model/"*.swift -o "$modules/model.o"
    main="$history"
    # Keep every production TLS policy and hostname check. The disposable CA
    # is trusted only by the SecTrust object for this test process.
    python3 diagnostics/linux-apple/fixture-native-trust.py "$app/NativeClient.swift" "$modules/NativeClient.swift"
    files=("$modules/NativeClient.swift" "$app/TunnelController.swift" "$app/Store.swift" "$app/NetworkChanges.swift" "$app/AboutInformation.swift")
    if [[ $product == tun ]]; then
        main="$modules/TunHistory.swift"
        sed -e 's/NetworkRelayNFModel/NetworkRelayTunModel/g' -e 's/serverIP: "127.0.0.1"/serverIP: "198.51.100.254"/g' -e '/let controller = TunnelController.shared/a\
            controller.setGlobalTUN(true)
' "$history" > "$main"
        files+=("$app/HostSession.swift")
    fi
    "${swift[@]}" -D NF_HISTORY_DIAGNOSTIC -I "$modules" -Xcc "-fmodule-map-file=$modules/module.modulemap" \
        -L "$parent/Core/target/release" "-lnetwork_relay_${product}_core" -framework Network -framework AppKit -framework Security \
        "$modules/model.o" "${files[@]}" "$main" -o "$out/$product"
done
