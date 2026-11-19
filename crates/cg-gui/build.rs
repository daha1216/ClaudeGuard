fn main() {
    // Note: `gpui` (`windows-manifest` feature enabled via `gpui_platform`) already embeds
    // `gpui.manifest.xml` (`level="asInvoker"`, `PerMonitorV2`, `Common-Controls` v6, `SegmentHeap`)
    // into `gpui.lib`. Adding `/MANIFEST:EMBED` here would trigger MSVC `CVTRES CVT1100`
    // (duplicate `RT_MANIFEST` #1 resource). Keep `app.manifest` as reference only.
    println!("cargo:rerun-if-changed=build.rs");
}
