fn main() {
    // release 嵌 requireAdministrator 清单走 tauri-build 官方通道（WindowsAttributes::app_manifest）。
    // 教训（调研 #11）：tauri-build 在 Windows 已用 tauri-winres 统一编资源，再自跑 winresource
    // 会二次编 RC → CVTRES CVT1100 duplicate resource。debug 不嵌清单，免 UAC 便于迭代（v1 传统）。
    if std::env::var("PROFILE").as_deref() == Ok("release") {
        tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(
            tauri_build::WindowsAttributes::new().app_manifest(include_str!("app.manifest")),
        ))
        .expect("tauri build failed (release, admin manifest)");
    } else {
        tauri_build::build();
    }
}
