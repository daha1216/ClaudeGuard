fn main() {
    // 仅 release 嵌入 requireAdministrator 清单与图标：
    // debug 版免清单，方便不经 UAC 快速迭代测试。
    let profile = std::env::var("PROFILE").unwrap_or_default();
    if profile != "release" {
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }
    #[cfg(target_os = "windows")]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_manifest(
            r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>"#,
        );
        res.set_icon("assets/claude.ico");
        if let Err(e) = res.compile() {
            println!("cargo:warning=winresource failed: {e}");
        }
    }
    println!("cargo:rerun-if-changed=assets/claude.ico");
}
