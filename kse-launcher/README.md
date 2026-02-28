# KSE launcher

The KSE launcher is a small Windows executable that detects Java runtime installations 
with [Bill Stewart's JavaInfo.dll](https://github.com/Bill-Stewart/JavaInfo) and 
then launches KeyStore Explorer with the newest JRE.  

The launcher searches first for a local folder with the name "jre" and uses this
Java runtime preferredly. This allows bundling a specific Java version with KSE.

## Requirements

- Install rustup (see https://www.rust-lang.org/tools/install)
- Install and use toolchain for 64bit Windows: `rustup default stable-i686-pc-windows-gnu`
- If on Ubuntu, install the mingw-w64 toolchain: `sudo apt-get install -y mingw-w64`

## Building

`cd kse-launcher`
`cargo build --release`
`cp kse-launcher/target/x86_64-pc-windows-gnu/release/kse-launcher.exe kse/res/kse.exe`