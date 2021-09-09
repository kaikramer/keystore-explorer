# KSE launcher

The KSE launcher is a small Windows executable that detects Java runtime installations 
with [Bill Stewart's JavaInfo.dll](https://github.com/Bill-Stewart/JavaInfo) and 
then launches KeyStore Explorer with the newest JRE.  

## Requirements

- Install rustup (see https://www.rust-lang.org/tools/install)
- Install and use toolchain for 32bit Windows: `rustup default stable-i686-pc-windows-gnu`

## Building

`cd kse-launcher`

`cargo build --release`

`strip .\target\i686-pc-windows-gnu\release\kse-launcher.exe`

`cp .\target\i686-pc-windows-gnu\release\kse-launcher.exe ..\kse\res\kse-launcher.exe`