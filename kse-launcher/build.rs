/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
 *
 * This file is part of KeyStore Explorer.
 *
 * KeyStore Explorer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KeyStore Explorer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KeyStore Explorer.  If not, see <http://www.gnu.org/licenses/>.
 */

use std::path::PathBuf;
use std::{env, process};

/// Parse a dotted version string like "5.6.1" into a (major, minor, patch, build) tuple
fn parse_version(version: &str) -> (u16, u16, u16, u16) {
    let mut parts = version.split('.').map(|p| p.parse::<u16>().unwrap_or(0));
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

/// Read `KSE.Version` from version.properties.
fn read_kse_version(manifest_dir: &std::path::Path) -> String {
    let props_path = manifest_dir.join("../kse/src/main/resources/org/kse/version.properties");
    let content = std::fs::read_to_string(&props_path).expect("Failed to read version.properties");
    for line in content.lines() {
        let line = line.trim();

        if let Some(rest) = line.strip_prefix("KSE.Version")
            && let Some(rest) = rest.trim().strip_prefix('=')
        {
            return rest.trim().to_string();
        }
    }
    panic!("KSE.Version not found in version.properties");
}

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "windows" {
        return;
    }

    println!("cargo:rerun-if-changed=../kse/src/main/resources/org/kse/version.properties");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let icon_path = manifest_dir.join("../kse/icons/kse.ico");
    let manifest_path = manifest_dir.join("kse.exe.manifest");

    let file_version = parse_version(&env::var("CARGO_PKG_VERSION").unwrap());

    let product_version = parse_version(&read_kse_version(&manifest_dir));

    let rc_content = format!(
        r#"
#include <winver.h>

// Application manifest (RT_MANIFEST)
1 24 "{manifest}"

// Application icon
IDI_ICON1 ICON "{icon}"

// Version information block
VS_VERSION_INFO VERSIONINFO
FILEVERSION     {fmaj},{fmin},{fpat},{fbld}
PRODUCTVERSION  {pmaj},{pmin},{ppat},{pbld}
FILEFLAGSMASK   VS_FFI_FILEFLAGSMASK
FILEFLAGS       0
FILEOS          VOS_NT_WINDOWS32
FILETYPE        VFT_APP
FILESUBTYPE     VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "FileDescription",  "KeyStore Explorer Launcher"
            VALUE "FileVersion",      "{fmaj}.{fmin}.{fpat}.{fbld}"
            VALUE "ProductName",      "KeyStore Explorer"
            VALUE "ProductVersion",   "{pmaj}.{pmin}.{ppat}.{pbld}"
            VALUE "CompanyName",      "KeyStore Explorer"
            VALUE "LegalCopyright",   "Copyright \xa9 2004-2026 Wayne Grant, Kai Kramer"
            VALUE "OriginalFilename", "kse.exe"
            VALUE "InternalName",     "kse"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        // English (US), Unicode
        VALUE "Translation", 0x0409, 1200
    END
END
"#,
        manifest = manifest_path.display(),
        icon = icon_path.display(),
        fmaj = file_version.0,
        fmin = file_version.1,
        fpat = file_version.2,
        fbld = file_version.3,
        pmaj = product_version.0,
        pmin = product_version.1,
        ppat = product_version.2,
        pbld = product_version.3,
    );

    let rc_path = out_dir.join("resource.rc");
    let obj_path = out_dir.join("resource.o");
    std::fs::write(&rc_path, &rc_content).expect("Failed to write resource.rc");

    let windres = if cfg!(target_os = "linux") {
        "x86_64-w64-mingw32-windres"
    } else {
        "windres"
    };

    let status = process::Command::new(windres)
        .args([
            rc_path.to_str().unwrap(),
            "-O",
            "coff",
            "-o",
            obj_path.to_str().unwrap(),
        ])
        .status()
        .unwrap_or_else(|e| panic!("Failed to run {windres}: {e}"));

    if !status.success() {
        panic!("windres failed with exit code: {status}");
    }

    // Link the object file directly — using a static lib loses the .rsrc section
    // with the GNU linker, so we pass the .o as a direct linker argument instead.
    println!("cargo:rustc-link-arg={}", obj_path.display());
}
