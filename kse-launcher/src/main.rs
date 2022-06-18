/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2022 Kai Kramer
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

#![windows_subsystem = "windows"]
extern crate libloading;
extern crate winapi;

use std::{env, process, ptr};
use std::ffi::CString;
use std::path::{PathBuf};
use std::process::Command;

use libloading::{Library, Symbol};
use winapi::shared::minwindef::DWORD;
use winapi::um::winnt::LPWSTR;
use winapi::um::winuser::{MB_ICONERROR, MB_OK, MessageBoxA};

type GetJavaHome = unsafe extern "system" fn(LPWSTR, DWORD) -> DWORD;

fn show_error_message(title: CString, message: CString) {
    unsafe {
        MessageBoxA(
            ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

fn get_java_home() -> String {
    unsafe {
        let java_info_lib = match Library::new("JavaInfo.dll") {
            Ok(lib) => lib,
            Err(_e) => {
                show_error_message(
                    CString::new("Error").unwrap(),
                    CString::new(format!("Error loading JavaInfo.dll!\n\
                        It has to be in the same folder as kse.exe!")).unwrap());
                process::exit(1);
            }
        };
        let ji_get_java_home: Symbol<GetJavaHome> = java_info_lib.get(b"GetJavaHome").unwrap();

        // first call to getter in order to determine length of path for memory allocation
        let java_home_length = ji_get_java_home(ptr::null_mut(), 0);
        let mut java_home= vec![0u16; (java_home_length as usize) + 1]; // len + 0 byte

        let result = ji_get_java_home(java_home.as_mut_ptr(), java_home_length);
        if result == 0 {
            show_error_message(
                CString::new("Error Detecting Java Installation").unwrap(),
                CString::new("No Java Runtime found! Please set JAVA_HOME!").unwrap());
            process::exit(1);
        }

        // convert zero-terminated utf-16 string to Rust's utf-8 string
        String::from_utf16_lossy(&java_home[0..java_home.len() - 1])
    }
}

fn get_absolute_parent_path() -> PathBuf {
    match env::current_exe() {
        Ok(exe_path) => exe_path.parent().unwrap().to_path_buf(),
        Err(e) => {
            show_error_message(
                CString::new("Error Detecting Current Directory").unwrap(),
                CString::new(e.to_string()).unwrap());
            process::exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    let local_jre_path = get_absolute_parent_path().join("jre");
    let kse_jar_path = get_absolute_parent_path().join("kse.jar");

    // use local JRE preferably
    let java_path: String = if local_jre_path.is_dir() {
        format!("{}\\bin\\javaw.exe", local_jre_path.display().to_string())
    } else {
        format!("{}\\bin\\javaw.exe", get_java_home())
    };

    let java_process = Command::new(&java_path)
        .arg("-Dkse.exe=true")
        .arg("-splash:splash.png")
        .arg("-jar")
        .arg(kse_jar_path.display().to_string())
        .args(&args)
        .spawn();

    if java_process.is_err() {
        show_error_message(
            CString::new("Error").unwrap(),
            CString::new(format!("Error running {}", &java_path)).unwrap());
    }
}
