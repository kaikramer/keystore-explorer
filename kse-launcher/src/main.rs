#![windows_subsystem = "windows"]
extern crate libloading;
extern crate winapi;

use std::{env, process, ptr};
use std::ffi::CString;
use std::path::Path;
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

fn get_jar_path() -> String {
    match env::current_exe() {
        Ok(exe_path) => exe_path.parent().unwrap().join("kse.jar").display().to_string(),
        Err(e) => {
            show_error_message(
                CString::new("Error Detecting Current Directory").unwrap(),
                CString::new(e.to_string()).unwrap());
            process::exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    // use local JRE preferably
    let java_path: String = if Path::new("jre").is_dir() {
        "jre\\bin\\javaw.exe".to_string()
    } else {
        format!("{}\\bin\\javaw.exe", get_java_home())
    };

    let kse_jar_path = get_jar_path();

    let java_process = Command::new(&java_path)
        .arg("-Dkse.exe=true")
        .arg("-splash:splash.png")
        .arg("-jar")
        .arg(kse_jar_path)
        // TODO allow multiple files!!
        .arg(args.get(1).get_or_insert(&"".to_string()))
        .spawn();

    if java_process.is_err() {
        show_error_message(
            CString::new("Error").unwrap(),
            CString::new(format!("Error running {}", &java_path)).unwrap());
    }
}
