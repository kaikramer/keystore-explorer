#![windows_subsystem = "windows"]
extern crate winapi;

use std::env;
use std::process;
use std::process::Command;
use std::ffi::CString;
use winapi::um::winuser::MessageBoxA;
use winapi::um::winuser::MB_ICONERROR;
use winapi::um::winuser::MB_OK;

fn show_error_message(title: CString, message: CString) {
    unsafe {
        MessageBoxA(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

fn get_java_path() -> String {
    let java_home = match env::var("JAVA_HOME") {
        Ok(jh) => jh,
        Err(_) => {
            show_error_message(
                CString::new("JAVA_HOME Not Found").unwrap(),
                CString::new("Please set the environment variable JAVA_HOME to a Java installation!").unwrap());
            process::exit(1);
        },
    };

    format!("{}\\bin\\javaw.exe", java_home)
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
    let java_path = get_java_path();
    let kse_jar_path = get_jar_path();

    let java_process = Command::new(&java_path)
            .arg("-jar")
            .arg(kse_jar_path)
            .spawn();

    if java_process.is_err() {
        show_error_message(
            CString::new("Error").unwrap(),
            CString::new(format!("Error running {}", &java_path)).unwrap());
    }
}
