#![windows_subsystem = "windows"]
extern crate winapi;

use std::env;
use std::process;
use std::process::Command;
use std::ffi::CString;
use winapi::um::winuser::MessageBoxA;
use winapi::um::winuser::MB_ICONERROR;
use winapi::um::winuser::MB_OK;
use winapi::shared::minwindef::UINT;

fn show_message(title: CString, message: CString, icon: UINT) {
    unsafe {
        MessageBoxA(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | icon,
        );
    }
}

fn get_java_path() -> String {
    let java_home = match env::var("JAVA_HOME") {
        Ok(jh) => jh,
        Err(..) => {
            show_message(
                CString::new("JAVA_HOME Not Found").unwrap(),
                CString::new("Please set the environment variable JAVA_HOME to a Java installation!").unwrap(),
                MB_ICONERROR);
            process::exit(1);
        },
    };

    let java_path = format!("{}\\bin\\javaw.exe", java_home);

    java_path
}

fn main() {

    let java_path = get_java_path();

    let java_process = Command::new(&java_path)
            .arg("-jar")
            .arg("kse.jar")
            .spawn();

    if java_process.is_err() {
        show_message(
            CString::new("Error").unwrap(),
            CString::new(format!("Error running {}", &java_path)).unwrap(),
            MB_ICONERROR);
    }
}
