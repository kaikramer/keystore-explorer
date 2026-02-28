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

#![windows_subsystem = "windows"]

use std::{env, process, ptr};
use std::ffi::{CString, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::FreeLibrary;
use windows_sys::Win32::System::LibraryLoader::{
    AddDllDirectory, GetProcAddress, LoadLibraryExW,
    SetDllDirectoryW, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_USER_DIRS,
};
use windows_sys::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;
use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_ICONERROR, MB_OK};

const SPLASH_FILE: &str = "splash.png";

type Handle = *mut core::ffi::c_void;

type GetJavaHomeFn = unsafe extern "system" fn(*mut u16, u32) -> u32;
type IsBinary64BitFn = unsafe extern "system" fn(*const u16, *mut u32) -> u32;
type JliLaunchFn = unsafe extern "system" fn(
    argc: i32, argv: *const *const i8,
    jargc: i32, jargv: *const *const i8,
    appclassc: i32, appclassv: *const *const i8,
    fullversion: *const i8, dotversion: *const i8,
    pname: *const i8, lname: *const i8,
    javaargs: u8, cpwildcard: u8, javaw: u8,
    ergo: i32,
) -> i32;
type SplashInitFn = unsafe extern "system" fn() -> i32;
type SplashLoadFileFn = unsafe extern "system" fn(*const i8) -> i32;

fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn show_error_message(title: &str, message: &str) {
    let title_c = CString::new(title).unwrap_or_default();
    let message_c = CString::new(message).unwrap_or_default();
    unsafe {
        MessageBoxA(ptr::null_mut(), message_c.as_ptr() as _, title_c.as_ptr() as _, MB_OK | MB_ICONERROR);
    }
}

fn get_app_dir() -> PathBuf {
    match env::current_exe() {
        Ok(exe_path) => exe_path.parent().unwrap().to_path_buf(),
        Err(e) => {
            show_error_message("Error Detecting Current Directory", &e.to_string());
            process::exit(1);
        }
    }
}

unsafe fn load_java_info_lib() -> Handle {
    let lib_wide = to_wide_null("JavaInfo.dll");
    let handle = unsafe { LoadLibraryExW(lib_wide.as_ptr(), ptr::null_mut(), 0) };
    if handle.is_null() {
        show_error_message("Error", "Error loading JavaInfo.dll!\nIt has to be in the same folder as kse.exe!");
        process::exit(1);
    }
    handle
}

fn get_java_home() -> String {
    unsafe {
        let handle = load_java_info_lib();
        let get_fn: GetJavaHomeFn = std::mem::transmute(GetProcAddress(handle, b"GetJavaHome\0".as_ptr()).unwrap());

        // first call to GetJavaHome is for determining the length of the path
        let java_home_length = get_fn(ptr::null_mut(), 0);
        let mut java_home = vec![0u16; (java_home_length as usize) + 1];

        let result = get_fn(java_home.as_mut_ptr(), java_home_length);
        if result == 0 {
            show_error_message("Error Detecting Java Installation", "No Java Runtime found! Please set JAVA_HOME!");
            process::exit(1);
        }

        FreeLibrary(handle);

        String::from_utf16_lossy(&java_home[0..java_home.len() - 1])
    }
}

fn is_64bit_dll(file_path: &str) -> bool {
    // loading JavaInfo.dll again should be avoided, but this happens only when no Java installation is found
    unsafe {
        let handle = load_java_info_lib();
        let proc = GetProcAddress(handle, b"IsBinary64Bit\0".as_ptr());
        if proc.is_none() {
            show_error_message("Error Detecting Java Installation", "Could not find symbol IsBinary64Bit");
            process::exit(1);
        }
        let is_binary_64bit: IsBinary64BitFn = std::mem::transmute(proc.unwrap());

        let path_wide = to_wide_null(file_path);
        let mut is_64bit: u32 = 0;
        if is_binary_64bit(path_wide.as_ptr(), &mut is_64bit) != 0 {
            show_error_message("Error Detecting Java Installation", "Could not call IsBinary64Bit");
            process::exit(1);
        }

        FreeLibrary(handle);
        is_64bit == 1
    }
}

fn set_app_user_model_id() {
    let app_id = to_wide_null("KeyStoreExplorer.App.54");
    unsafe {
        SetCurrentProcessExplicitAppUserModelID(app_id.as_ptr());
    }
}

fn show_splash_screen(jdk_dll_base_dir: &str, image_path: &str) {
    // Load splashscreen.dll before invoking JLI launch, see https://bugs.openjdk.org/browse/JDK-8250611
    let splash_dll_path = format!("{}\\splashscreen.dll", jdk_dll_base_dir);
    let splash_dll_wide = to_wide_null(&splash_dll_path);
    unsafe {
        let handle = LoadLibraryExW(
            splash_dll_wide.as_ptr(),
            ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS,
        );
        if handle.is_null() {
            return;
        }

        let splash_init_ptr = GetProcAddress(handle, b"SplashInit\0".as_ptr());
        let splash_load_file_ptr = GetProcAddress(handle, b"SplashLoadFile\0".as_ptr());
        if splash_init_ptr.is_none() || splash_load_file_ptr.is_none() {
            show_error_message("Error", "Failed to load required splash screen functions!");
            FreeLibrary(handle);
            return;
        }

        let splash_init: SplashInitFn = std::mem::transmute(splash_init_ptr.unwrap());
        let splash_load_file: SplashLoadFileFn = std::mem::transmute(splash_load_file_ptr.unwrap());

        if splash_init() == 0 {
            show_error_message("Error", "Failed to initialize splash screen!");
            FreeLibrary(handle);
            return;
        }

        let image_path_c = CString::new(image_path).unwrap();
        if splash_load_file(image_path_c.as_ptr()) == 0 {
            show_error_message("Error", &format!("Failed to load splash image: {}", image_path));
            FreeLibrary(handle);
        }
    }
}

fn add_dll_directories(jre_bin_dir: &str) {
    let dir_wide = to_wide_null(jre_bin_dir);
    unsafe {
        if SetDllDirectoryW(dir_wide.as_ptr()) == 0 {
            show_error_message("Error Loading DLL", "Could not set directory for DLL search path!");
            process::exit(1);
        }

        let server_dir = format!("{}\\server", jre_bin_dir);
        if PathBuf::from(&server_dir).is_dir() {
            let server_wide = to_wide_null(&server_dir);
            if AddDllDirectory(server_wide.as_ptr()).is_null() {
                show_error_message("Error Loading DLL", "Could not add directory to DLL search path!");
                process::exit(1);
            }
            return;
        }

        // IBM JDK
        let default_dir = format!("{}\\default", jre_bin_dir);
        if PathBuf::from(&default_dir).is_dir() {
            let default_wide = to_wide_null(&default_dir);
            if AddDllDirectory(default_wide.as_ptr()).is_null() {
                show_error_message("Error Loading DLL", "Could not add directory to DLL search path!");
                process::exit(1);
            }
        }
    }
}

fn load_jli_library() -> Handle {
    let local_jre_path = get_app_dir().join("jre");
    let jli_dll_path = if local_jre_path.is_dir() {
        local_jre_path.join("bin").join("jli.dll").to_string_lossy().into_owned()
    } else {
        format!("{}\\bin\\jli.dll", get_java_home())
    };
    let jdk_dll_base_dir = PathBuf::from(&jli_dll_path).parent().unwrap().to_string_lossy().into_owned();

    // Add the directories containing JVM DLLs to the search path for this application
    add_dll_directories(&jdk_dll_base_dir);

    show_splash_screen(&jdk_dll_base_dir, &format!("{}\\{}", get_app_dir().display(), SPLASH_FILE));

    let jli_path_wide = to_wide_null(&jli_dll_path);
    let handle = unsafe {
        LoadLibraryExW(jli_path_wide.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)
    };
    if handle.is_null() {
        if !is_64bit_dll(&jli_dll_path) {
            show_error_message(
                "Error Loading DLL",
                &format!("{} is a 32 bit Java runtime.\nPlease install a 64 bit JRE!", jli_dll_path),
            );
        } else {
            show_error_message("Error Loading DLL", "Could not load jli.dll!");
        }
        process::exit(1);
    }

    handle
}

fn call_jli_launch() {
    let jli_handle = load_jli_library();
    let jli_launch: JliLaunchFn = unsafe {
        let p = GetProcAddress(jli_handle, b"JLI_Launch\0".as_ptr());
        if p.is_none() {
            show_error_message("Error Loading DLL", "Failed to get JLI_Launch function address!");
            process::exit(1);
        }
        std::mem::transmute(p.unwrap())
    };

    let app_dir = get_app_dir();
    let splash_arg = format!("-splash:{}\\{}", app_dir.display(), SPLASH_FILE);
    let kse_jar = format!("{}\\kse.jar", app_dir.display());

    // Define the command-line arguments and JVM options
    let mut java_params: Vec<String> = vec![splash_arg, "-jar".to_string(), kse_jar];
    java_params.extend(env::args().skip(1));
    let jvm_params: Vec<String> = vec!["-Dkse.exe=true".to_string(), "-Djava.awt.headless=false".to_string()];

    let java_cstrings: Vec<CString> = java_params.iter().map(|s| CString::new(s.as_str()).unwrap()).collect();
    let jvm_cstrings: Vec<CString> = jvm_params.iter().map(|s| CString::new(s.as_str()).unwrap()).collect();
    let java_ptrs: Vec<*const i8> = java_cstrings.iter().map(|s| s.as_ptr()).collect();
    let jvm_ptrs: Vec<*const i8> = jvm_cstrings.iter().map(|s| s.as_ptr()).collect();

    let fullversion = CString::new("version").unwrap();
    let dotversion = CString::new("0.0").unwrap();
    let pname = CString::new("java").unwrap();
    let lname = CString::new("kse").unwrap();

    let result = unsafe {
        jli_launch(
            java_params.len() as i32, java_ptrs.as_ptr(),
            jvm_params.len() as i32, jvm_ptrs.as_ptr(),
            0, ptr::null(),
            fullversion.as_ptr(), dotversion.as_ptr(),
            pname.as_ptr(), lname.as_ptr(),
            (!jvm_params.is_empty()) as u8, // javaargs
            0u8,  // cpwildcard = JNI_FALSE
            1u8,  // javaw = JNI_TRUE
            0i32, // ergo
        )
    };

    if result != 0 {
        show_error_message("Error Starting Java", "Call to JLI_Launch failed!");
        process::exit(1);
    }
}

fn main() {
    set_app_user_model_id();
    call_jli_launch();
}
