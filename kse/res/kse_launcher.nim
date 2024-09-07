#
# Copyright 2004 - 2013 Wayne Grant
#           2013 - 2024 Kai Kramer
#
# This file is part of KeyStore Explorer.
#
# KeyStore Explorer is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# KeyStore Explorer is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with KeyStore Explorer.  If not, see <http://www.gnu.org/licenses/>.

# nim -d:mingw --cpu:amd64 -d:release --app:gui --opt:size --out:kse-launcher.exe c kse_launcher.nim

import os
import dynlib
import system/widestrs

type
    HANDLE* = int
    HWND* = HANDLE
    UINT* = int32
    DWORD* = int32
    LPCSTR* = cstring
    LPWSTR* = WideCString
    PCWSTR* = WideCString
    GetJavaHome = proc (path: LPWSTR, length: DWORD): DWORD {.gcsafe, stdcall.}
    IsBinary64Bit = proc (path: LPWSTR, is64Bit: ptr DWORD): DWORD {.gcsafe, stdcall.}

    JliLaunchProc = proc (argc: cint, argv: cstringArray, jargc: cint, jargv: cstringArray,
                           appclassc: cint, appclassv: cstringArray, fullversion: cstring, dotversion: cstring,
                           pname: cstring, lname: cstring, javaargs: uint8, cpwildcard: uint8, javaw: uint8,
                           ergo: cint): cint {.gcsafe, stdcall.}

const
    MB_ICONERROR = 0x00000010.DWORD
    MB_ICONWARNING = 0x00000030.DWORD
    MB_ICONINFO = 0x00000040.DWORD
    MB_ICONQUESTION = 0x00000020.DWORD
    JNI_TRUE = 1.uint8
    JNI_FALSE = 0.uint8

proc showMessageBox*(hWnd: HWND, lpText: LPCSTR, lpCaption: LPCSTR, uType: UINT): int32
    {.discardable, stdcall, dynlib: "user32", importc: "MessageBoxA".}

proc setCurrentProcessExplicitAppUserModelID*(appId: PCWSTR): int32
    {.discardable, stdcall, dynlib: "shell32", importc: "SetCurrentProcessExplicitAppUserModelID".}


proc getJavaHome(): string =
    let libHandle: LibHandle = loadLib("JavaInfo.dll")
    if libHandle == nil:
        showMessageBox(0, "Error loading JavaInfo.dll!\nIt has to be in the same folder as kse.exe!", "Error", MB_ICONERROR)
        quit(1)

    let javaInfoGetJavaHome = cast[GetJavaHome](symAddr(libHandle, "GetJavaHome"))

    # first call to GetJavaHome is for determining the length of the path
    var javaHomeLength = javaInfoGetJavaHome(nil, 0)
    var javaHomeWideStr = newWideCString(newString(javaHomeLength))

    javaHomeLength = javaInfoGetJavaHome(javaHomeWideStr, javaHomeLength)
    if javaHomeLength == 0:
        showMessageBox(0, "No Java Runtime found! Please set JAVA_HOME!", "Error Detecting Java Installation", MB_ICONERROR)
        quit(1)

    result = $javaHomeWideStr

    unloadLib(libHandle)


proc is64BitDll(filePath: string): bool =
    let libHandle: LibHandle = loadLib("JavaInfo.dll")
    if libHandle.isNil:
        showMessageBox(0, "Error loading JavaInfo.dll!\nIt has to be in the same folder as kse.exe!", "Error", MB_ICONERROR)
        quit(1)

    let isBinary64Bit = cast[IsBinary64Bit](symAddr(libHandle, "IsBinary64Bit"))
    if isBinary64Bit.isNil:
        showMessageBox(0, "Could not find symbol IsBinary64Bit", "Error Detecting Java Installation", MB_ICONERROR)
        quit(1)

    var is64Bit: ptr DWORD = cast[ptr DWORD](alloc(DWORD.sizeof))
    if isBinary64Bit(filePath.newWideCString(), is64Bit) != 0:
        showMessageBox(0, "Could not call IsBinary64Bit", "Error Detecting Java Installation", MB_ICONERROR)
        quit(1)

    result = is64Bit[] == DWORD(1)
    dealloc(is64Bit)
    unloadLib(libHandle)


proc getJliDllPath(): string =
    let localJrePath = getAppDir() & DirSep & "jre"

    if dirExists(localJrePath):
        result = localJrePath & DirSep & "bin" & DirSep & DirSep & "jli.dll"
    else:
        result = getJavaHome() & DirSep & "bin" & DirSep & DirSep & "jli.dll"


proc callJliLaunch() =
    let jliDllPath = getJliDllPath()
    let jliDllHandle: LibHandle = loadLib(jliDllPath)
    if jliDllHandle.isNil:
        if not is64BitDll(jliDllPath):
            let errMsg = cstring(jliDllPath & " is a 32 bit Java runtime.\nPlease install a 64 bit JRE!")
            showMessageBox(0, errMsg, "Error Loading DLL", MB_ICONERROR)
            quit(1)
        else:
            showMessageBox(0, "Could not load jli.dll!", "Error Loading DLL", MB_ICONERROR)
            quit(1)

    let jliLaunch: JliLaunchProc = cast[JliLaunchProc](symAddr(jliDllHandle, "JLI_Launch"))
    if jliLaunch.isNil:
        showMessageBox(0, "Failed to get JLI_Launch function address!", "Error Loading DLL", MB_ICONERROR)
        quit(1)

    # Define the command-line arguments and JVM options
    var javaParams = @["-splash:" & getAppDir() & DirSep & "splash.png", "-jar", getAppDir() & DirSep & "kse.jar"]
    javaParams.add(commandLineParams())
    var jvmParams = @["-Dkse.exe=true", "-Djava.awt.headless=false"]

    let argc = javaParams.len.cint
    let argv = javaParams.allocCStringArray()
    let jargc = jvmParams.len.cint
    let jargv = jvmParams.allocCStringArray()
    let appclassc = 0.cint
    let appclassv: cstringArray = nil
    let fullversion = cstring("version")
    let dotversion = cstring("0.0")
    let pname = cstring("java")
    let lname = cstring("kse")
    let jvmArgs = ord(jvmParams.len > 0).uint8
    let cpwildcard = JNI_FALSE
    let javaw = JNI_TRUE
    let ergo = 0.cint

    let result = jliLaunch(argc, argv, jargc, jargv, appclassc, appclassv, fullversion,
                           dotversion, pname, lname, jvmArgs, cpwildcard, javaw, ergo)

    if result != 0:
        showMessageBox(0, "Call to JLI_Launch failed!", "Error Starting Java", MB_ICONERROR)
        quit(1)

    unloadLib(jliDllHandle)


proc main() =
    try:
        setCurrentProcessExplicitAppUserModelID(newWideCString("KeyStoreExplorer.App.54"))
        callJliLaunch()
    except:
        showMessageBox(0, ("Error starting Java runtime: \n" & getCurrentExceptionMsg()).cstring, "Error", MB_ICONERROR)

main()
