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

{.pragma: jni, cdecl, gcsafe.}

const
    JNI_VERSION_1_1* = 0x00010001.cint
    JNI_VERSION_1_2* = 0x00010002.cint
    JNI_VERSION_1_4* = 0x00010004.cint
    JNI_VERSION_1_6* = 0x00010006.cint
    JNI_VERSION_1_8* = 0x00010008.cint
    JNI_VERSION_9* = 0x00090000.cint
    JNI_VERSION_10* = 0x000a0000.cint

type
    HANDLE* = int
    HWND* = HANDLE
    UINT* = int32
    LPCSTR* = cstring
    PCWSTR* = WideCString
    DWORD = int32
    GetJavaHome = proc (path: WideCString, length: DWORD): DWORD {.gcsafe, stdcall.}

    # see https://docs.oracle.com/en/java/javase/17/docs/specs/jni/invocation.html#jni_createjavavm
    JavaVMOption = object
        optionString: cstring
        extraInfo: pointer
    JavaVMInitArgs = object
        version: cint
        nOptions: cint
        options: ptr JavaVMOption
        ignoreUnrecognized: bool
    CreateJavaVMFunc = proc(jvm: ptr JavaVMPtr, env: ptr JNIEnvPtr, args: ptr JavaVMInitArgs): cint {.cdecl.}

    JClass = object
    JMethodID = object
    JObject = object
    JObjectArray = object
    JavaVM = ptr JavaVMProc
    JavaVMPtr = ptr JavaVM
    JNIEnv = ptr JNIEnvProc
    JNIEnvPtr = ptr JNIEnv

    # Invocation API functions (see https://docs.oracle.com/en/java/javase/17/docs/specs/jni/invocation.html#invocation-api-functions)
    JavaVMProc = object
        reserved: array[3, pointer]
        DestroyJavaVM*: proc(jvm: JavaVMPtr): cint {.cdecl.}

  # JNI functions (see https://docs.oracle.com/en/java/javase/17/docs/specs/jni/functions.html#interface-function-table)
    JNIEnvProc = object
        reserved: array[4, pointer]
        GetVersion*: proc(env: JNIEnvPtr): cint {.jni.}
        DefineClass*: proc(env: JNIEnvPtr, name: cstring, loader: JClass, buf: ptr uint8, len: cint): JClass {.jni.}
        FindClass*: proc(env: JNIEnvPtr, name: cstring): ptr JClass {.jni.}
        placeholder1: array[106, pointer]
        GetStaticMethodID*: proc(env: JNIEnvPtr, cls: ptr JClass, name, sig: cstring): ptr JMethodID {.jni.}
        placeholder2: array[27, pointer]
        CallStaticVoidMethod*: proc(env: JNIEnvPtr, cls: ptr JClass, methodID: ptr JMethodID, args: ptr JObjectArray) {.jni.}
        placeholder3: array[25, pointer]
        NewStringUTF*: proc(env: JNIEnvPtr, utf: cstring): ptr JObject {.jni.}
        placeholder4: array[4, pointer]
        NewObjectArray*: proc(env: JNIEnvPtr, len: cint, cls: ptr JClass, init: ptr JObjectArray): ptr JObjectArray {.jni.}
        placeholder5: pointer
        SetObjectArrayElement*: proc(env: JNIEnvPtr, array: ptr JObjectArray, index: cint, val: ptr JObject) {.jni.}


proc showMessageBox*(hWnd: HWND, lpText: LPCSTR, lpCaption: LPCSTR, uType: UINT): int32
    {.discardable, stdcall, dynlib: "user32", importc: "MessageBoxA".}

proc setCurrentProcessExplicitAppUserModelID*(appId: PCWSTR): int32
    {.discardable, stdcall, dynlib: "shell32", importc: "SetCurrentProcessExplicitAppUserModelID".}


proc getJavaHome(): string =
    let libHandle: LibHandle = loadLib("JavaInfo.dll")
    if libHandle == nil:
        showMessageBox(0, "Error loading JavaInfo.dll!\nIt has to be in the same folder as kse.exe!", "Error", 0x10)
        quit(1)

    let javaInfoGetJavaHome = cast[GetJavaHome](symAddr(libHandle, "GetJavaHome"))

    # first call to GetJavaHome is for determining the length of the path
    var javaHomeLength = javaInfoGetJavaHome(nil, 0)
    var javaHomeWideStr = newWideCString(newString(javaHomeLength))

    javaHomeLength = javaInfoGetJavaHome(javaHomeWideStr, javaHomeLength);
    if javaHomeLength == 0:
        showMessageBox(0, "No Java Runtime found! Please set JAVA_HOME!", "Error Detecting Java Installation", 0x10)
        quit(1)

    result = $javaHomeWideStr


proc getJvmDllPath(): string =
    let localJrePath = getAppDir() & DirSep & "jre"

    if dirExists(localJrePath):
        result = localJrePath & DirSep & "bin" & DirSep & "server" & DirSep & "jvm.dll"
    else:
        result = getJavaHome() & DirSep & "bin" & DirSep & "server" & DirSep & "jvm.dll"


proc createJvm(): (LibHandle, JNIEnvPtr, JavaVMPtr) =
    var jvmDllHandle: LibHandle = loadLib(getJvmDllPath())
    if jvmDllHandle == nil:
        showMessageBox(0, "Could not load jvm.dll!", "Error Loading DLL", 0x10)
        quit(1)

    let createJavaVM: CreateJavaVMFunc = cast[CreateJavaVMFunc](symAddr(jvmDllHandle, "JNI_CreateJavaVM"))

    var options = [
      JavaVMOption(optionString: cstring("-Djava.class.path=" & getAppDir() & DirSep & "kse.jar")),
      JavaVMOption(optionString: "-Dkse.exe=true")
    ]
    var vmArgs = JavaVMInitArgs(version: JNI_VERSION_1_8, nOptions: options.len.cint, options: addr options[0], ignoreUnrecognized: false)

    var jvm: JavaVMPtr = nil
    var env: JNIEnvPtr = nil

    let res = createJavaVM(addr jvm, addr env, addr vmArgs)
    if res != 0:
        showMessageBox(0, cstring("Could not create Java VM! Error code: " & $res), "Error Creating JVM", 0x10)
        quit(1)

    result = (jvmDllHandle, env, jvm)


proc executeMainMethod(env: JNIEnvPtr) =
    let mainClass = env.FindClass(env, "org/kse/KSE")
    if mainClass == nil:
        showMessageBox(0, "Could not find main class org/kse/KSE!", "Error Class Not Found", 0x10)
        quit(1)

    let mainMethodID = env.GetStaticMethodID(env, mainClass, "main", "([Ljava/lang/String;)V")
    if mainMethodID == nil:
        showMessageBox(0, "Could not find main method!", "Error Method Not Found", 0x10)
        quit(1)

    let stringClass = env.FindClass(env, "java/lang/String")
    let params = commandLineParams()
    # let params = ["c:\\KeyStore-Explorer\\testdata\\123.cer"]
    let mainArgs = env.NewObjectArray(env, params.len.cint, stringClass, nil)
    for i, p in params:
        let arg = env.NewStringUTF(env, cstring(p))
        env.SetObjectArrayElement(env, mainArgs, i.cint, arg)

    env.CallStaticVoidMethod(env, mainClass, mainMethodID, mainArgs)


proc destroyJavaVm(jvm: JavaVMPtr) =
    let res = jvm.DestroyJavaVM(jvm)
    if res != 0:
        showMessageBox(0, cstring("Could not unload Java VM! Error code: " & $res), "Error Unloading JVM", 0x10)


proc main() =
    try:
        var (jvmDll, env, jvm) = createJvm()
        setCurrentProcessExplicitAppUserModelID(newWideCString("KeyStoreExplorer.App.54"))
        executeMainMethod(env)
        destroyJavaVm(jvm)
        unloadLib(jvmDll)
    except:
        showMessageBox(0, ("Error starting Java runtime: \n" & getCurrentExceptionMsg()).cstring, "Error", 0x10)


main()
