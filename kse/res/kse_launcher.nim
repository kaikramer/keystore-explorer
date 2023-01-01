#
# Copyright 2004 - 2013 Wayne Grant
#           2013 - 2023 Kai Kramer
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

# nim -d:mingw --cpu:i386 -d:release --app:gui --opt:size --out:kse-launcher.exe c kse_launcher.nim

import os
import osproc
import dynlib
import system/widestrs

type
  HANDLE* = int
  HWND* = HANDLE
  UINT* = int32
  LPCSTR* = cstring
  DWORD = int32
  GetJavaHome = proc (path: WideCString, length: DWORD): DWORD {.gcsafe, stdcall.}


proc showMessageBox*(hWnd: HWND, lpText: LPCSTR, lpCaption: LPCSTR, uType: UINT): int32
  {.discardable, stdcall, dynlib: "user32", importc: "MessageBoxA".}


proc getJavaHome(): string =
  let lib = loadLib("JavaInfo.dll")
  if lib == nil:
    showMessageBox(0, "Error loading JavaInfo.dll!\nIt has to be in the same folder as kse.exe!", "Error", 0x10)

  let javaInfoGetJavaHome = cast[GetJavaHome](lib.symAddr("GetJavaHome"))

  # first call to GetJavaHome is for determining the length of the path
  var javaHomeLength = javaInfoGetJavaHome(nil, 0)
  var javaHomeWideStr = newWideCString(newString(javaHomeLength))

  javaHomeLength = javaInfoGetJavaHome(javaHomeWideStr, javaHomeLength);
  if javaHomeLength == 0:
    showMessageBox(0, "No Java Runtime found! Please set JAVA_HOME!", "Error Detecting Java Installation", 0x10)

  result = $javaHomeWideStr


proc getJavaExePath(): string =
  let localJrePath = getAppDir() & DirSep & "jre"

  if dirExists(localJrePath):
    result = localJrePath & DirSep & "bin" & DirSep & "javaw.exe"
  else:
    result = getJavaHome() & DirSep & "bin" & DirSep & "javaw.exe"


proc main() =
  var javaParams = @["-Dkse.exe=true", "-splash:splash.png", "-jar", getAppDir() & DirSep & "kse.jar"]
  javaParams.add(commandLineParams())

  try:
    discard startProcess(getJavaExePath(), workingDir="", args=javaParams, options={poInteractive})
  except:
    showMessageBox(0, ("Error starting Java runtime: \n" & getCurrentExceptionMsg()).cstring, "Error", 0x10)


main()