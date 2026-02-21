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

import org.gradle.api.GradleException
import java.io.File
import java.nio.file.Files

/**
 * Pre-compiled script plugin for building AppImage packages for KeyStore Explorer.
 *
 * Prerequisites:
 *   - appimagetool must be available on PATH
 *     (download from https://github.com/AppImage/appimagetool/releases)
 *   - The build JDK must be Java 25 (used by jlink to create the bundled runtime)
 *   - Build must run on Linux (x86_64 or aarch64)
 */

interface AppImagePackageExtension {
    val appName: Property<String>
    val appVersion: Property<String>
    val appSimpleName: Property<String>
    val appSimpleVersion: Property<String>
    val website: Property<String>
    val appImageStageDir: DirectoryProperty
    val jlinkOutDir: DirectoryProperty
    val distDir: DirectoryProperty
    val resDir: DirectoryProperty
    val iconsDir: DirectoryProperty
    val licensesDir: DirectoryProperty
}

val extension = extensions.create<AppImagePackageExtension>("appImagePackage")

tasks.register("buildAppImage") {
    group = "distribution"
    description = "Build AppImage package with bundled Java runtime"

    dependsOn("jar", "copyDependencies", "jlink")

    doFirst {
        val checkAppimagetool = providers.exec {
            commandLine("bash", "-c", "which appimagetool")
            isIgnoreExitValue = true
        }
        if (checkAppimagetool.result.get().exitValue != 0) {
            throw GradleException(
                "appimagetool is not installed or not on PATH. " +
                "Download it from https://github.com/AppImage/appimagetool/releases " +
                "and make sure it is executable and on your PATH."
            )
        }
    }

    doLast {
        val appName = extension.appName.get()
        val appVersion = extension.appVersion.get()
        val appSimpleName = extension.appSimpleName.get()
        val appSimpleVersion = extension.appSimpleVersion.get()
        val resDir = extension.resDir.get().asFile.absolutePath
        val iconsDir = extension.iconsDir.get().asFile.absolutePath
        val licensesDir = extension.licensesDir.get().asFile.absolutePath
        val website = extension.website.get()
        val stageDir = extension.appImageStageDir.get().asFile
        val jlinkOutDir = extension.jlinkOutDir.get().asFile.absolutePath
        val distDir = extension.distDir.get().asFile

        val appDir = File(stageDir, "AppDir")

        delete(stageDir)
        mkdir(appDir)

        val usrBinDir = File(appDir, "usr/bin")
        val usrLibDir = File(appDir, "usr/lib/$appSimpleName")
        val usrLibLibDir = File(appDir, "usr/lib/$appSimpleName/lib")
        val usrLibLicensesDir = File(appDir, "usr/lib/$appSimpleName/licenses")
        val usrShareAppsDir = File(appDir, "usr/share/applications")
        val usrShareMetainfoDir = File(appDir, "usr/share/metainfo")

        listOf(usrBinDir, usrLibDir, usrLibLibDir, usrLibLicensesDir,
               usrShareAppsDir, usrShareMetainfoDir).forEach { mkdir(it) }

        val iconSizes = listOf(16, 32, 48, 128, 256, 512)
        iconSizes.forEach { size ->
            val iconDir = File(appDir, "usr/share/icons/hicolor/${size}x${size}/apps")
            mkdir(iconDir)
            copy {
                from("$iconsDir/kse_${size}.png")
                into(iconDir)
                rename("kse_${size}.png", "kse.png")
            }
        }

        copy {
            from("$iconsDir/kse_256.png")
            into(appDir)
            rename("kse_256.png", "kse.png")
        }

        copy {
            from(tasks.named("jar").get().outputs.files)
            into(usrLibDir)
        }

        copy {
            from(configurations.getByName("runtimeClasspath").files)
            into(usrLibLibDir)
        }

        copy {
            from(resDir) {
                include("splash*.png")
            }
            into(usrLibDir)
        }

        copy {
            from(licensesDir) {
                include("**/*.txt")
            }
            into(usrLibLicensesDir)
        }

        val jreSourceDir = File("$jlinkOutDir/jre")
        if (!jreSourceDir.exists()) {
            throw GradleException("jlink JRE not found at $jreSourceDir. Make sure the jlink task ran successfully.")
        }
        copy {
            from(jreSourceDir)
            into(File(usrLibDir, "jre"))
        }

        copy {
            from("$resDir/kse.desktop")
            into(appDir)
        }
        copy {
            from("$resDir/kse.desktop")
            into(usrShareAppsDir)
        }

        val metainfoContent = """<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>org.kse.KeyStoreExplorer</id>
  <name>$appName</name>
  <summary>Multipurpose keystore and certificate tool</summary>
  <metadata_license>FSFAP</metadata_license>
  <project_license>GPL-3.0-or-later</project_license>
  <description>
    <p>
      KeyStore Explorer is a user friendly GUI application for creating,
      managing and examining keystores, keys, certificates, certificate requests,
      certificate revocation lists and more.
    </p>
  </description>
  <url type="homepage">$website</url>
  <launchable type="desktop-id">kse.desktop</launchable>
  <provides>
    <binary>kse</binary>
  </provides>
  <releases>
    <release version="$appVersion"/>
  </releases>
</component>
"""
        File(usrShareMetainfoDir, "org.kse.KeyStoreExplorer.metainfo.xml").writeText(metainfoContent)

        copy {
            from("$resDir/kse.sh")
            into(usrLibDir)
        }
        File(usrLibDir, "kse.sh").setExecutable(true, false)

        Files.createSymbolicLink(
            File(usrBinDir, "kse").toPath(),
            java.nio.file.Paths.get("../lib/$appSimpleName/kse.sh")
        )

        val appRunScript = """#!/bin/bash
# AppRun - entry point for the AppImage
# This script is executed when the AppImage is run
APPDIR="$(cd "$(dirname "${'$'}0")" && pwd)"
export PATH="${'$'}{APPDIR}/usr/bin:${'$'}{PATH}"
export JAVA_HOME="${'$'}{APPDIR}/usr/lib/$appSimpleName/jre"

exec "${'$'}{APPDIR}/usr/lib/$appSimpleName/kse.sh" "${'$'}@"
"""
        val appRunFile = File(appDir, "AppRun")
        appRunFile.writeText(appRunScript)
        appRunFile.setExecutable(true, false)

        File(usrLibDir, "jre/bin").listFiles()?.forEach { it.setExecutable(true, false) }
        File(usrLibDir, "jre/lib").walk().filter { it.name.endsWith(".so") }.forEach {
            it.setExecutable(true, false)
        }

        val arch = System.getProperty("os.arch")
        val appImageArch = if (arch == "aarch64") "aarch64" else "x86_64"

        val outputFileName = "$appSimpleName-$appSimpleVersion-$appImageArch.AppImage"
        mkdir(distDir)
        val outputFile = File(distDir, outputFileName)
        delete(outputFile)

        println("Creating AppImage with appimagetool...")
        val result = providers.exec {
            workingDir(stageDir)
            environment("ARCH", appImageArch)
            commandLine(
                "appimagetool",
                appDir.absolutePath,
                outputFile.absolutePath
            )
            isIgnoreExitValue = true
        }

        if (result.standardOutput.asText.get().isNotEmpty()) {
            println(result.standardOutput.asText.get())
        }
        if (result.standardError.asText.get().isNotEmpty()) {
            println(result.standardError.asText.get())
        }

        if (result.result.get().exitValue != 0) {
            throw GradleException("appimagetool failed with exit code ${result.result.get().exitValue}")
        }

        println("AppImage created successfully: ${outputFile.absolutePath}")
    }
}

