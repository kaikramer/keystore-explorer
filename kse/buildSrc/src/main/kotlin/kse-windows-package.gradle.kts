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

import org.apache.tools.ant.filters.ReplaceTokens
import java.io.File

/**
 * Pre-compiled script plugin for Windows packaging tasks
 */

// Extension for configuration
interface WindowsPackageExtension {
    val appVersion: Property<String>
    val appExe: Property<String>
    val appUserModelId: Property<String>
    val resDir: DirectoryProperty
    val iconsDir: DirectoryProperty
    val licensesDir: DirectoryProperty
    val jlinkOutDir: DirectoryProperty
    val distDir: DirectoryProperty
    val dependenciesDir: DirectoryProperty
    val jarFile: RegularFileProperty
}

val extension = extensions.create<WindowsPackageExtension>("windowsPackage")

tasks.register("innosetup") {
    group = "distribution"
    description = "Create Windows installer using InnoSetup"

    dependsOn("jar", "jlink", "copyDependencies")

    doLast {
        val appVersion = extension.appVersion.get()
        val appUserModelId = extension.appUserModelId.get()
        val appExe = extension.appExe.get()
        val resDir = extension.resDir.get().asFile.absolutePath
        val iconsDir = extension.iconsDir.get().asFile.absolutePath
        val licensesDir = extension.licensesDir.get().asFile.absolutePath
        val jlinkOutDir = extension.jlinkOutDir.get().asFile.absolutePath
        val distDir = extension.distDir.get().asFile.absolutePath
        val dependenciesDir = extension.dependenciesDir.get().asFile.absolutePath
        val jarFile = extension.jarFile.get().asFile.absolutePath

        mkdir(distDir)

        copy {
            from("innosetup/setup.iss.template")
            rename("setup.iss.template", "setup.iss")
            filter(
                ReplaceTokens::class, "tokens" to mapOf(
                    "KSE_VERSION" to appVersion,
                    "KSE_APP_USER_MODEL_ID" to appUserModelId,
                    "KSE_JAR" to jarFile,
                    "LIB_DIR" to dependenciesDir,
                    "LAUNCHER" to "$resDir\\$appExe",
                    "JAVA_INFO_DLL" to "$resDir\\JavaInfo.dll",
                    "NO_JRE" to if (JavaVersion.current() != JavaVersion.VERSION_17) "" else "-no-jre",
                    "ICONS_DIR" to iconsDir,
                    "RES_DIR" to resDir,
                    "JRE_DIR" to "$jlinkOutDir\\jre",
                    "LICENSES_DIR" to licensesDir,
                    "DIST_DIR" to distDir
                ),
                "beginToken" to "%",
                "endToken" to "%"
            )
            into("innosetup")
        }

        val result = providers.exec {
            workingDir("$projectDir/innosetup")
            commandLine("ISCC.exe", "setup.iss")
        }
        println("Innosetup output: ${result.standardOutput.asText.get()}")
        if (result.standardError.asText.get().isNotEmpty()) {
            println("Innosetup errors: ${result.standardError.asText.get()}")
        }

        println("Windows installer created successfully in: $distDir")
    }
}
