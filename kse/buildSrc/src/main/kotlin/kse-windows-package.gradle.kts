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
 * Pre-compiled script plugin for Windows packaging tasks (prepareExe and innosetup)
 */

// Extension for configuration
interface WindowsPackageExtension {
    val appName: Property<String>
    val appVersion: Property<String>
    val appSimpleName: Property<String>
    val appExe: Property<String>
    val appUserModelId: Property<String>
    val copyright: Property<String>
    val kseIco: Property<String>
    val resourceHacker: Property<String>
    val launcherOutDir: DirectoryProperty
    val resDir: DirectoryProperty
    val iconsDir: DirectoryProperty
    val licensesDir: DirectoryProperty
    val jlinkOutDir: DirectoryProperty
    val distDir: DirectoryProperty
    val dependenciesDir: DirectoryProperty
    val jarFile: RegularFileProperty
}

val extension = extensions.create<WindowsPackageExtension>("windowsPackage")

tasks.register("prepareExe") {
    group = "distribution"
    description = "Prepare Windows executable with version info and icon using Resource Hacker"

    doLast {
        val appExe = extension.appExe.get()
        val appName = extension.appName.get()
        val appVersion = extension.appVersion.get()
        val appSimpleName = extension.appSimpleName.get()
        val copyright = extension.copyright.get()
        val kseIco = extension.kseIco.get()
        val rh = extension.resourceHacker.get()
        val launcherOutDir = extension.launcherOutDir.get().asFile.absolutePath
        val resDir = extension.resDir.get().asFile.absolutePath

        copy {
            from("$resDir/kse-launcher.exe")
            rename("kse-launcher.exe", appExe)
            into(launcherOutDir)
        }

        val verInfo = appVersion.replace(".", ",") + ",0"
        delete("$launcherOutDir/kse.rc")
        File(launcherOutDir, "kse.rc").writeText(
            """
			1 VERSIONINFO
			FILEVERSION     $verInfo
			PRODUCTVERSION  $verInfo
			FILEOS 			VOS__WINDOWS32
			FILETYPE 		VFT_APP
			BEGIN
			  BLOCK "StringFileInfo"
			  BEGIN
				BLOCK "040904B0"
				BEGIN
				  VALUE "FileDescription", 	"$appName"
				  VALUE "FileVersion", 		"$appVersion.0"
				  VALUE "InternalName", 	"$appSimpleName"
				  VALUE "LegalCopyright", 	"$copyright"
				  VALUE "OriginalFilename", "$appExe"
				  VALUE "ProductName", 		"$appName"
				  VALUE "ProductVersion", 	"$appVersion"
				END
			  END
			  BLOCK "VarFileInfo"
			  BEGIN
				VALUE "Translation", 0x0409, 0x04B0
			  END
			END
		""".trimIndent()
        )

        var result = providers.exec {
            workingDir(projectDir)
            commandLine(
                rh,
                "-open", "$launcherOutDir\\kse.rc",
                "-save", "$launcherOutDir\\kse.res",
                "-action", "compile"
            )
        }
        println("RH1 finished with return code: ${result.result.get().exitValue}")
        if (result.standardError.asText.get().isNotEmpty()) {
            println("RH1 errors: ${result.standardError.asText.get()}")
        }

        result = providers.exec {
            workingDir(projectDir)
            commandLine(
                rh,
                "-open", "$launcherOutDir\\$appExe",
                "-save", "$launcherOutDir\\$appExe",
                "-action", "addoverwrite",
                "-mask", " VersionInfo,,",
                "-res", "$launcherOutDir\\kse.res"
            )
        }
        println("RH2 finished with return code: ${result.result.get().exitValue}")
        if (result.standardError.asText.get().isNotEmpty()) {
            println("RH2 errors: ${result.standardError.asText.get()}")
        }

        result = providers.exec {
            workingDir(projectDir)
            commandLine(
                rh,
                "-open", "$launcherOutDir\\$appExe",
                "-save", "$launcherOutDir\\$appExe",
                "-action", "addoverwrite",
                "-mask", "ICONGROUP,MAINICON,0",
                "-res", kseIco
            )
        }
        println("RH3 finished with return code: ${result.result.get().exitValue}")
        if (result.standardError.asText.get().isNotEmpty()) {
            println("RH3 errors: ${result.standardError.asText.get()}")
        }

        println("Windows executable prepared successfully: $launcherOutDir\\$appExe")
    }
}

tasks.register("innosetup") {
    group = "distribution"
    description = "Create Windows installer using InnoSetup"

    dependsOn("jar", "prepareExe", "jlink", "copyDependencies")

    doLast {
        val appVersion = extension.appVersion.get()
        val appUserModelId = extension.appUserModelId.get()
        val appExe = extension.appExe.get()
        val launcherOutDir = extension.launcherOutDir.get().asFile.absolutePath
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
                    "LAUNCHER" to "$launcherOutDir\\$appExe",
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
