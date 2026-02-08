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
import org.gradle.api.GradleException
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

/**
 * Pre-compiled script plugin for building RPM packages for KeyStore Explorer
 */

// Extension for configuration
interface RpmPackageExtension {
    val appVersion: Property<String>
    val appSimpleName: Property<String>
    val appJarName: Property<String>
    val website: Property<String>
    val vendor: Property<String>
    val rpmBuildDir: DirectoryProperty
    val rpmStageDir: DirectoryProperty
    val distDir: DirectoryProperty
    val resDir: DirectoryProperty
    val iconsDir: DirectoryProperty
    val licensesDir: DirectoryProperty
}

val extension = extensions.create<RpmPackageExtension>("rpmPackage")

tasks.register("buildRpm") {
    group = "distribution"
    description = "Build RPM package using rpmbuild"

    dependsOn("jar", "copyDependencies")

    doFirst {
        val checkRpmbuild = providers.exec {
            commandLine("bash", "-c", "which rpmbuild")
            isIgnoreExitValue = true
        }
        if (checkRpmbuild.result.get().exitValue != 0) {
            throw GradleException("rpmbuild is not installed. Install it with: sudo apt-get install rpm")
        }
    }

    doLast {
        val rpmBuildDir = extension.rpmBuildDir.get().asFile.absolutePath
        val rpmStageDir = extension.rpmStageDir.get().asFile.absolutePath
        val distDir = extension.distDir.get().asFile
        val resDir = extension.resDir.get().asFile.absolutePath
        val iconsDir = extension.iconsDir.get().asFile.absolutePath
        val licensesDir = extension.licensesDir.get().asFile.absolutePath

        // Create rpmbuild directory structure
        val buildRoot = File(rpmBuildDir, "BUILD")
        val specsDir = File(rpmBuildDir, "SPECS")
        val rpmsDir = File(rpmBuildDir, "RPMS")
        val sourcesDir = File(rpmBuildDir, "SOURCES")
        val srpmsDir = File(rpmBuildDir, "SRPMS")

        listOf(buildRoot, specsDir, rpmsDir, sourcesDir, srpmsDir, File(rpmStageDir)).forEach { dir ->
            delete(dir)
            mkdir(dir)
        }

        val stageAppDir = File(rpmStageDir)

        copy {
            from(tasks.named("jar").get().outputs.files)
            into(stageAppDir)
        }

        copy {
            from(configurations.getByName("runtimeClasspath").files)
            into(File(stageAppDir, "lib"))
        }

        copy {
            from(resDir) {
                include("kse.sh", "kse.desktop", "splash*.png")
            }
            into(stageAppDir)
        }

        copy {
            from(iconsDir) {
                include("kse_16.png", "kse_32.png", "kse_48.png", "kse_128.png", "kse_256.png", "kse_512.png")
            }
            into(File(stageAppDir, "icons"))
        }

        copy {
            from(licensesDir) {
                include("**/*.txt")
            }
            into(File(stageAppDir, "licenses"))
        }

        val dateFormatter = SimpleDateFormat("EEE MMM dd yyyy", Locale.ENGLISH)
        copy {
            from("rpmbuild/kse.spec.template")
            rename("kse.spec.template", "kse.spec")
            filter(
                ReplaceTokens::class, "tokens" to mapOf(
                    "KSE_PACKAGE_NAME" to extension.appSimpleName.get(),
                    "KSE_VERSION" to extension.appVersion.get(),
                    "KSE_WEBSITE" to extension.website.get(),
                    "KSE_JAR_NAME" to extension.appJarName.get(),
                    "KSE_BUILD_ROOT" to rpmStageDir,
                    "KSE_DATE" to dateFormatter.format(Date()),
                    "KSE_VENDOR" to extension.vendor.get()
                ),
                "beginToken" to "%",
                "endToken" to "%"
            )
            into(specsDir)
        }

        val result = providers.exec {
            workingDir(projectDir)
            commandLine(
                "rpmbuild",
                "-bb",
                "--define", "_topdir $rpmBuildDir",
                "--buildroot", "$buildRoot",
                "$specsDir/kse.spec"
            )
        }

        println("rpmbuild output: ${result.standardOutput.asText.get()}")
        if (result.standardError.asText.get().isNotEmpty()) {
            println("rpmbuild errors: ${result.standardError.asText.get()}")
        }

        mkdir(distDir)
        copy {
            from(fileTree(rpmsDir) {
                include("**/*.rpm")
            })
            into(distDir)
        }

        println("RPM package created successfully in: $distDir")
    }
}
