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
import org.gradle.api.tasks.Exec
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

/**
 * Pre-compiled script plugin for building Debian packages for KeyStore Explorer
 */

// Extension for configuration
interface DebianPackageExtension {
    val appVersion: Property<String>
    val website: Property<String>
    val vendor: Property<String>
    val distDir: DirectoryProperty
}

val extension = extensions.create<DebianPackageExtension>("debianPackage")

tasks.register("prepareDeb") {
    group = "distribution"
    description = "Prepare files for Debian package build"

    dependsOn("jar", "copyDependencies")

    doLast {
        val debStageDir = layout.buildDirectory.dir("deb-stage").get().asFile
        delete(debStageDir)
        mkdir(debStageDir)

        copy {
            from(configurations.getByName("runtimeClasspath").files)
            into(File(debStageDir, "lib"))
        }

        println("Prepared files for Debian package build in: $debStageDir")
    }
}

tasks.register("updateDebChangelog") {
    group = "distribution"
    description = "Update debian/changelog with current version"

    doLast {
        val dateFormatter = SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss Z", Locale.ENGLISH)

        copy {
            from("debian/changelog.template")
            rename("changelog.template", "changelog")
            filter(
                ReplaceTokens::class, "tokens" to mapOf(
                    "KSE_VERSION" to extension.appVersion.get(),
                    "KSE_WEBSITE" to extension.website.get(),
                    "KSE_VENDOR" to extension.vendor.get(),
                    "KSE_DATE" to dateFormatter.format(Date())
                ),
                "beginToken" to "%",
                "endToken" to "%"
            )
            into("debian")
        }

        println("Updated debian/changelog to version ${extension.appVersion.get()}")
    }
}

tasks.register<Exec>("buildDeb") {
    group = "distribution"
    description = "Build Debian package using debhelper and dpkg-buildpackage"

    dependsOn("jar", "prepareDeb", "updateDebChangelog")

    doFirst {
        val rulesFile = File(projectDir, "debian/rules")
        if (rulesFile.exists()) {
            rulesFile.setExecutable(true, false)
        }

        File(projectDir, "debian/postinst").apply { if (exists()) setExecutable(true, false) }
        File(projectDir, "debian/postrm").apply { if (exists()) setExecutable(true, false) }
    }

    workingDir(projectDir)

    standardOutput = System.out
    errorOutput = System.err
    isIgnoreExitValue = false

    commandLine(
        "dpkg-buildpackage",
        "-us", "-uc",  // Don't sign (use -k for signing)
        "-b",           // Binary only
        "--build=binary"
    )

    doLast {
        val distDir = extension.distDir.get().asFile
        mkdir(distDir)

        val parentDir = projectDir.parentFile
        val debFiles = fileTree(parentDir) {
            include("kse_*.deb")
        }

        if (debFiles.isEmpty) {
            println("Warning: No .deb file found in ${parentDir.absolutePath}")
        } else {
            copy {
                from(debFiles)
                into(distDir)
            }
            println("Debian package created successfully in: $distDir")

            delete(fileTree(parentDir) {
                include("kse_*.buildinfo", "kse_*.changes", "kse_*.deb")
            })
        }
    }
}
