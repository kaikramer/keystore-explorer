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

import org.gradle.api.tasks.Exec
import java.io.File

/**
 * Pre-compiled script plugin for macOS packaging (app bundling, code signing, DMG creation, and notarization)
 */

// Extension for configuration
interface MacPackageExtension {
    val appName: Property<String>
    val appAltName: Property<String>
    val appVersion: Property<String>
    val appBundle: Property<String>
    val copyright: Property<String>
    val mainClassName: Property<String>
    val kseIcns: Property<String>
    val keystoreIcns: Property<String>
    val appBundleDir: DirectoryProperty
    val resDir: DirectoryProperty
    val dependenciesDir: DirectoryProperty
    val appbundlerClasspath: Property<String>
    val dmgDir: DirectoryProperty
    val dmgFile: Property<String>
    val distDir: DirectoryProperty
    val signingIdentity: Property<String>
}

val extension = extensions.create<MacPackageExtension>("macPackage")

tasks.register("appbundler") {
    group = "distribution"
    description = "Create macOS application bundle using AppBundler"

    dependsOn("jar", "copyDependencies")

    doLast {
        val appBundleDir = extension.appBundleDir.get().asFile.absolutePath
        val appName = extension.appName.get()
        val appAltName = extension.appAltName.get()
        val appVersion = extension.appVersion.get()
        val appBundle = extension.appBundle.get()
        val copyright = extension.copyright.get()
        val mainClassName = extension.mainClassName.get()
        val kseIcns = extension.kseIcns.get()
        val keystoreIcns = extension.keystoreIcns.get()
        val resDir = extension.resDir.get().asFile.absolutePath
        val dependenciesDir = extension.dependenciesDir.get().asFile
        val appbundlerClasspath = extension.appbundlerClasspath.get()

        ant.withGroovyBuilder {
            "taskdef"(
                "name" to "bundleapp",
                "classname" to "com.oracle.appbundler.AppBundlerTask",
                "classpath" to appbundlerClasspath
            )
        }

        mkdir(appBundleDir)

        ant.withGroovyBuilder {
            "bundleapp"(
                "outputdirectory" to appBundleDir,
                "name" to appName,
                "displayname" to appName,
                "executableName" to appName,
                "identifier" to "org.kse.$appAltName",
                "shortversion" to appVersion,
                "version" to appVersion,
                "icon" to kseIcns,
                "mainclassname" to mainClassName,
                "copyright" to copyright,
                "applicationCategory" to "public.app-category.developer-tools"
            ) {
                "classpath"("dir" to dependenciesDir.absolutePath)
                "classpath"("file" to tasks.named("jar").get().outputs.files.singleFile.absolutePath)
                "arch"("name" to if (System.getProperty("os.arch") == "aarch64") "arm64" else "x86_64")

                "jlink"("runtime" to System.getProperty("java.home")) {
                    "jmod"("name" to "java.base")
                    "jmod"("name" to "java.datatransfer")
                    "jmod"("name" to "java.desktop")
                    "jmod"("name" to "java.logging")
                    "jmod"("name" to "java.naming")
                    "jmod"("name" to "java.net.http")
                    "jmod"("name" to "java.prefs")
                    "jmod"("name" to "java.scripting")
                    "jmod"("name" to "jdk.accessibility")
                    "jmod"("name" to "jdk.localedata")
                    "jmod"("name" to "jdk.net")
                    "jmod"("name" to "jdk.charsets")
                    "jmod"("name" to "jdk.crypto.ec")
                    "jmod"("name" to "jdk.security.auth")
                    "jmod"("name" to "jdk.crypto.cryptoki")
                    "jmod"("name" to "jdk.zipfs")
                    "jmod"("name" to "jdk.dynalink")
                    "jmod"("name" to "jdk.unsupported")

                    "argument"("value" to "--compress=2")
                    "argument"("value" to "--no-header-files")
                    "argument"("value" to "--no-man-pages")
                    "argument"("value" to "--strip-debug")
                    "argument"("value" to "--include-locales=en,de,fr,ru")
                }

                "bundledocument"(
                    "extensions" to "ks,jks,jceks,keystore,bks,uber,pfx,p12",
                    "icon" to keystoreIcns,
                    "name" to "KeyStore",
                    "role" to "editor"
                )
                "option"("value" to "-Dapple.laf.useScreenMenuBar=true")
                "option"("value" to "-Dcom.apple.macos.use-file-dialog-packages=true")
                "option"("value" to "-Dcom.apple.macos.useScreenMenuBar=true")
                "option"("value" to "-Dcom.apple.mrj.application.apple.menu.about.name=$appName")
                "option"("value" to "-Dcom.apple.smallTabs=true")
                "option"("value" to "-Dfile.encoding=UTF-8")
                "option"("value" to $$"-splash:$APP_ROOT/Contents/Resources/splash.png")
                "option"("value" to "-Dkse.app=true")
                "option"("value" to $$"-Dkse.app.stub=$APP_ROOT/Contents/MacOS/$appName")
            }
        }

        copy {
            from(resDir)
            include("splash*.png")
            into("$appBundleDir/$appBundle/Contents/Resources")
        }

        println("macOS app bundle created successfully in: $appBundleDir")
    }
}

tasks.register("signapp") {
    group = "distribution"
    description = "Code sign macOS application bundle and native libraries"

    dependsOn("appbundler")

    doLast {
        val appBundleDir = extension.appBundleDir.get().asFile.absolutePath
        val appBundle = extension.appBundle.get()
        val dmgDir = extension.dmgDir.get().asFile.absolutePath
        val signingIdentity = extension.signingIdentity.get()

        val javaDir = File("$appBundleDir/$appBundle/Contents/Java")

        // Sign FlatLaf native libraries
        fileTree(javaDir) {
            include("flatlaf-*-macos-*.dylib")
        }.forEach { flatlafDylib ->
            println("Signing FlatLaf native library: ${flatlafDylib.absolutePath}")
            val result = providers.exec {
                workingDir(appBundleDir)
                commandLine(
                    "codesign",
                    "-vvv",
                    "--force",
                    "-s", signingIdentity,
                    flatlafDylib.absolutePath
                )
            }
            println("Codesign output: ${result.standardOutput.asText.get()}")
            if (result.standardError.asText.get().isNotEmpty()) {
                println("Codesign errors: ${result.standardError.asText.get()}")
            }
        }

        // Helper function to extract, sign, and repackage jars containing native libraries
        fun processJarWithNativeLibs(jarPattern: String, jarName: String) {
            val jarFiles = fileTree("$appBundleDir/$appBundle/Contents/Java") {
                include("**/$jarPattern")
            }
            if (jarFiles.isEmpty) {
                println("No $jarName jar found, skipping...")
                return
            }

            val jar = jarFiles.singleFile
            val extractDir = "$appBundleDir/$jarName-temp"
            mkdir(extractDir)

            copy {
                from(zipTree(jar))
                into(extractDir)
            }

            // Find all .dylib files in the extracted content, but not in .dSYM dirs
            val dylibFiles = fileTree(extractDir) {
                include("**/*.dylib")
                exclude("**/*.dSYM/**")
            }
            if (dylibFiles.isEmpty) {
                println("No native libraries found in $jarName jar")
            } else {
                dylibFiles.forEach { dylibFile ->
                    println("Signing $jarName native library: ${dylibFile.absolutePath}")
                    val result = providers.exec {
                        workingDir(appBundleDir)
                        commandLine(
                            "codesign",
                            "-vvv",
                            "--force",
                            "-s", signingIdentity,
                            dylibFile.absolutePath
                        )
                    }
                    println("Codesign output: ${result.standardOutput.asText.get()}")
                    if (result.standardError.asText.get().isNotEmpty()) {
                        println("Codesign errors: ${result.standardError.asText.get()}")
                    }
                }
            }

            // Repackage the jar with all extracted and signed files
            ant.withGroovyBuilder {
                "jar"("destfile" to jar.absolutePath, "update" to true) {
                    "fileset"("dir" to extractDir) {
                        "include"("name" to "**/*")
                    }
                }
            }
            delete(extractDir)
        }

        // Process jars that contain native libraries
        processJarWithNativeLibs("vaqua-*.jar", "vaqua")
        processJarWithNativeLibs("vappearances-*.jar", "vappearances")
        processJarWithNativeLibs("jnr-*.jar", "jnr")

        // Sign Java runtime and app bundle
        val javaBaseDirName = File(System.getProperty("java.home")).parentFile.parentFile.name
        println("java.home: ${System.getProperty("java.home")}")
        println("Signing Java runtime: $appBundle/Contents/PlugIns/$javaBaseDirName")
        val result1 = providers.exec {
            workingDir(appBundleDir)
            commandLine(
                "codesign",
                "-vvv",
                "--force",
                "--options=runtime",
                "--entitlements", "$dmgDir/entitlements.xml",
                "-s", signingIdentity,
                "$appBundle/Contents/PlugIns/$javaBaseDirName"
            )
        }
        println("Codesign output: ${result1.standardOutput.asText.get()}")
        if (result1.standardError.asText.get().isNotEmpty()) {
            println("Codesign errors: ${result1.standardError.asText.get()}")
        }

        println("Signing app bundle: $appBundle")
        val result2 = providers.exec {
            workingDir(appBundleDir)
            commandLine(
                "codesign",
                "-vvv",
                "--force",
                "--options=runtime",
                "--entitlements", "$dmgDir/entitlements.xml",
                "-s", signingIdentity,
                appBundle
            )
        }
        println("Codesign output: ${result2.standardOutput.asText.get()}")
        if (result2.standardError.asText.get().isNotEmpty()) {
            println("Codesign errors: ${result2.standardError.asText.get()}")
        }

        println("App bundle signed successfully")
    }
}

tasks.register<Exec>("dmg") {
    group = "distribution"
    description = "Create macOS DMG disk image"

    dependsOn("signapp")

    doFirst {
        val distDir = extension.distDir.get().asFile.absolutePath
        val dmgFile = extension.dmgFile.get()
        mkdir(distDir)
        delete("$distDir/$dmgFile")
    }

    workingDir(layout.buildDirectory)

    commandLine("create-dmg", "--overwrite",
        "${extension.appBundleDir.get().asFile.absolutePath}/${extension.appBundle.get()}",
        extension.distDir.get().asFile.absolutePath)

    doLast {
        val distDir = extension.distDir.get().asFile.absolutePath
        val appName = extension.appName.get()
        val appVersion = extension.appVersion.get()
        val dmgFile = extension.dmgFile.get()

        file("$distDir/$appName $appVersion.dmg").renameTo(file("$distDir/$dmgFile"))
        println("DMG created successfully: $distDir/$dmgFile")
    }
}

tasks.register<Exec>("notarization") {
    group = "distribution"
    description = "Notarize macOS DMG with Apple"

    dependsOn("dmg")

    workingDir(layout.buildDirectory)

    commandLine(
        "xcrun",
        "notarytool",
        "submit",
        "--keychain-profile", "notarization-profile",
        "--wait",
        "${extension.distDir.get().asFile.absolutePath}/${extension.dmgFile.get()}"
    )

    doLast {
        println("Notarization submitted successfully")
    }
}
