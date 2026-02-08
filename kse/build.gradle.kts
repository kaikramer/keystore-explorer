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
import java.nio.file.Paths
import java.text.SimpleDateFormat
import java.util.*

/*
Notes:
======
- Task 'innosetup' requires an installation of InnoSetup 6 and ISCC.exe added to the PATH.
- Tasks 'signapp' and 'dmg' work only under macOS.
- Tasks 'prepareExe', 'zip' and 'innosetup' require an installation of Resource Hacker (http://www.angusj.com/resourcehacker/)
*/

plugins {
    application
    java
    eclipse
    idea
}

defaultTasks("zip")

repositories {
    mavenCentral()
}

val props = Properties().apply {
    load(project.rootProject.file("src/main/resources/org/kse/version.properties").inputStream())
}

version = props.getProperty("KSE.Version")

// Extension properties
val appName: String by extra(props.getProperty("KSE.Name"))
val appAltName: String by extra(props.getProperty("KSE.AltName"))
val appVersion: String by extra(props.getProperty("KSE.Version"))
val appSimpleName: String by extra(
    if (project.hasProperty("appSimpleName")) project.property("appSimpleName") as String
    else props.getProperty("KSE.SimpleName")
)
val appSimpleVersion: String by extra(props.getProperty("KSE.SimpleVersion"))
val appUserModelId: String by extra(props.getProperty("KSE.AppUserModelId"))
val distFileNamePrefix: String by extra("$appSimpleName-$appSimpleVersion")
val appJarName: String by extra("${appSimpleName}.jar")
val appExe: String by extra("${appSimpleName}.exe")
val appBundle: String by extra("${appName}.app")
val dmgFile: String by extra(
    if (System.getProperty("os.arch") == "aarch64") "${appSimpleName}-${appSimpleVersion}-arm64.dmg"
    else "${appSimpleName}-${appSimpleVersion}-x64.dmg"
)

// Resource Hacker for setting the version info and icon of kse.exe
val rh: String by extra("c:\\Program Files (x86)\\Resource Hacker\\ResourceHacker.exe")

// Directories
val resDir: String by extra(layout.projectDirectory.dir("res").asFile.absolutePath)
val iconsDir: String by extra(layout.projectDirectory.dir("icons").asFile.absolutePath)
val licensesDir: String by extra(layout.projectDirectory.dir("licenses").asFile.absolutePath)
val launcherOutDir: String by extra(layout.buildDirectory.dir("launcher").get().asFile.absolutePath)
val jlinkOutDir: String by extra(layout.buildDirectory.dir("jlink").get().asFile.absolutePath)
val appBundleDir: String by extra(layout.buildDirectory.dir("appBundle").get().asFile.absolutePath)
val distDir: String by extra(layout.buildDirectory.dir("distributions").get().asFile.absolutePath)
val dmgDir: String by extra(layout.projectDirectory.dir("dmg").asFile.absolutePath)
val rpmBuildDir: String by extra(layout.buildDirectory.dir("rpmbuild").get().asFile.absolutePath)
val rpmStageDir: String by extra(layout.buildDirectory.dir("rpm-stage").get().asFile.absolutePath)
val dependenciesDir: java.nio.file.Path by extra(
    Paths.get(layout.buildDirectory.get().asFile.absolutePath, "dependencies")
)

// Icons
val kseIco: String by extra("$iconsDir/kse.ico")
val ksePng: String by extra("$iconsDir/kse.png")
val kseIcns: String by extra("$iconsDir/kse.icns")
val keystoreIcns: String by extra("$iconsDir/keystore.icns")

// Vendor details
val copyright: String by extra("Copyright 2004 - 2013 Wayne Grant, 2013 - 2026 Kai Kramer")
val vendor: String by extra("Wayne Grant, Kai Kramer")
val website: String by extra("https://keystore-explorer.org")

// Main class (for manifest entry)
val mainClassName: String by extra("org.kse.KSE")

application {
    mainClass.set(mainClassName)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

gradle.startParameter.showStacktrace = ShowStacktrace.ALWAYS

val appbundler by configurations.creating

dependencies {
    implementation("org.bouncycastle:bcpkix-jdk18on:1.83")
    implementation("com.miglayout:miglayout-swing:11.4.2")
    implementation("com.formdev:flatlaf:3.7:no-natives")
    implementation("com.formdev:flatlaf:3.7:linux-x86_64@so")
    implementation("com.formdev:flatlaf:3.7:macos-arm64@dylib")
    implementation("com.formdev:flatlaf:3.7:macos-x86_64@dylib")
    implementation("com.formdev:flatlaf:3.7:windows-x86_64@dll")
    implementation("com.formdev:flatlaf:3.7:windows-x86@dll")
    implementation("com.formdev:flatlaf:3.7:windows-arm64@dll")
    implementation("com.formdev:flatlaf-extras:3.7") {
        exclude(group = "com.formdev", module = "flatlaf")
    }
    implementation("com.nimbusds:nimbus-jose-jwt:10.6")
    implementation("com.google.crypto.tink:tink:1.20.0") // nimbus-jose-jwt optional dep for ed25519

    implementation("org.violetlib:vaqua:13")

    implementation("io.github.java-diff-utils:java-diff-utils:4.15")
    implementation("org.openjdk.nashorn:nashorn-core:15.7")
    implementation("com.fasterxml.jackson.jr:jackson-jr-objects:2.20.1")
    implementation("com.fasterxml.jackson.jr:jackson-jr-annotation-support:2.20.1")

    if (gradle.startParameter.taskNames.any { it in listOf("innosetup", "zip") }) {
        implementation("org.openjfx:javafx-base:17.0.17:win")
        implementation("org.openjfx:javafx-graphics:17.0.17:win")
        implementation("org.openjfx:javafx-swing:17.0.17:win")
    }
    if (gradle.startParameter.taskNames.any { it in listOf("buildDeb", "buildRpm", "zip") }) {
        implementation("org.openjfx:javafx-swing:17.0.17:linux")
        implementation("org.openjfx:javafx-base:17.0.17:linux")
        implementation("org.openjfx:javafx-graphics:17.0.17:linux")
    }
    if (gradle.startParameter.taskNames.any { it in listOf("appbundler", "dmg") }) {
        if (System.getProperty("os.arch") == "aarch64") {
            implementation("org.openjfx:javafx-base:17.0.17:mac-aarch64")
            implementation("org.openjfx:javafx-graphics:17.0.17:mac-aarch64")
            implementation("org.openjfx:javafx-swing:17.0.17:mac-aarch64")
        } else {
            implementation("org.openjfx:javafx-base:17.0.17:mac")
            implementation("org.openjfx:javafx-graphics:17.0.17:mac")
            implementation("org.openjfx:javafx-swing:17.0.17:mac")
        }

        // don't include jar in app bundle because of Apple notarization failing due to unsigned native libraries
        compileOnly("net.java.dev.jna:jna:5.17.0")
    } else {
        // currently JNA is only used for Windows, so this is fine as a temporary workaround
        implementation("net.java.dev.jna:jna:5.17.0")
    }
    if (gradle.startParameter.taskNames.any { it in listOf("zip") }) {
        implementation("org.openjfx:javafx-base:17.0.17:mac")
        implementation("org.openjfx:javafx-graphics:17.0.17:mac")
        implementation("org.openjfx:javafx-swing:17.0.17:mac")
    }

    appbundler("com.evolvedbinary.appbundler:appbundler:1.3.1")

    testImplementation("org.assertj:assertj-core:3.27.7")
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.14.1")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.14.1")
    testImplementation("org.skyscreamer:jsonassert:1.5.3")
    testImplementation("org.mockito:mockito-core:5.21.0")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.14.1")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    val mockitoAgent = configurations.testRuntimeClasspath.get().find { it.name.contains("mockito-core") }
    jvmArgs("-javaagent:${mockitoAgent}")
}

tasks.jar {
    archiveFileName.set(appJarName)
    manifest {
        attributes(
            "Built-JDK" to System.getProperty("java.version"),
            "Implementation-Title" to appName,
            "Implementation-Version" to project.version,
            "Implementation-Vendor" to vendor,
            "Specification-Title" to appName,
            "Specification-Version" to project.version,
            "Specification-Vendor" to vendor,
            "Main-Class" to mainClassName,
            "Class-Path" to configurations.runtimeClasspath.get().files.joinToString(" ") { "lib/${it.name}" },
            "Built-Date" to SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Date()),
            "Sealed" to "true"
        )
    }
}

tasks.register("prepareExe") {
    doLast {
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
    }
}

tasks.register<Zip>("zip") {
    dependsOn("prepareExe")
    archiveVersion.set(appSimpleVersion)
    into(distFileNamePrefix) {
        from(tasks.jar.get().archiveFile)
        from("$launcherOutDir/$appExe")
        from(resDir) {
            include("JavaInfo.dll", "splash*.png")
        }
        from(resDir) {
            include("kse.sh")
            filePermissions {
                unix(0x1ed) // 0755
            }
            include("readme.txt")
        }
    }
    into("$distFileNamePrefix/lib") {
        from(configurations.runtimeClasspath.get().files)
    }
    into("$distFileNamePrefix/licenses") {
        from(licensesDir) {
            include("**/*.txt")
        }
    }
    into("$distFileNamePrefix/icons") {
        from(iconsDir) {
            include("**/kse_*.png")
        }
    }
}

tasks.register<Copy>("copyDependencies") {
    from(configurations.runtimeClasspath.get().files)
    into(dependenciesDir)
}

tasks.register<Exec>("jlink") {
    outputs.dir(jlinkOutDir)
    doFirst {
        delete("$jlinkOutDir/jre")
    }

    onlyIf {
        JavaVersion.current() != JavaVersion.VERSION_17
    }

    workingDir(layout.buildDirectory)

    val javaHome = System.getProperty("java.home")
    commandLine(
        "$javaHome/bin/jlink",
        "--module-path", "$javaHome/jmods",
        "--compress", "2",
        "--strip-debug",
        "--no-header-files",
        "--no-man-pages",
        "--include-locales=en,de,fr",
        "--add-modules",
        "java.base," +
                "java.datatransfer," +
                "java.desktop," +
                "java.logging," +
                "java.naming," +
                "java.net.http," +
                "java.prefs," +
                "java.scripting," +
                "jdk.accessibility," +
                "jdk.localedata," +
                "jdk.net," +
                "jdk.charsets," +
                "jdk.security.auth," +
                "jdk.crypto.ec," +
                "jdk.crypto.cryptoki," +
                "jdk.crypto.mscapi," +
                "jdk.zipfs," +
                "jdk.unsupported," +
                "jdk.dynalink",
        "--output", "$jlinkOutDir/jre"
    )
}

tasks.register("innosetup") {
    dependsOn(tasks.jar, "prepareExe", "jlink", "copyDependencies")
    doLast {
        mkdir(distDir)
        copy {
            from("innosetup/setup.iss.template")
            rename("setup.iss.template", "setup.iss")
            filter(
                ReplaceTokens::class, "tokens" to mapOf(
                    "KSE_VERSION" to appVersion,
                    "KSE_APP_USER_MODEL_ID" to appUserModelId,
                    "KSE_JAR" to tasks.jar.get().archiveFile.get().asFile.absolutePath,
                    "LIB_DIR" to dependenciesDir.toString(),
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
    }
}

tasks.register("appbundler") {
    dependsOn(tasks.jar, "copyDependencies")
    doLast {
        ant.withGroovyBuilder {
            "taskdef"(
                "name" to "bundleapp",
                "classname" to "com.oracle.appbundler.AppBundlerTask",
                "classpath" to configurations["appbundler"].asPath
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
                "classpath"("dir" to dependenciesDir)
                "classpath"("file" to tasks.jar.get().archiveFile.get().asFile.absolutePath)
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
                "option"("value" to $$"-Dkse.app.stub=$APP_ROOT/Contents/MacOS/KeyStore Explorer")
            }
        }
        copy {
            from(resDir)
            include("splash*.png")
            into("$appBundleDir/$appName.app/Contents/Resources")
        }
    }
}

tasks.register("signapp") {
    dependsOn("appbundler")
    doLast {
        val javaDir = File("$appBundleDir/$appBundle/Contents/Java")
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
                    "-s", "Kai Kramer",
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
                            "-s", "Kai Kramer",
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
                "-s", "Kai Kramer",
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
                "-s", "Kai Kramer",
                appBundle
            )
        }
        println("Codesign output: ${result2.standardOutput.asText.get()}")
        if (result2.standardError.asText.get().isNotEmpty()) {
            println("Codesign errors: ${result2.standardError.asText.get()}")
        }
    }
}

tasks.register<Exec>("dmg") {
    dependsOn("signapp")
    doFirst {
        mkdir(distDir)
        delete("$distDir/$dmgFile")
    }
    workingDir(layout.buildDirectory)

    commandLine("create-dmg", "--overwrite", "$appBundleDir/$appBundle", distDir)

    doLast {
        file("$distDir/$appName $appVersion.dmg").renameTo(file("$distDir/$dmgFile"))
    }
}

tasks.register<Exec>("notarization") {
    dependsOn("dmg")
    workingDir(layout.buildDirectory)

    commandLine(
        "xcrun",
        "notarytool",
        "submit",
        "--keychain-profile", "notarization-profile",
        "--wait",
        "$distDir/$dmgFile"
    )
}

tasks.register("buildRpm") {
    dependsOn(tasks.jar, "copyDependencies")
    group = "distribution"
    description = "Build RPM package using rpmbuild"

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
        // Create rpmbuild directory structure
        val buildRoot = File(rpmBuildDir, "BUILD")
        val specsDir = File(rpmBuildDir, "SPECS")
        val rpmsDir = File(rpmBuildDir, "RPMS")
        val sourcesDir = File(rpmBuildDir, "SOURCES")
        val srpmsDir = File(rpmBuildDir, "SRPMS")

        listOf(buildRoot, specsDir, rpmsDir, sourcesDir, srpmsDir, rpmStageDir).forEach { dir ->
            delete(dir)
            mkdir(dir)
        }

        val stageAppDir = File(rpmStageDir)

        copy {
            from(tasks.jar.get().archiveFile)
            into(stageAppDir)
        }

        copy {
            from(configurations.runtimeClasspath.get().files)
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
                    "KSE_PACKAGE_NAME" to appSimpleName,
                    "KSE_VERSION" to appVersion,
                    "KSE_WEBSITE" to website,
                    "KSE_JAR_NAME" to appJarName,
                    "KSE_BUILD_ROOT" to rpmStageDir,
                    "KSE_DATE" to dateFormatter.format(Date()),
                    "KSE_VENDOR" to vendor
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

tasks.register("prepareDeb") {
    dependsOn(tasks.jar, "copyDependencies")
    group = "distribution"
    description = "Prepare files for Debian package build"

    doLast {
        val debStageDir = layout.buildDirectory.dir("deb-stage").get().asFile
        delete(debStageDir)
        mkdir(debStageDir)

        copy {
            from(configurations.runtimeClasspath.get().files)
            into(File(debStageDir, "lib"))
        }

        println("Prepared files for Debian package build in: $debStageDir")
    }
}

tasks.register("updateDebChangelog") {
    group = "distribution"
    description = "Update debian/changelog with current version"

    doLast {
        val changelogFile = File(projectDir, "debian/changelog")
        val dateFormatter = SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss Z", Locale.ENGLISH)

        val changelogContent = """kse ($appVersion-1) unstable; urgency=medium

  * Version $appVersion release
  * See full changelog at $website

 -- $vendor <keystore-explorer@keystore-explorer.org>  ${dateFormatter.format(Date())}
"""
        changelogFile.writeText(changelogContent)
        println("Updated debian/changelog to version $appVersion")
    }
}

tasks.register<Exec>("buildDeb") {
    dependsOn(tasks.jar, "prepareDeb", "updateDebChangelog")
    group = "distribution"
    description = "Build Debian package using debhelper and dpkg-buildpackage"

    doFirst {
        val checkDebhelper = providers.exec {
            commandLine("bash", "-c", "which dpkg-buildpackage")
            isIgnoreExitValue = true
        }
        if (checkDebhelper.result.get().exitValue != 0) {
            throw GradleException("""
                |dpkg-buildpackage is not installed. Install it with:
                |  sudo apt-get install debhelper dpkg-dev build-essential
            """.trimMargin())
        }

        val rulesFile = File(projectDir, "debian/rules")
        if (rulesFile.exists()) {
            rulesFile.setExecutable(true, false)
        }

        File(projectDir, "debian/postinst").apply { if (exists()) setExecutable(true, false) }
        File(projectDir, "debian/postrm").apply { if (exists()) setExecutable(true, false) }
    }

    workingDir(projectDir)

    commandLine(
        "dpkg-buildpackage",
        "-us", "-uc",  // Don't sign (use -k for signing)
        "-b",           // Binary only
        "--build=binary"
    )

    doLast {
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

idea {
    module {
        isDownloadJavadoc = true
        isDownloadSources = true
    }
}
