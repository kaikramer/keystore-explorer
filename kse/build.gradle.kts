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

import java.nio.file.Paths
import java.text.SimpleDateFormat
import java.util.*

/*
Notes:
======
- Task 'innosetup' requires an installation of InnoSetup 6 and ISCC.exe added to the PATH.
- Tasks 'signapp' and 'dmg' work only under macOS.
- Tasks 'prepareExe', 'zip' and 'innosetup' require an installation of Resource Hacker (http://www.angusj.com/resourcehacker/)
- Task 'buildAppImage' requires appimagetool on PATH and must run on Linux with a Java 25 JDK.
*/

plugins {
    application
    java
    eclipse
    idea
    id("kse-deb-package")
    id("kse-rpm-package")
    id("kse-appimage-package")
    id("kse-mac-package")
    id("kse-windows-package")
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

tasks.withType<JavaCompile>().configureEach {
    options.release = 17
}

gradle.startParameter.showStacktrace = ShowStacktrace.ALWAYS

val appbundler by configurations.creating

// Keep packaged JavaFX compatible with the Java 17 minimum runtime.
val javaFxVersion = "17.0.19"

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
    implementation("com.nimbusds:nimbus-jose-jwt:10.8") {
        exclude(group = "com.google.crypto.tink", module = "tink")
    }

    implementation("io.github.java-diff-utils:java-diff-utils:4.15")
    implementation("org.mozilla:rhino:1.7.15")
    implementation("com.fasterxml.jackson.jr:jackson-jr-objects:2.20.1")
    implementation("com.fasterxml.jackson.jr:jackson-jr-annotation-support:2.20.1")

    if (gradle.startParameter.taskNames.any { it in listOf("innosetup", "zip") }) {
        implementation("org.openjfx:javafx-base:$javaFxVersion:win")
        implementation("org.openjfx:javafx-graphics:$javaFxVersion:win")
        implementation("org.openjfx:javafx-swing:$javaFxVersion:win")
    }
    if (gradle.startParameter.taskNames.any { it in listOf("buildDeb", "buildRpm", "buildAppImage", "zip") }) {
        implementation("org.openjfx:javafx-swing:$javaFxVersion:linux")
        implementation("org.openjfx:javafx-base:$javaFxVersion:linux")
        implementation("org.openjfx:javafx-graphics:$javaFxVersion:linux")
    }
    if (gradle.startParameter.taskNames.any { it in listOf("appbundler", "dmg") }) {
        if (System.getProperty("os.arch") == "aarch64") {
            implementation("org.openjfx:javafx-base:$javaFxVersion:mac-aarch64")
            implementation("org.openjfx:javafx-graphics:$javaFxVersion:mac-aarch64")
            implementation("org.openjfx:javafx-swing:$javaFxVersion:mac-aarch64")
        } else {
            implementation("org.openjfx:javafx-base:$javaFxVersion:mac")
            implementation("org.openjfx:javafx-graphics:$javaFxVersion:mac")
            implementation("org.openjfx:javafx-swing:$javaFxVersion:mac")
        }
    }
    if (gradle.startParameter.taskNames.any { it in listOf("zip") }) {
        implementation("org.openjfx:javafx-base:$javaFxVersion:mac")
        implementation("org.openjfx:javafx-graphics:$javaFxVersion:mac")
        implementation("org.openjfx:javafx-swing:$javaFxVersion:mac")
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

tasks.register<Zip>("zip") {
    group = "distribution"
    archiveVersion.set(appSimpleVersion)
    into(distFileNamePrefix) {
        from(tasks.jar.get().archiveFile)
        from("$resDir/$appExe")
        from(resDir) {
            include("JavaInfo.dll", "splash*.png")
        }
        from(resDir) {
            include("kse.sh")
            filePermissions {
                unix("755")
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

    // jlink uses the runtime JDK and OS-specific modules, which are easier to resolve
    // at execution time than to serialize into the configuration cache.
    notCompatibleWithConfigurationCache("Uses runtime Java home and OS detection")

    onlyIf {
        JavaVersion.current() != JavaVersion.VERSION_17
    }

    workingDir(layout.buildDirectory)

    // Delay command-line construction to execution time so the configuration cache
    // does not have to serialize build-script object references.
    doFirst {
        delete("$jlinkOutDir/jre")

        val javaHome = System.getProperty("java.home")
        val modules = buildList {
            add("java.base")
            add("java.datatransfer")
            add("java.desktop")
            add("java.logging")
            add("java.naming")
            add("java.net.http")
            add("java.prefs")
            add("java.scripting")
            add("jdk.accessibility")
            add("jdk.localedata")
            add("jdk.net")
            add("jdk.charsets")
            add("jdk.security.auth")
            add("jdk.crypto.ec")
            add("jdk.crypto.cryptoki")
            if (System.getProperty("os.name")?.lowercase()?.contains("windows") == true) {
                add("jdk.crypto.mscapi")
            }
            add("jdk.zipfs")
            add("jdk.unsupported")
            add("jdk.dynalink")
        }.joinToString(",")

        commandLine(
            "$javaHome/bin/jlink",
            "--module-path", "$javaHome/jmods",
            "--compress", "zip-6",
            "--strip-debug",
            "--no-header-files",
            "--no-man-pages",
            "--include-locales=en,de,fr",
            "--add-modules", modules,
            "--output", "$jlinkOutDir/jre"
        )
    }
}

windowsPackage {
    appVersion.set(project.extra["appVersion"].toString())
    appExe.set(project.extra["appExe"].toString())
    appUserModelId.set(project.extra["appUserModelId"].toString())
    resDir.set(layout.projectDirectory.dir("res"))
    iconsDir.set(layout.projectDirectory.dir("icons"))
    licensesDir.set(layout.projectDirectory.dir("licenses"))
    jlinkOutDir.set(layout.buildDirectory.dir("jlink"))
    distDir.set(layout.buildDirectory.dir("distributions"))
    dependenciesDir.set(layout.buildDirectory.dir("dependencies"))
    jarFile.set(tasks.named<Jar>("jar").flatMap { it.archiveFile })
}

macPackage {
    appName.set(project.extra["appName"].toString())
    appAltName.set(project.extra["appAltName"].toString())
    appVersion.set(project.extra["appVersion"].toString())
    appBundle.set(project.extra["appBundle"].toString())
    copyright.set(project.extra["copyright"].toString())
    mainClassName.set(project.extra["mainClassName"].toString())
    kseIcns.set(project.extra["kseIcns"].toString())
    keystoreIcns.set(project.extra["keystoreIcns"].toString())
    appBundleDir.set(layout.buildDirectory.dir("appBundle"))
    resDir.set(layout.projectDirectory.dir("res"))
    dependenciesDir.set(layout.buildDirectory.dir("dependencies"))
    appbundlerClasspath.set(configurations["appbundler"].asPath)
    dmgDir.set(layout.projectDirectory.dir("dmg"))
    dmgFile.set(project.extra["dmgFile"].toString())
    distDir.set(layout.buildDirectory.dir("distributions"))
    signingIdentity.set("Kai Kramer")
}

debianPackage {
    appVersion.set(project.version.toString())
    website.set(project.extra["website"].toString())
    vendor.set(project.extra["vendor"].toString())
    distDir.set(layout.buildDirectory.dir("distributions"))
}

rpmPackage {
    appVersion.set(project.extra["appVersion"].toString())
    appSimpleName.set(project.extra["appSimpleName"].toString())
    appJarName.set(project.extra["appJarName"].toString())
    website.set(project.extra["website"].toString())
    vendor.set(project.extra["vendor"].toString())
    rpmBuildDir.set(layout.buildDirectory.dir("rpmbuild"))
    rpmStageDir.set(layout.buildDirectory.dir("rpm-stage"))
    distDir.set(layout.buildDirectory.dir("distributions"))
    resDir.set(layout.projectDirectory.dir("res"))
    iconsDir.set(layout.projectDirectory.dir("icons"))
    licensesDir.set(layout.projectDirectory.dir("licenses"))
}

appImagePackage {
    appName.set(project.extra["appName"].toString())
    appVersion.set(project.extra["appVersion"].toString())
    appSimpleName.set(project.extra["appSimpleName"].toString())
    appSimpleVersion.set(project.extra["appSimpleVersion"].toString())
    website.set(project.extra["website"].toString())
    appImageStageDir.set(layout.buildDirectory.dir("appimage-stage"))
    jlinkOutDir.set(layout.buildDirectory.dir("jlink"))
    distDir.set(layout.buildDirectory.dir("distributions"))
    resDir.set(layout.projectDirectory.dir("res"))
    iconsDir.set(layout.projectDirectory.dir("icons"))
    licensesDir.set(layout.projectDirectory.dir("licenses"))
}

idea {
    module {
        isDownloadJavadoc = true
        isDownloadSources = true
    }
}
