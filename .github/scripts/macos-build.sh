#!/bin/bash
set -e +x

printf "%s" "$MACOS_CERT" | base64 --decode > macos_cert.p12
security create-keychain -p buildchain build.chain
security default-keychain -s build.chain
security unlock-keychain -p buildchain build.chain
security set-keychain-settings build.chain
security import macos_cert.p12 -k build.chain -P "$MACOS_CERT_PWD" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k buildchain build.chain
rm -f macos_cert.p12

JDK_URL=$1

wget "$JDK_URL"
JDK_FILENAME=$(basename "$JDK_URL")
JDK_DIR=$(tar -tzf "$JDK_FILENAME" | head -1 | cut -f1 -d"/")
tar zxf "$JDK_FILENAME" -C "$RUNNER_TEMP"
JAVA_HOME="$RUNNER_TEMP/$JDK_DIR/Contents/Home"
echo "JAVA_HOME=$JAVA_HOME" >> "$GITHUB_ENV"
echo "$JAVA_HOME/bin" >> "$GITHUB_PATH"

npm install --global create-dmg
brew install graphicsmagick imagemagick

cd kse
chmod +x gradlew
./gradlew -Dorg.gradle.java.home="$JAVA_HOME" dmg
