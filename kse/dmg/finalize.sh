#!/bin/bash

# params
dmgDir=$1
distDir=$2
appBundleFile=$3
appBundleDmg=$4
kseIcons=$5

# activate debugging
set -x

# unzip template dmg and move it to dist
#bunzip2 -k $dmgDir/template.dmg.bz2
#mv $dmgDir/template.dmg $distDir

hdiutil create -size 10m -ov $distDir/template.dmg -srcfolder "$distDir/$appBundleFile" -format UDRW -volname "KeyStore Explorer"

# mount template dmg
mkdir $distDir/tmp
hdiutil attach $distDir/template.dmg -noautoopen -mountpoint $distDir/tmp

# copy background image
mkdir $distDir/tmp/.background
cp $dmgDir/background.png $distDir/tmp/.background/

# copy DS_Store with icon positions and other settings
cp $dmgDir/DS_Store $distDir/tmp/.DS_Store

# create applications link
ln -s /Applications $distDir/tmp/

# rename app
mv "$distDir/tmp/$appBundleFile" "$distDir/tmp/KeyStore Explorer.app"

# replace placeholder dir in dmg with real app
#ditto -rsrc "$distDir/$appBundleFile" $distDir/tmp/kse.app   

# add dmg icon
cp $kseIcons $distDir/tmp/.VolumeIcon.icns
SetFile -a C $distDir/tmp

# detach dmg
sync
hdiutil detach $distDir/tmp

# compress dmg and make it read only 
rm -f "$appBundleDmg"
hdiutil convert $distDir/template.dmg -format UDZO -imagekey zlib-level=9 -o "$appBundleDmg"

# clean up
rm -rf $distDir/template.dmg $distDir/tmp
