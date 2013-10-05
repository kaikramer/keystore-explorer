#!/bin/sh

# Installation directory
INSTALL_DIR=kse5.0

# Archive file
ARCHIVE_FILE=archive.tmp

# Start script
START_KSE=${INSTALL_DIR}/kse.sh

# Create installation directory
echo
echo "Creating directory $INSTALL_DIR"
mkdir $INSTALL_DIR

if [ ! -d ${INSTALL_DIR} ]; then
    echo "Failed to create installation directory $INSTALL_DIR"
    echo
    echo "Installation aborted."
    exit 1
fi

# Extract archive into installation directory
echo "Extracting into $INSTALL_DIR"

# Calculate the line number of the last line of the script
# (where the archive begins)
LAST_LINE=`awk '/^__START_OF_ARCHIVE__/ { print NR; exit 0; }' $0`

# Calculate the size of this script in bytes (the offset
# in bytes of where the archive begins)
OFFSET=`head -n $LAST_LINE "$0" | wc -c | tr -d " "`

# Use dd to get the remainder of the file using a block size
# equal to the offset, skipping the first block, which is
# exactly equal in size to this script, leaving just the archive
# which we output to file
dd if="$0" skip=1 bs=$OFFSET of=${INSTALL_DIR}/${ARCHIVE_FILE} 2>/dev/null

# Untar the archive file and clean it up
cd ${INSTALL_DIR}
tar xf ${ARCHIVE_FILE}
rm ${ARCHIVE_FILE}
cd ..

if [ ! -f ${START_KSE} ]; then
    echo "Extraction failed"
    echo
    echo "Installation aborted."
    exit 1;
fi

echo "Install complete."
echo
echo "To start KeyStore Explorer run the following commands:"
echo "1 - cd $INSTALL_DIR"
echo "2 - ./kse.sh"
echo
echo "Note that KeyStore Explorer requires that an Oracle/OpenJDK JRE of version 1.6+ be present on your path."
echo

exit 0

__START_OF_ARCHIVE__
