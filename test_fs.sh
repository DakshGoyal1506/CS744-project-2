#!/bin/bash

# Define the mount point and executable names
MOUNT_POINT="./mountpoint"
FS_EXECUTABLE="./simple_fs"

# Ensure the mount point exists
mkdir -p "$MOUNT_POINT"

# Compile the filesystem code
echo "Compiling the filesystem code..."
gcc -Wall -o simple_fs simple_fs.c `pkg-config fuse3 --cflags --libs`
if [ $? -ne 0 ]; then
    echo "Compilation failed. Exiting."
    exit 1
fi

# Mount the filesystem in the background
echo "Mounting the filesystem..."
$FS_EXECUTABLE -f "$MOUNT_POINT" &
FS_PID=$!
sleep 2  # Give it some time to mount

# Function to clean up on exit
cleanup() {
    echo "Cleaning up..."
    # Unmount the filesystem
    fusermount3 -u "$MOUNT_POINT"
    # Kill the filesystem process if still running
    kill $FS_PID 2>/dev/null
    wait $FS_PID 2>/dev/null
    # Remove the mount point
    rm -rf "$MOUNT_POINT"
    echo "Done."
}
trap cleanup EXIT

# Navigate to the mount point
cd "$MOUNT_POINT"

echo "Filesystem mounted at $MOUNT_POINT"

# Begin the testing process

echo -e "\n===== Round 1: Creating directories and files =====\n"

echo "Creating directories dir1 and dir2..."
mkdir dir1
mkdir dir2

echo "Creating files file1.txt and file2.txt..."
touch file1.txt
touch dir1/file2.txt

echo "Writing data to file1.txt..."
echo "Hello, this is the first version of file1." > file1.txt

echo "Writing data to dir1/file2.txt..."
echo "This is file2 in dir1, first version." > dir1/file2.txt

echo "Listing the files and directories:"
ls -R

echo -e "\n===== Creating Snapshot 0 =====\n"
echo "Creating snapshot by writing to .snapshot_create..."
echo "snapshot" > .snapshot_create

echo "Listing snapshots:"
ls .snapshots

echo -e "\n===== Modifying files =====\n"

echo "Appending data to file1.txt..."
echo "Adding more content to file1." >> file1.txt

echo "Overwriting data in dir1/file2.txt..."
echo "This is the second version of file2 in dir1." > dir1/file2.txt

echo -e "\n===== Accessing previous versions =====\n"

echo "Reading the latest version of file1.txt:"
cat file1.txt

echo "Reading version 0 of file1.txt:"
cat "file1.txt@0"

echo "Reading the latest version of dir1/file2.txt:"
cat dir1/file2.txt

echo "Reading version 0 of dir1/file2.txt:"
cat "dir1/file2.txt@0"

echo -e "\n===== Creating Snapshot 1 =====\n"
echo "Creating another snapshot..."
echo "snapshot" > .snapshot_create

echo "Listing snapshots:"
ls .snapshots

echo -e "\n===== Modifying files again =====\n"

echo "Deleting file1.txt..."
rm file1.txt

echo "Creating new file file3.txt in dir2..."
echo "Content of file3 in dir2." > dir2/file3.txt

echo "Listing the files and directories:"
ls -R

echo -e "\n===== Creating Snapshot 2 =====\n"
echo "Creating another snapshot..."
echo "snapshot" > .snapshot_create

echo "Listing snapshots:"
ls .snapshots

echo -e "\n===== Generating Diff between Snapshot 0 and Snapshot 2 =====\n"
echo "Creating diff file in .diffs directory..."
touch ".diffs/0_2"

echo "Reading the diff file:"
cat ".diffs/0_2"

echo -e "\n===== Rolling back to Snapshot 0 =====\n"
echo "Rolling back to snapshot 0 by writing to .rollback..."
echo "0" > .rollback

echo "Listing the files and directories after rollback:"
ls -R

echo "Reading file1.txt after rollback:"
cat file1.txt

echo "Reading dir1/file2.txt after rollback:"
cat dir1/file2.txt

echo -e "\n===== Round 2: Modifying after rollback =====\n"

echo "Appending data to file1.txt..."
echo "This is new content after rollback." >> file1.txt

echo "Listing versions of file1.txt:"
echo "Reading latest version of file1.txt:"
cat file1.txt

echo "Reading version 0 of file1.txt:"
cat "file1.txt@0"

echo "Reading version 1 of file1.txt:"
cat "file1.txt@1"

echo -e "\n===== Creating Snapshot 3 =====\n"
echo "Creating another snapshot..."
echo "snapshot" > .snapshot_create

echo "Listing snapshots:"
ls .snapshots

echo -e "\n===== Final Cleanup =====\n"
echo "Script execution completed. Exiting."
