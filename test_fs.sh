#!/bin/bash

# # Define the mount point and executable names
MOUNT_POINT="./mnt"
# FS_EXECUTABLE="./simple_fs"

# # Ensure the mount point exists
# mkdir -p "$MOUNT_POINT"

# # Compile the filesystem code
# echo "Compiling the filesystem code..."
# gcc -Wall -o simple_fs simple_fs.c `pkg-config fuse3 --cflags --libs`
# if [ $? -ne 0 ]; then
#     echo "Compilation failed. Exiting."
#     exit 1
# fi

# # Mount the filesystem in the background
# echo "Mounting the filesystem..."
# $FS_EXECUTABLE -f "$MOUNT_POINT" &
# FS_PID=$!
# sleep 2  # Give it some time to mount

# # Function to clean up on exit
# cleanup() {
#     echo "Cleaning up..."
#     # Unmount the filesystem
#     fusermount3 -u "$MOUNT_POINT"
#     # Kill the filesystem process if still running
#     kill $FS_PID 2>/dev/null
#     wait $FS_PID 2>/dev/null
#     # Remove the mount point
#     rm -rf "$MOUNT_POINT"
#     echo "Done."
# }
# trap cleanup EXIT

# # Navigate to the mount point
cd "$MOUNT_POINT"

# echo "Filesystem mounted at $MOUNT_POINT"

# Begin the testing process

echo -e "\n===== Round 1: Creating directories and files =====\n"

echo -e "\nCreating directories dir1 and dir2..."
mkdir dir1
mkdir dir2

echo -e "\nCreating files file1.txt and file2.txt..."
touch file1.txt
touch dir1/file2.txt

echo -e "\nWriting data to file1.txt = Hello, this is the first version of file1."
echo "Hello, this is the first version of file1." > file1.txt

echo -e "\nWriting data to dir1/file2.txt = This is file2 in dir1, first version."
echo "This is file2 in dir1, first version." > dir1/file2.txt

echo -e "\nListing the files and directories:"
ls -R

echo -e "\n===== Creating Snapshot 0 =====\n"
echo -e "\nCreating snapshot by writing to .snapshot_create..."
echo "snapshot" > .snapshot_create

echo -e "\nListing snapshots:"
ls .snapshots

echo -e "\n===== Modifying files =====\n"

echo -e "\nAppending data to file1.txt = Adding more content to file1."
echo "Adding more content to file1." >> file1.txt

echo -e "\nOverwriting data in dir1/file2.txt = This is the second version of file2 in dir1."
echo "This is the second version of file2 in dir1." > dir1/file2.txt

echo -e "\n===== Accessing previous versions =====\n"

echo -e "\nReading the latest version of file1.txt:"
cat file1.txt

echo -e "\nReading version 1 of file1.txt:"
cat "file1.txt@1"

echo -e "\nReading the latest version of dir1/file2.txt:"
cat dir1/file2.txt

echo -e "\nReading version 1 of dir1/file2.txt:"
cat "dir1/file2.txt@1"

echo -e "\n===== Creating Snapshot 1 =====\n"
echo -e "\nCreating another snapshot..."
echo "snapshot" > .snapshot_create

echo -e "\nListing snapshots:"
ls .snapshots

echo -e "\n===== Modifying files again =====\n"

echo -e "\nDeleting file1.txt..."
rm file1.txt

echo -e "\nCreating new file file3.txt in dir2 = Content of file3 in dir2."
echo "Content of file3 in dir2." > dir2/file3.txt

echo -e "\nListing the files and directories:"
ls -R

echo -e "\n===== Creating Snapshot 2 =====\n"
echo -e "\nCreating another snapshot..."
echo "snapshot" > .snapshot_create

echo -e "\nListing snapshots:"
ls .snapshots

echo -e "\n===== Generating Diff between Snapshot 0 and Snapshot 2 =====\n"
echo -e "\nCreating diff file in .diffs directory..."
touch ".diffs/0_2"

echo -e "\nReading the diff file:"
cat ".diffs/0_2"

echo -e "\n===== Rolling back to Snapshot 0 =====\n"
echo -e "\nRolling back to snapshot 0 by writing to .rollback..."
echo "0" > .rollback

echo -e "\nListing the files and directories after rollback:"
ls -R

echo -e "\nReading file1.txt after rollback:"
cat file1.txt

echo -e "\nReading dir1/file2.txt after rollback:"
cat dir1/file2.txt

echo -e "\n===== Round 2: Modifying after rollback =====\n"

echo -e "\nAppending data to file1.txt = This is new content after rollback."
echo "This is new content after rollback." >> file1.txt

echo -e "\nListing versions of file1.txt:"
echo -e "\nReading latest version of file1.txt:"
cat file1.txt

echo -e "\nReading version 1 of file1.txt:"
cat "file1.txt@1"

echo -e "\n===== Creating Snapshot 3 =====\n"
echo -e "\nCreating another snapshot..."
echo "snapshot" > .snapshot_create

echo -e "\nListing snapshots:"
ls .snapshots

echo -e "\n===== Final Cleanup =====\n"
echo "Script execution completed. Exiting."
