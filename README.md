# SimpleFS: A Versioned FUSE Filesystem with Snapshots and Rollback

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
  - [Mounting the Filesystem](#mounting-the-filesystem)
  - [Creating Directories and Files](#creating-directories-and-files)
  - [Writing to Files](#writing-to-files)
  - [Snapshot Functionality](#snapshot-functionality)
  - [Viewing File Versions](#viewing-file-versions)
  - [Generating Diffs Between Snapshots](#generating-diffs-between-snapshots)
  - [Rollback Functionality](#rollback-functionality)
- [Function Descriptions](#function-descriptions)
  - [Core Functions](#core-functions)
  - [FUSE Callbacks](#fuse-callbacks)
- [Functionality Implementation](#functionality-implementation)
  - [Snapshot Creation](#snapshot-creation)
  - [File Versioning](#file-versioning)
  - [Diff Generation](#diff-generation)
  - [Rollback Mechanism](#rollback-mechanism)
- [Testing](#testing)
  - [Automated Testing Script](#automated-testing-script)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## Introduction

**SimpleFS** is a user-space filesystem built using FUSE (Filesystem in Userspace) that introduces advanced versioning features such as snapshots, file versioning, diffs between snapshots, and rollback capabilities. This filesystem allows users to create multiple versions of their files, capture the state of the filesystem at various points in time, and revert to previous states as needed.

## Features

- **File Versioning**: Automatically maintains multiple versions of files upon modifications.
- **Snapshots**: Capture the entire filesystem's state at specific points in time.
- **Diff Generation**: Generate diffs between any two snapshots to understand changes.
- **Rollback**: Revert the filesystem to any previously captured snapshot.
- **Special Control Files**: Utilize special files like `.snapshot_create` and `.rollback` to manage snapshots and rollbacks.
- **Read-Only Snapshot and Diff Directories**: Ensure integrity by making snapshot and diff directories read-only.

## Architecture

SimpleFS maintains an in-memory representation of the filesystem using linked structures. Each file or directory is represented by a `file_node`, which contains metadata, content, and versioning information. Snapshots capture the state of these nodes at specific times, allowing for version tracking and rollback functionality.

## Installation

### Prerequisites

- **FUSE 3**: Ensure FUSE version 3 is installed on your system.
- **C Compiler**: `gcc` is used for compiling the filesystem.
- **pkg-config**: Required for fetching FUSE compilation flags.

### Steps

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/simplefs.git
   cd simplefs
   ```

2. **Compile the Filesystem**

   ```bash
   gcc -Wall -o simple_fs simple_fs.c `pkg-config fuse3 --cflags --libs`
   ```

   This command compiles the `simple_fs.c` source file into an executable named `simple_fs`.

## Usage

### Mounting the Filesystem

1. **Create a Mount Point**

   ```bash
   mkdir -p ~/simplefs_mount
   ```

2. **Mount the Filesystem**

   ```bash
   ./simple_fs ~/simplefs_mount
   ```

   This command mounts the filesystem at the specified mount point. The filesystem will run in the foreground by default.

3. **Unmounting the Filesystem**

   To unmount, open a new terminal and execute:

   ```bash
   fusermount3 -u ~/simplefs_mount
   ```

### Creating Directories and Files

Navigate to the mount point and create directories and files as you would in a regular filesystem.

```bash
cd ~/simplefs_mount
mkdir dir1 dir2
touch file1.txt dir1/file2.txt
```

### Writing to Files

Write data to the created files using standard commands.

```bash
echo "Hello, World!" > file1.txt
echo "This is file2 in dir1." > dir1/file2.txt
```

### Snapshot Functionality

Create snapshots to capture the current state of the filesystem.

```bash
echo "snapshot" > .snapshot_create
```

Each write to `.snapshot_create` triggers the creation of a new snapshot. Snapshots are stored in the `.snapshots` directory.

### Viewing File Versions

Access different versions of files using the `@version` suffix.

- **Latest Version**

  ```bash
  cat file1.txt
  ```

- **Specific Version**

  ```bash
  cat "file1.txt@0"
  ```

  This command reads version `0` of `file1.txt`.

### Generating Diffs Between Snapshots

Generate diffs between two snapshots by creating a file in the `.diffs` directory.

```bash
touch ".diffs/0_1"
cat ".diffs/0_1"
```

This will generate and display the differences between Snapshot `0` and Snapshot `1`.

### Rollback Functionality

Rollback the filesystem to a specific snapshot.

```bash
echo "0" > .rollback
```

This command rolls back the filesystem to Snapshot `0`, restoring all files and directories to their state at that snapshot.

## Function Descriptions

### Core Functions

- **initialize_root()**

  Initializes the root node of the filesystem, creating the `.snapshots` and `.diffs` directories.

- **create_snapshot()**

  Captures the current state of the filesystem, recording versions of all files.

- **record_file_versions()**

  Recursively records the versions of files during snapshot creation.

- **rollback_to_snapshot(size_t snapshot_id)**

  Reverts the filesystem to the specified snapshot, restoring file versions and removing changes made after the snapshot.

- **restore_file_version(struct file_node *node, const char *content, size_t size)**

  Restores a file node to a specific version by updating its content and size.

- **generate_diff(size_t snapshot_id1, size_t snapshot_id2)**

  Generates a diff between two snapshots, detailing added, modified, or deleted files.

- **free_snapshots()**

  Frees all memory allocated for snapshots upon unmounting.

- **free_node(struct file_node *node)**

  Recursively frees memory allocated for file nodes.

- **create_or_get_node(const char *path)**

  Retrieves an existing node or creates a new one based on the provided path.

### FUSE Callbacks

- **simple_getattr()**

  Retrieves file attributes, handling special files and versioned paths.

- **simple_readdir()**

  Lists directory contents, including special directories like `.snapshots` and `.diffs`.

- **simple_create()**

  Creates new files, handling diff file creation if within the `.diffs` directory.

- **simple_mkdir()**

  Creates new directories, ensuring special directories cannot be duplicated.

- **simple_unlink()**

  Removes files, preventing the removal of special files.

- **simple_open()**

  Handles file opening, enforcing read-only access for snapshot and diff directories.

- **simple_read()**

  Reads file content, supporting versioned reads and special directory content.

- **simple_write()**

  Writes data to files, managing versioning by saving previous versions before modification.

- **simple_truncate()**

  Adjusts file sizes, ensuring consistency with versioning.

- **simple_utimens()**

  Updates file access and modification times.

- **simple_chmod()**

  Changes file permissions.

- **simple_chown()**

  Changes file ownership.

- **simple_statfs()**

  Provides filesystem statistics.

- **simple_flush()**

  Flushes file buffers; no-op in this implementation.

- **simple_getxattr()**

  Handles extended attributes; not supported in this implementation.

- **destroy_fs()**

  Cleans up memory and resources upon filesystem unmounting.

## Functionality Implementation

### Snapshot Creation

- **Process**:
  1. Triggered by writing to `.snapshot_create`.
  2. Calls `create_snapshot()`.
  3. `create_snapshot()` creates a new `snapshot` structure, assigns it a unique ID, and records the current state.
  4. `record_file_versions()` traverses the filesystem, recording the current version and content of each file.
  
- **Functions Involved**:
  - `create_snapshot()`
  - `record_file_versions()`
  - `create_or_get_node()`
  - `restore_file_version()`

### File Versioning

- **Process**:
  1. On every write to a file, `simple_write()` saves the current content as a new version before modification.
  2. Versions are maintained in a linked list within each `file_node`.
  3. Only the latest 5 versions are retained to manage memory usage.
  
- **Functions Involved**:
  - `simple_write()`
  - `free_version_list()`

### Diff Generation

- **Process**:
  1. User creates a diff file in `.diffs` directory (e.g., `touch ".diffs/0_1"`).
  2. `simple_create()` detects the creation within `.diffs` and calls `generate_diff(0,1)`.
  3. `generate_diff()` compares two snapshots and records added, modified, or deleted files.
  
- **Functions Involved**:
  - `simple_create()`
  - `generate_diff()`

### Rollback Mechanism

- **Process**:
  1. Triggered by writing a snapshot ID to `.rollback` (e.g., `echo "0" > .rollback`).
  2. `simple_write()` detects writing to `.rollback` and calls `rollback_to_snapshot(0)`.
  3. `rollback_to_snapshot()` restores all files and directories to their state at Snapshot `0`, removing any changes made after.
  
- **Functions Involved**:
  - `simple_write()`
  - `rollback_to_snapshot()`
  - `restore_file_version()`
  - `remove_unvisited_nodes()`

## Testing

### Automated Testing Script

A bash script named `test_fs.sh` is provided to automate the testing of SimpleFS functionalities. The script performs the following actions:

1. **Compiles the Filesystem**: Compiles `simple_fs.c` into an executable.
2. **Mounts the Filesystem**: Mounts SimpleFS to a designated mount point.
3. **Creates Directories and Files**: Sets up initial directories and files.
4. **Writes Data**: Populates files with initial data.
5. **Creates Snapshots**: Captures snapshots at various stages.
6. **Modifies Files**: Changes file contents to create new versions.
7. **Generates Diffs**: Creates diffs between snapshots.
8. **Performs Rollbacks**: Reverts the filesystem to previous snapshots.
9. **Cleans Up**: Unmounts the filesystem and removes the mount point.

#### Script Content

```bash
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
```

#### **How to Use the Script**

1. **Ensure Prerequisites**:

   - FUSE 3 is installed.
   - You have the necessary permissions to mount FUSE filesystems.

2. **Save the Script**:

   Save the script content above into a file named `test_fs.sh` in the same directory as your `simple_fs.c` file.

3. **Make the Script Executable**:

   ```bash
   chmod +x test_fs.sh
   ```

4. **Run the Script**:

   ```bash
   ./test_fs.sh
   ```

   The script will execute a series of operations, displaying messages that describe each step. It will automatically clean up by unmounting the filesystem and removing the mount point upon completion or interruption.

## Examples

### Example 1: Basic File Operations with Snapshot and Rollback

1. **Create and Write to a File**

   ```bash
   echo "Initial content" > example.txt
   ```

2. **Create a Snapshot**

   ```bash
   echo "snapshot" > .snapshot_create
   ```

3. **Modify the File**

   ```bash
   echo "Updated content" >> example.txt
   ```

4. **Access Previous Version**

   ```bash
   cat "example.txt@0"
   ```

   This displays "Initial content".

5. **Rollback to Snapshot**

   ```bash
   echo "0" > .rollback
   ```

   The filesystem reverts `example.txt` to "Initial content".

### Example 2: Generating Diffs Between Snapshots

1. **Create Snapshot 1**

   ```bash
   echo "snapshot" > .snapshot_create
   ```

2. **Modify Files**

   ```bash
   echo "Change in file1" >> file1.txt
   echo "Change in file2" > dir1/file2.txt
   ```

3. **Create Snapshot 2**

   ```bash
   echo "snapshot" > .snapshot_create
   ```

4. **Generate Diff Between Snapshot 1 and 2**

   ```bash
   touch ".diffs/1_2"
   cat ".diffs/1_2"
   ```

   This will display the differences, such as which files were modified, added, or deleted.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

### How to Contribute

1. **Fork the Repository**

   Click the "Fork" button on the repository page.

2. **Clone Your Fork**

   ```bash
   git clone https://github.com/yourusername/simplefs.git
   cd simplefs
   ```

3. **Create a Feature Branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Make Your Changes**

5. **Commit Your Changes**

   ```bash
   git commit -m "Add your descriptive message here"
   ```

6. **Push to Your Fork**

   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request**

   Navigate to your fork on GitHub and click the "Compare & pull request" button.

## License

This project is licensed under the [MIT License](LICENSE).

---

**Disclaimer**: This filesystem is a simplified implementation intended for educational purposes. It may not handle all edge cases or provide the performance and reliability of production-grade filesystems.
