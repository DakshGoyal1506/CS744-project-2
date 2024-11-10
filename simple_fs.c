#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <libgen.h>
#include <stdbool.h>

struct file_version {
    size_t version_number;
    char *content;
    size_t size;
    struct timespec timestamp;
    struct file_version *next;
};

// Structure representing a file or directory
struct file_node {
    char *name;
    char *content;           // Latest content
    size_t size;             // Latest size
    mode_t mode;
    uid_t uid;
    gid_t gid;
    struct timespec atime;
    struct timespec mtime;
    struct timespec ctime;
    struct file_node *next;
    int is_directory;
    struct file_node *children;

    // Versioning fields
    size_t current_version;
    struct file_version *versions;  // Linked list of versions
};

// Root node of the filesystem
static struct file_node *root = NULL;

// Function to initialize the root node
static void initialize_root() {
    root = malloc(sizeof(struct file_node));
    if (!root) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memset(root, 0, sizeof(struct file_node));
    root->name = strdup("");  // Root has an empty name
    if (!root->name) {
        perror("strdup");
        free(root);
        exit(EXIT_FAILURE);
    }
    root->mode = S_IFDIR | 0755;
    root->uid = getuid();
    root->gid = getgid();
    clock_gettime(CLOCK_REALTIME, &root->atime);
    root->mtime = root->atime;
    root->ctime = root->atime;
    root->is_directory = 1;
    root->children = NULL;
    root->next = NULL;
    root->current_version = 0;
    root->versions = NULL;
    printf("Initialized root directory.\n");
}

// Function to free version list
void free_version_list(struct file_version *ver) {
    while (ver) {
        struct file_version *next_ver = ver->next;
        free(ver->content);
        free(ver);
        ver = next_ver;
    }
}

// Function to free nodes recursively
static void free_node(struct file_node *node) {
    if (node == NULL)
        return;
    // Recursively free child nodes
    struct file_node *child = node->children;
    while (child != NULL) {
        struct file_node *next_child = child->next;
        free_node(child);
        child = next_child;
    }
    // Free the node's versions
    free_version_list(node->versions);
    // Free the node's name and content
    free(node->name);
    free(node->content);
    free(node);
}

// Cleanup function called on filesystem unmount
static void destroy_fs(void *private_data) {
    printf("Unmounting filesystem. Cleaning up memory.\n");
    free_node(root);
}

// Function to remove leading and trailing slashes from a path
static void trim_slashes(char *path) {
    // Remove leading slashes
    while (*path == '/' && *(path + 1) != '\0') {
        memmove(path, path + 1, strlen(path));
    }
    // Remove trailing slashes
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') {
        path[len - 1] = '\0';
        len--;
    }
}

// Function to find a node given a path
static struct file_node* find_node(const char *path) {
    printf("find_node called with path: %s\n", path);
    if (strcmp(path, "/") == 0) {
        printf("Path is root.\n");
        return root;
    }

    char *path_copy = strdup(path);
    if (!path_copy) {
        perror("strdup");
        return NULL;
    }

    // Versioning Logic: Remove version specifier if present
    char *version_sep = strchr(path_copy, '@');
    if (version_sep) {
        *version_sep = '\0';  // Terminate the path before '@'
    }

    trim_slashes(path_copy);

    struct file_node *current = root;
    char *token = strtok(path_copy, "/");
    while (token != NULL && current != NULL) {
        printf("Looking for token: %s\n", token);
        struct file_node *child = current->children;
        while (child != NULL) {
            if (strcmp(child->name, token) == 0) {
                printf("Found child: %s\n", child->name);
                current = child;
                break;
            }
            child = child->next;
        }
        if (child == NULL) {
            printf("Child not found for token: %s\n", token);
            free(path_copy);
            return NULL;
        }
        token = strtok(NULL, "/");
    }
    free(path_copy);
    printf("find_node returning node: %s\n", current->name);
    return current;
}

// getattr callback
static int simple_getattr(const char *path, struct stat *stbuf,
                          struct fuse_file_info *fi) {
    printf("getattr called for path: %s\n", path);
    (void) fi;
    memset(stbuf, 0, sizeof(struct stat));

    // Versioning Logic
    char *versioned_path = strdup(path);
    if (!versioned_path) {
        perror("strdup");
        return -ENOMEM;
    }
    char *version_str = strchr(versioned_path, '@');
    size_t version_number = (size_t)-1;
    if (version_str) {
        *version_str = '\0';
        version_str++;
        version_number = strtoul(version_str, NULL, 10);
    }
    struct file_node *node = find_node(versioned_path);
    free(versioned_path);

    if (node == NULL) {
        printf("getattr: No such file or directory: %s\n", path);
        return -ENOENT;
    }

    if (version_number != (size_t)-1) {
        // Get attributes for a specific version
        struct file_version *ver = node->versions;
        while (ver) {
            if (ver->version_number == version_number) {
                stbuf->st_mode = node->mode;
                stbuf->st_nlink = node->is_directory ? 2 : 1;
                stbuf->st_size = ver->size;
                stbuf->st_uid = node->uid;
                stbuf->st_gid = node->gid;
                stbuf->st_atim = node->atime;
                stbuf->st_mtim = ver->timestamp;
                stbuf->st_ctim = node->ctime;
                printf("getattr: path %s@%zu, mode %o, size %zu\n", path, version_number, node->mode, ver->size);
                return 0;
            }
            ver = ver->next;
        }
        printf("getattr: Version %zu not found for %s\n", version_number, node->name);
        return -ENOENT;
    }

    stbuf->st_mode = node->mode;
    stbuf->st_nlink = node->is_directory ? 2 : 1;
    stbuf->st_size = node->size;
    stbuf->st_uid = node->uid;
    stbuf->st_gid = node->gid;
    stbuf->st_atim = node->atime;
    stbuf->st_mtim = node->mtime;
    stbuf->st_ctim = node->ctime;
    printf("getattr: path %s, mode %o, size %zu\n", path, node->mode, node->size);
    return 0;
}

// readdir callback
static int simple_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                          off_t offset, struct fuse_file_info *fi,
                          enum fuse_readdir_flags flags) {
    printf("readdir called for path: %s\n", path);
    (void) offset;
    (void) fi;
    (void) flags;
    struct file_node *node = find_node(path);
    if (node == NULL || !node->is_directory) {
        printf("readdir: No such directory: %s\n", path);
        return -ENOENT;
    }
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    struct file_node *child = node->children;
    while (child != NULL) {
        if (child->name != NULL && strlen(child->name) > 0) {  // Ensure name is valid
            printf("readdir: Adding entry %s\n", child->name);
            filler(buf, child->name, NULL, 0, 0);
        } else {
            printf("readdir: Encountered child with invalid name.\n");
        }
        child = child->next;
    }
    return 0;
}

// mkdir callback
static int simple_mkdir(const char *path, mode_t mode) {
    printf("mkdir called for path: %s with mode: %o\n", path, mode);

    // Make copies of the path since dirname and basename may modify them
    char *path_copy1 = strdup(path);
    char *path_copy2 = strdup(path);
    if (!path_copy1 || !path_copy2) {
        perror("strdup");
        free(path_copy1);
        free(path_copy2);
        return -ENOMEM;
    }

    trim_slashes(path_copy1);
    trim_slashes(path_copy2);

    char *parent_path = dirname(path_copy1);
    char *base_name = basename(path_copy2);

    // Check if base_name is empty
    if (strlen(base_name) == 0 || strcmp(base_name, "/") == 0) {
        printf("mkdir: Invalid path (empty base name): %s\n", path);
        free(path_copy1);
        free(path_copy2);
        return -EINVAL;
    }

    // Handle parent path being empty
    if (strcmp(parent_path, ".") == 0) {
        parent_path = "/";
    }

    printf("After splitting: parent_path='%s', base_name='%s'\n", parent_path, base_name);

    struct file_node *parent = find_node(parent_path);
    if (parent == NULL || !parent->is_directory) {
        printf("mkdir: Parent directory does not exist: %s\n", parent_path);
        free(path_copy1);
        free(path_copy2);
        return -ENOENT;
    }

    // Check if directory already exists
    struct file_node *existing = parent->children;
    while (existing != NULL) {
        if (strcmp(existing->name, base_name) == 0) {
            printf("mkdir: Directory already exists: %s\n", base_name);
            free(path_copy1);
            free(path_copy2);
            return -EEXIST;
        }
        existing = existing->next;
    }

    struct file_node *new_dir = malloc(sizeof(struct file_node));
    if (!new_dir) {
        perror("malloc");
        free(path_copy1);
        free(path_copy2);
        return -ENOMEM;
    }
    memset(new_dir, 0, sizeof(struct file_node));
    new_dir->name = strdup(base_name);
    if (!new_dir->name) {
        perror("strdup");
        free(new_dir);
        free(path_copy1);
        free(path_copy2);
        return -ENOMEM;
    }

    new_dir->mode = S_IFDIR | mode;
    new_dir->uid = getuid();
    new_dir->gid = getgid();
    clock_gettime(CLOCK_REALTIME, &new_dir->atime);
    new_dir->mtime = new_dir->atime;
    new_dir->ctime = new_dir->atime;
    new_dir->is_directory = 1;
    new_dir->children = NULL;
    new_dir->next = parent->children;
    parent->children = new_dir;

    printf("mkdir: Created directory: %s\n", new_dir->name);

    free(path_copy1);
    free(path_copy2);

    return 0;
}

// rmdir callback
static int simple_rmdir(const char *path) {
    printf("rmdir called for path: %s\n", path);

    // Make copies of the path since dirname and basename may modify them
    char *path_copy1 = strdup(path);
    char *path_copy2 = strdup(path);
    if (!path_copy1 || !path_copy2) {
        perror("strdup");
        free(path_copy1);
        free(path_copy2);
        return -ENOMEM;
    }

    trim_slashes(path_copy1);
    trim_slashes(path_copy2);

    char *parent_path = dirname(path_copy1);
    char *base_name = basename(path_copy2);

    // Check if base_name is empty
    if (strlen(base_name) == 0 || strcmp(base_name, "/") == 0) {
        printf("rmdir: Invalid path (empty base name): %s\n", path);
        free(path_copy1);
        free(path_copy2);
        return -EINVAL;
    }

    if (strcmp(parent_path, ".") == 0) {
        parent_path = "/";
    }

    printf("After splitting: parent_path='%s', base_name='%s'\n", parent_path, base_name);

    struct file_node *parent = find_node(parent_path);
    if (parent == NULL || !parent->is_directory) {
        printf("rmdir: Parent directory does not exist: %s\n", parent_path);
        free(path_copy1);
        free(path_copy2);
        return -ENOENT;
    }

    // Find the directory to remove
    struct file_node **current = &parent->children;
    while (*current != NULL) {
        if (strcmp((*current)->name, base_name) == 0) {
            if ((*current)->children != NULL) {
                printf("rmdir: Directory not empty: %s\n", path);
                free(path_copy1);
                free(path_copy2);
                return -ENOTEMPTY;
            }
            struct file_node *to_delete = *current;
            *current = to_delete->next;
            printf("rmdir: Removing directory: %s\n", to_delete->name);
            free_node(to_delete);
            free(path_copy1);
            free(path_copy2);
            return 0;
        }
        current = &(*current)->next;
    }
    printf("rmdir: Directory not found: %s\n", base_name);
    free(path_copy1);
    free(path_copy2);
    return -ENOENT;
}

// create callback
static int simple_create(const char *path, mode_t mode,
                         struct fuse_file_info *fi) {
    printf("create called for path: %s with mode: %o\n", path, mode);

    // Make copies of the path since dirname and basename may modify them
    char *path_copy1 = strdup(path);
    char *path_copy2 = strdup(path);
    if (!path_copy1 || !path_copy2) {
        perror("strdup");
        free(path_copy1);
        free(path_copy2);
        return -ENOMEM;
    }

    trim_slashes(path_copy1);
    trim_slashes(path_copy2);

    char *parent_path = dirname(path_copy1);
    char *base_name = basename(path_copy2);

    // Check if base_name is empty
    if (strlen(base_name) == 0 || strcmp(base_name, "/") == 0) {
        printf("create: Invalid path (empty base name): %s\n", path);
        free(path_copy1);
        free(path_copy2);
        return -EINVAL;
    }

    // Handle parent path being empty
    if (strcmp(parent_path, ".") == 0) {
        parent_path = "/";
    }

    printf("After splitting: parent_path='%s', base_name='%s'\n", parent_path, base_name);

    struct file_node *parent = find_node(parent_path);
    if (parent == NULL || !parent->is_directory) {
        printf("create: Parent directory does not exist: %s\n", parent_path);
        free(path_copy1);
        free(path_copy2);
        return -ENOENT;
    }

    // Check if file already exists
    struct file_node *existing = parent->children;
    while (existing != NULL) {
        if (strcmp(existing->name, base_name) == 0) {
            printf("create: File already exists: %s\n", base_name);
            free(path_copy1);
            free(path_copy2);
            return -EEXIST;
        }
        existing = existing->next;
    }

    struct file_node *new_file = malloc(sizeof(struct file_node));
    if (!new_file) {
        perror("malloc");
        free(path_copy1);
        free(path_copy2);
        return -ENOMEM;
    }
    memset(new_file, 0, sizeof(struct file_node));
    new_file->name = strdup(base_name);
    if (!new_file->name) {
        perror("strdup");
        free(new_file);
        free(path_copy1);
        free(path_copy2);
        return -ENOMEM;
    }

    new_file->mode = S_IFREG | mode;
    new_file->uid = getuid();
    new_file->gid = getgid();
    clock_gettime(CLOCK_REALTIME, &new_file->atime);
    new_file->mtime = new_file->atime;
    new_file->ctime = new_file->atime;
    new_file->is_directory = 0;
    new_file->content = NULL;
    new_file->size = 0;
    new_file->next = parent->children;
    parent->children = new_file;

    printf("create: Created file: %s\n", new_file->name);

    free(path_copy1);
    free(path_copy2);

    return 0;
}

// unlink callback
static int simple_unlink(const char *path) {
    printf("unlink called for path: %s\n", path);

    // Make copies of the path since dirname and basename may modify them
    char *path_copy1 = strdup(path);
    char *path_copy2 = strdup(path);
    if (!path_copy1 || !path_copy2) {
        perror("strdup");
        free(path_copy1);
        free(path_copy2);
        return -ENOMEM;
    }

    trim_slashes(path_copy1);
    trim_slashes(path_copy2);

    char *parent_path = dirname(path_copy1);
    char *base_name = basename(path_copy2);

    // Check if base_name is empty
    if (strlen(base_name) == 0 || strcmp(base_name, "/") == 0) {
        printf("unlink: Invalid path (empty base name): %s\n", path);
        free(path_copy1);
        free(path_copy2);
        return -EINVAL;
    }

    if (strcmp(parent_path, ".") == 0) {
        parent_path = "/";
    }

    printf("After splitting: parent_path='%s', base_name='%s'\n", parent_path, base_name);

    struct file_node *parent = find_node(parent_path);
    if (parent == NULL || !parent->is_directory) {
        printf("unlink: Parent directory does not exist: %s\n", parent_path);
        free(path_copy1);
        free(path_copy2);
        return -ENOENT;
    }

    struct file_node **current = &parent->children;
    while (*current != NULL) {
        if (strcmp((*current)->name, base_name) == 0) {
            if ((*current)->is_directory) {
                printf("unlink: Cannot unlink directory: %s\n", path);
                free(path_copy1);
                free(path_copy2);
                return -EISDIR;
            }
            struct file_node *to_delete = *current;
            *current = to_delete->next;
            printf("unlink: Removing file: %s\n", to_delete->name);
            free_node(to_delete);
            free(path_copy1);
            free(path_copy2);
            return 0;
        }
        current = &(*current)->next;
    }
    printf("unlink: File not found: %s\n", base_name);
    free(path_copy1);
    free(path_copy2);
    return -ENOENT;
}

// open callback
static int simple_open(const char *path, struct fuse_file_info *fi) {
    printf("open called for path: %s\n", path);
    struct file_node *node = find_node(path);
    if (node == NULL || node->is_directory) {
        printf("open: No such file: %s\n", path);
        return -ENOENT;
    }
    // For simplicity, no file handles are managed
    return 0;
}

// read callback
static int simple_read(const char *path, char *buf, size_t size, off_t offset,
                       struct fuse_file_info *fi) {
    printf("read called for path: %s, size: %zu, offset: %ld\n", path, size, offset);
    (void) fi;

    // Versioning Logic
    char *versioned_path = strdup(path);
    if (!versioned_path) {
        perror("strdup");
        return -ENOMEM;
    }
    char *version_str = strchr(versioned_path, '@');
    size_t version_number = (size_t)-1;  // Default to latest
    if (version_str) {
        *version_str = '\0';  // Terminate the path at '@'
        version_str++;        // Move to the version number
        version_number = strtoul(version_str, NULL, 10);
    }

    struct file_node *node = find_node(versioned_path);
    free(versioned_path);
    if (node == NULL) {
        printf("read: No such file: %s\n", path);
        return -ENOENT;
    }
    if (node->is_directory) {
        printf("read: Attempted to read a directory: %s\n", path);
        return -EISDIR;
    }

    const char *data = NULL;
    size_t data_size = 0;

    if (version_number != (size_t)-1) {
        // Read specific version
        struct file_version *ver = node->versions;
        while (ver) {
            if (ver->version_number == version_number) {
                data = ver->content;
                data_size = ver->size;
                printf("read: Reading version %zu of %s\n", version_number, node->name);
                break;
            }
            ver = ver->next;
        }
        if (!data) {
            printf("read: Version %zu not found for %s\n", version_number, node->name);
            return -ENOENT;
        }
    } else {
        // Read latest version
        data = node->content;
        data_size = node->size;
    }

    if (data == NULL) {
        // No content to read
        size = 0;
    } else if (offset < data_size) {
        if (offset + size > data_size)
            size = data_size - offset;
        memcpy(buf, data + offset, size);
    } else {
        size = 0;
    }
    clock_gettime(CLOCK_REALTIME, &node->atime);
    printf("read: Returning %zu bytes from offset %ld\n", size, offset);
    return size;
}

// write callback
static int simple_write(const char *path, const char *buf, size_t size,
                        off_t offset, struct fuse_file_info *fi) {
    printf("write called for path: %s, size: %zu, offset: %ld\n", path, size, offset);
    (void) fi;
    struct file_node *node = find_node(path);
    if (node == NULL) {
        printf("write: No such file: %s\n", path);
        return -ENOENT;
    }
    if (node->is_directory) {
        printf("write: Attempted to write to a directory: %s\n", path);
        return -EISDIR;
    }

    // Versioning Logic
    // Save current content as a new version before modifying
    struct file_version *new_version = malloc(sizeof(struct file_version));
    if (!new_version) {
        perror("malloc");
        return -ENOMEM;
    }
    new_version->version_number = node->current_version++;
    new_version->timestamp = node->mtime;  // Use current modification time
    new_version->size = node->size;
    if (node->content && node->size > 0) {
        new_version->content = malloc(node->size);
        if (!new_version->content) {
            perror("malloc");
            free(new_version);
            return -ENOMEM;
        }
        memcpy(new_version->content, node->content, node->size);
    } else {
        new_version->content = NULL;
    }
    new_version->next = node->versions;
    node->versions = new_version;
    printf("write: Saved version %zu of %s\n", new_version->version_number, path);

    // Adjust content size and reallocate if necessary
    if (offset + size > node->size) {
        char *new_content = realloc(node->content, offset + size);
        if (!new_content) {
            perror("realloc");
            return -ENOMEM;
        }
        if (offset > node->size) {
            memset(new_content + node->size, 0, offset - node->size);
        }
        node->content = new_content;
        node->size = offset + size;
    }
    memcpy(node->content + offset, buf, size);
    clock_gettime(CLOCK_REALTIME, &node->mtime);
    printf("write: Wrote %zu bytes to %s at offset %ld\n", size, path, offset);

    // Optional: Keep only the last 5 versions
    struct file_version *ver = node->versions;
    int count = 0;
    while (ver) {
        count++;
        if (count > 5) {
            // Remove older versions
            struct file_version *to_delete = ver->next;
            if (to_delete) {
                ver->next = NULL;
                free_version_list(to_delete);
            }
            break;
        }
        ver = ver->next;
    }

    return size;
}


// truncate callback
static int simple_truncate(const char *path, off_t size,
                           struct fuse_file_info *fi) {
    printf("truncate called for path: %s, size: %ld\n", path, size);
    (void) fi;
    struct file_node *node = find_node(path);
    if (node == NULL) {
        printf("truncate: No such file or directory: %s\n", path);
        return -ENOENT;
    }
    if (node->is_directory) {
        printf("truncate: Cannot truncate a directory: %s\n", path);
        return -EISDIR;
    }
    if (size != node->size) {
        char *new_content = realloc(node->content, size);
        if (!new_content && size != 0) {
            perror("realloc");
            return -ENOMEM;
        }
        if (size > node->size) {
            memset(new_content + node->size, 0, size - node->size);
        }
        node->content = new_content;
        node->size = size;
        clock_gettime(CLOCK_REALTIME, &node->mtime);
        printf("truncate: Updated size to %zu\n", node->size);
    }
    return 0;
}

// utimens callback
static int simple_utimens(const char *path, const struct timespec tv[2],
                          struct fuse_file_info *fi) {
    printf("utimens called for path: %s\n", path);
    (void) fi;
    struct file_node *node = find_node(path);
    if (node == NULL) {
        printf("utimens: No such file or directory: %s\n", path);
        return -ENOENT;
    }
    node->atime = tv[0];
    node->mtime = tv[1];
    printf("utimens: Updated atime and mtime\n");
    return 0;
}

// chmod callback
static int simple_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
    printf("chmod called for path: %s, mode: %o\n", path, mode);
    (void) fi;
    struct file_node *node = find_node(path);
    if (node == NULL) {
        printf("chmod: No such file or directory: %s\n", path);
        return -ENOENT;
    }
    node->mode = (node->mode & S_IFMT) | (mode & ~S_IFMT);
    clock_gettime(CLOCK_REALTIME, &node->ctime);
    printf("chmod: Updated mode to %o\n", node->mode);
    return 0;
}

// chown callback
static int simple_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
    printf("chown called for path: %s, uid: %d, gid: %d\n", path, uid, gid);
    (void) fi;
    struct file_node *node = find_node(path);
    if (node == NULL) {
        printf("chown: No such file or directory: %s\n", path);
        return -ENOENT;
    }
    if (uid != (uid_t)-1) {
        node->uid = uid;
        printf("chown: Updated uid to %d\n", uid);
    }
    if (gid != (gid_t)-1) {
        node->gid = gid;
        printf("chown: Updated gid to %d\n", gid);
    }
    clock_gettime(CLOCK_REALTIME, &node->ctime);
    return 0;
}

// fuse_operations structure
static const struct fuse_operations simple_oper = {
    .getattr    = simple_getattr,
    .readdir    = simple_readdir,
    .mkdir      = simple_mkdir,
    .rmdir      = simple_rmdir,
    .create     = simple_create,
    .unlink     = simple_unlink,
    .open       = simple_open,
    .read       = simple_read,
    .write      = simple_write,
    .truncate   = simple_truncate,
    .utimens    = simple_utimens,
    .chmod      = simple_chmod,
    .chown      = simple_chown,
    .destroy    = destroy_fs,  // Cleanup callback
};

int main(int argc, char *argv[]) {
    initialize_root();
    printf("Starting FUSE filesystem...\n");
    return fuse_main(argc, argv, &simple_oper, NULL);
}