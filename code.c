#define FUSE_USE_VERSION 31
#define _GNU_SOURCE

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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// Structure for file versions
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

    int visited;
};

// Snapshot structures
struct file_snapshot {
    char *path;               // Full path of the file
    size_t version_number;    // Version number of the file at snapshot time
    char *content;            // Content of the file at snapshot time
    size_t size;              // Size of the file content
    struct file_snapshot *next;
};

struct snapshot {
    size_t snapshot_id;
    time_t timestamp;
    struct file_snapshot *file_snapshots; // Linked list of file snapshots
    struct snapshot *next;
};

// Global variables
static struct file_node *root = NULL;            // Root node of the filesystem
static struct snapshot *snapshots_list = NULL;   // Linked list of snapshots
static size_t snapshot_counter = 0;              // Snapshot ID counter

// Function prototypes
static bool is_special_file(const char *path);
static bool is_snapshots_dir(const char *path);
static bool is_rollback_file(const char *path);
static bool is_diff_file(const char *path);
void create_snapshot();
void record_file_versions(struct file_node *node, const char *path_prefix, struct snapshot *snap);
void free_snapshots();
char* prepare_snapshot_details(struct snapshot *snap);
static void initialize_root();
static void free_node(struct file_node *node);
static void destroy_fs(void *private_data);
static void trim_slashes(char *path);
static struct file_node* find_node(const char *path);
void rollback_to_snapshot(size_t snapshot_id);
void restore_file_version(struct file_node *node, size_t version_number);
char* generate_diff(size_t snapshot_id1, size_t snapshot_id2);

// Helper function to check if a path is the snapshot creation file
static bool is_snapshot_create_file(const char *path) {
    // Normalize path to remove trailing slashes
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') {
        len--;
    }
    char normalized_path[len + 1];
    strncpy(normalized_path, path, len);
    normalized_path[len] = '\0';

    return strcmp(normalized_path, "/.snapshot_create") == 0;
}

// Update is_special_file to include .snapshot_create instead of .snapshot
static bool is_special_file(const char *path) {
    return is_snapshot_create_file(path) || is_rollback_file(path);
}

static bool is_snapshots_dir(const char *path) {
    // Normalize path to remove trailing slashes
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') {
        len--;
    }
    char normalized_path[len + 1];
    strncpy(normalized_path, path, len);
    normalized_path[len] = '\0';

    return strcmp(normalized_path, "/.snapshots") == 0;
}

static bool is_rollback_file(const char *path) {
    size_t len = strlen(path);
    while (len > 1 && path[len -1] == '/') {
        len--;
    }
    char normalized_path[len +1];
    strncpy(normalized_path, path, len);
    normalized_path[len] = '\0';

    return strcmp(normalized_path, "/.rollback") == 0;
}

static bool is_diff_file(const char *path) {
    // Normalize path to remove trailing slashes
    size_t len = strlen(path);
    while (len > 1 && path[len -1] == '/') {
        len--;
    }
    char normalized_path[len +1];
    strncpy(normalized_path, path, len);
    normalized_path[len] = '\0';

    // Check if path is "/.diffs" or starts with "/.diffs/"
    return strcmp(normalized_path, "/.diffs") == 0 || strncmp(normalized_path, "/.diffs/", 8) == 0;
}

// Initialize the root node of the filesystem
static void initialize_root() {
    if (root == NULL) {
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
    } else {
        // If root already exists, reset its properties
        root->children = NULL;
        root->current_version = 0;
        root->versions = NULL;
        free(root->content);
        root->content = NULL;
        root->size = 0;
        clock_gettime(CLOCK_REALTIME, &root->atime);
        root->mtime = root->atime;
        root->ctime = root->atime;
        printf("Re-initialized root directory.\n");
    }

    // Create .snapshots directory directly under root
    struct file_node *snapshots_dir = malloc(sizeof(struct file_node));
    if (!snapshots_dir) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memset(snapshots_dir, 0, sizeof(struct file_node));
    snapshots_dir->name = strdup(".snapshots");
    if (!snapshots_dir->name) {
        perror("strdup");
        free(snapshots_dir);
        exit(EXIT_FAILURE);
    }
    snapshots_dir->mode = S_IFDIR | 0755;
    snapshots_dir->uid = getuid();
    snapshots_dir->gid = getgid();
    clock_gettime(CLOCK_REALTIME, &snapshots_dir->atime);
    snapshots_dir->mtime = snapshots_dir->atime;
    snapshots_dir->ctime = snapshots_dir->atime;
    snapshots_dir->is_directory = 1;
    snapshots_dir->children = NULL;
    snapshots_dir->next = root->children;
    root->children = snapshots_dir;
    printf("Created .snapshots directory.\n");

    // Create .diffs directory directly under root
    struct file_node *diffs_dir = malloc(sizeof(struct file_node));
    if (!diffs_dir) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memset(diffs_dir, 0, sizeof(struct file_node));
    diffs_dir->name = strdup(".diffs");
    if (!diffs_dir->name) {
        perror("strdup");
        free(diffs_dir);
        exit(EXIT_FAILURE);
    }
    diffs_dir->mode = S_IFDIR | 0755;
    diffs_dir->uid = getuid();
    diffs_dir->gid = getgid();
    clock_gettime(CLOCK_REALTIME, &diffs_dir->atime);
    diffs_dir->mtime = diffs_dir->atime;
    diffs_dir->ctime = diffs_dir->atime;
    diffs_dir->is_directory = 1;
    diffs_dir->children = NULL;
    diffs_dir->next = root->children;
    root->children = diffs_dir;
    printf("Created .diffs directory.\n");
}

// Free the list of file versions
void free_version_list(struct file_version *ver) {
    while (ver) {
        struct file_version *next_ver = ver->next;
        free(ver->content);
        free(ver);
        ver = next_ver;
    }
}

// Free nodes recursively
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
    if (node != root) {
        free(node->name);
        free(node->content);
        free(node);
    } else {
        // For root, reset properties but don't free
        free(node->content);
        node->content = NULL;
        node->size = 0;
        node->children = NULL;
        node->versions = NULL;
        node->current_version = 0;
    }
}

// Free all snapshots and their associated data
void free_snapshots() {
    struct snapshot *snap = snapshots_list;
    while (snap) {
        struct snapshot *next_snap = snap->next;
        // Free file snapshots
        struct file_snapshot *fsnap = snap->file_snapshots;
        while (fsnap) {
            struct file_snapshot *next_fsnap = fsnap->next;
            free(fsnap->path);
            free(fsnap->content); // Free the content
            free(fsnap);
            fsnap = next_fsnap;
        }
        free(snap);
        snap = next_snap;
    }
    snapshots_list = NULL;
    snapshot_counter = 0;
}


// Cleanup function called on filesystem unmount
static void destroy_fs(void *private_data) {
    (void) private_data;
    printf("Unmounting filesystem. Cleaning up memory.\n");
    free_snapshots();
    free_node(root);
    free(root->name);
    free(root);
    root = NULL;
}

// Trim leading and trailing slashes from a path
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

// Find a node given a path
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
    char *token;
    char *saveptr;
    token = strtok_r(path_copy, "/", &saveptr);
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
        token = strtok_r(NULL, "/", &saveptr);
    }
    free(path_copy);
    printf("find_node returning node: %s\n", current->name);
    return current;
}

// Create a snapshot of the current filesystem state
void create_snapshot() {
    struct snapshot *new_snapshot = malloc(sizeof(struct snapshot));
    if (!new_snapshot) {
        perror("malloc");
        return;
    }
    new_snapshot->snapshot_id = snapshot_counter++;
    new_snapshot->timestamp = time(NULL);
    new_snapshot->file_snapshots = NULL;
    new_snapshot->next = snapshots_list;
    snapshots_list = new_snapshot;

    printf("create_snapshot: Created snapshot ID %zu at time %ld\n",
           new_snapshot->snapshot_id, new_snapshot->timestamp);

    // Traverse the filesystem and record current versions of files
    record_file_versions(root, "", new_snapshot);
}

// Recursively record file versions for a snapshot
void record_file_versions(struct file_node *node, const char *path_prefix,
                          struct snapshot *snap) {
    if (node == NULL)
        return;

    char *current_path = NULL;
    if (strcmp(path_prefix, "") == 0) {
        // Root directory
        if (strcmp(node->name, "") == 0) {
            current_path = strdup("/");
        } else {
            asprintf(&current_path, "/%s", node->name);
        }
    } else {
        asprintf(&current_path, "%s/%s", path_prefix, node->name);
    }

    if (!current_path) {
        perror("asprintf");
        return;
    }

    if (!node->is_directory) {
        // Record the file's current version and content
        struct file_snapshot *fsnap = malloc(sizeof(struct file_snapshot));
        if (!fsnap) {
            perror("malloc");
            free(current_path);
            return;
        }
        fsnap->path = strdup(current_path);
        fsnap->version_number = node->current_version - 1;
        fsnap->content = NULL;
        fsnap->size = 0;
        if (node->content && node->size > 0) {
            fsnap->content = malloc(node->size);
            if (!fsnap->content) {
                perror("malloc");
                free(fsnap->path);
                free(fsnap);
                free(current_path);
                return;
            }
            memcpy(fsnap->content, node->content, node->size);
            fsnap->size = node->size;
        }
        fsnap->next = snap->file_snapshots;
        snap->file_snapshots = fsnap;
        printf("record_file_versions: Recorded %s@%zu\n",
               fsnap->path, fsnap->version_number);
    }

    // Recurse into children if directory
    if (node->is_directory) {
        struct file_node *child = node->children;
        while (child) {
            record_file_versions(child, current_path, snap);
            child = child->next;
        }
    }

    free(current_path);
}


// Prepare a string containing snapshot details
char* prepare_snapshot_details(struct snapshot *snap) {
    // Calculate required buffer size
    size_t buffer_size = 256; // Initial size
    struct file_snapshot *fsnap = snap->file_snapshots;
    while (fsnap) {
        buffer_size += strlen(fsnap->path) + 50;
        fsnap = fsnap->next;
    }

    char *details = malloc(buffer_size);
    if (!details) {
        perror("malloc");
        return NULL;
    }

    time_t ts = snap->timestamp;
    struct tm *tm_info = localtime(&ts);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    snprintf(details, buffer_size, "Snapshot ID: %zu\nTimestamp: %s\nFiles:\n",
             snap->snapshot_id, time_str);

    fsnap = snap->file_snapshots;
    while (fsnap) {
        char line[256];
        snprintf(line, sizeof(line), "%s@%zu\n", fsnap->path, fsnap->version_number);
        strcat(details, line);
        fsnap = fsnap->next;
    }

    return details;
}

// Rollback to a specific snapshot
void rollback_to_snapshot(size_t snapshot_id) {
    printf("rollback_to_snapshot: Rolling back to snapshot ID %zu\n", snapshot_id);

    // Find the snapshot
    struct snapshot *snap = snapshots_list;
    while (snap) {
        if (snap->snapshot_id == snapshot_id) {
            break;
        }
        snap = snap->next;
    }
    if (!snap) {
        printf("rollback_to_snapshot: Snapshot ID %zu not found\n", snapshot_id);
        return;
    }

    // Mark all nodes as not visited
    void mark_nodes_unvisited(struct file_node *node) {
        if (!node) return;
        node->visited = 0;
        if (node->is_directory) {
            struct file_node *child = node->children;
            while (child) {
                mark_nodes_unvisited(child);
                child = child->next;
            }
        }
    }
    mark_nodes_unvisited(root);

    // Restore files and directories from the snapshot
    struct file_snapshot *fsnap = snap->file_snapshots;
    while (fsnap) {
        // Find or create the file node
        char *path = fsnap->path;
        size_t version_number = fsnap->version_number;
        printf("Restoring %s to version %zu\n", path, version_number);

        struct file_node *node = create_or_get_node(path);
        if (!node) {
            printf("rollback_to_snapshot: Failed to create node for %s\n", path);
            fsnap = fsnap->next;
            continue;
        }

        node->visited = 1;

        // Set node properties
        node->is_directory = 0;
        node->mode = S_IFREG | 0644;
        node->current_version = version_number + 1;
        node->versions = NULL; // Reset versions

        // Restore the file content
        restore_file_version(node, fsnap->content, fsnap->size);

        fsnap = fsnap->next;
    }

    // Remove files and directories not in the snapshot
    void remove_unvisited_nodes(struct file_node *node) {
        if (!node) return;
        struct file_node **current = &node->children;
        while (*current) {
            if (!(*current)->visited) {
                // Remove this node
                struct file_node *to_delete = *current;
                *current = to_delete->next;
                free_node(to_delete);
            } else {
                // Recurse into child
                remove_unvisited_nodes(*current);
                current = &(*current)->next;
            }
        }
    }
    remove_unvisited_nodes(root);

    printf("rollback_to_snapshot: Rollback to snapshot ID %zu completed\n", snapshot_id);
}


// Restore a file node to a specific version
void restore_file_version(struct file_node *node, const char *content, size_t size) {
    printf("restore_file_version: Restoring %s\n", node->name);

    // Free the current content
    if (node->content) {
        free(node->content);
        node->content = NULL;
    }
    node->size = 0;

    // Restore content
    if (content && size > 0) {
        node->content = malloc(size);
        if (!node->content) {
            perror("malloc");
            node->size = 0;
            return;
        }
        memcpy(node->content, content, size);
        node->size = size;
    }
    clock_gettime(CLOCK_REALTIME, &node->mtime);
}

// Create or get a node based on a file path
struct file_node *create_or_get_node(const char *path) {
    if (!path || path[0] != '/') {
        return NULL;
    }

    char *path_copy = strdup(path);
    if (!path_copy) {
        perror("strdup");
        return NULL;
    }
    trim_slashes(path_copy);

    struct file_node *current = root;
    char *token;
    char *saveptr;
    token = strtok_r(path_copy, "/", &saveptr);
    while (token != NULL) {
        struct file_node *child = current->children;
        struct file_node *prev_child = NULL;
        while (child) {
            if (strcmp(child->name, token) == 0) {
                break;
            }
            prev_child = child;
            child = child->next;
        }
        if (!child) {
            // Create new node
            struct file_node *new_node = malloc(sizeof(struct file_node));
            if (!new_node) {
                perror("malloc");
                free(path_copy);
                return NULL;
            }
            memset(new_node, 0, sizeof(struct file_node));
            new_node->name = strdup(token);
            if (!new_node->name) {
                perror("strdup");
                free(new_node);
                free(path_copy);
                return NULL;
            }
            new_node->mode = S_IFDIR | 0755;
            new_node->uid = getuid();
            new_node->gid = getgid();
            clock_gettime(CLOCK_REALTIME, &new_node->atime);
            new_node->mtime = new_node->atime;
            new_node->ctime = new_node->atime;
            new_node->is_directory = 1;
            new_node->children = NULL;
            new_node->next = current->children;
            current->children = new_node;
            current = new_node;
        } else {
            current = child;
        }
        token = strtok_r(NULL, "/", &saveptr);
    }
    free(path_copy);
    return current;
}


char* generate_diff(size_t snapshot_id1, size_t snapshot_id2) {
    printf("generate_diff: Generating diff between snapshots %zu and %zu\n", snapshot_id1, snapshot_id2);

    // Find snapshots
    struct snapshot *snap1 = NULL, *snap2 = NULL;
    struct snapshot *snap = snapshots_list;
    while (snap) {
        if (snap->snapshot_id == snapshot_id1) {
            snap1 = snap;
        }
        if (snap->snapshot_id == snapshot_id2) {
            snap2 = snap;
        }
        snap = snap->next;
    }
    if (!snap1 || !snap2) {
        return strdup("One or both snapshots not found.\n");
    }

    // Use a dynamic string to build the diff output
    size_t buffer_size = 1024;
    char *diff_output = malloc(buffer_size);
    if (!diff_output) {
        perror("malloc");
        return NULL;
    }
    diff_output[0] = '\0';

    strcat(diff_output, "Differences between snapshots:\n");

    // Helper function to append text to diff_output
    void append_to_diff(const char *text) {
        size_t new_len = strlen(diff_output) + strlen(text) + 1;
        if (new_len > buffer_size) {
            buffer_size *= 2;
            diff_output = realloc(diff_output, buffer_size);
            if (!diff_output) {
                perror("realloc");
                diff_output = NULL;
                return;
            }
        }
        strcat(diff_output, text);
    }

    if (!diff_output) {
        return NULL;
    }

    // Iterate over snap1's files
    struct file_snapshot *fs1 = snap1->file_snapshots;
    while (fs1) {
        struct file_snapshot *fs2_curr = snap2->file_snapshots;
        int found = 0;
        while (fs2_curr) {
            if (strcmp(fs1->path, fs2_curr->path) == 0) {
                found = 1;
                if (fs1->version_number != fs2_curr->version_number) {
                    char line[256];
                    snprintf(line, sizeof(line), "Modified: %s (version %zu -> %zu)\n", fs1->path, fs1->version_number, fs2_curr->version_number);
                    append_to_diff(line);
                    if (!diff_output) return NULL; // realloc failed
                }
                break;
            }
            fs2_curr = fs2_curr->next;
        }
        if (!found) {
            char line[256];
            snprintf(line, sizeof(line), "Deleted: %s\n", fs1->path);
            append_to_diff(line);
            if (!diff_output) return NULL; // realloc failed
        }
        fs1 = fs1->next;
    }

    // Iterate over snap2's files to find added files
    struct file_snapshot *fs2 = snap2->file_snapshots;
    while (fs2) {
        struct file_snapshot *fs1_curr = snap1->file_snapshots;
        int found = 0;
        while (fs1_curr) {
            if (strcmp(fs2->path, fs1_curr->path) == 0) {
                found =1;
                break;
            }
            fs1_curr = fs1_curr->next;
        }
        if (!found) {
            char line[256];
            snprintf(line, sizeof(line), "Added: %s\n", fs2->path);
            append_to_diff(line);
            if (!diff_output) return NULL; // realloc failed
        }
        fs2 = fs2->next;
    }

    return diff_output;
}

// getattr callback
static int simple_getattr(const char *path, struct stat *stbuf,
                          struct fuse_file_info *fi) {
    printf("getattr called for path: %s\n", path);
    (void) fi;
    memset(stbuf, 0, sizeof(struct stat));

    // Handle .snapshots directory
    if (is_snapshots_dir(path)) {
        stbuf->st_mode = S_IFDIR | 0555; // Read-only directory
        stbuf->st_nlink = 2;
        stbuf->st_size = 0;
        stbuf->st_uid = getuid();
        stbuf->st_gid = getgid();
        clock_gettime(CLOCK_REALTIME, &stbuf->st_atim);
        stbuf->st_mtim = stbuf->st_atim;
        stbuf->st_ctim = stbuf->st_atim;
        return 0;
    }

    // Handle snapshot files within .snapshots
    if (strncmp(path, "/.snapshots/", 12) == 0) {
        // Extract snapshot ID from the path
        size_t snapshot_id = strtoul(path + 12, NULL, 10);
        struct snapshot *snap = snapshots_list;
        while (snap) {
            if (snap->snapshot_id == snapshot_id) {
                // Found the snapshot
                stbuf->st_mode = S_IFREG | 0444; // Read-only file
                stbuf->st_nlink = 1;
                // Calculate size of snapshot details
                char *details = prepare_snapshot_details(snap);
                if (details) {
                    stbuf->st_size = strlen(details);
                    free(details);
                } else {
                    stbuf->st_size = 0;
                }
                stbuf->st_uid = getuid();
                stbuf->st_gid = getgid();
                clock_gettime(CLOCK_REALTIME, &stbuf->st_atim);
                stbuf->st_mtim = stbuf->st_atim;
                stbuf->st_ctim = stbuf->st_atim;
                return 0;
            }
            snap = snap->next;
        }
        // Snapshot not found
        return -ENOENT;
    }

    // Handle special files like .snapshot_create, .rollback, and .diff
    if (is_special_file(path)) {
        if (is_snapshot_create_file(path)) {
            // .snapshot_create is a regular file with write permissions
            stbuf->st_mode = S_IFREG | 0222; // Write-only
            stbuf->st_nlink = 1;
            stbuf->st_size = 0;
            stbuf->st_uid = getuid();
            stbuf->st_gid = getgid();
            clock_gettime(CLOCK_REALTIME, &stbuf->st_atim);
            stbuf->st_mtim = stbuf->st_atim;
            stbuf->st_ctim = stbuf->st_atim;
            return 0;
        } else {
            // Handle other special files like .rollback and .diff
            stbuf->st_mode = S_IFREG | 0666; // Read-write file
            stbuf->st_nlink = 1;
            stbuf->st_size = 0;
            stbuf->st_uid = getuid();
            stbuf->st_gid = getgid();
            clock_gettime(CLOCK_REALTIME, &stbuf->st_atim);
            stbuf->st_mtim = stbuf->st_atim;
            stbuf->st_ctim = stbuf->st_atim;
            return 0;
        }
    }

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

    // Handle .snapshots directory
    if (is_snapshots_dir(path)) {
        filler(buf, ".", NULL, 0, 0);
        filler(buf, "..", NULL, 0, 0);

        // List snapshot IDs as files
        struct snapshot *snap = snapshots_list;
        while (snap) {
            char snap_name[32];
            snprintf(snap_name, sizeof(snap_name), "%zu", snap->snapshot_id);
            filler(buf, snap_name, NULL, 0, 0);
            snap = snap->next;
        }
        return 0;
    }

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

    // Include special entries if in root directory
    if (strcmp(path, "/") == 0) {
        filler(buf, ".snapshot_create", NULL, 0, 0);
        filler(buf, ".snapshots", NULL, 0, 0);
        filler(buf, ".rollback", NULL, 0, 0);
        filler(buf, ".diffs", NULL, 0, 0);  // Changed from ".diff" to ".diffs"
    }

    return 0;
}


// access callback
static int simple_access(const char *path, int mask) {
    printf("access called for path: %s, mask: %d\n", path, mask);

    // Handle special files
    if (is_special_file(path) || is_snapshots_dir(path) || is_rollback_file(path) || is_diff_file(path) || strncmp(path, "/.snapshots/", 12) == 0) {
        return 0;
    }

    struct file_node *node = find_node(path);
    if (node == NULL) {
        printf("access: No such file or directory: %s\n", path);
        return -ENOENT;
    }

    // Check permissions (simplified)
    if ((mask & R_OK) && !(node->mode & S_IRUSR)) return -EACCES;
    if ((mask & W_OK) && !(node->mode & S_IWUSR)) return -EACCES;
    if ((mask & X_OK) && !(node->mode & S_IXUSR)) return -EACCES;

    return 0;
}

// mkdir callback
static int simple_mkdir(const char *path, mode_t mode) {
    printf("mkdir called for path: %s with mode: %o\n", path, mode);

    // Disallow creating special directories
    if (is_special_file(path) || is_snapshots_dir(path) || is_rollback_file(path) || is_diff_file(path)) {
        return -EACCES;
    }

    // Make copies of the path since we modify them
    char *path_copy = strdup(path);
    if (!path_copy) {
        perror("strdup");
        return -ENOMEM;
    }

    trim_slashes(path_copy);

    char *base_name = strrchr(path_copy, '/');
    char *parent_path;
    if (base_name) {
        *base_name = '\0';
        base_name++;
        parent_path = strdup(path_copy);
        if (!parent_path) {
            perror("strdup");
            free(path_copy);
            return -ENOMEM;
        }
    } else {
        base_name = strdup(path_copy);
        if (!base_name) {
            perror("strdup");
            free(path_copy);
            return -ENOMEM;
        }
        parent_path = strdup("/");
        if (!parent_path) {
            perror("strdup");
            free(path_copy);
            free(base_name);
            return -ENOMEM;
        }
    }

    // Check if base_name is empty
    if (strlen(base_name) == 0 || strcmp(base_name, "/") == 0) {
        printf("mkdir: Invalid path (empty base name): %s\n", path);
        free(path_copy);
        free(parent_path);
        free(base_name);
        return -EINVAL;
    }

    printf("After splitting: parent_path='%s', base_name='%s'\n", parent_path, base_name);

    struct file_node *parent = find_node(parent_path);
    if (parent == NULL || !parent->is_directory) {
        printf("mkdir: Parent directory does not exist: %s\n", parent_path);
        free(path_copy);
        free(parent_path);
        free(base_name);
        return -ENOENT;
    }

    // Check if directory already exists
    struct file_node *existing = parent->children;
    while (existing != NULL) {
        if (strcmp(existing->name, base_name) == 0) {
            printf("mkdir: Directory already exists: %s\n", base_name);
            free(path_copy);
            free(parent_path);
            free(base_name);
            return -EEXIST;
        }
        existing = existing->next;
    }

    struct file_node *new_dir = malloc(sizeof(struct file_node));
    if (!new_dir) {
        perror("malloc");
        free(path_copy);
        free(parent_path);
        free(base_name);
        return -ENOMEM;
    }
    memset(new_dir, 0, sizeof(struct file_node));
    new_dir->name = strdup(base_name);
    if (!new_dir->name) {
        perror("strdup");
        free(new_dir);
        free(path_copy);
        free(parent_path);
        free(base_name);
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

    free(path_copy);
    free(parent_path);
    free(base_name);

    return 0;
}


// rmdir callback
static int simple_rmdir(const char *path) {
    printf("rmdir called for path: %s\n", path);

    // Disallow removing special directories
    if (is_special_file(path) || is_snapshots_dir(path) || is_rollback_file(path) || is_diff_file(path)) {
        return -EACCES;
    }

    // Make copies of the path since we modify them
    char *path_copy = strdup(path);
    if (!path_copy) {
        perror("strdup");
        return -ENOMEM;
    }

    trim_slashes(path_copy);

    char *parent_path = strdup(path_copy);
    char *base_name = strrchr(parent_path, '/');
    if (base_name) {
        *base_name = '\0';
        base_name++;
    } else {
        base_name = parent_path;
        parent_path = strdup("/");
    }

    // Check if base_name is empty
    if (strlen(base_name) == 0 || strcmp(base_name, "/") == 0) {
        printf("rmdir: Invalid path (empty base name): %s\n", path);
        free(path_copy);
        free(parent_path);
        return -EINVAL;
    }

    printf("After splitting: parent_path='%s', base_name='%s'\n", parent_path, base_name);

    struct file_node *parent = find_node(parent_path);
    if (parent == NULL || !parent->is_directory) {
        printf("rmdir: Parent directory does not exist: %s\n", parent_path);
        free(path_copy);
        free(parent_path);
        return -ENOENT;
    }

    // Find the directory to remove
    struct file_node **current = &parent->children;
    while (*current != NULL) {
        if (strcmp((*current)->name, base_name) == 0) {
            if ((*current)->children != NULL) {
                printf("rmdir: Directory not empty: %s\n", path);
                free(path_copy);
                free(parent_path);
                return -ENOTEMPTY;
            }
            struct file_node *to_delete = *current;
            *current = to_delete->next;
            printf("rmdir: Removing directory: %s\n", to_delete->name);
            free_node(to_delete);
            free(path_copy);
            free(parent_path);
            return 0;
        }
        current = &(*current)->next;
    }
    printf("rmdir: Directory not found: %s\n", base_name);
    free(path_copy);
    free(parent_path);
    return -ENOENT;
}

// create callback
static int simple_create(const char *path, mode_t mode,
                         struct fuse_file_info *fi) {
     printf("create called for path: %s with mode: %o\n", path, mode);
    (void) fi;

    // Check if creating a diff in .diffs directory
    if (strncmp(path, "/.diffs/", 8) == 0) {
        // Extract snapshot IDs from the filename
        const char *diff_name = path + 8; // ".diffs/" is 8 chars
        char *diff_name_copy = strdup(diff_name);
        if (!diff_name_copy) {
            perror("strdup");
            return -ENOMEM;
        }
        char *underscore = strchr(diff_name_copy, '_');
        if (!underscore) {
            free(diff_name_copy);
            return -EINVAL; // Invalid diff filename format
        }
        *underscore = '\0';
        size_t snap_id1 = strtoul(diff_name_copy, NULL, 10);
        size_t snap_id2 = strtoul(underscore + 1, NULL, 10);
        free(diff_name_copy);

        // Generate diff
        char *diff_output = generate_diff(snap_id1, snap_id2);
        if (!diff_output) {
            return -EIO; // I/O error
        }

        // Create a file node with the diff content
        struct file_node *parent = find_node("/.diffs");
        if (!parent || !parent->is_directory) {
            free(diff_output);
            return -ENOENT;
        }

        // Check if file already exists
        struct file_node *existing = parent->children;
        while (existing != NULL) {
            if (strcmp(existing->name, diff_name) == 0) {
                free(diff_output);
                return -EEXIST;
            }
            existing = existing->next;
        }

        struct file_node *new_diff = malloc(sizeof(struct file_node));
        if (!new_diff) {
            perror("malloc");
            free(diff_output);
            return -ENOMEM;
        }
        memset(new_diff, 0, sizeof(struct file_node));
        new_diff->name = strdup(diff_name);
        if (!new_diff->name) {
            perror("strdup");
            free(new_diff);
            free(diff_output);
            return -ENOMEM;
        }

        new_diff->mode = S_IFREG | 0444; // Read-only file
        new_diff->uid = getuid();
        new_diff->gid = getgid();
        clock_gettime(CLOCK_REALTIME, &new_diff->atime);
        new_diff->mtime = new_diff->atime;
        new_diff->ctime = new_diff->atime;
        new_diff->is_directory = 0;
        new_diff->content = diff_output;
        new_diff->size = strlen(diff_output);
        new_diff->next = parent->children;
        parent->children = new_diff;

        printf("create: Created diff file: %s between snapshots %zu and %zu\n", diff_name, snap_id1, snap_id2);
        return 0;
    }

    // Disallow creating special files
    if (is_special_file(path) || is_snapshots_dir(path) || is_rollback_file(path) || is_diff_file(path)) {
        return -EACCES;
    }

    // Make copies of the path since we modify them
    char *path_copy = strdup(path);
    if (!path_copy) {
        perror("strdup");
        return -ENOMEM;
    }

    trim_slashes(path_copy);

    char *parent_path = strdup(path_copy);
    char *base_name = strrchr(parent_path, '/');
    if (base_name) {
        *base_name = '\0';
        base_name++;
    } else {
        base_name = parent_path;
        parent_path = strdup("/");
    }

    // Check if base_name is empty
    if (strlen(base_name) == 0 || strcmp(base_name, "/") == 0) {
        printf("create: Invalid path (empty base name): %s\n", path);
        free(path_copy);
        free(parent_path);
        return -EINVAL;
    }

    printf("After splitting: parent_path='%s', base_name='%s'\n", parent_path, base_name);

    struct file_node *parent = find_node(parent_path);
    if (parent == NULL || !parent->is_directory) {
        printf("create: Parent directory does not exist: %s\n", parent_path);
        free(path_copy);
        free(parent_path);
        return -ENOENT;
    }

    // Check if file already exists
    struct file_node *existing = parent->children;
    while (existing != NULL) {
        if (strcmp(existing->name, base_name) == 0) {
            printf("create: File already exists: %s\n", base_name);
            free(path_copy);
            free(parent_path);
            return -EEXIST;
        }
        existing = existing->next;
    }

    struct file_node *new_file = malloc(sizeof(struct file_node));
    if (!new_file) {
        perror("malloc");
        free(path_copy);
        free(parent_path);
        return -ENOMEM;
    }
    memset(new_file, 0, sizeof(struct file_node));
    new_file->name = strdup(base_name);
    if (!new_file->name) {
        perror("strdup");
        free(new_file);
        free(path_copy);
        free(parent_path);
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
    new_file->current_version = 0;
    new_file->versions = NULL;
    new_file->next = parent->children;
    parent->children = new_file;

    printf("create: Created file: %s\n", new_file->name);

    free(path_copy);
    free(parent_path);

    return 0;
}

// unlink callback
static int simple_unlink(const char *path) {
    printf("unlink called for path: %s\n", path);

    // Disallow removing special files
    if (is_special_file(path) || is_snapshots_dir(path) || is_rollback_file(path) || is_diff_file(path)) {
        return -EACCES;
    }

    // Make copies of the path since we modify them
    char *path_copy = strdup(path);
    if (!path_copy) {
        perror("strdup");
        return -ENOMEM;
    }

    trim_slashes(path_copy);

    char *parent_path = strdup(path_copy);
    char *base_name = strrchr(parent_path, '/');
    if (base_name) {
        *base_name = '\0';
        base_name++;
    } else {
        base_name = parent_path;
        parent_path = strdup("/");
    }

    // Check if base_name is empty
    if (strlen(base_name) == 0 || strcmp(base_name, "/") == 0) {
        printf("unlink: Invalid path (empty base name): %s\n", path);
        free(path_copy);
        free(parent_path);
        return -EINVAL;
    }

    printf("After splitting: parent_path='%s', base_name='%s'\n", parent_path, base_name);

    struct file_node *parent = find_node(parent_path);
    if (parent == NULL || !parent->is_directory) {
        printf("unlink: Parent directory does not exist: %s\n", parent_path);
        free(path_copy);
        free(parent_path);
        return -ENOENT;
    }

    struct file_node **current = &parent->children;
    while (*current != NULL) {
        if (strcmp((*current)->name, base_name) == 0) {
            if ((*current)->is_directory) {
                printf("unlink: Cannot unlink directory: %s\n", path);
                free(path_copy);
                free(parent_path);
                return -EISDIR;
            }
            struct file_node *to_delete = *current;
            *current = to_delete->next;
            printf("unlink: Removing file: %s\n", to_delete->name);
            free_node(to_delete);
            free(path_copy);
            free(parent_path);
            return 0;
        }
        current = &(*current)->next;
    }
    printf("unlink: File not found: %s\n", base_name);
    free(path_copy);
    free(parent_path);
    return -ENOENT;
}

// open callback
static int simple_open(const char *path, struct fuse_file_info *fi) {
    printf("open called for path: %s\n", path);

    // Handle special control files
    if (is_special_file(path)) {
        // Allow read-write access
        if ((fi->flags & O_ACCMODE) != O_WRONLY && (fi->flags & O_ACCMODE) != O_RDONLY && (fi->flags & O_ACCMODE) != O_RDWR) {
            return -EACCES;
        }
        return 0;
    }

    // Files within .snapshots are read-only
    if (strncmp(path, "/.snapshots/", 12) == 0) {
        if ((fi->flags & O_ACCMODE) != O_RDONLY) {
            return -EACCES;
        }
        return 0;
    }

    // Files within .diffs are read-only
    if (strncmp(path, "/.diffs/", 8) == 0) {
        if ((fi->flags & O_ACCMODE) != O_RDONLY) {
            return -EACCES;
        }
        return 0;
    }

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

    // Handle reading from .diffs directory
    if (strncmp(path, "/.diffs/", 8) == 0) {
        struct file_node *diff_file = find_node(path);
        if (!diff_file || diff_file->is_directory) {
            return -ENOENT;
        }
        if (!diff_file->content) {
            return 0;
        }
        if (offset >= (off_t) diff_file->size) {
            size = 0;
        } else if (offset + size > diff_file->size) {
            size = diff_file->size - offset;
        }
        memcpy(buf, diff_file->content + offset, size);
        return size;
    }

    // Handle reading snapshot metadata
    if (strncmp(path, "/.snapshots/", 12) == 0) {
        const char *snap_id_str = path + 12;
        char *endptr;
        size_t snap_id = strtoul(snap_id_str, &endptr, 10);
        if (*endptr != '\0') {
            return -ENOENT;
        }
        struct snapshot *snap = snapshots_list;
        while (snap) {
            if (snap->snapshot_id == snap_id) {
                // Prepare snapshot details
                char *details = prepare_snapshot_details(snap);
                size_t len = strlen(details);
                if (offset >= (off_t) len) {
                    size = 0;
                } else if (offset + size > len) {
                    size = len - offset;
                }
                memcpy(buf, details + offset, size);
                free(details);
                return size;
            }
            snap = snap->next;
        }
        return -ENOENT;
    }

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
    } else if (offset < (off_t) data_size) {
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

    // Handle writing to .snapshot_create
    if (is_snapshot_create_file(path)) {
        printf("write to .snapshot_create: Creating a new snapshot\n");
        // Trigger snapshot creation
        create_snapshot();
        return size; // Indicate that all bytes were "written"
    }

    // Handle writing to .rollback
    if (is_rollback_file(path)) {
        // Expecting a snapshot ID to rollback to
        char *input = strndup(buf, size);
        if (!input) {
            perror("strndup");
            return -ENOMEM;
        }
        size_t snapshot_id = strtoul(input, NULL, 10);
        printf("write to .rollback: Rolling back to snapshot ID %zu\n", snapshot_id);
        rollback_to_snapshot(snapshot_id);
        free(input);
        return size;
    }

    // Handle regular file write operations
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
    clock_gettime(CLOCK_REALTIME, &new_version->timestamp);
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
        if (!new_content && size != 0) {
            perror("realloc");
            return -ENOMEM;
        }
        if (offset > (off_t) node->size) {
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
    if (size != (off_t) node->size) {
        char *new_content = realloc(node->content, size);
        if (!new_content && size != 0) {
            perror("realloc");
            return -ENOMEM;
        }
        if (size > (off_t) node->size) {
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

// statfs callback
static int simple_statfs(const char *path, struct statvfs *stbuf) {
    printf("statfs called for path: %s\n", path);
    memset(stbuf, 0, sizeof(struct statvfs));
    stbuf->f_namemax = 255;
    stbuf->f_bsize = 1024;
    stbuf->f_blocks = 1024;
    stbuf->f_bfree = 512;
    stbuf->f_bavail = 512;
    stbuf->f_files = 1024;
    stbuf->f_ffree = 512;
    return 0;
}

// FLUSH callback
static int simple_flush(const char *path, struct fuse_file_info *fi) {
    printf("flush called for path: %s\n", path);
    (void) fi;
    // Since we are not managing file handles, do nothing
    return 0;
}

// GETXATTR callback
static int simple_getxattr(const char *path, const char *name, char *value, size_t size) {
    printf("getxattr called for path: %s, name: %s\n", path, name);
    // Xattr not supported
    return -ENODATA;
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
    .access     = simple_access,
    .statfs     = simple_statfs,
    .flush      = simple_flush,   // Added
    .getxattr   = simple_getxattr
};

int main(int argc, char *argv[]) {
    initialize_root();
    printf("Starting FUSE filesystem...\n");
    return fuse_main(argc, argv, &simple_oper, NULL);
}