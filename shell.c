#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <pwd.h>
#include <time.h>
#include <grp.h>
#include <fcntl.h>
#include <errno.h>

#define PATH_LEN 1024
#define TOKEN_SIZE 100
#define TOKEN_NUM 100
#define MAX_PIPE 20
#define TOKEN_DELIM "\t\r\n\a "

/**
 * Execute non-builtin commands from child processes in shell
 */
void execute_process(char** args)
{
    // Check if background execution is required
    // Parse command arguments into separate char**
    bool is_background = false;
    int num_pipes = 0;
    int num_io_redirect = 0;

    int num_args;
    for (num_args = 0; args[num_args] != NULL; num_args++);
    num_args -= 1;

    // Parse arguments for background process execution
    char* tmp_arg = args[num_args];
    if (tmp_arg[strlen(tmp_arg) - 1] == '&')
    {
        is_background = true;
        tmp_arg[strlen(tmp_arg) - 1] = '\0';

        if (strlen(tmp_arg) == 0)
        {
            args[num_args] = NULL;
            num_args--;
        }
        else
            args[num_args] = tmp_arg;
    }

    // Check for piping and io redirection in command arguments
    for (int i = 0; i < num_args; i++)
    {
        if (strcmp(args[i], "|") == 0)
            num_pipes += 1;

        else if (strcmp(args[i], "<") == 0 || strcmp(args[i], ">") == 0)
            num_io_redirect += 1;
    }

    // Handle pipes for input output redirection
    if (num_pipes > 0 && num_args >= 2)
    {
        // Parse arguments of each command separately
        char* command_args[TOKEN_NUM][TOKEN_NUM];
        int num_command = 0;
        int num_arg = 0;
        for (int i = 0; i <= num_args; i++)
        {
            if (strcmp(args[i], "|") == 0)
            {
                // Terminate individual command
                command_args[num_command][num_arg] = NULL;
                num_command++;
                num_arg = 0;
            }

            else
            {
                command_args[num_command][num_arg] = args[i];
                num_arg++;
            }
        }

        // Create pipes for each executable command
        int pipe_fd[MAX_PIPE][2];
        for (int i = 0; i < num_pipes; i++)
        {
            if (pipe(pipe_fd[i]) == -1)
            {
                perror(args[0]);
                return;
            }
        }

        int pid;
        // Execute commands with input output piping
        for (int i = 0; i <= num_pipes; i++)
        {
            pid = fork();
            if (pid == 0)
            {
                // First command - before first pipe
                if (i == 0)
                {
                    close(pipe_fd[i][0]);
                    close(1); // 1 : stdout
                    dup(pipe_fd[i][1]);
                    close(pipe_fd[i][1]);
                    if (execvp(command_args[i][0], command_args[i]))
                    {
                        perror(command_args[i][0]);
                        return;
                    }
                }

                // Last command - after last pipe
                else if (i == num_pipes)
                {
                    close(pipe_fd[i - 1][1]);
                    close(0); // 0 : stdin
                    dup(pipe_fd[i - 1][0]);
                    close(pipe_fd[i - 1][0]);
                    if (execvp(command_args[i][0], command_args[i]))
                    {
                        perror(command_args[i][0]);
                        return;
                    }
                }

                // Other commands - redirecting input output on both ends
                else
                {
                    close(pipe_fd[i - 1][1]);
                    close(0); // 0 : stdin
                    dup(pipe_fd[i - 1][0]);
                    close(pipe_fd[i - 1][0]);

                    close(pipe_fd[i][0]);
                    close(1); // 1 : stdout
                    dup(pipe_fd[i][1]);
                    close(pipe_fd[i][1]);

                    if (execvp(command_args[i][0], command_args[i]))
                    {
                        perror(command_args[i][0]);
                        return;
                    }
                }
            }
        }

        // Close all pipes
        for (int j = 0; j < num_pipes; j++)
        {
            close(pipe_fd[j][0]);
            close(pipe_fd[j][1]);
        }

        // Wait for all child processes to end
        while (true)
        {
            waitpid(-1, NULL, 0);
            if (errno == ECHILD)
                break;
        }

        for (int k = 0; k < num_pipes; k++)
            wait(NULL);
        return;
    }

    // Handle input output file redirection
    else if (num_io_redirect > 0 && num_args >= 2)
    {
        num_args++; // Offset num_args from maximum arg index value by 1
        if (strcmp(args[num_args - 2], ">") == 0)
        {
            // Read from file not required
            if (((num_args > 4) && (strcmp(args[num_args - 4], "<") != 0)) || (num_args < 4))
            {
                int pid = fork();
                if (pid == 0)
                {
                    // Open write-to file
                    int fd_write = open(args[num_args - 1], O_WRONLY | O_CREAT | O_TRUNC,
                                        S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
                    if (fd_write == -1)
                    {
                        perror(args[0]);
                        return;
                    }

                    close(1); // 1 : stdout
                    dup(fd_write);
                    close(fd_write);

                    // Terminate args list with NULL
                    args[num_args - 2] = NULL;
                    if (execvp(args[0], args))
                    {
                        perror(args[0]);
                    }
                }
                else
                {
                    int status;
                    waitpid(pid, &status, 0);
                }
            }

            // Redirect both read and write to files
            else if (strcmp(args[num_args - 4], "<") == 0)
            {
                int pid = fork();
                if (pid == 0)
                {
                    int fd_read = open(args[num_args - 3], O_RDONLY);
                    if (fd_read == -1)
                    {
                        perror(args[0]);
                        return;
                    }

                    close(0);  // 0 : stdin
                    dup(fd_read);
                    close(fd_read);

                    int fd_write = open(args[num_args - 1], O_WRONLY | O_CREAT | O_TRUNC,
                                        S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
                    if (fd_write == -1)
                    {
                        perror(args[0]);
                        return;
                    }

                    close(1); // 1 : stdout
                    dup(fd_write);
                    close(fd_write);

                    // Terminate args list with NULL
                    args[num_args - 4] = NULL;
                    if (execvp(args[0], args))
                    {
                        perror(args[0]);
                    }
                }
                else
                {
                    int status;
                    waitpid(pid, &status, 0);
                }
            }
        }

        // Handle reversed order of read and write redirection
        else if (strcmp(args[num_args - 2], "<") == 0)
        {
            // Read from file not required
            if (((num_args > 4) && (strcmp(args[num_args - 4], ">") != 0)) || (num_args < 4))
            {
                int pid = fork();
                if (pid == 0)
                {
                    // Open write-to file
                    int fd_read = open(args[num_args - 1], O_RDONLY);
                    if (fd_read == -1)
                    {
                        perror(args[0]);
                        return;
                    }

                    close(0); // 0 : stdout
                    dup(fd_read);
                    close(fd_read);

                    // Terminate args list with NULL
                    args[num_args - 2] = NULL;
                    if (execvp(args[0], args))
                    {
                        perror(args[0]);
                    }
                }
                else
                {
                    int status;
                    waitpid(pid, &status, 0);
                }
            }

            // Redirect both read and write to files
            else if (strcmp(args[num_args - 4], ">") == 0)
            {
                int pid = fork();
                if (pid == 0)
                {
                    int fd_read = open(args[num_args - 1], O_RDONLY);
                    if (fd_read == -1)
                    {
                        perror(args[0]);
                        return;
                    }

                    close(0);  // 0 : stdin
                    dup(fd_read);
                    close(fd_read);

                    int fd_write = open(args[num_args - 3], O_WRONLY | O_CREAT | O_TRUNC,
                                        S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
                    if (fd_write == -1)
                    {
                        perror(args[0]);
                        return;
                    }

                    close(1); // 1 : stdout
                    dup(fd_write);
                    close(fd_write);

                    // Terminate args list with NULL
                    args[num_args - 4] = NULL;
                    if (execvp(args[0], args))
                    {
                        perror(args[0]);
                    }
                }
                else
                {
                    int status;
                    waitpid(pid, &status, 0);
                }
            }
        }
    }

    // Handle other processes
    else
    {
        int pid = fork();
        if (pid == 0)
        {
            if (execvp(args[0], args))
            {
                perror(args[0]);
                exit(EXIT_FAILURE);
            }
        }

        // Parent process - wait for child to finish if '&' not provided
        else
        {
            int status;
            if (is_background != true)
                waitpid(pid, &status, 0);
        }
    }
}


/**
 * Execute parsed command arguments
 * Create child processes for non-inbuilt commands
 */
int execute_command(char** args)
{
    if (args[0] == NULL)
    {
        return 0;
    }

    // pwd: print current directory
    if (strcmp(args[0], "pwd") == 0)
    {
        char cwd[PATH_LEN];
        getcwd(cwd, sizeof(cwd));
        printf("%s\n", cwd);
    }

    // cd: change directory
    else if (strcmp(args[0], "cd") == 0)
    {
        // Go to home directory if no argument provided
        if (args[1] == NULL)
        {
            // Get home directory from $HOME environment variable
            const char* home_dir;
            if ((home_dir = getenv("HOME")) == NULL)
                // If $HOME doesn't exist, try getpwuid
                home_dir = getpwuid(getuid())->pw_dir;

            if (chdir(home_dir) == -1)
                perror("cd");
        }

        else if (chdir(args[1]) == -1)
            perror("cd");
    }

    // exit: exit shell
    else if (strcmp(args[0], "exit") == 0)
    {
        exit(EXIT_FAILURE);
    }

    // mkdir: create new directory
    else if (strcmp(args[0], "mkdir") == 0)
    {
        // Handle no argument passed
        if (args[1] == NULL)
        {
            printf("mkdir: missing operand\n");
            return 0;
        }

        for (int i = 1; args[i] != NULL; i++)
        {
            mode_t process_mask = umask(0);
            int status = mkdir(args[i], S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
            umask(process_mask);

            if (status == -1)
                perror("mkdir");
        }

    }

    // rmdir: delete directory and all contents
    else if (strcmp(args[0], "rmdir") == 0)
    {
        // Handle no argument passed
        if (args[1] == NULL)
        {
            printf("rmdir: missing operand\n");
            return 0;
        }

        for (int i = 1; args[i] != NULL; i++)
        {
            int status = rmdir(args[i]);
            if (status == -1)
                perror("rmdir");
        }
    }

    // cp: copy file1 to file2 if file1 was modified after file2
    else if (strcmp(args[0], "cp") == 0)
    {
        // File stats
        struct stat file1_stat;
        struct stat file2_stat;

        char buf[1024];
        int file1, file2;
        ssize_t count;

        // Default modification time for file2 (if does not exist already)
        __time_t file2_mod_time = 0;

        if (args[1] == NULL)
        {
            printf("cp: missing source and destination file\n");
            return 0;
        }

        else if (args[2] == NULL)
        {
            printf("cp: missing destination file\n");
            return 0;
        }

        // Handle stat error
        if(stat(args[1], &file1_stat) == -1)
        {
            perror("cp");
            return 0;
        }

        // Handle un-created file2 modification time issue separately
        if(stat(args[2], &file2_stat) == -1)
            file2_mod_time = 0;
        else
            file2_mod_time = file2_stat.st_ctim.tv_sec;

        // Compare file modification dates
        // No action if modification time of file2 is more recent
        if (file1_stat.st_ctim.tv_sec <= file2_mod_time)
            return 0;

        // Open files, check permissions and errors
        if ((file1 = open(args[1], O_RDONLY)) == -1)
        {
            perror("cp");
            return 0;
        }

        if ((file2 = open(args[2], O_WRONLY | O_CREAT | O_TRUNC,
                          S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) == -1)
        {
            perror("cp");
            return 0;
        }

        while ((count = read(file1, buf, sizeof(buf))) != 0)
            write(file2, buf, (size_t) count);
    }

    // ls, ls -l: list current directory contents
    else if (strcmp(args[0], "ls") == 0)
    {
        char cwd[PATH_LEN];
        getcwd(cwd, sizeof(cwd));
        DIR* current_dir = opendir(cwd);
        struct dirent* dir_file;
        struct stat dir_stat;

        while ((dir_file = readdir(current_dir)) != NULL)
        {
            // Do not print hidden files (.name)
            if (dir_file->d_name[0] == '.')
                continue;

            // ls without any option flags
            if (args[1] == NULL)
                printf("%s\n", dir_file->d_name);

            // ls with "-l" option flag
            else if (strcmp(args[1], "-l") == 0)
            {
                // Handle stat error
                if(stat(dir_file->d_name, &dir_stat) == -1)
                {
                    perror("ls");
                    return 0;
                }

                char permissions[11];
                char* month[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

                // Get file permission flags
                strcpy(permissions, S_ISDIR(dir_stat.st_mode) ? "d" : "-");
                strcat(permissions, (dir_stat.st_mode & S_IRUSR) ? "r" : "-");
                strcat(permissions, (dir_stat.st_mode & S_IWUSR) ? "w" : "-");
                strcat(permissions, (dir_stat.st_mode & S_IXUSR) ? "x" : "-");
                strcat(permissions, (dir_stat.st_mode & S_IRGRP) ? "r" : "-");
                strcat(permissions, (dir_stat.st_mode & S_IWGRP) ? "w" : "-");
                strcat(permissions, (dir_stat.st_mode & S_IXGRP) ? "x" : "-");
                strcat(permissions, (dir_stat.st_mode & S_IROTH) ? "r" : "-");
                strcat(permissions, (dir_stat.st_mode & S_IWOTH) ? "w" : "-");
                strcat(permissions, (dir_stat.st_mode & S_IXOTH) ? "x" : "-");

                // Get time stamp into components
                struct tm* time_stamp;
                time_stamp = localtime(&dir_stat.st_atim.tv_sec);

                // Get user and group ID
                struct passwd* user = getpwuid(dir_stat.st_uid);
                struct group* gp = getgrgid(dir_stat.st_gid);

                printf("%s %2d %s %s %8d ", permissions, (int) dir_stat.st_nlink, user->pw_name, gp->gr_name,
                       (int) dir_stat.st_size);
                printf("%s %d %02d:%02d ", month[time_stamp->tm_mon], time_stamp->tm_mday, time_stamp->tm_hour,
                       time_stamp->tm_min);
                printf("%s\n", dir_file->d_name);
            }

            // Default case
            else
                printf("ls: Unrecognized option\n");
        }
        closedir(current_dir);
    }

    // Handle all other commands
    else
    {
        execute_process(args);
    }

    return 0;
}

/**
 * Tokenize and parse command line inputs
 */
char** parse_command(char* command)
{
    char** args = malloc(TOKEN_SIZE * sizeof(char*));
    char* token;

    // Argument indices and token size
    int pos = 0;
    int total_token_size = TOKEN_SIZE;

    // Parse and tokenize command input
    token = strtok(command, TOKEN_DELIM);
    while (token != NULL)
    {
        args[pos] = token;
        pos++;

        // Expand args buffer when full
        if (pos >= total_token_size)
        {
            total_token_size += TOKEN_SIZE;
            args = realloc(args, total_token_size * sizeof(char*));
        }

        token = strtok(NULL, TOKEN_DELIM);
    }

    args[pos] = NULL;
    return args;
}

/**
 * Run shell loop, get command line input
 * Parse and execute various commands
 */
void init_shell(void)
{
    char cwd[PATH_LEN]; // Current working directory
    char* command; // Command line input
    char** parsed_command; // Parsed and tokenized input

    while(true)
    {
        if (getcwd(cwd, sizeof(cwd)) != NULL)
            printf("%s> ", cwd);
        else
        {
            perror("cwd:");
            exit(EXIT_FAILURE);
        }

        size_t bufsize = 0;
        getline(&command, &bufsize, stdin);
        parsed_command = parse_command(command);
        int status = execute_command(parsed_command);

        free(command);
        free(parsed_command);

        // Execute command fails/error occurs
        if (status == -1)
            exit(EXIT_FAILURE);
    }
}

/**
 * Main function - start the shell and wait for input
 */
int main(int argc, char* argv[])
{
    init_shell();
    exit(EXIT_SUCCESS);
}
