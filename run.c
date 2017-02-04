//
// Operating Systems - Shell
// Madhav Datt 14CS30015
//

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>


int main(void)
{
    int pid;
    if ((pid = fork()) == -1)
    {
        perror("run");
        exit(EXIT_FAILURE);
    }

    if (pid == 0)
    {
        char** args;
        execl("shell", "shell", (char*) 0);
    }

    else
    {
        int status;
        waitpid(pid, &status, 0);
        exit(status);
    }
}
