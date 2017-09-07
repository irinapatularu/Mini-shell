/**
 * Operating Systems 2013-2017 - Assignment 2
 *
 * PATULARU IOANA-IRINA
 * 331CB
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	int ret;
	char *path;

	path = get_word(dir);
	ret = chdir(path);
	free(path);

	if (ret == 0)
		return EXIT_SUCCESS;
	else
		return EXIT_FAILURE;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	return SHELL_EXIT;
}

/**
 * Redirect output in the specified files
 */
void redirect_out(int flag_out, int flag_err, char *file_out,
				 char *file_err, int mode)
{
	int ret;
	int fd, fd_err;

	if (flag_out && flag_err) {
		if (strcmp(file_out, file_err) == 0) {
			/*
			 * redirect both standard output and
			 * error to the same file
			 */
			if (mode == IO_OUT_APPEND || mode == IO_ERR_APPEND)
				fd = open(file_out, O_WRONLY
						| O_APPEND | O_CREAT, 0644);
			else
				fd = open(file_out, O_WRONLY | O_CREAT
						| O_TRUNC, 0644);
			DIE(fd < 0, "open");
			ret = dup2(fd, STDOUT_FILENO);
			DIE(ret < 0, "dup2");

			ret = dup2(fd, STDERR_FILENO);
			DIE(ret < 0, "dup2");

			close(fd);
		} else {
			/*
			 * redirect both standard output and
			 * error but to different files
			 */
			if (mode == IO_OUT_APPEND)
				fd = open(file_out, O_WRONLY | O_APPEND
							| O_CREAT, 0644);
			else
				fd = open(file_out, O_WRONLY | O_CREAT
							 | O_TRUNC, 0644);
			DIE(fd < 0, "open");

			if (mode == IO_ERR_APPEND)
				fd_err = open(file_err, O_WRONLY | O_APPEND
							| O_CREAT, 0644);
			else
				fd_err = open(file_err, O_WRONLY | O_CREAT
							| O_TRUNC, 0644);
			DIE(fd < 0, "open");

			ret = dup2(fd, STDOUT_FILENO);
			DIE(ret < 0, "dup2");

			ret = dup2(fd_err, STDERR_FILENO);
			DIE(ret < 0, "dup2");

			close(fd);
			close(fd_err);
		}
	} else
		if (flag_out) {
		/*redirect only standard output*/
			if (mode == IO_OUT_APPEND)
				fd = open(file_out, O_WRONLY | O_APPEND
							 | O_CREAT, 0644);
			else
				fd = open(file_out, O_WRONLY | O_CREAT
							| O_TRUNC, 0644);
			DIE(fd < 0, "open");

			ret = dup2(fd, STDOUT_FILENO);
			close(fd);
		} else {
			/*redirect only standard error*/
			if (mode == IO_ERR_APPEND)
				fd_err = open(file_err, O_WRONLY | O_APPEND
							| O_CREAT, 0644);
			else
				fd_err = open(file_err, O_WRONLY | O_CREAT
							| O_TRUNC, 0644);
			DIE(fd_err < 0, "open");

			ret = dup2(fd_err, STDERR_FILENO);
			close(fd_err);
		}
}

/**
 * Redirect input from the specified file
 */
void redirect_in(char *filename)
{
	int fd;

	fd = open(filename, O_RDONLY);
	DIE(fd < 0, "erore citire fisier");

	dup2(fd, STDIN_FILENO);
	close(fd);
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	pid_t pid, wait_ret;
	char **args;
	int size;
	int status, ret;
	char *command, *out_file, *err_file, *in_file;
	char *variable, *value;
	int ret_val = 0;

	/*redirect output if it is necessary*/
	if (s->out && s->err) {
		out_file = get_word(s->out);
		err_file = get_word(s->err);
		redirect_out(1, 1, out_file, err_file, s->io_flags);
		free(out_file);
		free(err_file);
	} else {
		if (s->out) {
			out_file = get_word(s->out);
			redirect_out(1, 0, out_file, NULL,
							s->io_flags);
			free(out_file);
		} else
			if (s->err) {
				err_file = get_word(s->err);
				redirect_out(0, 1, NULL, err_file,
							s->io_flags);
				free(err_file);
			}
	}

	/*redirect input source if it is necessary*/
	if (s->in) {
		in_file = get_word(s->in);
		redirect_in(in_file);
		free(in_file);
	}

	/*take command*/
	command = get_word(s->verb);

	if (strcmp(command, "exit") == 0 || strcmp(command, "quit") == 0) {
		free(command);
		return shell_exit();
	}
	if (strcmp(command, "cd") == 0) {
		ret = shell_cd(s->params);
		free(command);
		return ret;
	}
	if (strcmp(command, "true") == 0) {
		free(command);
		return EXIT_SUCCESS;
	}
	if (strcmp(command, "false") == 0) {
		free(command);
		return EXIT_FAILURE;
	}
	if (strchr(command, '=')) {
		variable = strtok(command, "=");
		value = strtok(NULL, "\0\n");
		setenv(variable, value, 1);
		free(command);
		return EXIT_SUCCESS;
	}
	free(command);

	/*create child process*/
	pid = fork();

	switch (pid) {
	case -1:
		printf("eroare fork\n");
		return EXIT_FAILURE;
	case 0:
		/*child process, excute first command*/
		args = get_argv(s, &size);
		if (execvp(args[0], (char *const *) args) == -1) {
			printf("Execution failed for ");
			printf("'executabil_care_nu_exista'\n");
		}
		exit(EXIT_FAILURE);
	default:
		wait_ret = waitpid(pid, &status, 0);
		DIE(wait_ret < 0, "waitpid");

		ret_val = WEXITSTATUS(status);
		/*command couldn't be executed*/
		if  (ret_val == 1)
			return EXIT_FAILURE;
		return EXIT_SUCCESS;
	}
}

/**
 * Process two commands in parallel
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	pid_t pid;
	int status, ret, wait_ret;

	pid = fork();

	switch (pid) {
	case -1:
		printf("eroare\n");
		return false;
	case 0:
		ret = parse_command(cmd1, level + 1, father);
		exit(0);
	default:
		ret = parse_command(cmd2, level + 1, father);
		wait_ret = waitpid(pid, &status, 0);
		DIE(wait_ret < 0, "waitpid");
	}

	if (ret == 0)
		return true;
	return false;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int pipefd[2];
	pid_t pid, wait_ret;
	int rc, ret;
	int status;
	int aux_fd;

	/*copy stdin file descriptor to reuse later*/
	aux_fd = dup(STDIN_FILENO);

	/*create pipe*/
	rc = pipe(pipefd);
	DIE(rc < 0, "pipe problmes");

	/*create child process*/
	pid = fork();

	switch (pid) {
	case -1:
		printf("eroare fork\n");
		return false;
	case 0:
		/*close red end and stdout file descriptor*/
		close(pipefd[0]);
		close(STDOUT_FILENO);
		/*copy stdout to write point*/
		dup(pipefd[1]);
		close(pipefd[1]);
		ret = parse_command(cmd1, level + 1, father);
		exit(0);
	default:
		break;
	}

	/*close write point and stdin file descriptor*/
	close(pipefd[1]);
	close(STDIN_FILENO);
	/*copy stdin to read point*/
	dup(pipefd[0]);
	close(pipefd[0]);
	ret = parse_command(cmd2, level + 1, father);

	wait_ret = waitpid(-1, &status, 0);
	DIE(wait_ret < 0, "waitpid");
	dup2(aux_fd, STDIN_FILENO);
	if (ret == 0)
		return true;
	return false;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	int ret;
	int aux_fd;

	if (c->op == OP_NONE) {
		/* execute simple command */
		aux_fd = dup(STDIN_FILENO);
		ret = parse_simple(c->scmd, 0, father);
		dup2(aux_fd, STDIN_FILENO);
		return ret;
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/*execute the commands one after the other */
		if (c->cmd1)
			ret = parse_command(c->cmd1, level + 1, c);
		if (c->cmd2)
			ret = parse_command(c->cmd2, level + 1, c);
		return EXIT_SUCCESS;

	case OP_PARALLEL:
		/*execute the commands simultaneously */
		ret = do_in_parallel(c->cmd1, c->cmd2, level + 1, c);
		return EXIT_SUCCESS;

	case OP_CONDITIONAL_NZERO:
		/* execute the second command only if the first one
		 * returns non zero
		 */
		if (c->cmd1)
			ret = parse_command(c->cmd1, level + 1, c);
		if (ret != 0) {
			if (c->cmd2) {
				ret = parse_command(c->cmd2, level + 1, c);
				if (ret == 0)
					return EXIT_SUCCESS;
				else
					return EXIT_FAILURE;
			}
		} else
			return EXIT_SUCCESS;

	case OP_CONDITIONAL_ZERO:
		/* execute the second command only if the first one
		 * returns zero
		 */
		if (c->cmd1)
			ret = parse_command(c->cmd1, level + 1, c);
		if (ret == 0) {
			if (c->cmd2) {
				ret = parse_command(c->cmd2, level + 1, c);
				if (ret == 0)
					return EXIT_SUCCESS;
				else
					return EXIT_FAILURE;
			}
		} else
			return EXIT_FAILURE;

	case OP_PIPE:
		/* redirect the output of the first command to the
		 * input of the second
		 */
		ret = do_on_pipe(c->cmd1, c->cmd2, 0, c);
		if (ret == true)
			return EXIT_SUCCESS;
		return EXIT_FAILURE;

	default:
		return SHELL_EXIT;
	}

	return EXIT_SUCCESS;
}
