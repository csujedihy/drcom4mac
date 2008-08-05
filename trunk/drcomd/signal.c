#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include "drcomd.h"
#include "log.h"

void unblock_sigusr1(void)
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGTERM);
	pthread_sigmask(SIG_UNBLOCK, &set, NULL);
}

void block_sigusr1(void)
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
}

void sigusr1_handler (int sig)
{
	write(sigusr1_pipe[WRITE_END], &sig, sizeof(int));
}

int setup_sig_handlers(void)
{
	struct sigaction sa;
	int retval;

	retval = pipe(sigusr1_pipe);
	if (retval < 0) {
		logerr("error getting pipes: %s", strerror(errno));
		return -1;
	}

	retval = fcntl(sigusr1_pipe[READ_END], F_GETFL, 0);
	if (retval < 0) {
		logerr("error fcntl on read pipe: %s", strerror(errno));
		goto exit;
	}
	retval = fcntl(sigusr1_pipe[READ_END], F_SETFL, retval | O_NONBLOCK);
	if (retval < 0) {
		logerr("error fcntl on read pipe: %s", strerror(errno));
		goto exit;
	}

	retval = fcntl(sigusr1_pipe[WRITE_END], F_GETFL, 0);
	if (retval < 0) {
		logerr("error fcntl on write pipe: %s", strerror(errno));
		goto exit;
	}
	retval = fcntl(sigusr1_pipe[WRITE_END], F_SETFL, retval | O_NONBLOCK);
	if (retval < 0) {
		logerr("error fcntl on write pipe: %s", strerror(errno));
		goto exit;
	}

	memset(&sa, 0x00, sizeof(sa));
	sa.sa_handler = sigusr1_handler;
	sa.sa_flags = SA_RESTART;
	sigemptyset (&sa.sa_mask);
	sigaction (SIGUSR1, &sa, NULL);
	sigaction (SIGTERM, &sa, NULL);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGPIPE, &sa, NULL);

	return 0;

exit:
	close(sigusr1_pipe[READ_END]);
	close(sigusr1_pipe[WRITE_END]);
	return -1;
}

void do_signals(struct drcom_handle *h, int sig)
{
	int r;

	if (status == STATUS_LOGGED_IN) {
		loginfo("SIGUSR1/SIGTERM caught, force logout.\n");

		status = STATUS_BUSY;
		/* Stop the threads here, since they might interfere with
		   the logout process */
		module_stop_auth();
		pthread_cancel(th_keepalive);
		pthread_cancel(th_watchport);
		pthread_join(th_keepalive, NULL);
		pthread_join(th_watchport, NULL);
		/* Now try to log out */
		r = drcom_logout(-1, h, 0);
		if(r){
			/* If logout failed, that means we are still logged in,
			   so re-create the threads and continue authentication */
			module_start_auth(h);
			pthread_create(&th_watchport, NULL, daemon_watchport, h);
			pthread_create(&th_keepalive, NULL, daemon_keepalive, h);

			status = STATUS_LOGGED_IN;
		}else{
			status = STATUS_IDLE;
		}

		if(status == STATUS_IDLE)
			server_sock_destroy(h);
	}

	if(sig == SIGTERM){
		loginfo("received SIGTERM, let's exit...\n");

		exit(1);
	}
}

