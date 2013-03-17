#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include "sim.h"
#include "htif.h"
#include <string.h>

bool using_pty;
int pty;

static void help()
{
	fprintf(stderr, "usage: riscv-isa-run -f <fd> -t <fd> [additional options]\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -f <fd>         From-host pipe file descriptor\n");
	fprintf(stderr, "  -t <fd>         To-host pipe file descriptor\n");
	fprintf(stderr, "  -p <n>          Simulate <n> processors\n");
	fprintf(stderr, "  -d              Interactive debug mode\n");
	fprintf(stderr, "  -l              Create pty (for Linux)\n");
	exit(1);
}

int main(int argc, char** argv)
{
	bool debug = false;
	using_pty = false;
	int nprocs = 1;
	int fromhost_fd = -1, tohost_fd = -1;

	// parse command-line arguments
	for(int c; (c = getopt(argc,argv,"hldp:f:t:")) != -1; )
	{
		switch(c)
		{
			case 'd':
				debug = true;
				break;
			case 'l':
				using_pty = true;
				break;
			case 'p':
				nprocs = atoi(optarg);
				break;
			case 'f':
				fromhost_fd = atoi(optarg);
				break;
			case 't':
				tohost_fd = atoi(optarg);
				break;
			default:
				fprintf(stderr, "unknown option: -%c", optopt);
			case 'h':
				help();
		}
	}

	// we require -f and -t to be specified so we can communicate with the host
	if(fromhost_fd == -1 || tohost_fd == -1)
		help();

	// initialize host-target interface
	htif_t htif(tohost_fd, fromhost_fd);

	// create pty

	pty = 0;
	
	if (using_pty) {
		pty = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
		if (pty == -1 || grantpt(pty) == -1 || unlockpt(pty) == -1) {
			printf("warning: unable to allocate pty\n");
			pty = 0;
		} else {
			printf("%s allocated (you should open it) num = %d\n", ptsname(pty), pty);
			sleep(5);
		}
	}

	// initalize simulator and run to completion
	sim_t s(nprocs, &htif);
	s.run(debug);
}

