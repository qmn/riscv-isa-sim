#include "sim.h"
#include "htif.h"
#include "cachesim.h"
#include <fesvr/option_parser.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <memory>

bool using_pty;
int pty;

static void help()
{
	fprintf(stderr, "usage: riscv-isa-run [host options] <target program> [target options]\n");
	fprintf(stderr, "Host Options:\n");
	fprintf(stderr, "  -p <n>             Simulate <n> processors\n");
	fprintf(stderr, "  -m <n>             Provide <n> MB of target memory\n");
	fprintf(stderr, "  -d                 Interactive debug mode\n");
	fprintf(stderr, "  -h                 Print this help message\n");
	fprintf(stderr, "  -h                 Print this help message\n");
	fprintf(stderr, "  -l                 Create pty (for Linux)\n");
	fprintf(stderr, "  --ic=<S>:<W>:<B>   Instantiate a cache model with S sets,\n");
	fprintf(stderr, "  --dc=<S>:<W>:<B>     W ways, and B-byte blocks (with S and\n");
	fprintf(stderr, "  --l2=<S>:<W>:<B>     B both powers of 2).\n");
	exit(1);
}

int main(int argc, char** argv)
{
	bool debug = false;
	size_t nprocs = 1;
	size_t mem_mb = 0;
	using_pty = false;
	pty = 0;
	std::unique_ptr<icache_sim_t> ic;
	std::unique_ptr<dcache_sim_t> dc;
	std::unique_ptr<cache_sim_t> l2;

	option_parser_t parser;
	parser.help(&help);
	parser.option('d', 0, 0, [&](const char* s){debug = true;});
	parser.option('p', 0, 1, [&](const char* s){nprocs = atoi(s);});
	parser.option('m', 0, 1, [&](const char* s){mem_mb = atoi(s);});
	parser.option('l', 0, 0, [&](const char* s){using_pty = true;});
	parser.option(0, "ic", 1, [&](const char* s){ic.reset(new icache_sim_t(s));});
	parser.option(0, "dc", 1, [&](const char* s){dc.reset(new dcache_sim_t(s));});
	parser.option(0, "l2", 1, [&](const char* s){l2.reset(cache_sim_t::construct(s, "L2$"));});

	auto argv1 = parser.parse(argv);
	if (!*argv1)
	help();
	std::vector<std::string> htif_args(argv1, (const char*const*)argv + argc);
	sim_t s(nprocs, mem_mb, htif_args);

	if (ic && l2) ic->set_miss_handler(&*l2);
	if (dc && l2) dc->set_miss_handler(&*l2);
	for (size_t i = 0; i < nprocs; i++)
	{
		if (ic) s.get_core(i)->get_mmu()->register_memtracer(&*ic);
		if (dc) s.get_core(i)->get_mmu()->register_memtracer(&*dc);
	}

	/* create pty */
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
	s.run(debug);
}

