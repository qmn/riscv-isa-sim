#include "sim.h"
#include "htif.h"
#include <sys/mman.h>
#include <map>
#include <iostream>
#include <climits>
#include <assert.h>
#include <signal.h>
#include <unistd.h>

#ifdef __linux__
# define mmap mmap64
#endif

sim_t::sim_t(int _nprocs, int mem_mb, const std::vector<std::string>& args)
  : htif(new htif_isasim_t(this, args)),
    procs(_nprocs)
{
  // allocate target machine's memory, shrinking it as necessary
  // until the allocation succeeds
  size_t memsz0 = (size_t)mem_mb << 20;
  if (memsz0 == 0)
    memsz0 = 1L << (sizeof(size_t) == 8 ? 32 : 30);

  size_t quantum = std::max(PGSIZE, (reg_t)sysconf(_SC_PAGESIZE));
  memsz0 = memsz0/quantum*quantum;

	mmu = new mmu_t(mem, memsz);

	// initialize processors

	for(size_t i = 0; i < num_cores(); i++) {
		procs[i] = new processor_t(this, new mmu_t(mem, memsz), i);
	}

}

sim_t::~sim_t()
{
	for(size_t i = 0; i < num_cores(); i++)
	{
		mmu_t* pmmu = &procs[i]->mmu;
		delete procs[i];
		delete pmmu;
	}
	delete mmu;
	munmap(mem, memsz);
}

void sim_t::send_ipi(reg_t who)
{
	if(who < num_cores())
		procs[who]->deliver_ipi();
}

reg_t sim_t::get_scr(int which)
{
  switch (which)
  {
    case 0: return num_cores();
    case 1: return memsz >> 20;
    default: return -1;
  }
}

void sim_t::run(bool debug)
{
#if 1
	mmu->store_uint32(0, memsz >> 20);
	// word 1 of memory contains the core count
	mmu->store_uint32(4, num_cores());
#endif

  while (!htif->done())
  {
    if(!debug)
      step_all(10000, 1000, false);
    else
      interactive();
  }
}

void sim_t::step_all(size_t n, size_t interleave, bool noisy)
{
  htif->tick();
  for(size_t j = 0; j < n; j+=interleave)
  {
    for(int i = 0; i < (int)num_cores(); i++)
      procs[i]->step(interleave,noisy);
  }
}
