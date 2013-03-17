#include "sim.h"
#include "htif.h"
#include "pcr.h"
#include <sys/mman.h>
#include <map>
#include <iostream>
#include <climits>
#include <assert.h>
#include <stdlib.h>
#include <readline/readline.h>
#include <readline/history.h>

void sim_t::interactive()
{
	char *s;

	s = readline(": ");
	if (s && *s)
	{
		add_history(s);
	}

	char* p = strtok(s," ");
	if(!p)
	{
		interactive_run_noisy(std::string("r"), std::vector<std::string>(1,"1"));
		return;
	}
	std::string cmd = p;

	std::vector<std::string> args;
	while((p = strtok(NULL," ")))
		args.push_back(p);


	typedef void (sim_t::*interactive_func)(const std::string&, const std::vector<std::string>&);
	std::map<std::string,interactive_func> funcs;

	funcs["r"] = &sim_t::interactive_run_noisy;
	funcs["rs"] = &sim_t::interactive_run_silent;
	funcs["rp"] = &sim_t::interactive_run_proc_noisy;
	funcs["rps"] = &sim_t::interactive_run_proc_silent;
	funcs["reg"] = &sim_t::interactive_reg;
	funcs["pcreg"] = &sim_t::interactive_pcreg;
	funcs["fregs"] = &sim_t::interactive_fregs;
	funcs["fregd"] = &sim_t::interactive_fregd;
	funcs["mem"] = &sim_t::interactive_mem;
	funcs["str"] = &sim_t::interactive_str;
	funcs["cycle"] = &sim_t::interactive_cycle;
	funcs["until"] = &sim_t::interactive_until;
	funcs["while"] = &sim_t::interactive_until;
	funcs["lp"] = &sim_t::interactive_linux_process;
	funcs["tran"] = &sim_t::interactive_translate;
	funcs["lm"] = &sim_t::interactive_pagetable;
	funcs["q"] = &sim_t::interactive_quit;

	try
	{
		if(funcs.count(cmd))
			(this->*funcs[cmd])(cmd, args);
	}
	catch(trap_t t) {}
}

void sim_t::interactive_run_noisy(const std::string& cmd, const std::vector<std::string>& args)
{
	interactive_run(cmd,args,true);
}

void sim_t::interactive_run_silent(const std::string& cmd, const std::vector<std::string>& args)
{
	interactive_run(cmd,args,false);
}

void sim_t::interactive_run(const std::string& cmd, const std::vector<std::string>& args, bool noisy)
{
	if(args.size())
		step_all(atoll(args[0].c_str()),1,noisy);
	else
		while(1) step_all(1,1,noisy);
}

void sim_t::interactive_run_proc_noisy(const std::string& cmd, const std::vector<std::string>& args)
{
	interactive_run_proc(cmd,args,true);
}

void sim_t::interactive_run_proc_silent(const std::string& cmd, const std::vector<std::string>& args)
{
	interactive_run_proc(cmd,args,false);
}

void sim_t::interactive_run_proc(const std::string& cmd, const std::vector<std::string>& a, bool noisy)
{
	if(a.size() == 0)
		return;

	int p = atoi(a[0].c_str());
	if(p >= (int)num_cores())
		return;

	if(a.size() == 2)
		procs[p]->step(atoi(a[1].c_str()),noisy);
	else
		while(1) procs[p]->step(1,noisy);
}

void sim_t::interactive_quit(const std::string& cmd, const std::vector<std::string>& args)
{
	stop();
}

reg_t sim_t::get_pc(const std::vector<std::string>& args)
{
	if(args.size() != 1)
		throw trap_illegal_instruction;

	int p = atoi(args[0].c_str());
	if(p >= (int)num_cores())
		throw trap_illegal_instruction;

	return procs[p]->pc;
}

reg_t sim_t::get_reg(const std::vector<std::string>& args)
{
	if(args.size() != 2)
		throw trap_illegal_instruction;

	int p = atoi(args[0].c_str());
	int r = atoi(args[1].c_str());
	if(p >= (int)num_cores() || r >= NXPR)
		throw trap_illegal_instruction;

	return procs[p]->XPR[r];
}

reg_t sim_t::get_pcreg(const std::vector<std::string>& args)
{
	if(args.size() != 2)
		throw trap_illegal_instruction;

	int p = atoi(args[0].c_str());
	int r = atoi(args[1].c_str());
	if(p >= (int)num_cores() || r >= NXPR)
		throw trap_illegal_instruction;

	reg_t val = procs[p]->get_pcr(r);

	return val;
}

reg_t sim_t::get_freg(const std::vector<std::string>& args)
{
	if(args.size() != 2)
		throw trap_illegal_instruction;

	int p = atoi(args[0].c_str());
	int r = atoi(args[1].c_str());
	if(p >= (int)num_cores() || r >= NFPR)
		throw trap_illegal_instruction;

	return procs[p]->FPR[r];
}

reg_t sim_t::get_cycle(const std::vector<std::string>& args)
{
	if (args.size() != 1)
		throw trap_illegal_instruction;

	int p = atoi(args[0].c_str());
	if (p >= (int)num_cores())
		throw trap_illegal_instruction;

	return procs[p]->get_cycle();
}

void sim_t::interactive_reg(const std::string& cmd, const std::vector<std::string>& args)
{
	printf("0x%016llx\n",(unsigned long long)get_reg(args));
}

void sim_t::interactive_cycle(const std::string& cmd, const std::vector<std::string>& args)
{
	printf("0x%016llx\n",(unsigned long long)get_cycle(args));
}

void sim_t::interactive_pcreg(const std::string& cmd, const std::vector<std::string>& args)
{
	unsigned long long val;

	val = (unsigned long long)get_pcreg(args);

	printf("0x%016llx\n", val);

	if (atoi(args[1].c_str()) == 0) // decode status register
	{
		printf("Status: IM=%2x VM=%d S64=%d U64=%d S=%d PS=%d ET=%d\n",
		       (unsigned int)((val & SR_IM) >> SR_IM_SHIFT), !!(val & SR_VM), !!(val & SR_S64),
		       !!(val & SR_U64), !!(val & SR_S), !!(val & SR_PS), !!(val & SR_ET));
	}
}

union fpr
{
	reg_t r;
	float s;
	double d;
};

void sim_t::interactive_fregs(const std::string& cmd, const std::vector<std::string>& args)
{
	fpr f;
	f.r = get_freg(args);
	printf("%g\n",f.s);
}

void sim_t::interactive_fregd(const std::string& cmd, const std::vector<std::string>& args)
{
	fpr f;
	f.r = get_freg(args);
	printf("%g\n",f.d);
}

reg_t sim_t::get_mem(const std::vector<std::string>& args)
{
	bool old_vm_enable = 0;
	reg_t old_ptbr = 0; 

	if(args.size() != 1 && args.size() != 2)
		throw trap_illegal_instruction;

	std::string addr_str = args[0];
	if(args.size() == 2)
	{
		int p = atoi(args[0].c_str());
		if(p >= (int)num_cores())
			throw trap_illegal_instruction;

		old_vm_enable = mmu->get_vm_enabled();
		old_ptbr = mmu->get_ptbr();
		mmu->set_vm_enabled(!!(procs[p]->sr & SR_VM));
		mmu->set_ptbr(procs[p]->mmu.get_ptbr());

		addr_str = args[1];
	}

	reg_t addr = strtol(addr_str.c_str(),NULL,16), val;
	if(addr == LONG_MAX)
		addr = strtoul(addr_str.c_str(),NULL,16);

	switch(addr % 8)
	{
		case 0:
			val = mmu->load_uint64(addr);
			break;
		case 4:
			val = mmu->load_uint32(addr);
			break;
		case 2:
		case 6:
			val = mmu->load_uint16(addr);
			break;
		default:
			val = mmu->load_uint8(addr);
			break;
	}

	if (args.size() == 2) {
		mmu->set_vm_enabled(old_vm_enable);
		mmu->set_ptbr(old_ptbr);
	}

	return val;
}

void sim_t::interactive_mem(const std::string& cmd, const std::vector<std::string>& args)
{
	printf("0x%016llx\n",(unsigned long long)get_mem(args));
}

void sim_t::interactive_str(const std::string& cmd, const std::vector<std::string>& args)
{
	bool old_vm_enable;
	reg_t old_ptbr; 
	reg_t addr;

	if(args.size() < 1)
		throw trap_illegal_instruction;

	old_vm_enable = mmu->get_vm_enabled();
	old_ptbr = mmu->get_ptbr();

	if (args.size() > 1)
	{
		mmu->set_vm_enabled(!!(procs[0]->sr & SR_VM));
		mmu->set_ptbr(procs[0]->mmu.get_ptbr());
		addr = strtol(args[1].c_str(),NULL,16);
	}
	else
	{
		addr = strtol(args[0].c_str(), NULL, 16);
	}

	char ch;
	while((ch = mmu->load_uint8(addr++)))
		putchar(ch);

	putchar('\n');

	mmu->set_vm_enabled(old_vm_enable);
	mmu->set_ptbr(old_ptbr);
}

void sim_t::interactive_until(const std::string& cmd, const std::vector<std::string>& args)
{
	int count;

	if(args.size() < 3)
		return;

	std::string scmd;

	if (args.size() == 4 && args[1] == "pc") {
		scmd = args[1];
		count = atoi(args[0].c_str());
	} else {
		scmd = args[0];
		count = 1;
	}

	reg_t val = strtol(args[args.size()-1].c_str(),NULL,16);
	if(val == LONG_MAX)
		val = strtoul(args[args.size()-1].c_str(),NULL,16);


	std::vector<std::string> args2;

	if (args.size() == 4 && scmd == "pc") {
		args2 = std::vector<std::string>(args.begin()+2,args.end()-1);
	} else {
		args2 = std::vector<std::string>(args.begin()+1,args.end()-1);
	}

	while(1)
	{
		reg_t current;
		if(scmd == "reg")
			current = get_reg(args2);
		else if(scmd =="pcreg")
			current = get_pcreg(args2);
		else if(scmd == "pc")
			current = get_pc(args2);
		else if(scmd == "mem")
			current = get_mem(args2);
		else if(scmd == "cycle")
			current = get_cycle(args2);
		else
			return;

		if(cmd == "until" && current == val) {
			if (count == 1) break;
			count--;
		}
		if(cmd == "while" && current != val) {
			if (count == 1) break;
			count--;
		}

		step_all(1,1,false);
	}
}
	
#define COMM_OFF  0x2c0
#define PID_OFF	  0x118
#define TASKS_OFF 0xd8
#define KSP_OFF   728
#define STATE_OFF 0

void sim_t::lp_info(reg_t task_struct_ptr)
{
	reg_t kernel_stack_ptr;
	reg_t comm_ptr;
	char ch;

	kernel_stack_ptr = mmu->load_uint64(task_struct_ptr + KSP_OFF);
	// printf("kernel sp = %lx\n", kernel_stack_ptr);

	comm_ptr = task_struct_ptr + COMM_OFF;
	// printf("current->task->comm = ");

	printf ("Thread name: ");
	while((ch = mmu->load_uint8(comm_ptr++))) putchar(ch);
	
	printf("  (PID %d)\n", mmu->load_uint32(task_struct_ptr + PID_OFF));
	printf("  task = %lx\n", task_struct_ptr);
	printf("  ksp  = %lx\n", kernel_stack_ptr);

	reg_t task_ptr, task_comm;
	task_ptr = mmu->load_uint64(task_struct_ptr + TASKS_OFF) - TASKS_OFF;
	task_comm = task_ptr + COMM_OFF;

	printf("Threads in current->task->tasks:\n");
	printf("  PID\ttask_struct address\tstate\tName\n");
	while (task_ptr != task_struct_ptr) {
		printf("  %d\t(%lx)\t%lx\t", mmu->load_uint32(task_ptr + PID_OFF), 
		       task_ptr, mmu->load_uint64(task_ptr + STATE_OFF));
		while((ch = mmu->load_uint8(task_comm++))) putchar(ch);
		printf("\n");
		task_ptr = mmu->load_uint64(task_ptr + TASKS_OFF) - TASKS_OFF;
		task_comm = task_ptr + COMM_OFF;
	}
}

void sim_t::interactive_linux_process(const std::string& cmd, const std::vector<std::string>& args)
{
	reg_t task_struct_ptr;

	bool old_vm_enable;
	reg_t old_ptbr; 

	old_vm_enable = mmu->get_vm_enabled();
	old_ptbr = mmu->get_ptbr();

	mmu->set_vm_enabled(!!(procs[0]->sr & SR_VM));
	mmu->set_ptbr(procs[0]->mmu.get_ptbr());

	if (args.size() >= 1)
	{
		task_struct_ptr = strtoul(args[0].c_str(), NULL, 16);
	}
	else
	{
		task_struct_ptr = procs[0]->get_pcr(PCR_K0);
	}

	lp_info(task_struct_ptr);

	mmu->set_vm_enabled(old_vm_enable);
	mmu->set_ptbr(old_ptbr);
}

#define FMT_PTE "%016lx"
#define FMT_PPN "%013lx"

void sim_t::pte_decode(pte_t pte)
{
	static const char *perm[8] = {
		"---", "--x", "-w-", "-wx",
		"r--", "r-x", "rw-", "rwx"
	};
	static const char *resv[8] = {
		"000", "001", "010", "011",
		"100", "101", "110", "111",
	};

	printf(FMT_PPN " resv=%s S=%s U=%s D=%u R=%u E=%u T=%u\n",
		(pte),
		resv[(pte >> 10) & 0x7],
		perm[(pte >> 7) & 0x7],
		perm[(pte >> 4) & 0x7],
		(pte & PTE_D) != 0, (pte & PTE_R) != 0,
		(pte & PTE_E) != 0, (pte & PTE_T) != 0);
}

void sim_t::interactive_translate(const std::string& cmd, const std::vector<std::string>& args)
{
	reg_t addr;

	if (args.size() < 1)
		throw trap_illegal_instruction;

	addr = strtol(args[0].c_str(),NULL,16);
	if(addr == LONG_MAX) {
		addr = strtoul(args[0].c_str(),NULL,16);
	}

	bool old_vm_enable;
	old_vm_enable = mmu->get_vm_enabled();
	mmu->set_vm_enabled(0);

	reg_t ptbr = procs[0]->get_pcr(PCR_PTBR);
	printf("ptbr = %016lx\n", ptbr);

	reg_t vpn2 = ((addr >> 33) & 0x3FF) << 3;
	pte_t pte2 = mmu->load_uint64(ptbr + vpn2);
	printf("entry %4ld: ", vpn2 >> 3);
	pte_decode(pte2);

	if (pte2 & PTE_T) {
		reg_t base2 = (pte2 >> 13) << 13;
		reg_t vpn1 = ((addr >> 23) & 0x3FF) << 3;
		pte_t pte1 = mmu->load_uint64(base2 + vpn1);
		printf("entry %4ld: ", vpn1 >> 3);
		pte_decode(pte1);

		if (pte1 & PTE_T) {
			reg_t base1 = (pte1 >> 13) << 13;
			reg_t vpn0 = ((addr >> 13) & 0x3FF) << 3;
			pte_t pte0 = mmu->load_uint64(base1 + vpn0);
			printf("entry %4ld: ", vpn0 >> 3);
			pte_decode(pte0);
		}
	}

	mmu->set_vm_enabled(old_vm_enable);

}

#define MM_OFF 0xe8
#define PGD_OFF 0x48 /* the offset of mm->pgd */

void sim_t::interactive_pagetable(const std::string& cmd, const std::vector<std::string>& args)
{
	reg_t task_ptr;
	reg_t mm;

	bool old_vm_enable;
	reg_t old_ptbr; 

	old_vm_enable = mmu->get_vm_enabled();
	old_ptbr = mmu->get_ptbr();

	mmu->set_vm_enabled(!!(procs[0]->sr & SR_VM));
	mmu->set_ptbr(procs[0]->mmu.get_ptbr());

	if (args.size() >= 1)
	{
		task_ptr = strtoul(args[0].c_str(), NULL, 16);
	}
	else
	{
		task_ptr = procs[0]->get_pcr(PCR_K0);
	}

	mm = mmu->load_uint64(task_ptr + MM_OFF);

	reg_t pgd = mmu->load_uint64(mm + PGD_OFF); /* gives a virtual address */
	printf("virtual table  = %016lx\n", pgd);
	pgd = pgd & (unsigned long)(0x3fffffff);
	printf("physical table = %016lx\n", pgd);

	mmu->set_vm_enabled(0); // need to work with physical addresses now

	int vpn2, vpn1, vpn0;
	for (vpn2 = 0; vpn2 < 1024; vpn2++) {	
		pte_t pte2 = mmu->load_uint64(pgd + (vpn2 << 3));
		if (pte2 & (PTE_E | PTE_T)) {
			printf("pgd %4d: ", vpn2);
			pte_decode(pte2);
		}

		if (pte2 & PTE_T) {
			for (vpn1 = 0; vpn1 < 1024; vpn1++) {
				reg_t base2 = (pte2 >> 13) << 13;
				pte_t pte1 = mmu->load_uint64(base2 + (vpn1 << 3));
				if (pte1 & (PTE_E | PTE_T)) {
					printf("  pmd %4d: ", vpn1);
					pte_decode(pte1);
				}

				if (pte1 & PTE_T) {
					for (vpn0 = 0; vpn0 < 1024; vpn0++) {
						reg_t base1 = (pte1 >> 13) << 13;
						pte_t pte0 = mmu->load_uint64(base1 + (vpn0 << 3));
						if (pte0 & PTE_E) {
							printf("    pte %4d: ", vpn0);
							pte_decode(pte0);
						}
					}
				}
			}
		}
	}

	mmu->set_vm_enabled(old_vm_enable);
	mmu->set_ptbr(old_ptbr);
}
