
#include <linux/kvm.h>

#include "analyzer.h"
#include "vmm_agent.h"
#include "td_agent.h"
#include "state.h"
#include "defs.h"

extern struct comArea *com;
extern ulong td_0_created;

void analyer_function(){

    struct kvm_regs regs;
    ulong ret, page_pa;

    LOG("\nanalyzer function start\n");
    
    init_tdx_module();

    create_td(TD_0, LP_0, TD_GPA_RANGE, TD_INITIAL_PAGE_COUNT);
#ifdef ENABLE_SERVTD_BINDING
	td_0_created = 1;
#endif
    create_td(TD_1, LP_1, TD_GPA_RANGE, TD_INITIAL_PAGE_COUNT);

    run_td(TD_0, com->td[TD_0].vcpu_associated_lp);
	com->sreq.td_num_on_lp[com->td[TD_0].vcpu_associated_lp] = TD_0;

	com->sreq.td_running = 1;
	run_td(TD_1, com->td[TD_1].vcpu_associated_lp);
	com->sreq.td_num_on_lp[com->td[TD_1].vcpu_associated_lp] = TD_1;

    page_pa = reserve_and_get_tdmr_next_avl_pa(TD_0, com->td[TD_0].hkid, TD_0);
    ret = tdh_mem_sept_add(LP_2, (1UL << 48), SEPT_LVL_4, com->td[TD_0].tdr, page_pa);


	memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rax = TDH_MEM_SEPT_RD;
    regs.rcx = 0;
    regs.rdx = com->td[TD_0].tdr;
    if(do_seamcall(LP_2, &regs) != SEAMCALL_SUCCESS){
        LOG("TDH_MEM_SEPT_RD Failed\n");
		exit(0);
    }
    
    memset((void *)&regs, 0, sizeof(struct kvm_regs));
    com->td_owner_for_next_tdxcall = TD_0;
    regs.rax = TDG_MEM_PAGE_ATTR_RD;
    regs.rcx = 0;
    if(do_tdcall(LP_0, &regs) != TDCALL_SUCCESS){
        LOG("TDG_MEM_PAGE_ATTR_RD Failed\n");
		exit(0);    
    }

    /*memset((void *)&regs, 0, sizeof(struct kvm_regs));
    regs.rcx = 1UL << 2;
    if(tdg_vp_vmcall(LP_0, &regs) != VMEXIT_REASON_TDCALL){
        LOG("TDG_VP_VMCALL Failed\n");
		exit(0); 
    }*/

    start_se();
    ulong field_id = 0x9110000300000010;
    ulong data = 0x1;
    ulong write_mask = 0x1;
    regs.rax = TDG_VM_WR;
    regs.rdx = field_id;
    regs.r8 = data;
    regs.r9 = write_mask;
    if(do_tdcall(LP_0, &regs) != TDCALL_SUCCESS){
        LOG("TDG_VM_WR Failed\n");
		exit(0);    
    }
    

    exit(0);
}