#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>

#include "defs.h"
#include "seam.h"
#include "common.h"
#include "td_control_structures.h"
#include "tdx_local_data.h"

#include "state.h"
#include "vmm_agent.h"

// #define ENABLE_SERVTD_BINDING

void remove_debug_bp(ulong dr_num);
void set_debug_bp(ulong address, ulong dr_num, ulong trigger_condition, ulong bp_size);
extern int switch_to_tdx_module_context(TDXCALL_TYPE call_type);
extern void setup_tdxmodule_seamcall_state(ulong seamcall);
extern ulong do_tdxcall(ulong seamcall);
extern uint64_t get_saved_register_value(REGS_64 reg);
extern void log_active_keyhole_mappings();
extern void block_persistant_khole_mappings(ulong current_lp);
extern ulong get_tdmr_next_avl_pa(ulong td, ulong hkid, ulong hkid_owner);
extern ulong get_tdr_va_of_running_td(ulong pa, ulong lp);
extern ulong va_to_pa(ulong cr3, ulong va);
extern ulong get_region_base_pa(REGION region);
extern void fill_khole_refs(ulong lp);

ulong get_offset(OFFSET_TYPE type);

extern struct vm *vm;

void start_se();
extern void setup_and_do_tdcal(ulong tdcall_number, ulong lp);
void run_servtd_bind();
void do_tdh_mng_rd(ulong td, ulong lp);

#define SEAMCALL(...) do_tdxcall(__VA_ARGS__)

extern struct comArea *com;

#ifdef ENABLE_SERVTD_BINDING
ulong td_0_created = 0;
#endif


void start_se(){
	LOG("Starting _se\n");
	com->seam_state = SEAM_STATE_TEMP;
	com->single_step_on = true;
}

void set_common_seamcall_state(ulong lp_id, ulong scall){

	com->is_tdcall = 0;
	com->current_lp = lp_id;
	com->seamcall_vmcs[lp_id].vm_exit_reason = VMEXIT_REASON_SEAMCALL;
	com->current_tdx_vmcs_pa = com->seamcall_vmcs[lp_id].vmcs_pa;
	memset((void *)&com->last_seamcall, 0, sizeof(struct tdxCall));
	com->last_seamcall.tdxcall = scall;
	com->last_seamcall.state = STATE_DO_SEAMCALL;
}

ulong tdh_sys_init(ulong lp_id){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_SYS_INIT);
	regs.rax = TDH_SYS_INIT;
	regs.rcx = 0;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_SYS_INIT);
}

ulong tdh_sys_lp_init(ulong lp_id){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_SYS_LP_INIT);
	regs.rax = TDH_SYS_LP_INIT;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_SYS_LP_INIT);
}

ulong tdh_sys_config(ulong lp_id, ulong tdmrinfo_pa, ulong num_ptrs, ulong global_hkid){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_SYS_CONFIG);
	regs.rax = TDH_SYS_CONFIG;
	regs.rcx = tdmrinfo_pa;
	regs.rdx = num_ptrs;
	regs.r8 = global_hkid;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_SYS_CONFIG);
}

ulong tdh_sys_key_config(ulong lp_id){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_SYS_KEY_CONFIG);
	regs.rax = TDH_SYS_KEY_CONFIG;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_SYS_KEY_CONFIG);
}

ulong tdh_sys_tdmr_init(lp_id){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_SYS_TDMR_INIT);
	regs.rax = TDH_SYS_TDMR_INIT;
	regs.rcx = TDX_TDMR0_START_PA;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_SYS_TDMR_INIT);
}

ulong tdh_mng_create(ulong lp_id, ulong tdr, ulong hkid){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_MNG_CREATE);

	regs.rax = TDH_MNG_CREATE;
	regs.rcx = tdr;
	regs.rdx = hkid;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_MNG_CREATE);
}

ulong tdh_mng_key_config(ulong lp_id, ulong tdr){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_MNG_KEY_CONFIG);

	regs.rax = TDH_MNG_KEY_CONFIG;
	regs.rcx = tdr;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_MNG_KEY_CONFIG);
}

ulong tdh_mng_addcx(ulong lp_id, ulong tdr, ulong page_pa){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_MNG_ADDCX);

	regs.rax = TDH_MNG_ADDCX;
	regs.rcx = page_pa;
	regs.rdx = tdr;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_MNG_ADDCX);
}

ulong tdh_sys_info(ulong lp_id, ulong tdsysinfo_page_pa, ulong tdsysinfo_page_size, ulong cmrinfo_ary_pa, ulong num_cmrinfo_entries){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_SYS_INFO);

	regs.rax = TDH_SYS_INFO;
	regs.rcx = tdsysinfo_page_pa;
	regs.rdx = tdsysinfo_page_size;
	regs.r8 = cmrinfo_ary_pa;
	regs.r9 = num_cmrinfo_entries;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_SYS_INFO);
}

ulong tdh_mng_init(ulong lp_id, ulong tdr, ulong tdparams_pa){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_MNG_INIT);

	regs.rax = TDH_MNG_INIT;
	regs.rcx = tdr;
	regs.rdx = tdparams_pa;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_MNG_INIT);
}

ulong tdh_vp_create(ulong lp_id, ulong tdr, ulong tdvps_pa){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_VP_CREATE);

	regs.rax = TDH_VP_CREATE;
	regs.rcx = tdvps_pa;
	regs.rdx = tdr;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_VP_CREATE);
}

ulong tdh_vp_addcx(ulong lp_id, ulong tdvpr, ulong tdcx_pa){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_VP_ADDCX);

	regs.rax = TDH_VP_ADDCX;
	regs.rcx = tdcx_pa;
	regs.rdx = tdvpr;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_VP_ADDCX);
}

ulong tdh_vp_init(ulong lp_id, ulong tdvpr, ulong initial_rcx){

	struct kvm_regs regs;
	ulong vp_init_leaf_version = 0;
	uint32_t x2apic_id = 0;

	set_common_seamcall_state(lp_id, TDH_VP_INIT);

	regs.rax = TDH_VP_INIT | (vp_init_leaf_version << 16);
	regs.rcx = tdvpr;
	regs.rdx = initial_rcx;
	regs.r8 |= x2apic_id;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_VP_INIT);
}

ulong tdh_mem_sept_add(ulong lp_id, ulong gpa, ulong level, ulong tdr, ulong new_sept_pa){

	struct kvm_regs regs;
	ulong allow_existing = 0;
	ulong sept_add_leaf_version = 1;

	set_common_seamcall_state(lp_id, TDH_MEM_SEPT_ADD);

	regs.rax = TDH_MEM_SEPT_ADD | (sept_add_leaf_version << 16);
	regs.rcx = gpa | (level & 0b111UL);
	regs.rdx = tdr | (allow_existing & 0x1);
	regs.r8 = new_sept_pa;
	regs.r9 = -1;
	regs.r10 = -1;
	regs.r11 = -1;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);
	
	return SEAMCALL(TDH_MEM_SEPT_ADD);
}

ulong tdh_mem_page_add(ulong lp_id, ulong gpa, ulong level, ulong tdr, ulong target_page, ulong source_page){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_MEM_PAGE_ADD);

	regs.rax = TDH_MEM_PAGE_ADD;
	regs.rcx = gpa | (level & 0b111UL);
	regs.rdx = tdr;
	regs.r8 = target_page;
	regs.r9 = source_page;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_MEM_PAGE_ADD);
}

ulong tdh_mr_extend(ulong lp_id, ulong gpa, ulong tdr){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_MR_EXTEND);

	regs.rax = TDH_MR_EXTEND;
	regs.rcx = gpa;
	regs.rdx = tdr;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_MR_EXTEND);
}

ulong tdh_mr_finalize(ulong lp_id, ulong tdr){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_MR_FINALIZE);

	regs.rax = TDH_MR_FINALIZE;
	regs.rcx = tdr;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_MR_FINALIZE);
}

ulong tdh_vp_enter(ulong lp_id, ulong tdvpr){

	struct kvm_regs regs;

	set_common_seamcall_state(lp_id, TDH_VP_ENTER);

	regs.rax = TDH_VP_ENTER;
	regs.rcx = tdvpr;
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, &regs);

	return SEAMCALL(TDH_VP_ENTER);
}

ulong do_seamcall(ulong lp_id, struct kvm_regs *regs){

	set_common_seamcall_state(lp_id, regs->rax);
	switch_to_module_context(TDXCALL_TYPE_SEAMCALL, regs);

	return SEAMCALL(regs->rax);
}

void setup_and_do_seamcall(ulong seamcall_number, ulong lp){
	
	com->is_tdcall = 0;
	com->current_lp = lp;
	com->seamcall_vmcs[lp].vm_exit_reason = VMEXIT_REASON_SEAMCALL;
	com->current_tdx_vmcs_pa = com->seamcall_vmcs[lp].vmcs_pa;
	switch_to_tdx_module_context(TDXCALL_TYPE_SEAMCALL);
	setup_tdxmodule_seamcall_state(seamcall_number);
	SEAMCALL(seamcall_number);
}

void add_a_new_page_custom(ulong td_id, ulong lp_id){

	com->td_mem.next_td_page_gpa = com->td[td_id].next_4k_pg_gpa_to_add;
	com->td[td_id].next_4k_pg_gpa_to_add += _4K;

	// /*we do not care about the actual physical page content copied to the TD page,
	// so it will be copied from the following shared page*/
	// com->td_mem.next_source_page_hpa = SEAM_AGENT_SEAMCALL_DATA_PA + 2*_4K;

	block_persistant_khole_mappings(lp_id);
	setup_and_do_seamcall(TDH_MEM_PAGE_ADD ,lp_id);
}

void add_a_new_sept_custom(ulong td_id, ulong lp_id, int level, ulong gpa){

	com->current_td_being_setup = td_id;
	com->sept.septe_level = level;
	com->sept.start_gpa = gpa;
	
	block_persistant_khole_mappings(lp_id);
	setup_and_do_seamcall(TDH_MEM_SEPT_ADD, lp_id);
}

/*TD Creation and Key Resource Assignment-----------
	TDH_MNG_CREATE,
	TDH_MNG_KEY_CONFIG,
TDCS Memory Allocation and TD Initialization--------
	TDH_MNG_ADDCX,
	TDH_SYS_INFO,
	TDH_MNG_INIT,
Virtual Processor Creation and Configuration--------
	TDH_VP_CREATE,
	TDH_VP_ADDCX,
	TDH_VP_INIT,
	TDH_VP_WR -The host VMM may modify a few TD VMCS execution control fields using this SEAMCALL
TD Boot Memory Setup, measurement & finalize--------
	TDH_MEM_SEPT_ADD,
	TDH_MEM_PAGE_ADD,
	TDH_MR_EXTEND
	TDH_MR_FINALIZE*/
void create_td(ulong td_id, ulong lp_id, ulong initial_gpa_max, ulong initial_pages_to_add){

	// ulong lp_id = 0;
	ulong tdcs_add_count, tdvps_add_count, sept_parent_level, gpa_start, pg_count, pg_start;
	ulong chunk_gpa;
	ulong tdr, hkid, page_pa, current_lvl, current_gpa;
	ulong tdsysinfo_page_pa, tdsysinfo_page_size, cmrinfo_ary_pa, num_cmrinfo_entries;
	struct kvm_regs regs;

	if((td_id >= MAX_TDS) || (td_id < 0)){
		LOG("invalid TD id: %lu\n", td_id);
		exit(0);
	}
	if((initial_gpa_max <= 0) || (initial_gpa_max > TD_GPA_RANGE_MAX) || (initial_gpa_max & PAGE_OFST != 0)){
		LOG("invalid initial_gpa_max: 0x%lx\n", initial_gpa_max);
		exit(0);
	}
	com->current_td_being_setup = td_id;
	com->td[td_id].initial_gpa_max = initial_gpa_max;
	com->td[td_id].next_gpa_to_allocate_in_sept = initial_gpa_max;

	/*TD Creation and Key Resource Assignment------------*/
	tdr = reserve_and_get_tdmr_next_avl_pa(td_id, TDX_GLOBAL_PRIVATE_HKID,TDX_MOD);
	hkid = reserve_and_get_next_available_hkid();
	com->td[td_id].tdr = tdr;
	com->td[td_id].hkid = hkid;
	if(tdh_mng_create(lp_id, tdr, hkid) != SEAMCALL_SUCCESS){
		LOG("TDH_MNG_CREATE Failed\n");
		exit(0);
	}

	if(tdh_mng_key_config(lp_id, tdr) != SEAMCALL_SUCCESS){
		LOG("TDH_MNG_KEY_CONFIG Failed\n");
		exit(0);
	}

	/*TDCS Memory Allocation and TD Initialization-------*/
	tdcs_add_count = 0;
	do{
		if (tdcs_add_count == 0){
			com->td[td_id].tdcs_base = get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
		}
		else if(tdcs_add_count == 3){
			com->td[td_id].tdcs_eptp_root = get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
		}
		page_pa = reserve_and_get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
		if(tdh_mng_addcx(lp_id, tdr, page_pa) != SEAMCALL_SUCCESS){
			LOG("TDH_MNG_ADDCX Failed\n");
		}

		tdcs_add_count++;
	}while(tdcs_add_count < MIN_NUM_TDCS_PAGES);

	tdsysinfo_page_pa = SEAM_AGENT_SEAMCALL_DATA_PA;
	cmrinfo_ary_pa = SEAM_AGENT_SEAMCALL_DATA_PA + _4K;
	tdh_sys_info(lp_id, tdsysinfo_page_pa, _4K, cmrinfo_ary_pa, MAX_CMR);

	/*TDH_MNG_INIT uses data retrived from TDH_SYS_INFO*/

	memset((void *)&regs, 0, sizeof(struct kvm_regs));
	prep_tdh_mng_init_args(&regs);
	regs.rax = TDH_MNG_INIT;
	if(do_seamcall(lp_id, &regs) != SEAMCALL_SUCCESS){
		LOG("TDH_MNG_INIT Failed\n");
		exit(0);
	}

	/*testing TDH_SERVTD_BIND*/
#ifdef ENABLE_SERVTD_BINDING
	run_servtd_bind();
#endif

	/*Virtual Processor Creation and Configuration-------*/
	/*In the current design, we provide only 1 vCPU for a TD (i.e. only 1 VP CREATE). If this is 
	changed in future, we also need to update all places where we consider a TD to only have 1 vCPU.*/
	page_pa = reserve_and_get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
	com->td[td_id].tdvpr = page_pa;
	if(tdh_vp_create(lp_id, tdr, page_pa) != SEAMCALL_SUCCESS){
		LOG("TDH_VP_CREATE Failed\n");
		exit(0);
	}

	tdvps_add_count = 0;
	do{
		page_pa = reserve_and_get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
		if(tdvps_add_count == 0){
			com->tdcall_vmcs[td_id].vmcs_pa = page_pa;
		}
		if(tdh_vp_addcx(lp_id, com->td[td_id].tdvpr, page_pa) != SEAMCALL_SUCCESS){
			LOG("TDH_VP_ADDCX Failed\n");
			exit(0);
		}

		tdvps_add_count++;
	}while(tdvps_add_count < (MAX_TDVPS_PAGES - 1));

	if(tdh_vp_init(lp_id, com->td[td_id].tdvpr, 0x0) != SEAMCALL_SUCCESS){
		LOG("TDH_VP_INIT Failed\n");
		exit(0);
	}

	/*As noticed, during VP Init the corresponding tdvps is associated with the current LP id.
	This is the LP on which the VMLAUNCH must take place. So we save the value for future use.*/
	com->td[td_id].vcpu_associated_lp = lp_id;

	/*TD Boot Memory Setup : sept-------------------------------*/
	/*here we create the initial sept tree. the root sept page, sPML4 (for 4 level ept) OR sPML5
	(for 5 level ept) has already been created,
	under TDH_MNG_ADDCX. Now, we add the remaining lower level sEPT pages accordingly.
	For 4 level EPT : one sPDPT (parent sept level 3), one sPD (parent sept level 2), and one or 
	few sPT (parent sept level 1) pages.	
	For 5 level EPT : one sPML4 (parent sept level 4), one sPDPT (parent sept level 3), one sPD 
	(parent sept level 2), and one or few sPT (parent sept level 1) pages.	
	The number of sPT pages added depends on the initial_gpa_max. Eg: if initial_gpa_max = 4M, we 
	add a sPT page for each 2M block. i.e. 1 for GPA range starting at 0, another for GPA range 
	starting at 2M*/
	gpa_start = 0;
	sept_parent_level = TDX_SEPT_LEVELS;
	while(sept_parent_level > 0){

		current_lvl = sept_parent_level;
		current_gpa = gpa_start;
		// com->sept.septe_level = sept_parent_level;
		// com->sept.start_gpa = 0;

		if(sept_parent_level == 1){
			if(gpa_start < initial_gpa_max){
				// com->sept.start_gpa = gpa_start;
				gpa_start += _2M;
			}
			else{
				break;
			}
		}
		else{
			// com->sept.start_gpa = 0;
			sept_parent_level--;
		}

		page_pa = reserve_and_get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
		if(tdh_mem_sept_add(lp_id, current_gpa, current_lvl, tdr, page_pa) != SEAMCALL_SUCCESS){
			LOG("TDH_MEM_SEPT_ADD Failed\n");
			exit(0);
		}

		/*For TDH.MEM.SEPT.ADD version 1 or higher: If a provided L1 SEPT page has been added, R8 returns -1*/
		if(get_saved_register_value(R8) != NULL_PA){
			LOG("SEPT add issue, investiate ...\n");
			exit(0);
		}
	}

	/*TD Boot Memory Setup : initial pages---------------------------*/
	pg_count = 0;
	pg_start = 0;
	while (pg_count < initial_pages_to_add){
		
		/*We do not actually run  the TD. Therefore, for the moment we do not need to pass actuall data 
		in to td pages being added. So, we use some page in the host as the source page. 
		we have used the first 2 pages of SEAM_AGENT_SEAMCALL_DATA_PA, so use the 3rd page here.*/

		page_pa = reserve_and_get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
		if(tdh_mem_page_add(lp_id, pg_start, SEPT_LVL_0, tdr, page_pa, SEAM_AGENT_SEAMCALL_DATA_PA + 2*_4K) != SEAMCALL_SUCCESS){
			LOG("TDH_MEM_PAGE_ADD Failed\n");
			exit(0);
		}

		pg_start += _4K;
		com->td[td_id].next_4k_pg_gpa_to_add = pg_start + _4K;
		pg_count++;
	}

	/*TD Boot Memory Setup : measurement-----------------------------*/
	chunk_gpa = 0;
	while (chunk_gpa < initial_pages_to_add*_4K){
		
		if(tdh_mr_extend(lp_id, chunk_gpa, tdr) != SEAMCALL_SUCCESS){
			LOG("TDH_MR_EXTEND Failed\n");
			exit(0);	
		}

		chunk_gpa += 256; /*each chunk is 256B*/
	}

	/*TD Boot Memory Setup : finalize--------------------------------*/
	if(tdh_mr_finalize(lp_id, tdr) != SEAMCALL_SUCCESS){
		LOG("TDH_MR_FINALIZE Failed\n");
		exit(0);
	}
	com->td[td_id].is_created = true;
}

void init_tdx_module(){

	ulong lp;
	ulong next_to_init_adr;
	struct kvm_regs regs;

	LOG("init_tdx_module\n");

	/*TDH_SYS_INIT-----------------------------------*/
	if(tdh_sys_init(LP_0) != SEAMCALL_SUCCESS){
		LOG("TDH_SYS_INIT Failed\n");
		exit(0);
	}

	/*TDH_SYS_LP_INIT--------------------------------*/
	lp = LP_0;
	while(lp < NUM_ADDRESSIBLE_LPS){
		com->current_lp = lp;

		if(tdh_sys_lp_init(lp) != SEAMCALL_SUCCESS){
			LOG("TDH_SYS_LP_INIT Failed\n");
			exit(0);
		}
		lp++;
	}

	/*TDH_SYS_CONFIG-----------------------------------*/
	lp = LP_0;
	com->current_lp = lp;

	prep_tdh_sys_config_args(&regs);
	regs.rax = TDH_SYS_CONFIG;
	if(do_seamcall(lp, &regs) != SEAMCALL_SUCCESS){
		LOG("TDH_SYS_CONFIG Failed\n");
		exit(0);
	}

	/*TDH_SYS_KEY_CONFIG-------------------------------*/
	if(tdh_sys_key_config(lp) != SEAMCALL_SUCCESS){
		LOG("TDH_SYS_KEY_CONFIG Failed\n");
		exit(0);
	}

	/*TDH_SYS_TDMR_INIT--------------------------------*/
	do{
		 if(tdh_sys_tdmr_init(lp) != SEAMCALL_SUCCESS){
			LOG("TDH_SYS_TDMR_INIT Failed\n");
			exit(0);
		 }
		next_to_init_adr = get_saved_register_value(RDX);
	}while(next_to_init_adr < (TDX_TDMR0_START_PA + TDX_TDMR0_FULL_SIZE));
	/*The above terminating condition is consistant with the specs and kvm.
	The returned rdx is the block in the tdmr to be initialized next.*/
}

void run_td(ulong td_id, ulong lp){

	/*LOG("\nRun td: %lu", td_id);*/
	
	com->td_owner_for_next_tdxcall = td_id;
	com->tdcall_vmcs[td_id].vm_exit_qualification = 0;
	com->tdcall_vmcs[td_id].rip = TD_START_RIP;

	if(tdh_vp_enter(lp, com->td[td_id].tdvpr) != SEAMCALL_SUCCESS){
		LOG("TDH_VP_ENTER Failed\n");
		exit(0);
	}
	com->td[td_id].is_running = true;
}

void bind_serv_td(ulong td_id, ulong serv_td_id, ulong lp_id){

	com->current_td_being_setup = td_id;
	com->serv_td_owenr_being_setup = serv_td_id;

	setup_and_do_seamcall(TDH_SERVTD_BIND, lp_id);
}

void prebind_serv_td(ulong td_id, ulong lp_id){

	com->current_td_being_setup = td_id;

	setup_and_do_seamcall(TDH_SERVTD_PREBIND, lp_id);
}

void add_a_new_sept(ulong td_id, ulong lp_id, int level){

	com->current_td_being_setup = td_id;
	com->sept.septe_level = level;
	com->sept.start_gpa = com->td[td_id].next_gpa_to_allocate_in_sept;
	
	block_persistant_khole_mappings(lp_id);
	setup_and_do_seamcall(TDH_MEM_SEPT_ADD, lp_id);
}

void tdh_sept_rd(ulong td_id, ulong lp_id, int level, ulong gpa){

	com->current_td_being_setup = td_id;
	com->sept.septe_level = level;
	com->sept.start_gpa = gpa;
	
	block_persistant_khole_mappings(lp_id);
	setup_and_do_seamcall(TDH_MEM_SEPT_RD, lp_id);
}

void add_a_new_page(ulong td_id, ulong lp_id){

	com->td_mem.next_td_page_gpa = com->td[td_id].next_4k_pg_gpa_to_add;
	com->td[td_id].next_4k_pg_gpa_to_add += _4K;

	// /*we do not care about the actual physical page content copied to the TD page,
	// so it will be copied from the following shared page*/
	// com->td_mem.next_source_page_hpa = SEAM_AGENT_SEAMCALL_DATA_PA + 2*_4K;

	block_persistant_khole_mappings(lp_id);
	setup_and_do_seamcall(TDH_MEM_PAGE_AUG ,lp_id);
}

#ifdef ENABLE_SERVTD_BINDING
void run_servtd_bind(){
	
	if(td_0_created == 1){

		ulong target_td = TD_1;
		ulong service_td = TD_0;

		/*gathering object offsets for symbolization*/
		tdcs_t tdcs_base;
		/*offset for  tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].state  1 byte*/
		ulong binding_state_ofst = (ulong)&tdcs_base.service_td_fields.servtd_bindings_table[0].state - (ulong)&tdcs_base;
		/*offset for  attributes  8 bytes , can also consider the first 4 bytes to capture migratable flag*/
		ulong attributes_offset = (ulong)&tdcs_base.executions_ctl_fields.attributes - (ulong)&tdcs_base;
		/*offset for  tdcs_p->management_fields.op_state   4 bytes*/
		ulong op_state_ofst = (ulong)&tdcs_base.management_fields.op_state - (ulong)&tdcs_base;

		com->sreq.tdcs_binding_state_ofst = binding_state_ofst;
		com->sreq.tdcs_attributes_offset = attributes_offset;
		com->sreq.tdcs_op_state_ofst = op_state_ofst;
		com->sreq.tdcs_start_pa = com->td[target_td].tdcs_base;

		/*ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + get_offset(OFFSET_TYPE_TDH_SERVTD_BIND_LEAF);
		set_debug_bp(dr_adr, DEBUG_DR0, DB_CONDITION_INS_EXEC, DB_LENGTH_1_BYTE);
		start_se();*/

		/*service td binding*/
#if SERVTD_BIND_TYPE == TD_BIND
		struct kvm_regs regs;
		memset((void *)&regs, 0, sizeof(struct kvm_regs));
		com->current_td_being_setup = target_td;
		com->serv_td_owenr_being_setup = service_td;
		prep_tdh_servtd_bind_args(&regs);
		regs.rax = TDH_SERVTD_BIND;
		if(do_seamcall(LP_0, &regs) != SEAMCALL_SUCCESS){
			LOG("TDH_SERVTD_BIND Failed\n");
			exit(0);
		}
#endif

		com->td[service_td].servtd.binding_handle =  get_saved_register_value(RCX);
		com->td[service_td].servtd.targtd_uuid_0_63 =  get_saved_register_value(R10);
		com->td[service_td].servtd.targtd_uuid_64_127 = get_saved_register_value(R11);
		com->td[service_td].servtd.targtd_uuid_128_191 = get_saved_register_value(R12);
		com->td[service_td].servtd.targtd_uuid_192_255 = get_saved_register_value(R13);

		/*service td prebinding*/
#if SERVTD_BIND_TYPE == TD_PREBIND
		struct kvm_regs regs;
		memset((void *)&regs, 0, sizeof(struct kvm_regs));
		com->current_td_being_setup = target_td;
		com->serv_td_owenr_being_setup = service_td;
		prep_tdh_servtd_prebind_args(&regs);
		regs.rax = TDH_SERVTD_PREBIND;
		if(do_seamcall(LP_0, &regs) != SEAMCALL_SUCCESS){
			LOG("TDH_SERVTD_PREBIND Failed\n");
			exit(0);
		}
#endif
		/*LOG("Ending TD binding test case.\n");
		exit(0);*/
	}

}
#endif

void do_tdh_mng_rd(ulong td, ulong lp){

	com->td_owner_for_next_tdxcall = td;

	setup_and_do_seamcall(TDH_MNG_RD, lp);
	LOG("RDX: %lx\n", get_saved_register_value(RDX));
	LOG("R8: %lx\n", get_saved_register_value(R8));

	exit(0);

}

ulong check_lock_and_map_explicit_tdr = 0x2550;
ulong map_pa = 0x9b30;
void vmm_agent(){
	
    LOG("VMM agent\n");

	init_tdx_module();

	// start_se();
	// setup_and_do_seamcall(TDH_SYS_RDALL, LP_0);
	// exit(0);

	/*The same LP# on which a given TD vcpu was initialized must be used for VP_ENTER. At VP_INIT, 
	associate_vcpu_initial() binds the tdvpr to the LP on which the init is done, Later at VP_ENTER, 
	check_and_associate_vcpu() --> associate_vcpu() checks the folowing :
	"Check if VCPU is not associated with any LP, and associate it with the current LP.  The VCPU may 
	already be associated with the current LP, but if it's associated with another LP this is an error."
	Thus, make sure to create the two TDs on different LPs for them to be run on two lps later*/
	create_td(TD_0, LP_0, TD_GPA_RANGE, TD_INITIAL_PAGE_COUNT);
#ifdef ENABLE_SERVTD_BINDING
	td_0_created = 1;
#endif
	create_td(TD_1, LP_1, TD_GPA_RANGE, TD_INITIAL_PAGE_COUNT);
	LOG("\nTwo TDs created.\n");

	// com->td_owner_for_next_tdxcall = TD_0;
	// setup_and_do_seamcall(TDH_VP_RD, LP_0);

    run_td(TD_0, com->td[TD_0].vcpu_associated_lp);
	com->sreq.td_num_on_lp[com->td[TD_0].vcpu_associated_lp] = TD_0;

	com->sreq.td_running = 1;
	run_td(TD_1, com->td[TD_1].vcpu_associated_lp);
	com->sreq.td_num_on_lp[com->td[TD_1].vcpu_associated_lp] = TD_1;


	// com->sept.start_gpa = 0;
	// setup_and_do_seamcall(TDH_MEM_RANGE_BLOCK, LP_2);
	// // exit(0);
	
	// com->td_owner_for_next_tdxcall = TD_0;
	// setup_and_do_seamcall(TDH_MEM_TRACK, LP_2);

	// setup_and_do_seamcall(TDH_MEM_RANGE_UNBLOCK, LP_2);
	// analyer_function();
	exit(0);
//--------------------------------------------------------------------


	com->td_owner_for_next_tdxcall = TD_0;
	com->current_td_being_setup = TD_0;

	// setup_and_do_tdcal(TDG_VM_RD, LP_0);
	// setup_and_do_seamcall(TDH_VP_WR, LP_2);
	// LOG("RCX: 0x%lx\n", get_saved_register_value(RCX));
	// LOG("RDX: 0x%lx\n", get_saved_register_value(RDX));
	// LOG("R8: 0x%lx\n", get_saved_register_value(R8));
	// LOG("R9: 0x%lx\n", get_saved_register_value(R9));
	// LOG("R10: 0x%lx\n", get_saved_register_value(R10));
	// LOG("R11: 0x%lx\n", get_saved_register_value(R11));
	// exit(0);

	// setup_and_do_seamcall(TDH_MEM_TRACK, LP_2);
	// exit(0);

	ulong cur_td = TD_0;
	ulong gpa = 0;
	gpa = (1UL << 48);

	ulong lp_1 = LP_2;
	
	// setup_and_do_tdcal(TDG_SERVTD_WR, LP_0);
	// LOG("RCX: 0x%lx\n", get_saved_register_value(RCX));
	// LOG("RDX: 0x%lx\n", get_saved_register_value(RDX));
	// LOG("R8: 0x%lx\n", get_saved_register_value(R8));
	// LOG("R9: 0x%lx\n", get_saved_register_value(R9));
	// LOG("R10: 0x%lx\n", get_saved_register_value(R10));
	// LOG("R11: 0x%lx\n", get_saved_register_value(R11));
	// exit(0);

	add_a_new_sept_custom(cur_td, lp_1, SEPT_LVL_4, gpa);

	add_a_new_sept_custom(cur_td, lp_1, SEPT_LVL_3, gpa);
	add_a_new_sept_custom(cur_td, lp_1, SEPT_LVL_2, gpa);

	add_a_new_sept_custom(cur_td, lp_1, SEPT_LVL_1, gpa);
	
	com->current_td_being_setup = TD_0;
	// com->td_mem.next_td_page_gpa = gpa | SEPT_LVL_1;
	// setup_and_do_seamcall(TDH_MEM_PAGE_AUG ,LP_2);

	// int i = 0;
	// ulong gpa_st = 0;
	// com->sept.start_gpa = gpa | SEPT_LVL_1;
	// while(i < 512){
	// 	com->td_mem.next_td_page_gpa = gpa + gpa_st;
	// 	setup_and_do_seamcall(TDH_MEM_PAGE_AUG ,LP_2);

	// 	gpa_st += _4K;
	// 	i++;
	// }

	setup_and_do_tdcal(TDG_VP_VMCALL, LP_0);
	// // setup_and_do_tdcal(TDG_VP_VMCALL, LP_1);

	exit(0);

	// gpa = 0;
	com->sept.start_gpa = gpa | SEPT_LVL_1;
	setup_and_do_seamcall(TDH_MEM_RANGE_BLOCK, LP_2);
	// exit(0);
	
	com->td_owner_for_next_tdxcall = TD_0;
	setup_and_do_seamcall(TDH_MEM_TRACK, LP_2);

	com->sept.start_gpa = gpa | SEPT_LVL_1;
	setup_and_do_seamcall(TDH_MEM_PAGE_PROMOTE, LP_2);
	// setup_and_do_seamcall(TDH_MEM_PAGE_DEMOTE, LP_2);

	// setup_and_do_seamcall(TDH_MEM_PAGE_RELOCATE, LP_2);
	// setup_and_do_seamcall(TDH_MEM_SEPT_REMOVE, LP_2);
	// setup_and_do_seamcall(TDH_MEM_PAGE_REMOVE, LP_2);
	// setup_and_do_seamcall(TDH_PHYMEM_PAGE_RECLAIM, LP_2);

	
	// com->sept.start_gpa = gpa; // | SEPT_LVL_1;
	// setup_and_do_seamcall(TDH_MEM_RANGE_UNBLOCK, LP_2);
	// exit(0);

	// setup_and_do_seamcall(TDH_MEM_PAGE_RELOCATE, LP_2);
	// exit(0);

	// setup_and_do_tdcal(TDG_VP_VMCALL, LP_0);
	// setup_and_do_seamcall(TDH_VP_WR, LP_2);

	// setup_and_do_seamcall(TDH_SYS_RDALL, LP_2);

	// setup_and_do_seamcall(TDH_VP_RD, LP_2);

	// setup_and_do_tdcal(TDG_VP_VMCALL, LP_0);
	// setup_and_do_seamcall(TDH_MNG_VPFLUSHDONE, LP_0);

	
	// setup_and_do_tdcal(TDG_VP_VMCALL, LP_0);
	// setup_and_do_seamcall(TDH_VP_FLUSH, LP_0);

	// setup_and_do_seamcall(TDH_MNG_WR, LP_2);
	// do_tdh_mng_rd(TD_0, LP_2);
	// setup_and_do_tdcal(TDG_MR_RTMR_EXTEND, LP_0);
	// setup_and_do_tdcal(TDG_VP_RD, LP_0);
	// setup_and_do_tdcal(TDG_VP_CPUIDVE_SET, LP_0);
	// setup_and_do_tdcal(TDG_VP_VEINFO_GET, LP_0);
	// setup_and_do_tdcal(TDG_VP_INFO, LP_0);

	// setup_and_do_seamcall(TDH_MEM_WR, LP_2);
	// setup_and_do_seamcall(TDH_SYS_RD, LP_2);

	LOG("RCX: %lx\n", get_saved_register_value(RCX));
	LOG("RDX: %lx\n", get_saved_register_value(RDX));
	LOG("R8: %lx\n", get_saved_register_value(R8));
	LOG("R9: %lx\n", get_saved_register_value(R9));
	LOG("R10: %lx\n", get_saved_register_value(R10));
	LOG("R11: %lx\n", get_saved_register_value(R11));

	exit(0);

	// ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + 0x3581d; //tdx_tdexit_entry_point + 1 ins
	// set_debug_bp(dr_adr, DEBUG_DR1, DB_CONDITION_INS_EXEC, DB_LENGTH_1_BYTE);

	// setup_and_do_tdcal(TDG_VP_VMCALL, LP_0);

	// LOG("RDX: %lx\n", get_saved_register_value(RDX));
	// exit(0);

/*ffull test 5*/
	// com->td_owner_for_next_tdxcall = TD_0;
	
	// setup_and_do_tdcal(TDG_VP_WR, LP_0);
	// LOG("RDX: %lx\n", get_saved_register_value(RDX));
	// LOG("R8: %lx\n", get_saved_register_value(R8));
	// exit(0);

	// setup_and_do_tdcal(TDG_VM_RD, LP_0);
	// LOG("RDX: %lx\n", get_saved_register_value(RDX));
	// LOG("R8: %lx\n", get_saved_register_value(R8));

	// exit(0);

	// com->sreq.tdxcall_args.expected_field_val = get_saved_register_value(R8);

	// // ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + 0x13950; //tdg_vm_wr
	// ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + 0x3581d; //tdx_tdexit_entry_point + 1 ins
	// set_debug_bp(dr_adr, DEBUG_DR1, DB_CONDITION_INS_EXEC, DB_LENGTH_1_BYTE);

	// setup_and_do_tdcal(TDG_VM_WR, LP_0);
	// LOG("R8: %lx\n", get_saved_register_value(R8));

	// exit(0);

/*FFULL TEST 4*/
	// com->td_owner_for_next_tdxcall = TD_0;
	
	// // ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + 0x13a70; //tdg_vm_rd
	// // set_debug_bp(dr_adr, DEBUG_DR1, DB_CONDITION_INS_EXEC, DB_LENGTH_1_BYTE);

	// setup_and_do_tdcal(TDG_VM_RD, LP_0);
	// LOG("RDX: %lx\n", get_saved_register_value(RDX));
	// LOG("R8: %lx\n", get_saved_register_value(R8));

	// exit(0);

/*ffull test 3*/

	// com->td_owner_for_next_tdxcall = TD_0;
	
	// // ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + 0x12950; // tdg_sys_rd
	// // set_debug_bp(dr_adr, DEBUG_DR1, DB_CONDITION_INS_EXEC, DB_LENGTH_1_BYTE);

	// setup_and_do_tdcal(TDG_SYS_RD, LP_0);
	// LOG("RDX: %lx\n", get_saved_register_value(RDX));
	// LOG("R8: %lx\n", get_saved_register_value(R8));

	// exit(0);


/*faithful test 1*/

	// setup_and_do_seamcall(TDH_SYS_RD, LP_2);
	// setup_and_do_tdcal(TDG_SYS_RDALL, LP_2);
	// LOG("RDX: %lx\n", get_saved_register_value(RDX));
	// LOG("R8: %lx\n", get_saved_register_value(R8));
	// exit(0);

	// com->td_owner_for_next_tdxcall = TD_0;

	// // ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + 0xa650; //md_check_element_and_get_entry
	// ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + 0x27d80; //tdh_mng_rd
	// set_debug_bp(dr_adr, DEBUG_DR1, DB_CONDITION_INS_EXEC, DB_LENGTH_1_BYTE);

	// setup_and_do_seamcall(TDH_MNG_RD, LP_2);
	// // // LOG("RCX : %lx\n", get_saved_register_value(RCX));
	// LOG("RDX: %lx\n", get_saved_register_value(RDX));
	// LOG("R8: %lx\n", get_saved_register_value(R8));
	// // // LOG("com->td[td_id].tdcs_eptp_root: 0x%lx\n", com->td[TD_0].tdcs_eptp_root);
	// exit(0);
//----------------------------------

// /*faithful test 1.1*/

// 	com->td_owner_for_next_tdxcall = TD_0;

// 	// ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + 0x27d80; 
// 	// set_debug_bp(dr_adr, DEBUG_DR1, DB_CONDITION_INS_EXEC, DB_LENGTH_1_BYTE);

// 	setup_and_do_seamcall(TDH_MNG_WR, LP_2);
// 	// LOG("RCX : %lx\n", get_saved_register_value(RCX));
// 	LOG("RDX: %lx\n", get_saved_register_value(RDX));
// 	LOG("R8: %lx\n", get_saved_register_value(R8));
// 	// LOG("com->td[td_id].tdcs_eptp_root: 0x%lx\n", com->td[TD_0].tdcs_eptp_root);
// 	exit(0);
// //----------------------------------

/*faithful test 2*/
	com->td_owner_for_next_tdxcall = TD_0;

	// ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + 0x223b0; 
	// set_debug_bp(dr_adr, DEBUG_DR1, DB_CONDITION_INS_EXEC, DB_LENGTH_1_BYTE);

	// setup_and_do_seamcall(TDH_MEM_WR, LP_2);
	// LOG("RDX : %lx\n", get_saved_register_value(RCX));
	// LOG("RDX: %lx\n", get_saved_register_value(RDX));
	// LOG("R8: %lx\n", get_saved_register_value(R8));

	setup_and_do_seamcall(TDH_MEM_RD, LP_3);
	LOG("RDX : %lx\n", get_saved_register_value(RCX));
	LOG("RDX: %lx\n", get_saved_register_value(RDX));
	LOG("R8: %lx\n", get_saved_register_value(R8));

	exit(0);

//----------------------------------



// //------------------case 2-revised
// // add_a_new_sept_custom(cur_td, LP_3, SEPT_LVL_1, gpa);
// com->sreq.khole_state_seam_va = com->lp_khole_state[LP_0].khole_state_seam_va;


// ulong dr_adr1 = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + map_pa;
// set_debug_bp(dr_adr1, DEBUG_DR0, DB_CONDITION_INS_EXEC, DB_LENGTH_1_BYTE);


// com->td_mem.next_td_page_gpa = gpa;
// block_persistant_khole_mappings(LP_2);
// setup_and_do_seamcall(TDH_MEM_PAGE_AUG ,LP_2);


// exit(0);
// //case 2 rev-----------------------------


	// exit(0);

	/*IMPORTANT: CALL block_persistant_khole_mappings() BEFORE EACH SEAMCALL
	SET "com->td_owner_for_next_tdxcall" from now on. It is the TD context for each TDX call.*/
	// start_se(); /*start SE at Mod entry*/


	// ulong cur_td = TD_0;
	// ulong gpa = 0;
	// gpa = (1UL << 19);

	// // add_a_new_sept_custom(cur_td, LP_2, SEPT_LVL_4, gpa);
	// // add_a_new_sept_custom(cur_td, LP_2, SEPT_LVL_3, gpa);
	// // add_a_new_sept_custom(cur_td, LP_2, SEPT_LVL_2, gpa);

// if(0){
	// add_a_new_sept_custom(cur_td, LP_2, SEPT_LVL_1, gpa);

	// com->td_mem.next_td_page_gpa = gpa;
	// // block_persistant_khole_mappings(LP_2);
	// setup_and_do_seamcall(TDH_MEM_PAGE_AUG ,LP_2);
// }


	// exit(0);
		
//----------SERVER test start-----------
// 	LOG("\n\n-############################server test start\n\n");
// 	// add_a_new_sept_custom(TD_0, LP_2, SEPT_LVL_3, 0x0); //already avail
// 	// add_a_new_sept_custom(TD_0, LP_2, SEPT_LVL_2, 0xc0000000);

// 	// add_a_new_sept_custom(TD_0, LP_2, SEPT_LVL_1, 0xffc00000);
// 	add_a_new_sept_custom(TD_0, LP_2, SEPT_LVL_1, 0xffe00000);
// 	// add_a_new_sept_custom(TD_0, LP_2, SEPT_LVL_2, 0x0);  //already avail
// 	add_a_new_sept_custom(TD_0, LP_2, SEPT_LVL_1, 0x800000);

// 	ulong sept_rd_lvl = SEPT_LVL_4;
// 	ulong sept_rd_gpa = 0x0;
// 	LOG("sept_rd level: %d gpa:0x%lx\n", sept_rd_lvl, sept_rd_gpa);
// 	tdh_sept_rd(TD_0, LP_2, sept_rd_lvl, sept_rd_gpa);

// 	sept_rd_lvl = SEPT_LVL_3;
// 	sept_rd_gpa = 0;
// 	LOG("sept_rd level: %d gpa:0x%lx\n", sept_rd_lvl, sept_rd_gpa);
// 	tdh_sept_rd(TD_0, LP_2, sept_rd_lvl, sept_rd_gpa);

// 	sept_rd_lvl = SEPT_LVL_2;
// 	sept_rd_gpa = 0xc0000000;
// 	LOG("sept_rd level: %d gpa:0x%lx\n", sept_rd_lvl, sept_rd_gpa);
// 	tdh_sept_rd(TD_0, LP_2, sept_rd_lvl, sept_rd_gpa);

// 	sept_rd_lvl = SEPT_LVL_1;
// 	sept_rd_gpa = 0xffc00000;
// 	LOG("sept_rd level: %d gpa:0x%lx\n", sept_rd_lvl, sept_rd_gpa);
// 	tdh_sept_rd(TD_0, LP_2, sept_rd_lvl, sept_rd_gpa);

// 	sept_rd_lvl = SEPT_LVL_1;
// 	sept_rd_gpa = 0xffe00000;
// 	LOG("sept_rd level: %d gpa:0x%lx\n", sept_rd_lvl, sept_rd_gpa);
// 	tdh_sept_rd(TD_0, LP_2, sept_rd_lvl, sept_rd_gpa);

// 	sept_rd_lvl = SEPT_LVL_2;
// 	sept_rd_gpa = 0;
// 	LOG("sept_rd level: %d gpa:0x%lx\n", sept_rd_lvl, sept_rd_gpa);
// 	tdh_sept_rd(TD_0, LP_2, sept_rd_lvl, sept_rd_gpa);

// 	sept_rd_lvl = SEPT_LVL_1;
// 	sept_rd_gpa = 0x800000;
// 	LOG("sept_rd level: %d gpa:0x%lx\n", sept_rd_lvl, sept_rd_gpa);
// 	tdh_sept_rd(TD_0, LP_2, sept_rd_lvl, sept_rd_gpa);

// 	sept_rd_lvl = SEPT_LVL_0;
// 	sept_rd_gpa = 0;
// 	LOG("sept_rd level: %d gpa:0x%lx\n", sept_rd_lvl, sept_rd_gpa);
// 	tdh_sept_rd(TD_0, LP_2, sept_rd_lvl, sept_rd_gpa);

// 	// com->td[TD_0].next_4k_pg_gpa_to_add = 0xffc00000;
// 	// int pt_index = 0;
// 	// while(pt_index < 512){
// 	// 	add_a_new_page_custom(TD_0, LP_2);
// 	// 	pt_index++;
// 	// }


// 	LOG("\n###Rreading the entire PD--------------------------------------------\n");
// 	int pd_idx = 0;
// 	while(pd_idx < 512){
// 		sept_rd_lvl = SEPT_LVL_1;
// 		sept_rd_gpa = (3UL << 30) | (pd_idx << 21);
// 		LOG("\n##Read pd index: %d sept_rd level: %d gpa:0x%lx\n", pd_idx, sept_rd_lvl, sept_rd_gpa);
// 		tdh_sept_rd(TD_0, LP_2, sept_rd_lvl, sept_rd_gpa);

// 		pd_idx++;
// 	}

// 	LOG("\n###Rreading the entire PT--------------------------------------------\n");
// 	int pt_idx = 0;
// 	while(pt_idx < 512){
// 		sept_rd_lvl = SEPT_LVL_0;
// 		sept_rd_gpa = 0xffc00000 | (pt_idx << 12);
// 		LOG("\n##Read pt index: %d sept_rd level: %d gpa:0x%lx\n", pt_idx, sept_rd_lvl, sept_rd_gpa);
// 		tdh_sept_rd(TD_0, LP_2, sept_rd_lvl, sept_rd_gpa);

// 		pt_idx++;
// 	}


// 	exit(0);
// //----------SERVER test end-----------


	// /*setup a instruction fetch DR at TD call handler start*/
	// ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + get_offset(OFFSET_TYPE_TDG_MEM_PAGE_ATTR_RD_LEAF);
	// LOG("dr adr: 0x%lx\n", dr_adr); 
	// set_debug_bp(dr_adr, DEBUG_DR0, DB_CONDITION_INS_EXEC, DB_LENGTH_1_BYTE);

	// ulong tdr_keyid_adr = vm->mem2 + com->td[TD_0].tdr + 192;
	// ulong dr_adr = tdr_keyid_adr;
	// LOG("dr adr: 0x%lx\n", dr_adr); 
	// set_debug_bp(dr_adr, DEBUG_DR0, DB_CONDITION_DATA_RDWR, DB_LENGTH_2_BYTE);

	// com->sreq.cur_td_local_data = com->seamcall_vmcs[LP_0].gsbase;
	// LOG("com->sreq.cur_td_local_data 0x%lx\n", com->sreq.cur_td_local_data);
	// com->sreq.cur_td_tdr_adr_in_local_data = com->sreq.cur_td_local_data + 0x126;
	// LOG("com->sreq.cur_td_tdr_adr_in_local_data 0x%lx\n", com->sreq.cur_td_tdr_adr_in_local_data);

	// ulong lp_local_data_va = vm->mem + (SEAM_RANGE_START_PA + _4K*(1 + EFFECTIVE_NUM_ADDRESSIBLE_LPS + (TDX_MODULE_HANDOFF_DATA_PAGES + 1) + LP_0*(TDX_MODULE_TLS_PAGES + 1)));
	// ulong tdx_module_cr3 = get_region_base_pa(RGN_PML4);
	// LOG("tdx_module_cr3: 0x%lx\n", tdx_module_cr3);
	// ulong lp_local_data_va = vm->mem + va_to_pa(tdx_module_cr3, com->sreq.cur_td_local_data);
	// ulong tdr_adr = *(ulong *)(lp_local_data_va + 0x126);
	// LOG("lp_local_data_va: 0x%lx\n", lp_local_data_va);
	// LOG("tdr_adr: 0x%lx\n", tdr_adr);

	// exit(0);

	// ulong dr_adr = SEAM_AGENT_CODE + 0x600;
	// LOG("dr adr: 0x%lx\n", dr_adr); 
	// set_debug_bp(dr_adr, DEBUG_DR0, DB_CONDITION_INS_EXEC, DB_LENGTH_1_BYTE);

	// ulong dr_adr = 0xffffa0020005e100;
	// LOG("dr adr: 0x%lx\n", dr_adr); 
	// set_debug_bp(dr_adr, DEBUG_DR0, DB_CONDITION_DATA_RDWR, DB_LENGTH_2_BYTE);

	// start_se();

	//-----------------------------
	tdxmod_keyhole_state_t *khs = (tdxmod_keyhole_state_t *)com->lp_khole_state[LP_0].khole_state;
	LOG("total_ref_count: %d\n", khs->total_ref_count);

	int idx = 0;
	while(idx < 128){
		LOG("mapped pa: 0x%lx ref:%lu\n", khs->keyhole_array[idx].mapped_pa, khs->keyhole_array[idx].ref_count);
		idx++;
	}
	// exit(0);

	//-----------------------------

	com->sreq.validate_hkid = 1;
	ulong tdr_va_seam = get_tdr_va_of_running_td(0, 0);
	LOG("tdr_va_seam:0x%lx\n", tdr_va_seam);
	ulong hkid_va_seam_in_tdr = tdr_va_seam + 256;
	// ulong tdr_va_manager = vm->mem2 + com->td[TD_0].tdr - _1G;
	// int hkid_in_tdr = *(uint16_t *)(tdr_va_manager + 256);
	// LOG("hkid_in_tdr: %d\n", hkid_in_tdr);
	// com->sreq.dr0_bp_adr = hkid_va_seam_in_tdr;
	// ulong dr_adr = hkid_va_seam_in_tdr;
	// LOG("dr adr: 0x%lx\n", dr_adr); 
	// set_debug_bp(dr_adr, DEBUG_DR3, DB_CONDITION_DATA_RDWR, DB_LENGTH_2_BYTE);

	// ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + 0x8dc0; //secure_ept_walk
	// ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + 0x9b30; //map_pa
	// ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + 0x95f0; //map_pa_with_mem_type()
	// set_debug_bp(dr_adr, DEBUG_DR0, DB_CONDITION_INS_EXEC, DB_LENGTH_1_BYTE);

	// com->sreq.targt_fn_adr = com->sreq.mod_code_rgn_start + 0x9b30;
	fill_khole_refs(LP_0);

	com->sreq.khole_state_seam_va = com->lp_khole_state[LP_0].khole_state_seam_va;
	LOG("com->sreq.khole_state_seam_va: 0x%lx\n", com->sreq.khole_state_seam_va); 
	// exit(0);

	
	// com->sreq.tdx_call_handler_start = get_offset(OFFSET_TYPE_TDG_MEM_PAGE_ATTR_RD_LEAF);
	com->td_owner_for_next_tdxcall = TD_0;
	com->sreq.td_owner_for_next_tdxcall = TD_0;

	com->td_mem.next_td_page_gpa = gpa;
	setup_and_do_seamcall(TDH_MEM_PAGE_AUG ,LP_2);
	setup_and_do_tdcal(TDG_MEM_PAGE_ACCEPT, LP_0);
	LOG("com1\n");
	com->td_mem.next_td_page_gpa = gpa | (1 << 12);





	setup_and_do_seamcall(TDH_MEM_PAGE_AUG ,LP_2);
	// exit(0);



	setup_and_do_tdcal(TDG_MEM_PAGE_ACCEPT, LP_0);


	com->sreq.idx = 1;
	com->sreq.khole_state_seam_va = com->lp_khole_state[LP_0].khole_state_seam_va;
	start_se();
	com->is_last_api_call = 1;
	setup_and_do_tdcal(TDG_MEM_PAGE_ATTR_WR, LP_0);
	// tdh_sept_rd(TD_0, LP_2, 4, 0);
	exit(0);

	// setup_and_do_tdcal(TDG_MEM_PAGE_ATTR_RD, LP_0);

	// com->is_last_api_call = 1;
	// start_se();
	// setup_and_do_tdcal(TDG_VP_INVEPT, LP_0);
	// exit(0);
	
	// setup_and_do_tdcal(TDG_VM_RD, LP_0);
	// exit(0);
	// setup_and_do_tdcal(TDG_SYS_RDALL, LP_0);
// 
	// com->td_mem.next_td_page_gpa = gpa;
	// setup_and_do_tdcal(TDG_SYS_RD, LP_0);

	// com->td_mem.next_td_page_gpa = gpa;
	// setup_and_do_tdcal(TDG_MR_REPORT, LP_0);

	// com->is_last_api_call = 1;
	// start_se();
	// setup_and_do_tdcal(TDG_MEM_PAGE_ACCEPT, LP_0);
	

	exit(0);


	// com->is_last_api_call = 1;
	// start_se();
	// setup_and_do_tdcal(TDG_MEM_PAGE_ATTR_WR, LP_0);

	// // exit(0);
	// setup_and_do_tdcal(TDG_MEM_PAGE_ATTR_WR, LP_0);
	// com->sreq.khole_state_seam_va = com->lp_khole_state[lp].khole_state_seam_va;



	//--------------------------



	// exit(0);

	/*add a new sept page*/
	//add_a_new_sept(TD_1, com->td[TD_1].vcpu_associated_lp, 1 /*level*/);
	// add_a_new_page(TD_1, com->td[TD_1].vcpu_associated_lp);

	// ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + 0x1b440; 
	// set_debug_bp(dr_adr, DEBUG_DR0, DB_CONDITION_INS_EXEC, DB_LENGTH_1_BYTE);
	// remove_debug_bp(DEBUG_DR0);
	// com->single_step_on = true;
	// start_se();
	// add_a_new_sept(TD_0, LP_2, SEPT_LVL_1);

	// ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + get_offset(OFFSET_TYPE_TDH_MEM_PAGE_AUG_LEAF);
	// set_debug_bp(dr_adr, DEBUG_DR0, DB_CONDITION_INS_EXEC, DB_LENGTH_1_BYTE);
	// add_a_new_page(TD_0, LP_2);



	/*vmm-agent for case-study-I*/
	// ulong dr_adr;
	// dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + get_offset(OFFSET_TYPE_TDH_MEM_SEPT_ADD_LEAF);
	// set_debug_bp(dr_adr, DEBUG_DR0, DB_CONDITION_INS_EXEC, DB_LENGTH_1_BYTE);
	// LOG("data bp adr: 0x%lx\n", dr_adr);
	/*Ins exec BP is triggered before ins exec, so rip = dr_bp_adr*/

	// dr_adr = com->seamcall_vmcs[LP_2].gsbase;
	// LOG("data bp adr: 0x%lx\n", dr_adr);
	// set_debug_bp(dr_adr, DEBUG_DR1, DB_CONDITION_DATA_RDWR, DB_LENGTH_8_BYTE);
	/*Data access BP is triggered after ins exec, so rip = next ins*/
	
	/*IMPORTANT: CALL block_persistant_khole_mappings() BEFORE EACH SEAMCALL*/
}

