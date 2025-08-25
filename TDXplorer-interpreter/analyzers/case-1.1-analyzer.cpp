#include "Analyze.h"
#include <asm/ptrace.h>
#include "VMState.h"
#include "HistoryTree.h"
#include "thinctrl.h"
#include "common_idata.h"
// #include "com.h" /*from seam manager*/
#include "seam.h"

struct iData *tdx_sp_ins;

using namespace std;
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;

extern bool endCurrentPath;
extern PATH_END_RSN endCurrentPathReason;
extern struct servReq *sreq;

struct MacReg*  m_regs;
std::map<unsigned long, anaMemBlk*> ana_memblk_map;

int             dispatch_count = 0;
unsigned long   scall_handler_address = 0x0;
int is_se = 0;

CAnalyze::CAnalyze(VMState *VM, EveMeta* meta) {
    m_VM = VM;
    execData = new ExecData;
    execData->insn_count = 0; 
    execData->is_next_ins_seamret = false;
    execProfile = new ExecProfile;
    execProfile->executionMode = 0; /*DEFAULT, single pat hseeded*/
    execProfile->terminationMode = 0; /*DEFAULT, terminate at stack balance, function return*/
    execProfile->terminate_ins_count = 0;
}

CAnalyze::~CAnalyze() {
}

void CAnalyze::setExecProfileSinglePath(){
        execProfile->executionMode = EXEC_MD_SINGLE_PATH_SEDED;
        execProfile->terminationMode = END_AT_ANA_REQUEST;
        execProfile->startIncCount = 0;
}

void CAnalyze::setExecProfileMultiPath(){
    std::cout << "setExecProfileMultiPath" << std::endl;
    execProfile->executionMode = EXEC_MD_START_PATH_SEARCH_AT_INS_COUNT;
    // execProfile->startRip = rip;
    execProfile->startIncCount = 0;
    // execProfile->terminationMode = END_AT_GIVEN_INS_COUNT;
    // execProfile->terminate_ins_count = 100;
}   

void CAnalyze::setupScallAnalysis(){

    bool ret = m_AnaCtrl->setupKernSymMap();
    if(!ret)
        assert(0);
    scall_handler_address = m_AnaCtrl->kernel_symbol_lookup("__x64_sys_getpriority");
    if(!scall_handler_address)
        assert(0);
}


int CAnalyze::onEndOfInsExec(){ //analysis at the end of each instruction
    uint64_t scall_id;

    std::cout << "rip: 0x" << std::hex << m_regs->regs.rip << std::endl;
    if(*(uint8_t *)m_regs->regs.rip == 0xcc) { /*if next rip is int3*/
        ulong int3_adr = m_regs->regs.rip;
        uint32_t ins_seamret = 0xcd010fcc;
        if(*(uint32_t *)int3_adr == ins_seamret){ /*if next sp ins is seamret*/
            std::cout << ":) ------------------------------- SEAMRET: "<< (m_regs->regs.rax == 0 ? "SUCCESS" : "FAIL") << " : ins count :";
            std::cout << std::dec << execData->insn_count << std::endl;
            if(execProfile->executionMode != EXEC_MD_SINGLE_PATH_SEDED){
                execData->is_next_ins_seamret = true; /*To notify thinctrl to end the current path*/
                if(m_regs->regs.rax == 0){
                    endCurrentPathReason = PATH_SEAMRET_PASS;
                }
                else{
                    endCurrentPathReason = PATH_SEAMRET_FAIL;
                }
                std::cout << "\nEnd of cur path ..." << std::endl;
                std::cout << "\npath constraints : " << std::endl;
                a_EFlagsMgr->PrintConstraint();
                std::cout << std::endl;
            }
            else { /*if in seeded mode*/
                std::cout << "\nEnd of SE ..." << std::endl;
                std::cout << "\npath constraints : " << std::endl;
                a_EFlagsMgr->PrintConstraint();
                std::cout << "\nKRover END ..." << std::endl;
                exit(0);
            }
        }
    }
    else if(endCurrentPath){
        std::cout << "\n##End of cur path (imposbl or ud2) ..." << std::endl;
        std::cout << "\npath constraints : " << std::endl;
        a_EFlagsMgr->PrintConstraint();
        std::cout << "\nKRover END ..." << std::endl;
        // exit(0);
    }

    int i = 0;
    ulong adr;
    for(i = 0; i < 2; i++){
        adr = execData->opDetails[i].opmemac.memAddress;
        if(execData->opDetails[i].opmemac.memrdwr){
            if((adr >= sreq->khole_start) && (adr < (sreq->khole_start + sreq->khole_size))){
                std::cout << "access keyhole: 0x" << std::hex << adr << std::endl;
            }

        }
    }

    return 0;

}

#define PTE_TO_PA_MASK		0xfffffff000UL
#define PG_SZ_4K            0x1000UL

ulong td_pml5_seam_va_1 = 0;
ulong td_pml5_seam_va_2 = 0;
ulong td_epml4_seam_va = 0;
ulong td_epdpt_seam_va = 0;
ulong td_epd_seam_va = 0;
ulong td_ept_seam_va = 0;

int CAnalyze::onBeforeCIESIE(){

    ulong eff_rip = m_regs->regs.rip - execData->win->in->size();

    int i = 0;
    ulong adr, pte, pa, seam_va;

    ulong current_lp = 2;
    ulong lp_keyhole_va_base = sreq->khole_start_seam_va + current_lp*(PG_SZ_4K * 128);
	ulong lp_khole_edit_base_va = sreq->khole_edit_start_seam_va + current_lp*8*128;
    std::cout << "lp_keyhole_va_base: 0x " << std::hex << lp_keyhole_va_base << std::endl;
    std::cout << "lp_khole_edit_base_va: 0x " << std::hex << lp_khole_edit_base_va << std::endl;
    // std::cout << "sreq->khole_start_seam_va: 0x " << std::hex << sreq->khole_start_seam_va << std::endl;
    // std::cout << "sreq->khole_start_seam_va + 1G: 0x " << std::hex << sreq->khole_start_seam_va + (PG_SZ_4K*4096*4096) << std::endl;
    // assert(0);
    for(i = 0; i < 2; i++){

        adr = execData->opDetails[i].opmemac.memAddress;
        if(execData->opDetails[i].opmemac.wrmem){
            if(adr < 0x300000000000){ /*khole edit mapping*/
                std::cout << "khole-edit write: 0x" << std::hex << adr << std::endl;
                if(eff_rip == 0xffffa00000009a9c){
                    pte = m_regs->regs.rdx;
                    std::cout << "pte-x: 0x" << std::hex << pte << std::endl;
                }
                else if(eff_rip == 0xffffa00000009d68){
                    pte = m_regs->regs.rsi;
                    std::cout << "pte-y: 0x" << std::hex << pte << std::endl;
                }
                else{
                    assert(0);
                }
                pa = pte & PTE_TO_PA_MASK;
                seam_va = lp_keyhole_va_base + ((adr - lp_khole_edit_base_va)/8)*(PG_SZ_4K);
                std::cout << "pa: 0x" << std::hex << pa << "\t seam va: 0x" << seam_va << std::endl;
                if(pa == sreq->td_epml4_pa){
                    /*in SEPT add, the ePML5 is mapped twice. 
                    1: gets mapped in to static keyhole region when 6 contiguous pages in TDCX are mapped
                    2.: gets mapped as part of secure_ept_walk.
                    We do our subsequent checks to see if a given write is on ePML5 page based on the last map returned la
                    As of now we assume that after the 2nd mapping, the first mapping is not used by TDX module to write 
                    on to ePML5. Need to check if this is valid. OR use both mappings for subsequent checks.
                    Checked. ok.*/
                    if(td_epml4_seam_va == 0)
                        td_epml4_seam_va = seam_va;

                    std::cout << "td_epml4_seam_va: 0x" << seam_va << std::endl;
                }
            }
            if((adr & ~(0xfffUL)) == td_epml4_seam_va){
                std::cout << "write to epml4 la" << std::endl;
            }
            if((adr >= sreq->khole_start_seam_va) && (adr < (sreq->khole_start_seam_va + (1024*1024*1024)))){
                std::cout << "khole write: 0x" << std::hex << adr << std::endl;
                if((adr < lp_keyhole_va_base) && (adr >= (lp_keyhole_va_base + PG_SZ_4K*128))){
                    std::cout << "khole write, out of LP khole renge" << std::endl;
                    assert(0);
                }
            }
        }

    }

    return 0;
} 

int CAnalyze::analyztsHub(int anaPoint) { //analysis of KRover's SE by analyzer goes through this hub
    std::cout << "at analyztsHub" << std::endl;
    switch(anaPoint){
        case ON_END_OF_INS_EXEC:
        {
            return CAnalyze::onEndOfInsExec();
        }   break;
        case ON_BFR_CIE_OR_SIE:
        {
            return CAnalyze::onBeforeCIESIE();
            break;
        }
        default:
            break;
    }
    return 0;
}

extern struct servReq *sreq;
bool CAnalyze::beginAnalysis(ulong addr) { //Analysis start

    uint64_t scall_id;
    m_regs = (struct MacReg*)m_VM->getPTRegs();
    std::cout << "at beginAnalysis" << std::endl;

    if(dispatch_count == 0){
        // std::cout << "gs_base : " << std::hex << m_regs->gs_base << std::endl;
        // scall_id = *(uint64_t *)m_regs->gs_base;
        // std::cout << "seamcall id: " << std::dec << scall_id << std::endl;
        // m_VM->createSYMemObject(m_regs->gs_base, 8, 1, 1, scall_id, "seamcall_id");

        /*sept_add, KRover starts at seam entry
        ulong sept_level_and_gpa = m_regs->regs.rcx;
        std::cout << "sept_level_and_gpa: " << std::hex << sept_level_and_gpa << std::endl;
        m_VM->createSYRegObject(x86_64::rcx, 8, 1, 1, sept_level_and_gpa, "gpa_lv");
        // m_VM->createSYRegObject(x86_64::cl, 1, 1, 1, 1, "lvl");*/

        /*sept_add, KRover starts at sept_add()*/
        // ulong seamcall_version = m_regs->regs.rcx;
        // std::cout << "seamcall_version: " << std::hex << seamcall_version << std::endl;
        // m_VM->createSYRegObject(x86_64::rcx, 8, 1, 1, seamcall_version, "version");

        /*sept_add, KRover starts at sept_add()*/
        ulong sept_level_and_gpa = m_regs->regs.rdi;
        std::cout << "sept_level_and_gpa: " << std::hex << sept_level_and_gpa << std::endl;
        m_VM->createSYRegObject(x86_64::rdi, 8, 1, 1, sept_level_and_gpa, "gpa_lv");

        // ulong tdr_and_flg = m_regs->regs.rsi;
        // std::cout << "tdr_and_flg: " << std::hex << tdr_and_flg << std::endl;
        // ulong flg = tdr_and_flg & 0x1UL;
        // m_VM->createSYRegObject(x86_64::sil, 1, 1, 1, flg, "flg");

        setExecProfileMultiPath();
        // setExecProfileSinglePath();

    }
    dispatch_count++;

    return m_Thin->processFunction(addr);
}













