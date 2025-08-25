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

uint8_t sym_buffer[4096];
#define PTE_TO_PA_MASK		0xfffffff000UL
#define PG_SZ_4K            0x1000UL
// #define LINEAR_BASE_KEYHOLE_REGION          0xFFFF800200000000
// #define PSEAMLDR_RDRAND_VAL                 0x2000
// #define ASLR_MASK                           0x7FFC
// #define TDX_MODULE_ADR_MASK                 (ulong)(PSEAMLDR_RDRAND_VAL & ASLR_MASK) << 32

ulong td_pml5_seam_va_1 = 0;
ulong td_pml5_seam_va_2 = 0;
ulong td_pml5_seam_va = 0;
bool is_epte_defined = false;

ulong last_path = 0;

CAnalyze::CAnalyze(VMState *VM, EveMeta* meta) {
    m_VM = VM;
    execData = new ExecData;
    execData->insn_count = 0; 
    execData->is_next_ins_seamret = false;
    execData->current_path = 0;
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
    execProfile->startIncCount = 358;
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

    if(execData->insn_count == 2){
        std::cout << "gs_base : " << std::hex << m_regs->gs_base << std::endl;
        ulong rcx_adr = m_regs->gs_base + 0x8;
        ulong seed_gpa = *(uint64_t *)(rcx_adr);
        ulong gpa_B1 = (seed_gpa & 0xff00UL) >> 8;
        ulong gpa_B2 = (seed_gpa & 0xff0000UL) >> 16;
        ulong gpa_B3 = (seed_gpa & 0xff000000UL) >> 24;
        ulong gpa_B4_7 = (seed_gpa & 0xffffffff00000000UL) >> 32;
        
        std::cout << "gpa: " << std::dec << seed_gpa << std::endl;
        std::cout << "gpa_B1: " << std::dec << gpa_B1 << std::endl;
        std::cout << "gpa_B2: " << std::dec << gpa_B2 << std::endl;
        std::cout << "gpa_B3: " << std::dec << gpa_B3 << std::endl;
        std::cout << "gpa_B4_7: " << std::dec << gpa_B4_7 << std::endl;

        m_VM->createSYMemObject(rcx_adr + 1, 1, 1, 1, gpa_B1, "gpa_B1");
        m_VM->createSYMemObject(rcx_adr + 2, 1, 1, 1, gpa_B2, "gpa_B2");
        m_VM->createSYMemObject(rcx_adr + 3, 1, 1, 1, gpa_B3, "gpa_B3");
        m_VM->createSYMemObject(rcx_adr + 4, 4, 1, 1, gpa_B4_7, "gpa_B4_7");

    }

    if(execData->current_path > last_path){

        td_pml5_seam_va_1 = 0;
        td_pml5_seam_va_2 = 0;
        td_pml5_seam_va = 0;
        is_epte_defined = false;
        last_path = execData->current_path;
    }

    if(execData->insn_count > 1824){
        
        ulong sp_adr = 0xffffa0020015f008;
        MemValue mv2 ;
        mv2.addr = sp_adr;
        mv2.size = 8 ;
        mv2.isSymList = false ;
        bool res = m_VM->readMemory (mv2);
        assert(res);
        
        std::cout << "sp_adr_val: 0x" << std::hex << mv2.i64 << std::endl;
    }

    if((td_pml5_seam_va_2 != 0) && !is_epte_defined){
        ulong epte_seed = 0x80e0000000000000;
        td_pml5_seam_va = td_pml5_seam_va_2;
        std::cout << "considered td_pml5_seam_va: 0x" << td_pml5_seam_va << std::endl;
        m_VM->createSYMemObject(td_pml5_seam_va + 0x8, 8, 1, 1, epte_seed, "epte");
        is_epte_defined = true;
    }

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
        std::cout << "\n##End of cur path (imposbl) ..." << std::endl;
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
    // if(m_regs->regs.rip == 0xffffa00000035bac){
            
    //         std::cout << "\nEnd of SE ..." << std::endl;
    //         std::cout << "\n\npath constraints : " << std::endl;
    //         a_EFlagsMgr->PrintConstraint();
    //         std::cout << "\n" << std::endl;
    // }
 
    // if(m_regs->regs.rip == 0xffffa0000003738d){
    //     scall_id = *(uint64_t *)m_regs->gs_base;
    //     std::cout << "SEAMCALL: " << std::dec << scall_id << " starting";
    //     std::cout << "-----------------------------------------------" << std::endl;

    //     // if(scall_id == 35){
    //     //     m_VM->createSYMemObject(m_regs->gs_base, 8, 1, 1, scall_id, "seamcall_id");
    //     //     is_se = 1;
    //     // }
    // }

    // if(m_regs->regs.rip == 0xffffa000000374dc){
    //     std::cout << "SEAMRET: "<< (m_regs->regs.rax == 0 ? "SUCCESS" : "FAIL") << " ins count :" << std::dec << execData->insn_count;
    //     std::cout << "-----------------------------------------------" << std::endl;
    //     // execData->insn_count = 0;

    //     if(is_se){
    //         std::cout << "\nEnd of SE ..." << std::endl;
    //         std::cout << "\n\npath constraints : " << std::endl;
    //         a_EFlagsMgr->PrintConstraint();
    //         std::cout << "\n" << std::endl;
    //         // exit(0);
    //     }
        
    // }
        // std::cout << "rax at 0xffffa000000022a2: " << std::hex << m_regs->regs.rax << std::endl;

        // ulong *pt = (ulong *)0x0000200100000000;
        // int i = 0;
        // while(i < 12){
        //     std::cout << pt[i] << std::endl;
        //     i++;
        // }
        // exit(0);
    
    // char * sret = (char *)m_regs->regs.rip;
    /*.byte 0x66, 0x0F, 0x01, 0xCD*/
    // if((sret[0] == 0x66) && (sret[1] == 0x0f) && (sret[2] == 0x01) && (sret[3] == 0xcd)){
    //     std::cout << "SEAMRET_INS" << std::endl;
    //     exit(0);
    // }
    
    // if(execData->insn_count == 468){
    //     std::cout << "\nEnd of SE ..." << std::endl;
    //     std::cout << "\n\npath constraints : " << std::endl;
    //     a_EFlagsMgr->PrintConstraint();
    //     std::cout << "\n" << std::endl;
    //     return -1;
    // }
    
    // if(m_regs->regs.rip == 0x0xffffa00000003029){
        
    //     bool res ;
    //     RegValue R ;
    //     R.indx = x86_64::rdi ;
    //     R.size = 8 ;
    //     m->VM->readRegister(R) ;
    //     assert(res);

        
    // }

    return 0;

}

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
                if(pa == sreq->td_pml5_pa){
                    /*in SEPT add, the ePML5 is mapped twice. 
                    1: gets mapped in to static keyhole region when 6 contiguous pages in TDCX are mapped
                    2.: gets mapped as part of secure_ept_walk.
                    We do our subsequent checks to see if a given write is on ePML5 page based on the last map returned la
                    As of now we assume that after the 2nd mapping, the first mapping is not used by TDX module to write 
                    on to ePML5. Need to check if this is valid. OR use both mappings for subsequent checks.
                    Checked. ok.*/
                    if(td_pml5_seam_va_1 == 0)
                        td_pml5_seam_va_1 = seam_va;
                    else {
                        td_pml5_seam_va_2 = seam_va;
                    }
                    std::cout << "td_pml5_seam_va: 0x" << seam_va << std::endl;
                }
            }
            if((adr & ~(0xfffUL)) == td_pml5_seam_va_1){
                std::cout << "write to pml5 la-1" << std::endl;
            }
            if((adr & ~(0xfffUL)) == td_pml5_seam_va_2){
                std::cout << "write to pml5 la-2" << std::endl;
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
        m_VM->createSYRegObject(x86_64::rcx, 8, 1, 1, sept_level_and_gpa, "gpa_lv");*/
        // m_VM->createSYRegObject(x86_64::cl, 1, 1, 1, 1, "lvl");

        /*sept_add, KRover starts at sept_add()*/
        // ulong seamcall_version = m_regs->regs.rcx;
        // std::cout << "seamcall_version: " << std::hex << seamcall_version << std::endl;
        // m_VM->createSYRegObject(x86_64::rcx, 8, 1, 1, seamcall_version, "version");

        /*sept_add, KRover starts at sept_add()*/
        // ulong sept_level_and_gpa = m_regs->regs.rdi;
        // std::cout << "sept_level_and_gpa: " << std::hex << sept_level_and_gpa << std::endl;
        // m_VM->createSYRegObject(x86_64::rdi, 8, 1, 1, sept_level_and_gpa, "gpa_lv");


        // setExecProfileSinglePath();
        setExecProfileMultiPath();
        // /*symbolize the data in the symbolic buffer*/
        ulong sym_buf1 = 0xffffa00000056270;
        MemValue mv ;
        mv.addr = sym_buf1;
        mv.size = 8 ;
        mv.isSymList = false ;
        bool res = m_VM->readMemory (mv);
        assert(res);
        ulong sym_buf1_seed = mv.i64;
        std::cout << "sym_buf1_seed: 0x" << std::hex << sym_buf1_seed << std::endl;
        m_VM->createSYMemObject(sym_buf1, 8, 1, 1, sym_buf1_seed, "sym_buf1");

        
        ulong sym_buf2 = 0xffffa00000055700;
        MemValue mv2 ;
        mv2.addr = sym_buf2;
        mv2.size = 8 ;
        mv2.isSymList = false ;
        res = m_VM->readMemory (mv2);
        assert(res);
        ulong sym_buf2_seed = mv2.i64;
        std::cout << "sym_buf2_seed: 0x" << std::hex << sym_buf2_seed << std::endl;
        m_VM->createSYMemObject(sym_buf2, 8, 1, 1, sym_buf2_seed, "sym_buf2");


        // ulong epte_seed = 0x80e0000000000000;
        // *(ulong *)sym_buffer = epte_seed;
        // // m_VM->createSYMemObject((ulong)sym_buffer + 0x8, 8, 1, 1, epte_seed, "epte");

    }
    dispatch_count++;

    return m_Thin->processFunction(addr);
}













