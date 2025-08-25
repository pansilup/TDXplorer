#include "Analyze.h"
#include <asm/ptrace.h>
#include "VMState.h"
#include "HistoryTree.h"
#include "thinctrl.h"
#include "common_idata.h"
// #include "com.h" /*from seam manager*/
#include "seam.h"
#include "pageManager.h"

struct iData *tdx_sp_ins;

using namespace std;
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;

extern bool endCurrentPath;
extern PATH_END_RSN endCurrentPathReason;
extern struct servReq *sreq;

struct MacReg*  m_regs;
// std::map<unsigned long, anaMemBlk*> ana_memblk_map;
std::map<ulong, ulong> seam_va_pa_map;
std::map<ulong, ulong> seam_pa_va_map;

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

// ulong td_pml5_seam_va_1 = 0;
// ulong td_pml5_seam_va_2 = 0;
// ulong td_pml5_seam_va = 0;
bool epml5_mapped_once = false;
ulong td_sept_seam_va = 0;
bool is_epte_defined = false;

ulong last_path = 0;
int scall_failed_count = 0; 

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

/*---sanitiy checks and post processing --------------------------------------------------------------------------------START*/
void CAnalyze::doEndOfPathChecks(int scall_status){

    std::cout << "doEndOfPAthChecks ....................." << std::endl;
    std::set<unsigned long> sym_range;
    std::string s_name = "gpa_B4_7";
    
    switch (scall_status)
    {
        case PATH_SEAMRET_FAIL: /*scall fail*/
        {
                
        }break;
        case PATH_SEAMRET_PASS: /*scall success*/
        {
            /*Solving the path constraint iteratively to get the full range of ePTE idx.
            We do not need this as this is a bruite force technique.
            sym_range = a_EFlagsMgr->SolveConstraint(a_EFlagsMgr->m_Constraint, s_name);

            std::cout << "range of ept_idx: ";
            for (unsigned long val: sym_range){
                std::cout << std::hex << ((val >> 16) & 0x1ff) << ", ";
            }
            std::cout << std::endl;*/
        } break;
        default:
            break;
    }
    
    /*Checking for all modified data can tell us which regions have been changed. But since we do not 
    know what those memory objects are, given a modified address we can not reason
    m_Thin->m_PM->checkModifiedData();*/

    /*check sEPT data, symbolic buffer----------*/
    if(td_sept_seam_va != 0){
        std::cout << "checking sEPT page symbolic buffer contents ..." << std::endl;
        int sept_idx = 0;
        bool res;

        MemValue mv2 ;
        mv2.size = 8 ;

        /*read the exact 8 byte block that is expected to be modified*/
        mv2.addr = td_sept_seam_va + 8;
        mv2.bsym = false;
        mv2.isSymList = false;

        res = m_VM->readMemory (mv2);
        assert(res);
        if(mv2.bsym){
            assert(mv2.expr);
            std::cout << "Update expected sEPTE: ";
            mv2.expr->print();
            std::cout << std::endl;
        }
        else{
            std::cout << "Update expected sEPTE: 0x" << std::hex << mv2.i64 << std::endl;
        }

        /*check sEPT data, symbolic buffer*/
        while(sept_idx < 512){
            mv2.bsym = false;
            mv2.addr = td_sept_seam_va + 8*sept_idx;
            // mv2.isSymList = false ;  ???
            res = m_VM->readMemory (mv2);
            assert(res);
            if(mv2.bsym){
                assert(mv2.expr);
                std::cout << "buffer offset: 0x" << std::hex << sept_idx*8; 
                std::cout << " 8 byte block: ";
                mv2.expr->print();
                std::cout << std::endl;
            }
            
            sept_idx +=1;
        }
    }


    // assert(scall_failed_count <= 1);

}
/*---sanitiy checks and post processing ----------------------------------------------------------------------------------END*/

void CAnalyze::endOfPathJobs(int scall_status){ //analysis at the end of each path

        // td_pml5_seam_va_1 = 0;
        // td_pml5_seam_va_2 = 0;
        // td_pml5_seam_va = 0;
        epml5_mapped_once = false;
        td_sept_seam_va = 0;
        is_epte_defined = false;
        last_path = execData->current_path;

        seam_va_pa_map.clear();
        seam_pa_va_map.clear();
}

// bool CAnalyze::validateKHoleMapping(ulong khole_edit_va){

//     ulong lp_khole_edit_base_va = sreq->khole_edit_start_seam_va + sreq->current_lp*8*128;

//     if((khole_edit_va < lp_khole_edit_base_va) || (khole_edit_va) >= (lp_khole_edit_base_va + 128*8)){
//         std::cout << "key hole edit write out off range for current LP !" << std::endl;
//         assert(0);
//     }
// }

// bool CAnalyze::validateKHoleAccess(ulong khole_va){
    
//     ulong lp_keyhole_va_base = sreq->khole_start_seam_va + sreq->current_lp*(PG_SZ_4K * 128);
//     std::cout << "sreq->khole_start_seam_va: 0x" << sreq->khole_start_seam_va << " " << (sreq->khole_start_seam_va + (1024*1024*1024)) << std::endl;
//     std::cout << "(khole_va >= sreq->khole_start_seam_va):" << (khole_va >= sreq->khole_start_seam_va) << std::endl;
//     std::cout << "(khole_va < (sreq->khole_start_seam_va + (1024*1024*1024))):" << (khole_va < (sreq->khole_start_seam_va + (1024*1024*1024))) << std::endl;

//     if((khole_va >= sreq->khole_start_seam_va) && (khole_va < (sreq->khole_start_seam_va + (1024*1024*1024)))){
//         std::cout << "khole write: 0x" << std::hex << khole_va << std::endl;
//         if((khole_va < lp_keyhole_va_base) || (khole_va >= (lp_keyhole_va_base + PG_SZ_4K*128))){
//             std::cout << "khole write, out of LP khole renge" << std::endl;
//             assert(0);
//         }
//     }

// }

ulong CAnalyze::getKholePte(ulong rip){

    ulong pte;

    std::cout << "khe-ins: 0x" << sreq->keyhole_edit_ins_adr[0] << " 0x" << sreq->keyhole_edit_ins_adr[1] << std::endl;
    // assert(0);
    // if(eff_rip == 0xffffa00000009a9c){
    if(rip == sreq->keyhole_edit_ins_adr[0]){
        pte = m_regs->regs.rdx;
        std::cout << "pte-x: 0x" << std::hex << pte << std::endl;
    }
    // else if(eff_rip == 0xffffa00000009d68){
    else if(rip == sreq->keyhole_edit_ins_adr[1]){
        pte = m_regs->regs.rsi;
        std::cout << "pte-y: 0x" << std::hex << pte << std::endl;
    }
    else{
        assert(0);
    }
    return pte;
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

    // if(execData->current_path > last_path){

    //     td_pml5_seam_va_1 = 0;
    //     td_pml5_seam_va_2 = 0;
    //     td_pml5_seam_va = 0;
    //     is_epte_defined = false;
    //     last_path = execData->current_path;
    // }

    // if(execData->insn_count > 1824){
        
    //     ulong sp_adr = 0xffffa0020015f008;
    //     MemValue mv2 ;
    //     mv2.addr = sp_adr;
    //     mv2.size = 8 ;
    //     mv2.isSymList = false ;
    //     bool res = m_VM->readMemory (mv2);
    //     assert(res);
        
    //     std::cout << "sp_adr_val: 0x" << std::hex << mv2.i64 << std::endl;
    // }

    if((td_sept_seam_va != 0) && !is_epte_defined){
        ulong epte_seed = 0x80e0000000000000;
        // td_pml5_seam_va = td_pml5_seam_va_2;
        // td_sept_seam_va = td_pml5_seam_va;
        std::cout << "considered td_pml5_seam_va: 0x" << td_sept_seam_va << std::endl;
        m_VM->createSYMemObject(td_sept_seam_va + 0x8, 8, 1, 1, epte_seed, "epte");
        is_epte_defined = true;
    }

    // std::cout << "rip: 0x" << std::hex << m_regs->regs.rip << std::endl;
    if(*(uint8_t *)m_regs->regs.rip == 0xcc) { /*if next rip is int3*/
        ulong int3_adr = m_regs->regs.rip;
        uint32_t ins_seamret = 0xcd010fcc;
        if(*(uint32_t *)int3_adr == ins_seamret){ /*if next sp ins is seamret*/
            std::cout << ":) ------------------------------- SEAMRET: "<< (m_regs->regs.rax == 0 ? "SUCCESS" : "FAIL") << " : ins count :";
            std::cout << std::dec << execData->insn_count << std::endl;
            if(execProfile->executionMode != EXEC_MD_SINGLE_PATH_SEDED){
                execData->is_next_ins_seamret = true; /*To notify thinctrl to end the current path*/
                endCurrentPath = true;
                if(m_regs->regs.rax == 0){
                    endCurrentPathReason = PATH_SEAMRET_PASS;
                }
                else{
                    endCurrentPathReason = PATH_SEAMRET_FAIL;
                    scall_failed_count++;
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
                doEndOfPathChecks(0);
                std::cout << "\nKRover END ..." << std::endl;
                exit(0);
            }
        }

        if(endCurrentPath){
            doEndOfPathChecks(endCurrentPathReason);
        }
    }
    else if(endCurrentPath){
        std::cout << "\n##End of cur path (imposbl) ..." << std::endl;
        std::cout << "\npath constraints : " << std::endl;
        a_EFlagsMgr->PrintConstraint();
        std::cout << "\nKRover END ..." << std::endl;
        // exit(0);
    }

    if(endCurrentPath){
        endOfPathJobs(endCurrentPathReason);
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

int CAnalyze::onBeforeCIESIE(){

    ulong eff_rip = m_regs->regs.rip - execData->win->in->size();

    int i = 0;
    ulong adr, pte, pa, seam_va;

    // ulong current_lp = 2;
    ulong lp_keyhole_va_base = sreq->khole_start_seam_va + sreq->current_lp*(PG_SZ_4K * 128);
	ulong lp_khole_edit_base_va = sreq->khole_edit_start_seam_va + sreq->current_lp*8*128;
    // std::cout << "lp_keyhole_va_base: 0x " << std::hex << lp_keyhole_va_base << std::endl;
    // std::cout << "lp_khole_edit_base_va: 0x " << std::hex << lp_khole_edit_base_va << std::endl;
    // std::cout << "sreq->khole_start_seam_va: 0x " << std::hex << sreq->khole_start_seam_va << std::endl;
    // std::cout << "sreq->khole_start_seam_va + 1G: 0x " << std::hex << sreq->khole_start_seam_va + (PG_SZ_4K*4096*4096) << std::endl;
    // assert(0);
    for(i = 0; i < 2; i++){

        adr = execData->opDetails[i].opmemac.memAddress;
        if(execData->opDetails[i].opmemac.wrmem){
            if(adr < (sreq->khole_edit_start_seam_va + (NUM_ADDRESSIBLE_LPS + 1)*8*1028)){ /*khole edit mapping*/
                std::cout << "khole-edit write: 0x" << std::hex << adr << std::endl;
                if((adr < lp_khole_edit_base_va) || (adr) >= (lp_khole_edit_base_va + 128*8)){
                    std::cout << "key hole edit write out off range for current LP !" << std::endl;
                    assert(0);
                }
                // // if(eff_rip == 0xffffa00000009a9c){
                // if(eff_rip == sreq->khole_edit_ins_adr[0]){
                //     pte = m_regs->regs.rdx;
                //     std::cout << "pte-x: 0x" << std::hex << pte << std::endl;
                // }
                // // else if(eff_rip == 0xffffa00000009d68){
                // else if(eff_rip == sreq->khole_edit_ins_adr[1]){
                //     pte = m_regs->regs.rsi;
                //     std::cout << "pte-y: 0x" << std::hex << pte << std::endl;
                // }
                // else{
                //     assert(0);
                // }
                pte = getKholePte(eff_rip);
                pa = pte & PTE_TO_PA_MASK;
                seam_va = lp_keyhole_va_base + ((adr - lp_khole_edit_base_va)/8)*(PG_SZ_4K);
                seam_pa_va_map.insert({pa, seam_va});
                seam_va_pa_map.insert({seam_va, pa});
                std::cout << "pa: 0x" << std::hex << pa << "\t seam va: 0x" << seam_va << std::endl;
                if(pa == sreq->td_sept_pa){
                    /*in SEPT add, the ePML5 is mapped twice. 
                    1: gets mapped in to static keyhole region when 6 contiguous pages in TDCX are mapped
                    2.: gets mapped as part of secure_ept_walk.
                    We do our subsequent checks to see if a given write is on ePML5 page based on the last map returned la
                    As of now we assume that after the 2nd mapping, the first mapping is not used by TDX module to write 
                    on to ePML5. Need to check if this is valid. OR use both mappings for subsequent checks.
                    Checked. ok.*/
                    if(sreq->sept_level == 4){
                        if(!epml5_mapped_once)
                            epml5_mapped_once = true;
                        else {
                            td_sept_seam_va = seam_va;
                        }
                    }
                    else{
                        td_sept_seam_va = seam_va;
                    }
                    std::cout << "td_pml" << std::dec << sreq->sept_level << "_seam_va: 0x" << std::hex << seam_va << std::endl;
                }
            }
            // if((adr & ~(0xfffUL)) == td_pml5_seam_va_1){
            //     std::cout << "write to pml5 la-1" << std::endl;
            // }
            // if((adr & ~(0xfffUL)) == td_sept_seam_va){
            //     std::cout << "write to pml5 la-2" << std::endl;
            // }
            // if((adr >= sreq->khole_start_seam_va) && (adr < (sreq->khole_start_seam_va + (1024*1024*1024)))){
            //     std::cout << "khole write: 0x" << std::hex << adr << std::endl;
            //     if((adr < lp_keyhole_va_base) && (adr >= (lp_keyhole_va_base + PG_SZ_4K*128))){
            //         std::cout << "khole write, out of LP khole renge" << std::endl;
            //         assert(0);
            //     }
            // }
        }
        if((adr >= sreq->khole_start_seam_va) && (adr < (sreq->khole_start_seam_va + (1024*1024*1024)))){
            std::cout << "khole write: 0x" << std::hex << adr << std::endl;
            if((adr < lp_keyhole_va_base) || (adr >= (lp_keyhole_va_base + PG_SZ_4K*128))){
                std::cout << "khole write, out of LP khole renge" << std::endl;
                assert(0);
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

    // std::cout << "rip: 0x" << std::hex << m_regs->regs.rip << std::endl;
    // assert(0);

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













