#include <string>
#include "Analyze.h"
#include <asm/ptrace.h>
#include "VMState.h"
#include "HistoryTree.h"
#include "thinctrl.h"
#include "common_idata.h"
#include "seam.h"
#include "pageManager.h"

using namespace std;
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;

#define PTE_TO_PA_MASK		0xfffffff000UL
#define PG_SZ_4K            0x1000UL
#define PTE_PRESENT_MASK    0x1

extern bool endCurrentPath;
extern PATH_END_RSN endCurrentPathReason;
extern struct servReq *sreq;

std::map<ulong, ulong> seam_va_pa_map;
std::map<ulong, ulong> seam_pa_va_map;
std::map<ulong /*buf base*/, ulong /*conc adr from seeded*/> sym_buf_bases;
struct MacReg*  m_regs;
int         is_se = 0;
bool        epml5_mapped_once = false;
ulong       updated_sept_page_seam_va = 0;
ulong       td_sept_page_seam_va[5];
bool        is_epte_defined = false;
ulong       last_path = 0;
int         scall_failed_count = 0; 
ulong       lp_keyhole_va_base;
ulong       lp_khole_edit_base_va;
int         sym_buf_count = 1;

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

ulong CAnalyze::getSeedFromMemory(ulong adr){

    bool res;
    MemValue mv;

    mv.size = 8;
    mv.addr = adr;
    mv.bsym = false;
    mv.isSymList = false;
    res = m_VM->readMemory (mv);
    assert(res);
    assert(!mv.bsym);

    return mv.i64;
}

ulong CAnalyze::findKeyHoleVa(ulong pa){

    int lp_keyhole_idx = 0;
    bool res;
    MemValue mv;
    ulong seam_va = 0;
    ulong khole_pte;

    if(pa == 0x0){
        return 0;
    }

    while(lp_keyhole_idx < 128){

        khole_pte = *(ulong *)(lp_khole_edit_base_va + lp_keyhole_idx*8);
        /*std::cout << "khole_pte:0x" << khole_pte << std::endl;*/

        if((khole_pte & PTE_PRESENT_MASK) && ((khole_pte & PTE_TO_PA_MASK) == pa)){
                seam_va = keyholeIdxToVa(lp_keyhole_idx, pa);
                /*std::cout << "sEPTE: 0x" << std::hex << khole_pte << std::endl;
                std::cout << "seam_va: 0x" << std::hex << seam_va << std::endl;*/
                return seam_va;
        }
        lp_keyhole_idx++;
    }
    return seam_va;
}

ulong CAnalyze::keyholeIdxToVa(int khole_idx, ulong pa){

    ulong seam_va = lp_keyhole_va_base + khole_idx*(PG_SZ_4K);
    seam_pa_va_map.insert({pa, seam_va});
    seam_va_pa_map.insert({seam_va, pa});
    std::cout << "pa: 0x" << std::hex << pa << "\t seam va: 0x" << seam_va << std::endl;

    return seam_va;
}

bool CAnalyze::validateKholeEditRange(ulong adr){
    if((adr < lp_khole_edit_base_va) || (adr) >= (lp_khole_edit_base_va + 128*8)){
        std::cout << "key hole edit access out off range for current LP !" << std::endl;
        assert(0);
    }
    return false;
}

bool CAnalyze::isKholeEditAddress(ulong adr){
    std::cout << "1adr: 0x" << std::hex << adr << std::endl;
    if((adr >> 63) != 1){ /*khole edit mapping in the lower half of 48bit adr space*/
        std::cout << "2khole-edit adr: 0x" << std::hex << adr << std::endl;
        return true;
    }
    return false;
}

bool CAnalyze::validateKholeRange(ulong adr){

    if((adr < lp_keyhole_va_base) || (adr >= (lp_keyhole_va_base + PG_SZ_4K*128))){
        std::cout << "khole access, out of LP khole renge" << std::endl;
        assert(0);
    }
    return false;
}

bool CAnalyze::isKholeAddress(ulong adr){

    if((adr >= sreq->khole_start) && (adr < sreq->mod_data_rgn_start)){
        std::cout << "khole access: 0x" << std::hex << adr << std::endl;
        return true;
    }
    return false;
}

bool CAnalyze::isModuleLibSymAccess(ulong adr){
    
    if((adr >= sreq->mod_code_rgn_start) && (adr < sreq->mod_stack_rgn_start)){
        std::cout << "Module lib symbol access: 0x" << std::hex << adr << std::endl;
        return true;
    }
    return false;
}

bool CAnalyze::findMapedKholes(){

    td_sept_page_seam_va[4] = findKeyHoleVa(sreq->td_epml5_pa);
    td_sept_page_seam_va[3] = findKeyHoleVa(sreq->td_epml4_pa);
    td_sept_page_seam_va[2] = findKeyHoleVa(sreq->td_epdpt_pa);
    td_sept_page_seam_va[1] = findKeyHoleVa(sreq->td_epd_pa);    

    std::cout << "td_epml5_seam_va\t:0x" << std::hex << td_sept_page_seam_va[4] << std::endl;
    std::cout << "td_epml4_seam_va\t:0x" << std::hex << td_sept_page_seam_va[3] << std::endl;
    std::cout << "td_epdpt_seam_va\t:0x" << std::hex << td_sept_page_seam_va[2] << std::endl;
    std::cout << "td_epd_seam_va\t:0x" << std::hex << td_sept_page_seam_va[1] << std::endl;
    return true;
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
    if(updated_sept_page_seam_va != 0){
        std::cout << "checking sEPT page symbolic buffer contents ..." << std::endl;
        int sept_idx = 0;
        bool res;

        MemValue mv2 ;
        mv2.size = 8 ;

        /*read the exact 8 byte block that is expected to be modified*/
        mv2.addr = updated_sept_page_seam_va;
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
            mv2.addr = updated_sept_page_seam_va + 8*sept_idx;
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
}
/*---sanitiy checks and post processing ----------------------------------------------------------------------------------END*/

void CAnalyze::endOfPathJobs(int scall_status){ //analysis at the end of each path

        epml5_mapped_once = false;
        updated_sept_page_seam_va = 0;
        is_epte_defined = false;
        last_path = execData->current_path;
        sym_buf_count = 1; /*start at 1*/

        for(int i = 0; i < 5; i++){
            td_sept_page_seam_va[i] = 0;
        }

        seam_va_pa_map.clear();
        seam_pa_va_map.clear();
        sym_buf_bases.clear();
}

ulong CAnalyze::getKholePte(ulong rip){

    ulong pte;

    std::cout << "khe-ins: 0x" << sreq->keyhole_edit_ins_adr[0] << " 0x" << sreq->keyhole_edit_ins_adr[1] << std::endl;
    if(rip == sreq->keyhole_edit_ins_adr[0]){
        pte = m_regs->regs.rdx;
        std::cout << "pte-x: 0x" << std::hex << pte << std::endl;
    }
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
    }

    if(endCurrentPath){
        endOfPathJobs(endCurrentPathReason);
    }
    return 0;
}

int CAnalyze::onBeforeCIESIE(){

    ulong eff_rip = m_regs->regs.rip - execData->win->in->size();
    int i = 0;
    ulong adr, pte, pa, seam_va;

    for(i = 0; i < 2; i++){

        adr = execData->opDetails[i].opmemac.memAddress;
        if(execData->opDetails[i].opmemac.wrmem){
            std::cout << "mem write: 0x" << std::hex << adr << std::endl;
            if(isKholeEditAddress(adr)){ /*khole edit mapping*/
                pte = getKholePte(eff_rip);
                pa = pte & PTE_TO_PA_MASK;
                int khole_idx = ((adr - lp_khole_edit_base_va)/8);
                seam_va = keyholeIdxToVa(khole_idx, pa);

                if(pa == sreq->td_epml5_pa){
                    /*in SEPT add, the ePML5 is mapped twice. 
                    1: gets mapped in to static keyhole region when 6 contiguous pages in TDCX are mapped
                    2.: gets mapped as part of secure_ept_walk.
                    We do our subsequent checks to see if a given write is on ePML5 page based on the last map returned la
                    As of now we assume that after the 2nd mapping, the first mapping is not used by TDX module to write 
                    on to ePML5. Need to check if this is valid. OR use both mappings for subsequent checks.
                    Checked. ok.*/
                    if(!epml5_mapped_once)
                        epml5_mapped_once = true;
                    else {
                        td_sept_page_seam_va[4] = seam_va;
                    }
                    std::cout << "td_epml5_seam_va: 0x" << std::hex << seam_va << std::endl;
                }
            }
        }
        if(execData->opDetails[i].opmemac.memrdwr){
            if(isKholeEditAddress(adr)){
                validateKholeEditRange(adr);
            }
            if(isKholeAddress(adr)){
                validateKholeRange(adr);
            }
        }

        if(execData->opDetails[i].opmemac.rdmem){
            if(((adr & ~(0xfffUL)) == td_sept_page_seam_va[sreq->sept_level] ) && !is_epte_defined){
                
                ulong epte_seed = 0x80e0000000000000;
                updated_sept_page_seam_va = td_sept_page_seam_va[sreq->sept_level];
                std::cout << "updated_sept_page_seam_va: 0x" << updated_sept_page_seam_va << std::endl;
                sym_buf_bases.insert({updated_sept_page_seam_va, updated_sept_page_seam_va});
                std::cout << "td sept lvl" << std::dec << sreq->sept_level << " seam_va: 0x" << updated_sept_page_seam_va << std::endl;
                m_VM->createSYMemObject(updated_sept_page_seam_va, 8, 1, 1, epte_seed, "epte");
                is_epte_defined = true;
            }
            // if(isModuleLibSymAccess(adr)){
            //     auto it = sym_buf_bases.find(adr);
            //     if(!(it == sym_buf_bases.end())){
            //         /*now provide a symbolic buffer*/
            //         ulong sym_buf_seed = getSeedFromMemory(it->second);
            //         ulong sym_buf_base = it->first;
            //         std::cout << "sym buf base: 0x" << std::hex << sym_buf_base << " concretized adr: 0x" << it->second << std::endl;
            //         std::string sym_buf_name = "sym_buf_" + to_string(sym_buf_count);
            //         std::cout << sym_buf_name << " seed:0x" << std::hex << sym_buf_seed << std::endl;
            //         m_VM->createSYMemObject(sym_buf_base, 8, 1, 1, sym_buf_seed, sym_buf_name.c_str());
            //         sym_buf_count++;
            //     }
            // }
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

    m_regs = (struct MacReg*)m_VM->getPTRegs();
    std::cout << "at beginAnalysis: " << sreq->is_seed_mode << std::endl;

    lp_keyhole_va_base = sreq->khole_start_seam_va + sreq->current_lp*(PG_SZ_4K * 128);
    lp_khole_edit_base_va = sreq->khole_edit_start_seam_va + sreq->current_lp*8*128;
    findMapedKholes();

    if(sreq->is_seed_mode == 1){
        setExecProfileSinglePath();
    }
    else{
        setExecProfileMultiPath();
    }

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

    return m_Thin->processFunction(addr);
}













