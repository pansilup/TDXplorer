#include <string>
#include "Analyze.h"
#include <asm/ptrace.h>
#include "VMState.h"
#include "HistoryTree.h"
#include "thinctrl.h"
#include "common_idata.h"
#include "seam.h"
#include "pageManager.h"
#include "tdx_local_data.h"

struct iData *tdx_sp_ins;

using namespace std;
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;

extern bool endCurrentPath;
extern PATH_END_RSN endCurrentPathReason;
extern struct servReq *sreq;

struct MacReg*  m_regs;
std::map<ulong, ulong> seam_va_pa_map;
std::map<ulong, ulong> seam_pa_va_map;
std::map<ulong /*buf base*/, ulong /*conc adr from seeded*/> sym_buf_bases;

int             dispatch_count = 0;
int is_se = 0;

uint8_t sym_buffer[4096];
#define PTE_TO_PA_MASK		0xfffffff000UL
#define PG_SZ_4K            0x1000UL
#define PTE_PRESENT_MASK    0x1

bool epml5_mapped_once = false;
ulong updated_sept_page_seam_va = 0;
ulong td_sept_page_seam_va[5];

bool is_epte_defined = false;

ulong last_path = 0;
int scall_failed_count = 0; 

ulong lp_keyhole_va_base;
ulong lp_khole_edit_base_va;

int sym_buf_count = 1;
ulong tdx_call_ret_adr = 0;
bool path_to_end_at_next_ins  = false;

CAnalyze::CAnalyze(VMState *VM, EveMeta* meta) {
    m_VM = VM;
    execData = new ExecData;
    execData->insn_count = 0; 
    execData->is_next_ins_seamret = false;
    execData->current_path = 0;

    execData->last_conc_exprptr = NULL;
    execData->last_conc_ins_count = 0;

    execProfile = new ExecProfile;
    execProfile->executionMode = 0; /*DEFAULT, single pat hseeded*/
    execProfile->terminationMode = 0; /*DEFAULT, terminate at stack balance, function return*/
    execProfile->terminate_ins_count = 0;

}

CAnalyze::~CAnalyze() {
}

void CAnalyze::setExecProfileSinglePath(){
    std::cout << "setExecProfileSinglePath" << std::endl;
    execProfile->executionMode = EXEC_MD_SINGLE_PATH_SEDED;
    execProfile->terminationMode = END_AT_ANA_REQUEST;
    execProfile->startIncCount = 0;
}

void CAnalyze::setExecProfileMultiPath(){
    std::cout << "setExecProfileMultiPath" << std::endl;
    execProfile->executionMode = EXEC_MD_START_PATH_SEARCH_AT_INS_COUNT;
    // execProfile->startRip = rip;
    // execProfile->startIncCount = 2089;
    execProfile->startIncCount = 0;
    
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
    std::cout << "adr: 0x" << std::hex << adr << std::endl;
    if((adr >> 63) != 1){ /*khole edit mapping in the lower half of 48bit adr space*/
        std::cout << "khole-edit adr: 0x" << std::hex << adr << std::endl;
        return true;
    }
    return false;
}

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


/*-----Analyzer Begins here -----------------------------------------------------------------------------------------------------------*/


ulong ret_addr = 0;
ulong tdcs_ptr = 0;
ulong tdcs_va = 0;
int CAnalyze::onEndOfInsExec(){ //analysis at the end of each instruction
    
    if(m_regs->regs.rip == 0xffffa00000002b10){ //check_state_map_tdcs_and_lock
        tdcs_ptr = m_regs->regs.r9;
        ret_addr = *(ulong *)m_regs->regs.rsp;
        std::cout << "at check_state_map_tdcs_and_lock\nret addr: 0x" << ret_addr << std::endl;
    }

    if(m_regs->regs.rip == ret_addr){

        std::cout << "end of function\n";
        a_EFlagsMgr->PrintConstraint();
        tdcs_va = *(ulong *)tdcs_ptr;
        std::cout << "tdcs va: 0x" << tdcs_va << std::endl;
        ulong seed = getSeedFromMemory(tdcs_va + 0x80);
        m_VM->createSYMemObject(tdcs_va + 0x80, 8, 1, 1, seed , "attributes");
    }

    return 0;
}

int CAnalyze::onBeforeCIESIE(){

    return 0;
} 

int CAnalyze::onPathEnd(){
    std::cout << "path end ana\n";
    return 1;
}

int CAnalyze::analyztsHub(int anaPoint) { //analysis of KRover's SE by analyzer goes through this hub
    std::cout << "at analyztsHub" << std::endl;
    switch(anaPoint){
        case ON_END_OF_INS_EXEC: {
            return CAnalyze::onEndOfInsExec();
        }   break;
        case ON_BFR_CIE_OR_SIE: {
            // return CAnalyze::onBeforeCIESIE();
            break;
        }
        case ON_PATH_END: {
            return CAnalyze::onPathEnd();
        }
        default:
            break;
    }
    return 0;
}

bool CAnalyze::beginAnalysis(ulong addr) { //Analysis start

    uint64_t scall_id;
    m_regs = (struct MacReg*)m_VM->getPTRegs();
    std::cout << "at beginAnalysis" << std::endl;


    lp_keyhole_va_base = sreq->khole_start_seam_va + sreq->current_lp*(PG_SZ_4K * 128);
    lp_khole_edit_base_va = sreq->khole_edit_start_seam_va + sreq->current_lp*8*128;

    std::cout << "rip:0x" << std::hex << m_regs->regs.rip << std::endl;

    m_VM->createSYRegObject(x86_64::rcx, 8, 1, 1, m_regs->regs.rcx, "rcx");
    ulong version_addr = m_regs->gs_base + 0x80 + 0x2;
    uint8_t version = *(uint8_t *)version_addr;
    m_VM->createSYMemObject(version_addr, 1, 1, 1, version, "version");


    /*setExecProfileSinglePath();*/
    setExecProfileMultiPath();

    dispatch_count++;

    m_Thin->processFunction(addr);
    std::cout << "ending analsis at interpreter's analyzer function\n" << std::endl;

    return false;
}













