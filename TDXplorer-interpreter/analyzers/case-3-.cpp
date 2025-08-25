#include <string>
#include "Analyze.h"
#include <asm/ptrace.h>
#include "VMState.h"
#include "HistoryTree.h"
#include "thinctrl.h"
#include "common_idata.h"
// #include "com.h" /*from seam manager*/
#include "seam.h"
#include "pageManager.h"
#include "tdx_local_data.h"
#include <cstring>

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

KVExprPtr pte_expr(nullptr);

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

ulong CAnalyze::findKeyHoleVa(ulong pa){

    // ulong lp_khole_edit_base_va = sreq->khole_edit_start_seam_va + sreq->current_lp*8*128;
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
        // std::cout << "khole_pte:0x" << khole_pte << std::endl;

        if((khole_pte & PTE_PRESENT_MASK) && ((khole_pte & PTE_TO_PA_MASK) == pa)){
                seam_va = keyholeIdxToVa(lp_keyhole_idx, pa);
                // std::cout << "sEPTE: 0x" << std::hex << khole_pte << std::endl;
                // std::cout << "seam_va: 0x" << std::hex << seam_va << std::endl;
                return seam_va;
        }

        lp_keyhole_idx++;
    }


    std::cout << "end\n";
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
    std::cout << "adr: 0x" << std::hex << adr << std::endl;
    if((adr >> 63) != 1){ /*khole edit mapping in the lower half of 48bit adr space*/
        std::cout << "khole-edit adr: 0x" << std::hex << adr << std::endl;
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

    // updated_sept_page_seam_va = findKeyHoleVa(sreq->updated_sept_page);
    // td_epml5_seam_va = findKeyHoleVa(sreq->td_epml5_pa);
    // td_epml4_seam_va = findKeyHoleVa(sreq->td_epml4_pa);
    // td_epdpt_seam_va = findKeyHoleVa(sreq->td_epdpt_pa);
    // td_epd_seam_va = findKeyHoleVa(sreq->td_epd_pa);
    // td_ept_seam_va = findKeyHoleVa(sreq->td_ept_pa);

    td_sept_page_seam_va[4] = findKeyHoleVa(sreq->td_epml5_pa);
    td_sept_page_seam_va[3] = findKeyHoleVa(sreq->td_epml4_pa);
    td_sept_page_seam_va[2] = findKeyHoleVa(sreq->td_epdpt_pa);
    td_sept_page_seam_va[1] = findKeyHoleVa(sreq->td_epd_pa);    

    std::cout << "td_epml5_seam_va\t:0x" << std::hex << td_sept_page_seam_va[4] << std::endl;
    std::cout << "td_epml4_seam_va\t:0x" << std::hex << td_sept_page_seam_va[3] << std::endl;
    std::cout << "td_epdpt_seam_va\t:0x" << std::hex << td_sept_page_seam_va[2] << std::endl;
    std::cout << "td_epd_seam_va\t:0x" << std::hex << td_sept_page_seam_va[1] << std::endl;
    // std::cout << "td_ept_seam_va\t:0x" << std::hex << td_ept_seam_va << std::endl;

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


    // assert(scall_failed_count <= 1);

}
/*---sanitiy checks and post processing ----------------------------------------------------------------------------------END*/

void CAnalyze::endOfPathJobs(int scall_status){ //analysis at the end of each path

        path_to_end_at_next_ins = false;
        // td_pml5_seam_va_1 = 0;
        // td_pml5_seam_va_2 = 0;
        // td_pml5_seam_va = 0;
        epml5_mapped_once = false;
        updated_sept_page_seam_va = 0;
        is_epte_defined = false;
        last_path = execData->current_path;
        sym_buf_count = 1;

        seam_va_pa_map.clear();
        seam_pa_va_map.clear();
        sym_buf_bases.clear();
}

ulong CAnalyze::getKholePte(ulong rip){

    ulong pte;
    uint reg_idx;

    std::cout << "khe-ins: 0x" << sreq->keyhole_edit_ins_adr[0] << " 0x" << sreq->keyhole_edit_ins_adr[1] << std::endl;
    // assert(0);
    // if(eff_rip == 0xffffa00000009a9c){
    if(rip == sreq->keyhole_edit_ins_adr[0]){
        pte = m_regs->regs.rdx;
        reg_idx = x86_64::rdx;
        std::cout << "pte-x: 0x" << std::hex << pte << std::endl;
    }
    // else if(eff_rip == 0xffffa00000009d68){
    else if(rip == sreq->keyhole_edit_ins_adr[1]){
        pte = m_regs->regs.rsi;
        reg_idx = x86_64::rsi;
        std::cout << "pte-y: 0x" << std::hex << pte << std::endl;
    }
    else{
        assert(0);
    }

    //check if reg is symbolic
    bool res;
    RegValue rv;
    rv.indx = reg_idx;
    rv.size = 8;
    rv.isSymList = false;
    res = m_VM->readRegister(rv);
    assert(res);
    
    if(rv.bsym){
        assert(rv.expr);
        std::cout << "keyhole pte is symbolic" << std::endl;
        pte_expr = rv.expr;
        pte = m_VM->m_EFlagsMgr->ConcretizeExpression(rv.expr);
    }

    return pte;
}

uint CAnalyze::isKholePteSymbolic(ulong rip){

    ulong pte;
    bool res;

    std::cout << "khe-ins: 0x" << sreq->keyhole_edit_ins_adr[0] << " 0x" << sreq->keyhole_edit_ins_adr[1] << std::endl;
    // assert(0);
    // if(eff_rip == 0xffffa00000009a9c){
    RegValue rv;
    rv.size = 8;
    if(rip == sreq->keyhole_edit_ins_adr[0]){
        rv.indx = x86_64::rdx;
        // pte = m_regs->regs.rdx;
        // std::cout << "pte-x: 0x" << std::hex << pte << std::endl;
    }
    // else if(eff_rip == 0xffffa00000009d68){
    else if(rip == sreq->keyhole_edit_ins_adr[1]){
        rv.indx = x86_64::rsi;
        // pte = m_regs->regs.rsi;
        // std::cout << "pte-y: 0x" << std::hex << pte << std::endl;
    }
    else{
        assert(0);
    }

    res = m_VM->readRegister(rv);
    assert(res);
    if(rv.bsym){
        return rv.indx;
    }
    return 0;
}


void CAnalyze::pageAccessSanitizer(ulong seam_va){
    std::cout << "pageAccessSanitizer\n";

    endCurrentPathReason = PATH_SEAMRET_PASS;
    endCurrentPath = true;
    std::cout << "\nEnd of cur path .... SEAMRET: SUCCESS" << std::endl;

    return;

    //get the khole edit entry from va
    // ulong khole_lp = ((seam_va & !(0xfffUL)) - sreq->khole_start_seam_va)/(PG_SZ_4K*128);
    ulong global_khole_idx = ((seam_va & ~(0xfffUL)) - sreq->khole_start_seam_va)/PG_SZ_4K;
    std::cout << "pageAccessSanitizer global_khole_idx " << std::dec << global_khole_idx << std::endl;

    ulong khole_edit_pte = *(ulong *)(sreq->khole_edit_start_seam_va + global_khole_idx*8);
    std::cout << "pageAccessSanitizer khole_edit_pte " << std::hex << khole_edit_pte << std::endl;

    ulong pfn = ((khole_edit_pte & ~(HKID_MASK)) & PTE_TO_PA_MASK) >> 12;
    ulong secure_page_idx = pfn - (TDX_TDMR0_START_PA >> 12);

    securePage *sp = (securePage *)&sreq->secPages[secure_page_idx];
    ulong page_owner_td = sp->mdata.td;
    ulong mod_running_td_ctx = sreq->td_owner_for_next_tdxcall;

    if(page_owner_td != mod_running_td_ctx){
        std::cout << "\npageAccessSanitizer ERROR: ILLEGAL page 0x" << std::hex << (pfn << 12) << " (Owner: TD_" << std::dec << page_owner_td << ") for currently serving TD: TD_" << mod_running_td_ctx << std::endl;
        endCurrentPathReason = PATH_ERROR;
        endCurrentPath = true;  
	}
}

void CAnalyze::pageAccessSanitizerSymbolic(){

    KVExprPtr e = execData->last_conc_exprptr;
    ulong v = execData->last_conc_expr_val;
    assert(v >> 63);

    ulong get_page_idx_shift = 12; /*shr 12 to divide by 4096*/
    ulong khole_edit_addr_conc;
    KVExprPtr global_khole_idx;
    KVExprPtr c1 = NULL;
    KVExprPtr c2 = NULL;
    KVExprPtr c3 = NULL;
    KVExprPtr c4 = NULL;
    KVExprPtr c5 = NULL;
    KVExprPtr c6 = NULL;

    KVExprPtr e1 = NULL;
    KVExprPtr e2 = NULL;
    KVExprPtr e3 = NULL;
    KVExprPtr khole_edit_addr = NULL;
    KVExprPtr mapped_pa = NULL;
    KVExprPtr e4 = NULL;
    KVExprPtr e5 = NULL;
    KVExprPtr e6 = NULL;

    KVExprPtr s_const = NULL;

    c1.reset(new ConstExpr(sreq->khole_start_seam_va, 8, 0));
    e1.reset(new SubExpr(e, c1));
    c2.reset(new ConstExpr(get_page_idx_shift, 8, 0));
    e2.reset(new ShrExpr(e1, c2));  //global khole idx
    c3.reset(new ConstExpr(sreq->khole_edit_start_seam_va, 8, 0));
    c4.reset(new ConstExpr(8, 8, 0));
    e3.reset(new MulExpr(e2, c4));
    khole_edit_addr.reset(new AddExpr(c3, e3));
    khole_edit_addr_conc = a_EFlagsMgr->ConcretizeExpression(khole_edit_addr, false);
    assert(khole_edit_addr_conc >= sreq->khole_edit_start_seam_va);

    std::cout << "khole_edit_addr_conc: 0x" << std::hex << khole_edit_addr_conc << std::endl;
    ulong pte = *(ulong *)khole_edit_addr_conc;
    m_VM->createSYMemObject(khole_edit_addr_conc, 8, 1, 1, pte, "pte");

    bool res;
    MemValue mv;
    mv.size = 8;
    mv.addr = khole_edit_addr_conc;
    mv.bsym = true;
    mv.isSymList = false;
    res = m_VM->readMemory (mv);
    assert(res);
    assert(mv.bsym);
    assert(mv.expr);

    c5.reset(new ConstExpr(PTE_TO_PA_MASK, 8, 0));
    mapped_pa.reset(new AndExpr(mv.expr, c5));

    ulong round;
    for(round = 0; round < SECURE_PAGE_COUNT; round++){
        if((sreq->secPages[round].mdata.base_pa != 0) && (sreq->secPages[round].mdata.td == sreq->td_owner_for_next_tdxcall)){
      
            c6.reset(new ConstExpr((sreq->secPages[round].mdata.base_pa << 12), 8, 0));
            e4.reset(new SubExpr(mapped_pa, c6));
            e5.reset(new EqualExpr(e4));

            if(s_const == NULL){
                s_const = e5;
            }
            else {
                e6.reset(new OrExpr(s_const, e5));
                s_const = e6;
            }
        }
    }
    std::cout << "page access sanitizer constraint : ";
    s_const->print();
    std::cout << std::endl;
    // assert(0);
    a_EFlagsMgr->m_Constraint.insert(s_const);
    // assert(0);
}


void CAnalyze::pageMapSanitizer(ulong pte){
    std::cout << "pageMapSanitizer\n";

    ulong mod_running_td_ctx = sreq->td_owner_for_next_tdxcall;
	ulong executing_td_context;
	
	ulong pfn = ((pte & ~(HKID_MASK)) & PTE_TO_PA_MASK) >> 12;
    ulong secure_page_idx = pfn - (TDX_TDMR0_START_PA >> 12);

	ulong hkid = (pte & HKID_MASK) >> HKID_START_BIT;

	securePage *sp = (securePage *)&sreq->secPages[secure_page_idx];
	ulong page_owner_td = sp->mdata.td;
	/*check if the hkid has a configured key on the platform*/
	if((hkid < TDX_GLOBAL_PRIVATE_HKID) || (hkid > (TDX_GLOBAL_PRIVATE_HKID + 2))){ /*we have 2 TDs*/
        std::cout << "\npageMapSanitizer ERROR: UNCONFIGURED HKID " << std::dec << hkid << " , mapped page 0x" << std::hex << (pfn << 12) << std::endl;
	    a_EFlagsMgr->PrintConstraint();
        endCurrentPathReason = PATH_ERROR;
        endCurrentPath = true;
        // assert(0);
    }
	/*check if the hkid used is the valid hkid for the page*/
	else if(sp->mdata.hkid != hkid){
        std::cout << "\npageMapSanitizer ERROR: INVALID HKID " << std::dec << hkid << " for page 0x" << std::hex << (pfn << 12) << std::endl;
	    a_EFlagsMgr->PrintConstraint();
        endCurrentPathReason = PATH_ERROR;
        endCurrentPath = true;        
        // assert(0);
    }
	/*check if the hkid used is valid in the current TD context*/
	else if(sp->mdata.td != sreq->td_owner_for_next_tdxcall){
        std::cout << "\npageMapSanitizer ERROR: ILLEGAL page 0x" << std::hex << (pfn << 12) << " (Owner: TD_" << std::dec << page_owner_td << ") for currently serving TD: TD_" << mod_running_td_ctx << std::endl;
        a_EFlagsMgr->PrintConstraint();
        endCurrentPathReason = PATH_ERROR;
        endCurrentPath = true;  
        // assert(0);
	}
}

void CAnalyze::pageMapChecker(uint reg_idx){

    std::cout << "pageAccessSanitizerSymbolic\n";
    ulong va = execData->last_conc_expr_val;
    assert(va >> 63);
    ulong pte_val = m_VM->m_EFlagsMgr->ConcretizeExpression(pte_expr);
    //get the pa
    ulong pa = pte_val & PTE_TO_PA_MASK;

    //get the keyid used to map this pa for this va
    KVExprPtr cons1 = NULL;
    KVExprPtr cons2 = NULL;
    KVExprPtr cons3 = NULL;
    KVExprPtr exp1 = NULL;
    KVExprPtr exp2 = NULL;
    KVExprPtr exp3 = NULL;
    KVExprPtr exp_pass = NULL;
    KVExprPtr exp_fail = NULL;

    cons1.reset(new ConstExpr(HKID_MASK, 8, 0));
    cons2.reset(new ConstExpr(HKID_START_BIT, 8, 0));
    exp1.reset(new AndExpr(pte_expr, cons1));  
    exp2.reset(new ShrExpr(exp1, cons2));//hkid

    std::cout << "hkid used to map the currently used va: \n";   
    exp2->print();
    std:cout << std::endl;

    //get the keyid used to encrypt this va
	ulong hkid_encrypted; //hkid used to encrypt the page
	ulong pfn = pa >> 12;
	ulong secure_page_idx = pfn - (TDX_TDMR0_START_PA >> 12);
	securePage *sp = (securePage *)&sreq->secPages[secure_page_idx];
    hkid_encrypted = sp->mdata.hkid;

    //compare
    cons3.reset(new ConstExpr(hkid_encrypted, 8, 0));
    exp3.reset(new SubExpr(exp2, cons3));

    //passing constraint
    exp_pass.reset(new EqualExpr(exp3));

    //failing constraint
    exp_fail.reset(new DistinctExpr(exp3));


    std::cout << "sani passing constraint: \n";
    exp_pass->print();
    std::cout << std::endl;

    std::cout << "sani failing constraint: \n";
    exp_fail->print();
    std::cout << std::endl;

    //solve for failing constraint
    // a_EFlagsMgr->m_Constraint.insert(exp_fail);
    a_EFlagsMgr->one_constraint.insert(exp_fail);
    a_EFlagsMgr->SolveOneConstraint();

    // a_EFlagsMgr->one_constraint.insert(exp_pass);
    // a_EFlagsMgr->SolveOneConstraint();

    std::cout << "end of page access checker" << std::endl;

    return;
}
void CAnalyze::pageMapSanitizerSymbolic(ulong reg_idx){

    bool res;
    RegValue rv;
    rv.indx = reg_idx;
    rv.size = 8;
    rv.isSymList = false;
    res = m_VM->readRegister(rv);
    assert(res);

    std::cout << "pageMapSanitizerSymbolic\n";
    KVExprPtr e = rv.expr;
    assert(e);
    std::cout << "EPTE : ";
    rv.expr->print();
    std::cout << std::endl;

    rv.indx = reg_idx;
    rv.size = 8;
    rv.isSymList = false;
    res = m_VM->readRegister(rv);
    assert(res);

    KVExprPtr e1 = NULL;
    KVExprPtr e2 = NULL;
    KVExprPtr e3 = NULL;
    KVExprPtr e4 = NULL;
    KVExprPtr e5 = NULL;
    KVExprPtr e6 = NULL;
    KVExprPtr e7 = NULL;
    KVExprPtr s_const = NULL;


    ulong hkid_pa = 0;
    ulong round = 0;
    // std::cout << "0x" << std::hex << (HKID_MASK | PTE_TO_PA_MASK) << std::endl;
    for(round = 0; round < SECURE_PAGE_COUNT; round++){
        // std::cout << "\nround " << std::dec << round << " " << std::hex << sreq->secPages[round].raw << std::endl;
        // std::cout << "Address 0x" << std::hex << (unsigned long)&sreq->secPages[round] << std::endl;

        if((sreq->secPages[round].mdata.base_pa != 0) && (sreq->secPages[round].mdata.td == sreq->td_owner_for_next_tdxcall)){
            hkid_pa = sreq->secPages[round].raw & (HKID_MASK | PTE_TO_PA_MASK);
            std::cout << "hkid_pa: 0x" << std::hex << hkid_pa << std::endl;
            e1.reset(new ConstExpr(hkid_pa, 8, 0));
            e2.reset(new ConstExpr((HKID_MASK | PTE_TO_PA_MASK), 8, 0));
            e3.reset(new AndExpr(rv.expr, e2));
            e4.reset(new SubExpr(e3, e1));
            e5.reset(new EqualExpr(e4));

            if(s_const == NULL){
                s_const = e5;
            }
            else {
                e6.reset(new OrExpr(s_const, e5));
                s_const = e6;
            }
            // std::cout << "sanitizer constraint : ";
            // s_const->print();
            // std::cout << std::endl;
            // assert(0);
            // assert(0);
        }
    }
    std::cout << "sanitizer constraint : ";
    s_const->print();
    std::cout << std::endl;
    // assert(0);
    a_EFlagsMgr->m_Constraint.insert(s_const);

    // e1.reset(new ConstExpr(HKID_MASK, 8, 0));
    // e2.reset(new AndExpr(e1, rv.expr));
    // e3.reset(new ConstExpr(HKID_START_BIT, 8, 0));
    // e4.reset(new Shl_SalExpr(e3, e2));
    // ulong current_td_hkid = 5;
    // e5.reset(new ConstExpr(current_td_hkid, 8, 0));
    // e6.reset(new SubExpr(e4, e5));
    // e7.reset(new EqualExpr(e6));
    // a_EFlagsMgr->m_Constraint.insert(e7);
    // // e2.reset(new )

    // KVExprPtr e8 = NULL;
    // KVExprPtr e9 = NULL;
    // KVExprPtr e10 = NULL;
    // KVExprPtr e11 = NULL;
    // KVExprPtr pg_pa = NULL;
    // e8.reset(new ConstExpr(PTE_TO_PA_MASK, 8, 0));
    // pg_pa.reset(new AndExpr(e1, rv.expr));
    // e9.reset(new ConstExpr(0x40004026, 8, 0));
    // e10.reset(new SubExpr(pg_pa, e9));
    // e11.reset(new EqualExpr(e10));
    // a_EFlagsMgr->m_Constraint.insert(e11);

}

//-----Analyzer Begins here -----------------------------------------------------------------------------------------------------------

ulong tdr_va = 0;
ulong map_pa_ret = 0;
ulong map_pa_addr = 0;

int CAnalyze::onEndOfInsExec(){ //analysis at the end of each instruction
    
    //if vmresume end path;
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
    // if(m_regs->regs.rip == (sreq->mod_code_rgn_start + 0x8dc0)){ //8dc0 t secure_ept_walk()
    //     // ulong eptp = 0x40022026; //m_regs->regs.rdi;
    //     ulong eptp = m_regs->regs.rdi;
    //     // ulong keyid = 0b000100; //m_regs->regs.rdx;
    //     ulong keyid = m_regs->regs.rdx;

    //     // m_VM->createSYRegObject(x86_64::rdi, 8, 1, 1, eptp, "eptp");
    //     // m_VM->createSYRegObject(x86_64::rdx, 8, 1, 1, keyid, "keyid");

    //     std::cout << "eptp seed: " << std::hex << eptp << std::endl;
    //     std::cout << "keyid seed: " << std::hex << keyid << std::endl;

    //     // ulong seed = m_regs->regs.rdi;
    //     // std::cout << "gpa seed: " << std::hex << seed << std::endl;
    //     // m_VM->createSYRegObject(x86_64::rdi, 8, 1, 1, seed, "gpa");
    // }

    // if(m_regs->regs.rip == (sreq->mod_code_rgn_start + 0x9b30)){ //9b30 map_pa()
        
    //     if(map_pa_count == 0){
    //         map_pa_count++;
    //         ulong pa = m_regs->regs.rdi;
    //         std::cout << "pa seed: " << std::hex << pa << std::endl;
    //         m_VM->createSYRegObject(x86_64::rdi, 8, 1, 1, pa, "pa");
    //     }
    // }

    // if(m_regs->regs.rip == (sreq->mod_code_rgn_start + 0x13490)){
    //     tdx_call_ret_adr = *(ulong *)(m_regs->regs.rsp);
    //     std::cout << "ret adr 0x" << std::hex << tdx_call_ret_adr << std::endl;
    // }

    // if(m_regs->regs.rip  == (SEAM_AGENT_CODE + 0x600)){

    //     ulong pte = m_regs->regs.rdi;
    //     m_VM->createSYRegObject(x86_64::rdi, 8, 1, 1, pte, "pte");
    //     ulong pte_without_hkid = pte & ~(HKID_MASK);

    //     bool res;
    //     RegValue rv;
    //     rv.indx = x86_64::rdi;
    //     rv.size = 8;
    //     rv.isSymList = false;
    //     res = m_VM->readRegister(rv);
    //     assert(res);
    //     assert(rv.bsym);

    //     KVExprPtr c1(nullptr), c2(nullptr), e1(nullptr), e2(nullptr), e3(nullptr);
    //     c1.reset(new ConstExpr(pte_without_hkid, 8, 0));
    //     c2.reset(new ConstExpr(~(HKID_MASK), 8, 0));
    //     e1.reset(new AndExpr(rv.expr, c2));
    //     e2.reset(new SubExpr(e1, c1));
    //     e3.reset(new EqualExpr(e2));
    //     a_EFlagsMgr->m_Constraint.insert(e3);
    //     std::cout << "adding new constraint: ";
    //     a_EFlagsMgr->PrintConstraint();

    //     sanitizer_ret_addr = *(ulong *)(m_regs->regs.rsp);
    //     std::cout << "sanitizer_ret_addr:0x" << sanitizer_ret_addr << std::endl;
    
    // }

    // if(m_regs->regs.rip == map_pa_addr){
    //     map_pa_ret = *(ulong *)(m_regs->regs.rsp);
    //     std::cout << "map_pa_ret adr:0x" << map_pa_ret << std::endl;
    // }
    if(m_regs->regs.rip == map_pa_ret){
        std::cout << "at_map_pa_ret adr" << std::endl;

        tdr_va = m_regs->regs.rax;
        m_VM->createSYRegObject(x86_64::rax, 8, 1, 1, tdr_va, "tdr");
        std::cout << "tdr_va:" << std::hex << tdr_va << std::endl;

        // bool res;
        // RegValue rv;
        // rv.indx = x86_64::rax;
        // rv.size = 8;
        // rv.isSymList = false;
        // res = m_VM->readRegister(rv);
        // assert(res);

        // mapped_keyhole = 0;
        // if(rv.bsym){
        //     assert(rv.expr);
        //     std::cout << "symbolic keyhole va: ";
        //     rv.expr->print();
        //     std::cout << std::endl;
        //     mapped_keyhole = m_VM->m_EFlagsMgr->ConcretizeExpression(rv.expr);
        //     assert(mapped_keyhole > sreq->khole_start_seam_va);
        // }
        // else{
        //     mapped_keyhole = m_regs->regs.rax;
        // }
        // std::cout << "At: map_pa_ret mapped_keyhole va:0x" << mapped_keyhole << std::endl;
        // if(is_pa_remapped){
        //     is_pa_remapped = false;

        // }
        // //print the path constraint 
        // m_VM->m_EFlagsMgr->PrintConstraint();
    }

    // if(is_keyhole_accessed){
    //     std::cout << "\nEnd of SE ..." << std::endl;
    //     std::cout << "\npath constraints : " << std::endl;
    //     std::cout << "\nEnd of cur path .... SEAMRET: SUCCESS" << std::endl;
    //     endCurrentPath = true;
    //     endCurrentPathReason = PATH_SEAMRET_PASS;
    //     a_EFlagsMgr->PrintConstraint();
    //     a_EFlagsMgr->SolveConstraints();
    //     doEndOfPathChecks(0);
    //     std::cout << "\nKRover END ..." << std::endl;
    //     if(execProfile->executionMode == EXEC_MD_SINGLE_PATH_SEDED){
    //         exit(0);
    //     }
    // }

    return 0;
}

int CAnalyze::onBeforeCIESIE(){
    // return 0;
    ulong eff_rip = m_regs->regs.rip - execData->win->in->size();
    bool res;
    int i = 0;
    ulong adr, pte, pa, seam_va, s_seed;

    for(i = 0; i < 2; i++){

        adr = execData->opDetails[i].opmemac.memAddress;
        // std::cout << "access adr: 0x" << std::hex << adr << std::endl;

        if(execData->opDetails[i].opmemac.rdmem){
            if((adr >= tdr_va) && (adr < (tdr_va + 4096))){
                std::cout << "read from tdr: va 0x" << std::hex << adr << std::endl;
                // m_VM->createSYMemObject(adr, execData->opDetails[i].opmemac.size, 1,1, s_seed, s_name);
            }
        }
        else if(execData->opDetails[i].opmemac.wrmem){
            std::cout << "mem write: 0x" << std::hex << adr << std::endl;
            // if((adr >> 63) != 1){ /*khole edit mapping*/
            // if(isKholeEditAddress(adr)){ /*khole edit mapping*/
            //     std::cout << "khole-edit write: 0x" << std::hex << adr << std::endl;
            //     is_pa_remapped = true;

            //     pte = getKholePte(eff_rip);
            //     pa = pte & PTE_TO_PA_MASK;
            //     int khole_idx = ((adr - lp_khole_edit_base_va)/8);
            //     newly_mapped_keyhole = keyholeIdxToVa(khole_idx, pa);
            //     std::cout << "newly_mapped_keyhole va: 0x" << std::hex << newly_mapped_keyhole << std::endl;

            //     uint pte_reg_idx = isKholePteSymbolic(eff_rip);
            //     pageMapChecker(pte_reg_idx);
            //     // pageAccessSanitizerSymbolic();

            //     //print tot ref count expr
            //     MemValue mv;
            //     mv.addr = sreq->lp_khole_ref_adr.tot_ref_count_adr;
            //     mv.size = 8;
            //     mv.isSymList = false;
            //     bool res_2 = m_VM->readMemory(mv);
            //     assert(res_2);
            //     if(mv.bsym){
            //         std::cout << "t_refs_expr: ";
            //         mv.expr->print();
            //         std::cout << std::endl;
            //     }
            //     else{
            //         std::cout << "t refs: " << mv.i64 << std::endl;
            //     }

            //     //print hole ref count expr
            //     int idx = 0;
            //     while(idx < 128){

            //         mv.addr = sreq->lp_khole_ref_adr.hole_ref_count_adr[idx];
            //         mv.size = 8;
            //         mv.isSymList = false;
            //         res_2 = m_VM->readMemory(mv);
            //         assert(res_2);

            //         if(mv.bsym){
            //             std::cout << " idx " << std::dec << idx << " k_refs_expr: ";
            //             mv.expr->print();
            //             std::cout << std::endl;
            //         }
            //         else{
            //             std::cout << " idx " << std::dec << idx << " k_refs: " << mv.i64 << std::endl;
            //         }
            //         idx++;
            //     }


            //     // exit(0);

            //     // if(sreq->validate_hkid == 1){
            //     //     ulong pte_reg_idx = isKholePteSymbolic(eff_rip);

            //     //     if(pte_reg_idx != 0){
            //     //         pageMapSanitizerSymbolic(pte_reg_idx);
            //     //         std::cout << "pte_reg_idx: 0x" << std::hex << pte_reg_idx << std::endl;
                        
            //     //         endCurrentPathReason = PATH_SEAMRET_PASS;
            //     //         endCurrentPath = true;
            //     //         std::cout << "\nEnd of cur path .... SEAMRET: SUCCESS" << std::endl;


            //     //         bool res;
            //     //         RegValue rv;
            //     //         rv.indx = pte_reg_idx;
            //     //         rv.size = 8;
            //     //         rv.isSymList = false;
            //     //         res = m_VM->readRegister(rv);
            //     //         assert(res);

            //     //         rv.i64 = a_EFlagsMgr->ConcretizeExpression(rv.expr, false);
            //     //         std::cout << "conc EPTE: 0x" << std::hex << rv.i64 << std::endl;
            //     //         rv.bsym = false;
            //     //         res = m_VM->writeRegister(rv);
            //     //     }
            //     //     else{
            //     //         pte = getKholePte(eff_rip);
            //     //         pageMapSanitizer(pte);
            //     //     }
            //     // }
            // }
        }
        if(execData->opDetails[i].opmemac.memrdwr){
            adr = execData->opDetails[i].opmemac.memAddress;
            std::cout << "access adr: 0x" << std::hex << adr << std::endl;
            std::cout << "access adr: 0x" << std::hex << adr << std::endl;

            // if(newly_mapped_keyhole > 0){
            //     if((adr & ~(0xfff)) == newly_mapped_keyhole){
            //         is_keyhole_accessed = true;
            //         endCurrentPathReason = PATH_SEAMRET_PASS;
            //         endCurrentPath = true;
            //         std::cout << "\nEnd of cur path vv ..." << std::endl;
            //         std::cout << "\npath constraints before sanitizer----------------------------------------------------: " << std::endl;
            //         a_EFlagsMgr->PrintConstraint();

            //         std::cout << "\n\npageAccessSanitizerSymbolic sanitizer----------------------------------------------------: " << std::endl;
            //         pageAccessSanitizerSymbolic();

            //         std::cout << std::endl;
            //         exit(0);
            //     }
            // }

            // if(isKholeAddress(adr)){
            //         if(execData->last_conc_ins_count == execData->insn_count){ /*smbolic address in this ins*/
            //             pageAccessSanitizerSymbolic();
            //             if(mapped_keyhole)
            //             endCurrentPathReason = PATH_SEAMRET_PASS;
            //             endCurrentPath = true;
            //             std::cout << "\nEnd of cur path .... SEAMRET: SUCCESS" << std::endl;
            //         }
            //         else{
            //             pageAccessSanitizer(adr);
            //         }
            //     // validateKholeRange(adr);

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

bool CAnalyze::beginAnalysis(ulong addr) { //Analysis start

    uint64_t scall_id;
    m_regs = (struct MacReg*)m_VM->getPTRegs();
    std::cout << "at beginAnalysis" << std::endl;


    lp_keyhole_va_base = sreq->khole_start_seam_va + sreq->current_lp*(PG_SZ_4K * 128);
    lp_khole_edit_base_va = sreq->khole_edit_start_seam_va + sreq->current_lp*8*128;

    std::cout << "rip:0x" << std::hex << m_regs->regs.rip << std::endl;

    // ulong keyid = m_regs->regs.rdx;
    // m_VM->createSYRegObject(x86_64::rdx, 8, 1, 1, keyid, "keyid");
    // std::cout << "rip:" << std::dec << keyid << std::endl;

    map_pa_addr = sreq->targt_fn_adr;
    map_pa_ret = *(ulong *)(m_regs->regs.rsp);
    std::cout << "map_pa_ret adr:0x" << map_pa_ret << std::endl;

    // unsigned long tot_ref_count_adr;
    // unsigned long hole_ref_count_adr[128];

    // ulong tot_refs_adr = sreq->lp_khole_ref_adr.tot_ref_count_adr;
    // std::cout << "tot refs: 0x" << *(ulong *)tot_refs_adr << std::endl;

    // std::string sym_prf_t = "t_ref";

    // int count = 0;
    // while(count < 8){
    //     std::string sym_str = sym_prf_t + std::to_string(count);
    //     const char* t_name = sym_str.c_str();
    //     m_VM->createSYMemObject(tot_refs_adr + count, 1, 1, 1, *(uint8_t *)(tot_refs_adr + count), t_name);
    //     count++;
    // }

    // ulong hole_ref_adr;
    // int idx = 0;
    // std::string sym_prf = "h_ref";
    // char *sym_name; 
    // while(idx < 128){
    //     hole_ref_adr = sreq->lp_khole_ref_adr.hole_ref_count_adr[idx];
    //     std::cout << "hole refs: 0x" << *(ulong *)hole_ref_adr << std::endl;

    //     std::string sym_s = sym_prf + std::to_string(idx);

    //     count = 0;
    //     while(count < 8){
    //         std::string sym_str = sym_s + std::to_string(count);
    //         const char* name = sym_str.c_str();
    //         m_VM->createSYMemObject(hole_ref_adr + count, 1, 1, 1, *(uint8_t *)(hole_ref_adr + count), name);
    //         count++;
    //     }
    //     idx++;
    // }

    // exit(0);

    // ulong eptp = m_regs->regs.rdi;
    // m_VM->createSYRegObject(x86_64::rdi, 8, 1, 1, eptp, "eptp");

    // ulong tdr_adr_seam = sreq->khole_start_seam_va + sreq->current_lp*4096*128;
    // ulong key_id_adr_in_tdr = tdr_adr_seam + 256;
    
    // bool res;
    // MemValue mv;

    // mv.size = 2;
    // mv.addr = key_id_adr_in_tdr;
    // mv.bsym = false;
    // mv.isSymList = false;

    // res = m_VM->readMemory (mv);
    // assert(res);
    // std::cout << "keyid:" << std::dec << mv.i32 << std::endl;
    // assert(0);

    /*ulong eptp = m_regs->regs.rdi;
    ulong keyid = 0x4LU;
    m_VM->createSYRegObject(x86_64::rdi, 8, 1, 1, eptp, "eptp");
    m_VM->createSYRegObject(x86_64::rdx, 8, 1, 1, keyid, "keyid");

    bool res;
    RegValue rv;
    rv.indx = x86_64::rdi;
    rv.size = 8;
    rv.isSymList = false;
    res = m_VM->readRegister(rv);
    assert(res);
    assert(rv.bsym);

    KVExprPtr e1 = NULL;
    KVExprPtr e2 = NULL;
    KVExprPtr e3 = NULL;
    KVExprPtr e4 = NULL;
    KVExprPtr e5 = NULL;

    ulong mask = 0xfffLU;
    ulong eptp_bits_0_3 = 0x026;
    e1.reset(new ConstExpr(mask, 8, 0));
    e2.reset(new ConstExpr(eptp_bits_0_3, 8, 0));
    e3.reset(new AndExpr(rv.expr, e1));
    e4.reset(new SubExpr(e3, e2));
    e5.reset(new EqualExpr(e4));
    a_EFlagsMgr->m_Constraint.insert(e5);*/



    // ulong pte = m_regs->regs.rdi;
    // m_VM->createSYRegObject(x86_64::rdi, 8, 1, 1, pte, "pte");
    // ulong pte_without_hkid = pte & ~(HKID_MASK);

    // bool res;
    // RegValue rv;
    // rv.indx = x86_64::rdi;
    // rv.size = 8;
    // rv.isSymList = false;
    // res = m_VM->readRegister(rv);
    // assert(res);
    // assert(rv.bsym);

    // KVExprPtr c1(nullptr), c2(nullptr), e1(nullptr), e2(nullptr), e3(nullptr);
    // c1.reset(new ConstExpr(pte_without_hkid, 8, 0));
    // c2.reset(new ConstExpr(~(HKID_MASK), 8, 0));
    // e1.reset(new AndExpr(rv.expr, c2));
    // e2.reset(new SubExpr(e1, c1));
    // e3.reset(new EqualExpr(e2));
    // a_EFlagsMgr->m_Constraint.insert(e3);
    // std::cout << "adding new constraint: ";
    // a_EFlagsMgr->PrintConstraint();

    // sanitizer_ret_addr = *(ulong *)(m_regs->regs.rsp);
    // std::cout << "sanitizer_ret_addr:0x" << sanitizer_ret_addr << std::endl;
    
    // m_regs->regs.rdx = 0b100000;
    // m_VM->createSYRegObject(x86_64::edx, 4, 1, 1, keyid, "keyid");


    setExecProfileSinglePath();
    // setExecProfileMultiPath();

    
    dispatch_count++;

    return m_Thin->processFunction(addr);
}













