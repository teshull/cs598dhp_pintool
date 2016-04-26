
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
//#include "control_manager.H"
#include "portability.H"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <map>
#include <stack>
#include <vector>
#include <algorithm>
#include <string.h>
#include <stdlib.h>
#include "cache.H"
//this is for multithreading
#include "atomic.hpp"

/* ================================================================== */
// Global variables 
/* ================================================================== */


//TODO LIST
//include instructions in the count --don
//virtual to physical address translation --done
//adding cache behaviour --done
//think about replacement policy for instructions --done
//when printing out address make it a constant size --done
//have a last used policy in the cache --done
//also list the cache hits (this is for mem footprint numbers) --done


typedef enum{
    LOAD_OP=1,
    STORE_OP=2,
    INSTRUCTION_OP=4
}mem_operations;

VOID printCacheStats();
VOID accumulateCacheStats();
VOID printFootprintInfo();
VOID recordInFootprint(ADDRINT addr, mem_operations mem_type);
VOID failurePrintout(const char *message);

static std::ostream * out = &cerr;
static PIN_LOCK lock;
static PIN_SEMAPHORE record_mem_sem;
static PIN_RWMUTEX rwlock;

static int NumArgs = 0;
static char **Args;

CACHE_BASE::ACCESS_TYPE types[] = {CACHE_BASE::ACCESS_TYPE_LOAD, CACHE_BASE::ACCESS_TYPE_STORE, CACHE_BASE::ACCESS_TYPE_INST};
const char* typeNames[] = {
    "Loads",
    "Stores",
    "Instructions"
};

// used for keeping track of the state
static volatile BOOL withinGC = false;
//static BOOL withinGC = true;

static BOOL somethingFailed = false;

static map<ADDRINT, ADDRINT> page_table;
static ADDRINT next_page = 0;

//counters that are thread-safe
static volatile int numThreads = 0;

UINT64 accessInfo[CACHE_BASE::ACCESS_TYPE_NUM + 1][CACHE_BASE::HIT_MISS_NUM];

map<ADDRINT, UINT8> gcFootprint;
const unsigned int FOOTPRINT_CATEGORIES = 8;

namespace LLC
{
    const UINT32 max_sets = 8*KILO; // cacheSize / (lineSize * associativity);
    const UINT32 max_associativity = 16; // associativity;
    const CACHE_ALLOC::STORE_ALLOCATION allocation = CACHE_ALLOC::STORE_ALLOCATE;

    //typedef CACHE_ROUND_ROBIN(max_sets, max_associativity, allocation) CACHE;
    typedef CACHE_LEAST_RECENTLY_USED(max_sets, max_associativity, allocation) CACHE;
}

LLC::CACHE* llc = NULL;

#define PAGE_SIZE KILO
#define MEM_SIZE ((long long int)4*GIGA)




/* ===================================================================== */
// Helper Classes
/* ===================================================================== */

struct MEM_INFO{
    ADDRINT address;
    mem_operations mem_op_type;
    UINT32 access_size;
    UINT64 cycle_num;
    MEM_INFO(ADDRINT addr, mem_operations mem_op, UINT32 size, UINT64 cycle = 0): address(addr), mem_op_type(mem_op), 
        access_size(size), cycle_num(cycle) {}
    MEM_INFO(): address(0), mem_op_type(LOAD_OP), access_size(0), cycle_num(0) {}

};

const UINT64 LOG_SIZE = 5E7; //50 million
//size in bytes of a dram access
#define ACCESS_SIZE 8
static MEM_INFO memValues[LOG_SIZE];
static volatile UINT64 arrayOffset = 0;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
        "o", "", "specify file name for GC Tracer output");
KNOB<BOOL> KnobVirtualAddressTranslation(KNOB_MODE_WRITEONCE,  "pintool",
        "at", "", "translate virtual address into physical address");
KNOB<BOOL> KnobSimulateCache(KNOB_MODE_WRITEONCE,  "pintool",
        "cs", "", "simulate llc cache");
KNOB<BOOL> KnobPrintCacheHits(KNOB_MODE_WRITEONCE,  "pintool",
        "pch", "", "print the llc cache hits");
KNOB<BOOL> KnobMonitorFromStart(KNOB_MODE_WRITEONCE,  "pintool",
        "mfs", "", "monitor program from the beginning (for testing)");
KNOB<UINT32> KnobCacheSize(KNOB_MODE_WRITEONCE, "pintool",
    "c","32", "cache size in kilobytes");
KNOB<UINT32> KnobLineSize(KNOB_MODE_WRITEONCE, "pintool",
    "l","64", "cache line size in bytes");
KNOB<UINT32> KnobAssociativity(KNOB_MODE_WRITEONCE, "pintool",
    "a","4", "cache associativity (1 for direct mapped)");



/* ===================================================================== */
// Utilities
/* ===================================================================== */

VOID printArguments(){
    cerr << "Arguments for said program\n";
    for(int i = 0; i < NumArgs; i++){
        cerr << Args[i] << endl;
    }
    cerr << endl;
}



/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
        "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

VOID initializeVariables(){
    //don't actually have to do this...
}

inline ADDRINT mask(ADDRINT ea, ADDRINT mask_size)  {
    const ADDRINT mask = ~static_cast<ADDRINT>(mask_size-1);
    return ea & mask;
}

const char * memOpToString(mem_operations mem_op){
    switch(mem_op){
        case LOAD_OP:
            return "READ   ";
            break;
        case STORE_OP:
            return "WRITE  ";
            break;
        case INSTRUCTION_OP:
            return "IFETCH ";
            break;
        default:
            cerr << "didn't recognize mem op type: " << mem_op << endl;
            failurePrintout("couldn't recognize mem op type");
    }
    return "";
}

ADDRINT retrieveNewPage(){
    if(next_page == MEM_SIZE){
        failurePrintout("ran out of pages to allocate");
    }
    ADDRINT new_page = next_page;
    next_page += PAGE_SIZE;
    return new_page;
}

ADDRINT convertVirtualToPhysical(ADDRINT v_addr){
    ADDRINT v_page = mask(v_addr, PAGE_SIZE);
    //allocating new page if this hasn't been seen yet
    if(page_table.find(v_page) == page_table.end()){
        ADDRINT new_page = retrieveNewPage();
        page_table[v_page] = new_page;
    }
    ADDRINT p_page = page_table[v_page];
    const ADDRINT page_num_mask = static_cast<ADDRINT>(PAGE_SIZE-1);
    ADDRINT p_addr = p_page | (v_addr & page_num_mask);
    return p_addr;
}

BOOL accessCache(ADDRINT addr, CACHE_BASE::ACCESS_TYPE access){
    const BOOL llcHit = llc->AccessSingleLine(addr, access);
    return llcHit;
}

CACHE_BASE::ACCESS_TYPE retrieve_ACCESS_TYPE(mem_operations mem_op){
    switch (mem_op){
        case LOAD_OP:
            return CACHE_BASE::ACCESS_TYPE_LOAD;
        case STORE_OP:
            return CACHE_BASE::ACCESS_TYPE_STORE;
        case INSTRUCTION_OP:
            return CACHE_BASE::ACCESS_TYPE_INST;
    }
    failurePrintout("Not able to discern the access type");
    //not possible to get here
    return CACHE_BASE::ACCESS_TYPE_INST;
}

VOID writeOutMemLog(){
    cerr << "writing out log" << endl;
    for(UINT64 i = 0; i < arrayOffset; i++){
        MEM_INFO &data = memValues[i];
        //splitting it up into as many addresses as necessary
        ADDRINT start = mask(data.address, ACCESS_SIZE);
        ADDRINT end   = mask(data.address + data.access_size - 1, ACCESS_SIZE);
        ADDRINT lastLine = 0;
        const char * access_type_name = memOpToString(data.mem_op_type);
        for(ADDRINT addr = start ; addr <= end ; addr += ACCESS_SIZE) {
            //printing here
            ADDRINT real_addr = addr;
            //checking to see if this is a new cache line
            ADDRINT currLine = mask(real_addr, KnobLineSize.Value());
            if(currLine == lastLine){
                //not a new line - this isn't really another acces
                continue;
            }
            lastLine = currLine;
            //converting to physical address if necessary
            //converting to physical address if necessary
            if(KnobVirtualAddressTranslation){
                real_addr = convertVirtualToPhysical(addr);
            }
            recordInFootprint(real_addr, data.mem_op_type);
            //logging both the cache hits and misses
            CACHE_BASE::ACCESS_TYPE access_type = retrieve_ACCESS_TYPE(data.mem_op_type);
            if(KnobSimulateCache && accessCache(real_addr, access_type)){
                //may want to record these are well
                if(KnobPrintCacheHits){
                    *out << "0x" << std::hex << std::uppercase << setw(16) <<  setfill('0') << real_addr <<
                        " " << "CACHE HIT " << access_type_name << std::nouppercase << std::dec << 
                        data.cycle_num << endl;
                }
            }else{
                *out << "0x" << std::hex << std::uppercase << setw(16) <<  setfill('0') << real_addr <<
                    " " << access_type_name << std::nouppercase << std::dec << data.cycle_num << endl;
            }
        }
    }
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*!
 * Increase counter of the executed basic blocks and instructions.
 * This function is called for every basic block when it is about to be executed.
 * @param[in]   numInstInBbl    number of instructions in the basic block
 * @note use atomic operations for multi-threaded applications
 */

// This function is called before every block
//
//

VOID PIN_FAST_ANALYSIS_CALL record_mem(THREADID threadid, ADDRINT memea, UINT32 length, UINT32 mem_type) {
    bool finished = false;
    UINT64 indexValue;
    UINT64 newValue;
    do{
        //get read lock
        PIN_RWMutexReadLock(&rwlock);
        //trying to get a place in the array
        do{
            indexValue = ATOMIC::OPS::Load(&arrayOffset);
            newValue = indexValue + 1;
        }while(!(ATOMIC::OPS::CompareAndDidSwap(&arrayOffset, indexValue, newValue)));
        if(indexValue < LOG_SIZE){
            //can write value to a spot in the array and be done
            memValues[indexValue] = MEM_INFO(memea, (mem_operations)mem_type, length);
            PIN_RWMutexUnlock(&rwlock);
            finished = true;
        }else if(indexValue > LOG_SIZE){
            //need to run again when the log has be flushed
            PIN_RWMutexUnlock(&rwlock);
        }else{ //this means this thread is responsible for writing out the log
            //releasing reader lock
            PIN_RWMutexUnlock(&rwlock);
            //NOTE: i'm pretty sure it tries to prevent writer starvation
            //attaining writing lock
            PIN_RWMutexWriteLock(&rwlock);
            writeOutMemLog();
            ATOMIC::OPS::Store<UINT64>(&arrayOffset, 0);
            PIN_RWMutexUnlock(&rwlock);
            //now will re-execute and try to get a real position
        }
    } while(!finished);
}

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    ATOMIC::OPS::Increment(&numThreads,1);
}


/*!
 * Increase counter of threads in the application.
 * This function is called for every thread created by the application when it is
 * about to start running (including the root thread).
 * @param[in]   threadIndex     ID assigned by PIN to the new thread
 * @param[in]   ctxt            initial register state for the new thread
 * @param[in]   flags           thread creation flags (OS specific)
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddThreadStartFunction function call
 */


VOID CallSimulationBegin(THREADID threadid){
    PIN_RWMutexWriteLock(&rwlock);
    //want to make sure the cache stats are cleared
    llc->clearCacheStats();
    //also clearing the footprint stats
    gcFootprint.clear();
    ATOMIC::OPS::Store<BOOL>(&withinGC, true);
    PIN_RWMutexUnlock(&rwlock);
    PIN_RemoveInstrumentation();
}

VOID CallSimulationEnd(THREADID threadid, ADDRINT regval = 0){
    //probably should write out memory to log here
    PIN_RWMutexWriteLock(&rwlock);
    ATOMIC::OPS::Store<BOOL>(&withinGC, false);
    //FIXME need to print out the proper GC type here (full or local)
    const char *gcType = regval == 0? "YOUNG" : "FULL";
    *out << "Start GC Section Info: Type = " << *gcType << endl;
    writeOutMemLog();
    printCacheStats();
    printFootprintInfo();
    *out << "End GC Section Info" << endl;
    accumulateCacheStats();
    PIN_RWMutexUnlock(&rwlock);
    PIN_RemoveInstrumentation();
}

VOID CallSimulationExit(THREADID threadid){
}


/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

/*!
 * Insert call to the CountBbl() analysis routine before every basic block 
 * of the trace.
 * This function is called every time a new trace is encountered.
 * @param[in]   trace    trace to be instrumented
 * @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
 *                       function call
 */
VOID Trace(TRACE trace, VOID *v)
{
    //do not need to do anything when not taking count
    if(!withinGC){
        return;
    }
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
            //checking for the beginning and end of gc sections
            if (INS_IsXchg(ins) && INS_OperandReg(ins, 0) == INS_OperandReg(ins, 1)) {
                ADDRINT regval = INS_OperandReg(ins, 0);
                if(regval != REG_R11 && regval != REG_R12){
                    //have a problem here
                    failurePrintout("xchg without proper register");
                }
                //think i'm actually only going to use the CallSimulationEnd
                if(regval == REG_R11){
                    INS_InsertCall(
                            ins, IPOINT_BEFORE, 
                            (AFUNPTR)CallSimulationBegin,
                            IARG_THREAD_ID,
                            IARG_END);
                }
                if(regval == REG_R12){
                    INS_InsertCall(
                            ins, IPOINT_BEFORE, 
                            (AFUNPTR)CallSimulationEnd,
                            IARG_THREAD_ID,
                            IARG_REG_VALUE, regval,
                            IARG_END);
                }
            }
            //instrument the code
            unsigned int instruction_bytes = INS_Size(ins);
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) record_mem,
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, instruction_bytes,
                    IARG_UINT32, INSTRUCTION_OP,
                    IARG_END);
            // instrument the load(s)
            if (INS_IsMemoryRead(ins)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) record_mem,
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_THREAD_ID,
                        IARG_MEMORYREAD_EA,
                        IARG_MEMORYREAD_SIZE,
                        IARG_UINT32, LOAD_OP,
                        IARG_END);

            }
            if (INS_HasMemoryRead2(ins)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) record_mem,
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_THREAD_ID,
                        IARG_MEMORYREAD2_EA,
                        IARG_MEMORYREAD_SIZE,
                        IARG_UINT32, LOAD_OP,
                        IARG_END);

            }
            // instrument the store
            if (INS_IsMemoryWrite(ins)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) record_mem,
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_THREAD_ID,
                        IARG_MEMORYWRITE_EA,
                        IARG_MEMORYWRITE_SIZE,
                        IARG_UINT32, STORE_OP,
                        IARG_END);

            }
        }
    }
}

VOID Routine(RTN rtn, VOID* v)
{
    RTN_Open(rtn);
    if (RTN_Name(rtn).find("pin_simulation_begin") != string::npos)
    {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallSimulationBegin, IARG_THREAD_ID, IARG_END);
    }
    else if (RTN_Name(rtn).find("pin_simulation_end") != string::npos)
    {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallSimulationEnd, IARG_THREAD_ID, IARG_END);
    }
    else if (RTN_Name(rtn).find("pin_simulation_exit") != string::npos)
    {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallSimulationExit, IARG_THREAD_ID, IARG_END);
    }

    RTN_Close(rtn);
}

VOID accumulateCacheStats(){
    int i = 0;
    for(; i < CACHE_BASE::ACCESS_TYPE_NUM; i++){
        accessInfo[i][false] = llc->Misses(types[i]);
        accessInfo[i][true] = llc->Hits(types[i]);
    }
    accessInfo[i][false] = llc->Misses();
    accessInfo[i][true] = llc->Hits();
}

VOID printCacheStats(){
    if(KnobSimulateCache){
        *out << "*****CACHE INFO*****" << endl;
        int i = 0;
        UINT64 temp_hits, temp_misses, temp_accesses;
        double temp_hit_rate, temp_miss_rate;
        for(; i < CACHE_BASE::ACCESS_TYPE_NUM; i++){
            temp_misses = llc->Misses(types[i]);
            temp_hits = llc->Hits(types[i]);
            temp_accesses = temp_hits + temp_misses;
            temp_hit_rate = 1.0 * temp_hits / temp_accesses * 100;
            temp_miss_rate = 1.0 * temp_misses / temp_accesses * 100;
            *out << "Cache Type: " << typeNames[i] << endl;
            *out << "Total Accesses: " << temp_accesses << endl;
            *out << "Total Hits: " << temp_hits << endl;
            *out << "Total Misses: " << temp_misses << endl;
            *out << "Hit Rate: " << temp_hit_rate << endl;
            *out << "Miss Rate: " << temp_miss_rate << endl;
            *out << endl;
        }
        temp_misses = llc->Misses();
        temp_hits = llc->Hits();
        temp_accesses = temp_hits + temp_misses;
        temp_hit_rate = 1.0 * temp_hits / temp_accesses * 100;
        temp_miss_rate = 1.0 * temp_misses / temp_accesses * 100;
        *out << "Cache Type: Everything" << endl;
        *out << "Total Accesses: " << temp_accesses << endl;
        *out << "Total Hits: " << temp_hits << endl;
        *out << "Total Misses: " << temp_misses << endl;
        *out << "Hit Rate: " << temp_hit_rate << endl;
        *out << "Miss Rate: " << temp_miss_rate << endl;
    }
}

VOID recordInFootprint(ADDRINT addr, mem_operations mem_type){
    map<ADDRINT,UINT8>::iterator it =  gcFootprint.find(addr);
    if (it == gcFootprint.end()) {
        gcFootprint[addr] = mem_type;
    }
    else {
        gcFootprint[addr] = it->second | mem_type;
    }
}

VOID printFootprintInfo(){
    //determining the footprint results
    UINT64 footprint_totals[FOOTPRINT_CATEGORIES];
    for(UINT64 i = 0; i < FOOTPRINT_CATEGORIES; i++){
        footprint_totals[i] = 0;
    }
    map<ADDRINT,UINT8>::iterator it =  gcFootprint.begin();
    for( ; it != gcFootprint.end() ; it++ ) {
        footprint_totals[it->second]++;
    }
    const char* header[] = {
        /*0*/ "error",
        /*1*/ "load",
        /*2*/ "store",
        /*3*/ "load+store",
        /*4*/ "code",
        /*5*/ "load+code",
        /*6*/ "store+code",
        /*7*/ "load+store+code",
    };
    *out << "*****FOOTPRINT INFO*****" << endl;
    for(UINT64 i=0; i<FOOTPRINT_CATEGORIES; i++) {
        *out << setfill(' ') << std::setw(30) << header[i] << "  "  << std::setw(20) << (footprint_totals[i]*ACCESS_SIZE) << " Bytes";
        *out << std::setw(20) << std::setprecision(4) << ((double)footprint_totals[i]*ACCESS_SIZE/KILO) << " KB" << endl;
    }
}

//printing this out when a failure occurs
VOID failurePrintout(const char *message){
    *out << message << endl;
    cerr << message << endl;
    somethingFailed = true;
    ASSERTX(false && "");
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
    if(somethingFailed){
        *out << "something failed: these results are not valid" << endl;
        cerr << "something failed: these results are not valid" << endl;
        return;
    }
    //writing out remaining mem accesses
    //needed lock around this to make sure it is at the right point
    PIN_RWMutexWriteLock(&rwlock);
    if(KnobMonitorFromStart){
        //need to take care of this if the cache was never finished
        writeOutMemLog();
        *out << "Start GC Section Info: Type = " << "FULL" << endl;
        printCacheStats();
        printFootprintInfo();
        *out << "End GC Section Info" << endl;
        accumulateCacheStats();
    }

    //printing out cache info (if cache used)
    if(KnobSimulateCache){
        *out << "Start Overall Info" << endl;
        *out << "*****CACHE INFO*****" << endl;
        int i = 0;
        UINT64 temp_hits, temp_misses, temp_accesses;
        double temp_hit_rate, temp_miss_rate;
        for(; i < CACHE_BASE::ACCESS_TYPE_NUM; i++){
            temp_misses = accessInfo[i][false];
            temp_hits = accessInfo[i][true];
            temp_accesses = temp_hits + temp_misses;
            temp_hit_rate = 1.0 * temp_hits / temp_accesses * 100;
            temp_miss_rate = 1.0 * temp_misses / temp_accesses * 100;
            *out << "Cache Type: " << typeNames[i] << endl;
            *out << "Total Accesses: " << temp_accesses << endl;
            *out << "Total Hits: " << temp_hits << endl;
            *out << "Total Misses: " << temp_misses << endl;
            *out << "Hit Rate: " << temp_hit_rate << endl;
            *out << "Miss Rate: " << temp_miss_rate << endl;
            *out << endl;
        }
        temp_misses = accessInfo[i][false];
        temp_hits = accessInfo[i][true];
        temp_accesses = temp_hits + temp_misses;
        temp_hit_rate = 1.0 * temp_hits / temp_accesses * 100;
        temp_miss_rate = 1.0 * temp_misses / temp_accesses * 100;
        *out << "Cache Type: Everything" << endl;
        *out << "Total Accesses: " << temp_accesses << endl;
        *out << "Total Hits: " << temp_hits << endl;
        *out << "Total Misses: " << temp_misses << endl;
        *out << "Hit Rate: " << temp_hit_rate << endl;
        *out << "Miss Rate: " << temp_miss_rate << endl;
    }
    PIN_RWMutexUnlock(&rwlock);
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    PIN_InitSymbols();

    //copying arguments to heap
    NumArgs = argc;
    Args = (char **) malloc(sizeof(char *) * argc);
    for(int i = 0; i < argc; i++){
        char * arg = argv[i];
        Args[i] = (char *) malloc(sizeof(char) * (strlen(arg)+ 1));
        strcpy(Args[i], arg);
    }


    initializeVariables(); //setting up variables

    if(KnobSimulateCache){
        llc = new LLC::CACHE("LLC cache", 
                KnobCacheSize.Value() * KILO,
                KnobLineSize.Value(),
                KnobAssociativity.Value());
    }

    // Initialize the lock
    PIN_InitLock(&lock);
    PIN_SemaphoreInit(&record_mem_sem);
    PIN_RWMutexInit(&rwlock);



    string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str());}

    //checking if we want to simulate from the beginning
    withinGC = KnobMonitorFromStart;

    //to identify calls in the code for starting/stoping instruction count
    RTN_AddInstrumentFunction(Routine, 0);


    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Register function to be called to instrument traces
    TRACE_AddInstrumentFunction(Trace, 0);

    //for threads
    PIN_AddThreadStartFunction(ThreadStart, 0);
    //may want to do something with this eventually
    //PIN_AddThreadFiniFunction(ThreadStart, 0);

    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by MyPinTool" << endl;
    if (!KnobOutputFile.Value().empty()) 
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    printArguments();
    cerr <<  "===============================================" << endl;


    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
