
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


VOID printCacheStats();
VOID accumulateCacheStats();

static std::ostream * out = &cerr;
static PIN_LOCK lock;
static int NumArgs = 0;
static char **Args;

// used for keeping track of the state
static BOOL withinGC = false;
//static BOOL withinGC = true;

static THREADID gcThreadid = 0;
static BOOL somethingFailed = false;

static map<ADDRINT, ADDRINT> page_table;
static ADDRINT next_page = 0;

UINT64 total_accesses = 0;
UINT64 total_hits = 0;
UINT64 total_misses = 0;


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

typedef enum{
    LOAD_OP=0,
    STORE_OP,
    INSTRUCTION_OP
}mem_operations;

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
//const UINT64 LOG_SIZE = 1000000;
//size in bytes of a dram access
#define ACCESS_SIZE 8
static UINT64 arrayOffset = 0;
static MEM_INFO memValues[LOG_SIZE];

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
            ASSERTX(false && "couldn't recognize mem op type");
    }
    return "";
}

ADDRINT retrieveNewPage(){
    if(next_page == MEM_SIZE){
        ASSERTX(false && "ran out of pages to allocate");
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

VOID writeOutMemLog(){
    //cerr << "writing out log" << endl;
    for(UINT64 i = 0; i < arrayOffset; i++){
        MEM_INFO &data = memValues[i];
        //splitting it up into as many addresses as necessary
        ADDRINT start = mask(data.address, ACCESS_SIZE);
        ADDRINT end   = mask(data.address + data.access_size - 1, ACCESS_SIZE);
        const char * access_type = memOpToString(data.mem_op_type);
        for(ADDRINT addr = start ; addr <= end ; addr += ACCESS_SIZE) {
            //printing here
            ADDRINT real_addr = addr;
            //converting to physical address if necessary
            if(KnobVirtualAddressTranslation){
                real_addr = convertVirtualToPhysical(addr);
            }
            //FIXME need to change this to the right type
            //actually don't really think it is necessary
            //logging both the cache hits and misses
            if(KnobSimulateCache && accessCache(real_addr, CACHE_BASE::ACCESS_TYPE_LOAD)){
                //may want to record these are well
                if(KnobPrintCacheHits){
                    *out << "0x" << std::hex << std::uppercase << setw(16) <<  setfill('0') << real_addr <<
                        " " << "CACHE HIT " << access_type << std::nouppercase << std::dec << 
                        data.cycle_num << endl;
                }
            }else{
                *out << "0x" << std::hex << std::uppercase << setw(16) <<  setfill('0') << real_addr <<
                    " " << access_type << std::nouppercase << std::dec << data.cycle_num << endl;
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
    if(threadid != gcThreadid){
        return;
    }
    memValues[arrayOffset++] = MEM_INFO(memea, (mem_operations)mem_type, length);
    if(arrayOffset == LOG_SIZE){
        //at this point need to write it out
        writeOutMemLog();
        arrayOffset = 0;
    }
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
    gcThreadid = threadid;
    //want to make sure the cache stats are cleared
    llc->clearCacheStats();
    withinGC = true;
    PIN_RemoveInstrumentation();
}

VOID CallSimulationEnd(THREADID threadid){
    //need to print out results right here
    writeOutMemLog();
    printCacheStats();
    accumulateCacheStats();
    withinGC = false;
    PIN_RemoveInstrumentation();
}

VOID CallSimulationExit(THREADID threadid){
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
        UINT64 accesses, hits, misses;
        accesses = llc->Accesses();
        hits = llc->Hits();
        misses = llc->Misses();
        total_accesses += accesses;
        total_hits += hits;
        total_misses += misses;
}

VOID printCacheStats(){
    if(KnobSimulateCache){
        *out << "*****SESSION CACHE INFO*****" << endl;
        UINT64 accesses, hits, misses;
        double hit_rate, miss_rate;
        accesses = llc->Accesses();
        hits = llc->Hits();
        misses = llc->Misses();
        hit_rate = 1.0 * hits / accesses * 100;
        miss_rate = 1.0 * misses / accesses * 100;
        *out << "Total Accesses: " << accesses << endl;
        *out << "Total Hits: " << hits << endl;
        *out << "Total Misses: " << misses << endl;
        *out << "Hit Rate: " << hit_rate << endl;
        *out << "Miss Rate: " << miss_rate << endl;
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

    if(KnobMonitorFromStart){
        //need to take care of this if the cache was never finished
        writeOutMemLog();
        accumulateCacheStats();
    }

    //printing out cache info (if cache used)
    if(KnobSimulateCache){
        *out << "*****FINAL CACHE INFO*****" << endl;
        UINT64 accesses, hits, misses;
        double hit_rate, miss_rate;
        accesses = total_accesses;
        hits = total_hits;
        misses = total_misses;
        hit_rate = 1.0 * hits / accesses * 100;
        miss_rate = 1.0 * misses / accesses * 100;
        *out << "Total Accesses: " << accesses << endl;
        *out << "Total Hits: " << hits << endl;
        *out << "Total Misses: " << misses << endl;
        *out << "Hit Rate: " << hit_rate << endl;
        *out << "Miss Rate: " << miss_rate << endl;
    }
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
