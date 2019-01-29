//
//  offsets.c
//  treadm1ll
//
//  Created by tihmstar on 09.01.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include "offsets.h"
static offsets_t offs;
static bool didInit = false;

extern "C" offsets_t* get_offsets(void *fi_){
    if (!didInit){
        //"Darwin Kernel Version 17.4.0: Fri Dec  8 19:35:52 PST 2017; root:xnu-4570.40.9~1/RELEASE_ARM64_S5L8960X"
        offs.base =                             0xfffffff007004000;

        offs.task_bsd_info = 0x368;
        offs.ipc_space_is_task = 0x28;
        offs.task_itk_registered = 0x2f0;
        offs.vtab_get_external_trap_for_index = 183;
        offs.zone_map = 0xfffffff0075d5e50;
        offs.rop_ldr_x0_x0_0x10 = 0xfffffff00723f47c;
        offs.kernel_task = 0xfffffff007624048;
        offs.copyout = 0xfffffff007198d44;
        offs.copyin = 0xfffffff007198b14;
        offs.proc_ucred = 0x100;
        offs.kauth_cred_ref = 0xfffffff0073b017c;
        offs.osserializer_serialize = 0xfffffff0074bda44;
        offs.chgproccnt = 0xfffffff0073dafc8;
        offs.kalloc_external = 0xfffffff0070c07c4;
        offs.kfree = 0xfffffff0070c07f4;
        offs.kernel_map = 0xfffffff007624050;
        offs.vm_map_hdr = 0x10;
        offs.ipc_port_alloc_special = 0xfffffff0070a8368;
        offs.ipc_kobject_set = 0xfffffff0070bd4b4;
        offs.ipc_port_make_send = 0xfffffff0070a7df4;
        offs.sizeof_task = 0x568;
        offs.realhost = 0xfffffff0075b8b98;
        offs.realhost_special = 0x10;
        
        didInit = true;
    }
    return &offs;
}
