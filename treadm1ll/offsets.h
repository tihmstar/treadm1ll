//
//  offsets.h
//  treadm1ll
//
//  Created by tihmstar on 09.01.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#ifndef offsets_h
#define offsets_h

#include <stdint.h>

typedef uint64_t kptr_t;
typedef struct{
    kptr_t base;
    kptr_t task_bsd_info;
    kptr_t ipc_space_is_task;
    kptr_t task_itk_registered;
    kptr_t vtab_get_external_trap_for_index;
    kptr_t zone_map;
    kptr_t rop_ldr_x0_x0_0x10;
    kptr_t copyin;
    kptr_t copyout;
    kptr_t chgproccnt;
    kptr_t kernel_task;
    kptr_t proc_ucred;
    kptr_t kauth_cred_ref;
    kptr_t osserializer_serialize;
    kptr_t kalloc_external;
    kptr_t kfree;
    kptr_t kernel_map;
    kptr_t vm_map_hdr;
    kptr_t ipc_port_alloc_special;
    kptr_t ipc_kobject_set;
    kptr_t ipc_port_make_send;
    kptr_t sizeof_task;
    kptr_t realhost;
    kptr_t realhost_special;

} offsets_t;

#ifdef __cplusplus
extern "C"
#endif
offsets_t* get_offsets(void*);

#endif /* offsets_h */
