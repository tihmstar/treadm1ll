//
//  exploit.h
//  treadm1ll
//
//  Created by tihmstar on 27.12.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef treadm1ll_h
#define treadm1ll_h

#include <stdio.h>
#include "offsets.h"
#include <mach/mach.h>


typedef kern_return_t(*treadm1ll_cb_t)(task_t tfp0, kptr_t kbase, void *data);

int treadm1ll(offsets_t *off, treadm1ll_cb_t callback, void *cb_data);

#endif /* treadm1ll_h */
