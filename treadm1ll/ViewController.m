//
//  ViewController.m
//  treadm1ll
//
//  Created by tihmstar on 27.12.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#import "ViewController.h"
#import "treadm1ll.h"
#include "offsets.h"

kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);


@interface ViewController ()

@end

@implementation ViewController

void DumpHex(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

kern_return_t dumpSomeKernel(task_t tfp0, kptr_t kbase, void *data){
    kern_return_t err = 0;
    char buf[0x1000] = {};
    
    mach_vm_size_t rSize = 0;
    err = mach_vm_read_overwrite(tfp0, kbase, sizeof(buf), buf, &rSize);
    
    printf("some kernel:\n");
    DumpHex(buf, sizeof(buf));
    
    printf("lol\n");
    
    return err;
}


- (void)viewDidLoad {
    [super viewDidLoad];

    printf("starting\n");
    
    offsets_t *offs = get_offsets(NULL);
    
    treadm1ll(offs, dumpSomeKernel, NULL);
    
   
    
    
    printf("done!\n");

}


@end
