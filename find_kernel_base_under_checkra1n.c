// find_kernel_base_under_checkra1n.c

#include "find_kernel_base_under_checkra1n.h"

// ---- mach_vm.h ---------------------------------------------------------------------------------

extern
kern_return_t mach_vm_read_overwrite
(
	vm_map_t target_task,
	mach_vm_address_t address,
	mach_vm_size_t size,
	mach_vm_address_t data,
	mach_vm_size_t *outsize
);

extern
kern_return_t mach_vm_region_recurse
(
	vm_map_t target_task,
	mach_vm_address_t *address,
	mach_vm_size_t *size,
	natural_t *nesting_depth,
	vm_region_recurse_info_t info,
	mach_msg_type_number_t *infoCnt
);

kern_return_t mach_vm_write
(
    vm_map_t target_task, 
    mach_vm_address_t address, 
    vm_offset_t data, 
    mach_msg_type_number_t dataCnt
);

// ---- Kernel task -------------------------------------------------------------------------------

static mach_port_t kernel_task_port;

void
kernel_task_init() {
	task_for_pid(mach_task_self(), 0, &kernel_task_port);
	assert(kernel_task_port != MACH_PORT_NULL);
	printf("kernel task: 0x%x\n", kernel_task_port);
}

bool
kernel_read(uint64_t address, void *data, size_t size) {
	mach_vm_size_t size_out;
	kern_return_t kr = mach_vm_read_overwrite(kernel_task_port, address, size,
			(mach_vm_address_t) data, &size_out);
	return (kr == KERN_SUCCESS);
}

uint64_t
kernel_read64(uint64_t address) {
	uint64_t value = 0;
	bool ok = kernel_read(address, &value, sizeof(value));
	if (!ok) {
		printf("error: %s(0x%016llx)\n", __func__, address);
	}
	return value;
}


bool kernel_write(uint64_t address, const void *data, size_t size) {
    size_t offset = 0;
    kern_return_t kr = KERN_FAILURE;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        kr = mach_vm_write(kernel_task_port, address + offset, (mach_vm_offset_t)data + offset, (int)chunk);
        if (kr != KERN_SUCCESS) {
            printf("error: %s(0x%016llx)\n",__func__, address);
            break;
        }
        offset += chunk;
    }
    return (kr == KERN_SUCCESS);
}
