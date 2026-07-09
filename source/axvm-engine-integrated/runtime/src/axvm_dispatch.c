#include "axvm_pack.h"

__attribute__((visibility("default")))
void axvm_rescan_modules(void)
{
    axvm_scan_proc_maps();
}
