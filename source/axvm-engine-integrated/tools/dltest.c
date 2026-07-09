#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>

typedef uint64_t (*fn2)(uint64_t, uint64_t);

int main(void)
{
    void *h = dlopen("libvictim.so", RTLD_NOW);
    if (!h) {
        printf("dlopen fail: %s\n", dlerror());
        return 1;
    }
    fn2 add = (fn2)dlsym(h, "victim_add");
    if (!add) {
        printf("dlsym fail: %s\n", dlerror());
        return 2;
    }
    printf("victim_add(41,1)=%llu\n", (unsigned long long)add(41, 1));
    return 0;
}
