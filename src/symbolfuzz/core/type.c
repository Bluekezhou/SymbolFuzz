/* When debugging with gdb, sometimes we may need some
 * special type or struct definition to assist us, so
 * we have this short program which might contains some
 * basic useful type or struct definition.
*/

#include <stdio.h>
#include <inttypes.h>

int main()
{
    uint32_t t1 = 1;
    uint64_t t2 = 2;
    return t1 + t2;
}
