#include "types.h"
#include "memutil.h"
#include "sh4_mem.h"

u32 LoadFileToSh4Mem(u32 offset, wchar_t* file) {
    FILE *fd = _wfopen(file, L"rb");
    if (fd == NULL) {
        wprintf(L"LoadFileToSh4Mem: can't load file \"%ls\" to memory, file not found\n", file);
        return 0;
    }

    u32 e_ident;
    fread(&e_ident, 1, 4, fd);
    fseek(fd, 0, SEEK_SET);

    if (0x464C457F == e_ident) {
        fclose(fd);
        wprintf(L"!\tERROR: Loading elf is not supported (%ls)\n", file);
        return 0;
    } else {
        int toff = offset;
        int size;
        fseek(fd, 0, SEEK_END);
        size = ftell(fd);
        fseek(fd, 0, SEEK_SET);

        fread(&mem_b[toff], 1, size, fd);
        fclose(fd);
        toff += size;

        wprintf(L"LoadFileToSh4Mem: loaded file \"%ls\" to {SysMem[%x]-SysMem[%x]}\n"
                L"LoadFileToSh4Mem: file size : %d bytes\n", file, offset, toff - 1, toff - offset);
        return 1;
    }
}

u32 LoadBinfileToSh4Mem(u32 offset, wchar_t* file) {
    u8 CheckStr[8] = {0x7, 0xd0, 0x8, 0xd1, 0x17, 0x10, 0x5, 0xdf};
    u32 rv = LoadFileToSh4Mem(0x10000, file);

    for (int i = 0; i < 8; i++) {
        if (ReadMem8(0x8C010000 + i + 0x300) != CheckStr[i])
            return rv;
    }
    return LoadFileToSh4Mem(0x8000, file);
}

bool LoadFileToSh4Bootrom(wchar_t *szFile) {
    FILE *fd = _wfopen(szFile, L"rb");
    if (fd == NULL) {
        wprintf(L"LoadFileToSh4Bootrom: can't load file \"%ls\", file not found\n", szFile);
        return false;
    }
    fseek(fd, 0, SEEK_END);
    int flen = ftell(fd);
    fseek(fd, 0, SEEK_SET);

#ifndef BUILD_DEV_UNIT
    if (flen > (BIOS_SIZE)) {
        wprintf(L"LoadFileToSh4Bootrom: can't load file \"%ls\", Too Large! size(%d bytes)\n", szFile, flen);
        fclose(fd);
        return false;
    }
#else
    fseek(fd, 0x15014, SEEK_SET);
#endif

    size_t rd = fread(&bios_b[0], 1, flen, fd);
    wprintf(L"LoadFileToSh4Bootrom: loaded file \"%ls\", size : %zu bytes\n", szFile, rd);
    fclose(fd);
    return true;
}

bool LoadFileToSh4Flashrom(wchar_t *szFile) {
    FILE *fd = _wfopen(szFile, L"rb");
    if (fd == NULL) {
        wprintf(L"LoadFileToSh4Flashrom: can't load file \"%ls\", file not found\n", szFile);
        return false;
    }
    fseek(fd, 0, SEEK_END);
    int flen = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    if (flen > (FLASH_SIZE)) {
        wprintf(L"LoadFileToSh4Flashrom: can't load file \"%ls\", Too Large! size(%d bytes)\n", szFile, flen);
        fclose(fd);
        return false;
    }

    size_t rb = fread(&flash_b[0], 1, flen, fd);
    wprintf(L"LoadFileToSh4Flashrom: loaded file \"%ls\", size: %zu bytes\n", szFile, rb);
    fclose(fd);
    return true;
}

bool SaveSh4FlashromToFile(wchar_t *szFile) {
    FILE *fd = _wfopen(szFile, L"wb");
    if (fd == NULL) {
        wprintf(L"SaveSh4FlashromToFile: can't open file \"%ls\"\n", szFile);
        return false;
    }

    size_t written = fwrite(&flash_b[0], 1, FLASH_SIZE, fd);
    if (written != FLASH_SIZE) {
        wprintf(L"Error writing to file \"%ls\": Only %zu bytes written out of %d\n", szFile, written, FLASH_SIZE);
    } else {
        wprintf(L"SaveSh4FlashromToFile: Saved flash file \"%ls\"\n", szFile);
    }

    fclose(fd);
    return true;
}

void AddHook(u32 Addr, u16 Opcode) {
    if (Addr == 0)
        return;
    u32 Offs = (Opcode != 0x000B) ? 2 : 0;
    static const u16 RtsNOP[2] = {0x000B, 0x0009};

    if (Opcode != 0x000B)
        WriteMem16_nommu(Addr, Opcode);

    WriteMem16_nommu(Addr + Offs, RtsNOP[0]);
    WriteMem16_nommu(Addr + Offs + 2, RtsNOP[1]);
}

#define SYSINFO_OPCODE    ((u16)0x30F1)
#define dc_bios_syscall_system       0x8C0000B0
#define dc_bios_syscall_font         0x8C0000B4
#define dc_bios_syscall_flashrom     0x8C0000B8
#define dc_bios_syscall_GDrom_misc   0x8C0000BC
#define dc_bios_syscall_resets_Misc  0x8c0000E0
#define GDROM_OPCODE      ((u16)0x30F9)

u32 EnabledPatches = 0;

void LoadSyscallHooks() {
    AddHook(ReadMem32(dc_bios_syscall_system), 0x000B);
    AddHook(ReadMem32_nommu(dc_bios_syscall_font),  0x000B);
    AddHook(ReadMem32_nommu(dc_bios_syscall_flashrom), 0x000B);
    AddHook(ReadMem32_nommu(dc_bios_syscall_GDrom_misc), 0x000B);
    AddHook(0x1000, GDROM_OPCODE);
    AddHook(ReadMem32_nommu(dc_bios_syscall_resets_Misc), 0x000B);
}

void SetPatches() {
    LoadSyscallHooks();
}
