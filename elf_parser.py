from optparse import OptionParser
import os, sys
import struct


class ELF_META:
    @staticmethod
    def GET_ENDIAN(buf):
        size = len(buf)
        fmt = None

        if size == 1:
            fmt = "<B"
        elif size == 2:
            fmt = "<H"
        elif size == 4:
            fmt = "<I"
        elif size == 8:
            fmt = "<Q"
        else:
            return None

        try:
            return struct.unpack(fmt, buf)[0]
        except:
            return None


class ELF_HEADER:
    DIC_ABI = {
            0x00 : "System V",
            0x01 : "HP-UX",
            0x02 : "NetBSD",
            0x03 : "Linux",
            0x04 : "GNU Hurd",
            0x06 : "Solaris",
            0x07 : "AIX",
            0x08 : "IRIX",
            0x09 : "FreeBSD",
            0x0A : "Tru64",
            0x0B : "Novell Modesto",
            0x0C : "OpenBSD",
            0x0D : "OpenVMS",
            0x0E : "NonStop Kernel",
            0x0F : "AROS",
            0x10 : "Fenix OS",
            0x11 : "CloudABI"
            }

    DIC_TYPE = {
            0x00 : "ET_NONE",
            0x01 : "ET_REL",
            0x02 : "ET_EXEC",
            0x03 : "ET_DYN",
            0x04 : "ET_CORE",
            0xfe00 : "ET_LOOS",
            0xfeff : "ET_HIOS",
            0xff00 : "ET_LOPROC",
            0xffff : "ET_HIPROC"
            }

    DIC_MACHINE = {
            0x00 : "No specific instruction set",
            0x02 : "SPARC",
            0x03 : "x86",
            0x08 : "MIPS",
            0x14 : "PowerPC",
            0x16 : "S390",
            0x28 : "ARM",
            0x2A : "SuperH",
            0x32 : "IA-64",
            0x3E : "x86-64",
            0xB7 : "AArch64",
            0xF3 : "RISC-V"
            }

    H_KEY_EI_CLASS = 0
    H_KEY_EI_DATA = 1
    H_KEY_EI_VERSION = 2
    H_KEY_EI_OSABI = 3
    H_KEY_EI_ABIVERSION = 4
    H_KEY_EI_PAD = 5
    H_KEY_E_TYPE = 6
    H_KEY_E_MACHINE = 7
    H_KEY_E_VERSION = 8
    H_KEY_E_ENTRY = 9
    H_KEY_E_PHOFF = 10
    H_KEY_E_SHOFF = 11
    H_KEY_E_FLAGS = 12
    H_KEY_E_EHSIZE = 13
    H_KEY_E_PHENTSIZE = 14
    H_KEY_E_PHNUM = 15
    H_KEY_E_SHENTSIZE = 16
    H_KEY_E_SHNUM = 17
    H_KEY_E_SHSTRNDX = 18


    DIC_H_KEY = {
            H_KEY_EI_CLASS : "EI_CLASS",
            H_KEY_EI_DATA : "EI_DATA",
            H_KEY_EI_VERSION : "EI_VERSION",
            H_KEY_EI_OSABI : "EI_OSABI",
            H_KEY_EI_ABIVERSION : "EI_ABIVERSION",
            H_KEY_EI_PAD : "EI_PAD",
            H_KEY_E_TYPE : "e_type",
            H_KEY_E_MACHINE : "e_machine",
            H_KEY_E_VERSION : "e_version",
            H_KEY_E_ENTRY : "e_entry",
            H_KEY_E_PHOFF : "e_phoff",
            H_KEY_E_SHOFF : "e_shoff",
            H_KEY_E_FLAGS : "e_flags",
            H_KEY_E_EHSIZE : "e_ehsize",
            H_KEY_E_PHENTSIZE : "e_phentsize",
            H_KEY_E_PHNUM : "e_phnum",
            H_KEY_E_SHENTSIZE : "e_shentsize",
            H_KEY_E_SHNUM : "e_shnum",
            H_KEY_E_SHSTRNDX : "e_shstrndx"
            }

    TUP_32BIT_OFFSET = (
            (H_KEY_EI_DATA, (0x05, 1)),
            (H_KEY_EI_VERSION, (0x06, 1)),
            (H_KEY_EI_OSABI, (0x07, 1)),
            (H_KEY_EI_ABIVERSION, (0x08, 1)),
            (H_KEY_EI_PAD, (0x09, 7)),
            (H_KEY_E_TYPE, (0x10, 2)),
            (H_KEY_E_MACHINE, (0x12, 2)),
            (H_KEY_E_VERSION, (0x14, 4)),
            (H_KEY_E_ENTRY, (0x18, 4)),
            (H_KEY_E_PHOFF, (0x1C, 4)),
            (H_KEY_E_SHOFF, (0x20, 4)),
            (H_KEY_E_FLAGS, (0x24, 4)),
            (H_KEY_E_EHSIZE, (0x28, 2)),
            (H_KEY_E_PHENTSIZE, (0x2A, 2)),
            (H_KEY_E_PHNUM, (0x2C, 2)),
            (H_KEY_E_SHENTSIZE, (0x2E, 2)),
            (H_KEY_E_SHNUM, (0x30, 2)),
            (H_KEY_E_SHSTRNDX, (0x32, 2))
            )

    TUP_64BIT_OFFSET = (
            (H_KEY_EI_DATA, (0x05, 1)),
            (H_KEY_EI_VERSION, (0x06, 1)),
            (H_KEY_EI_OSABI, (0x07, 1)),
            (H_KEY_EI_ABIVERSION, (0x08, 1)),
            (H_KEY_EI_PAD, (0x09, 7)),
            (H_KEY_E_TYPE, (0x10, 2)),
            (H_KEY_E_MACHINE, (0x12, 2)),
            (H_KEY_E_VERSION, (0x14, 4)),
            (H_KEY_E_ENTRY, (0x18, 8)),
            (H_KEY_E_PHOFF, (0x20, 8)),
            (H_KEY_E_SHOFF, (0x28, 8)),
            (H_KEY_E_FLAGS, (0x30, 4)),
            (H_KEY_E_EHSIZE, (0x34, 2)),
            (H_KEY_E_PHENTSIZE, (0x36, 2)),
            (H_KEY_E_PHNUM, (0x38, 2)),
            (H_KEY_E_SHENTSIZE, (0x3A, 2)),
            (H_KEY_E_SHNUM, (0x3C, 2)),
            (H_KEY_E_SHSTRNDX, (0x3E, 2))
            )

    DIC_OFFSET = {
            1: TUP_32BIT_OFFSET,
            2: TUP_64BIT_OFFSET
            }

    HEADER_32BIT_SIZE = 47
    HEADER_64BIT_SIZE = 59

    DIC_HEADER_SIZE = {
            1: HEADER_32BIT_SIZE,
            2: HEADER_64BIT_SIZE
            }

    DIC_VALUE = {
            H_KEY_EI_DATA : [1, 2],
            H_KEY_EI_VERSION : [1],
            H_KEY_EI_OSABI : DIC_ABI.keys(),
            H_KEY_E_TYPE : DIC_TYPE.keys(),
            H_KEY_E_MACHINE : DIC_MACHINE.keys(),
            }

    DIC_CLASS = {
            1 : "ELF32",
            2 : "ELF64"
            }

    @staticmethod
    def GET_OS_ABI_STR(bit_mask):
        return ELF_HEADER.DIC_ABI.get(bit_mask, None)

    @staticmethod
    def GET_TYPE(bit_mask):
        return ELF_HEADER.DIC_TYPE.get(bit_mask, None)

    @staticmethod
    def GET_MACHINE(bit_mask):
        return ELF_HEADER.DIC_MACHINE.get(bit_mask, None)

    @staticmethod
    def GET_CLASS(bit_mask):
        return ELF_HEADER.DIC_CLASS.get(bit_mask, None)

    @staticmethod
    def PRINT_RESULT(parsing_result):
        print("========== elf header ==========")
        DIC_I2A = {
                ELF_HEADER.H_KEY_EI_OSABI : ELF_HEADER.GET_OS_ABI_STR,
                ELF_HEADER.H_KEY_E_TYPE : ELF_HEADER.GET_TYPE,
                ELF_HEADER.H_KEY_E_MACHINE : ELF_HEADER.GET_MACHINE,
                ELF_HEADER.H_KEY_EI_CLASS : ELF_HEADER.GET_CLASS,
                }

        for k in sorted(parsing_result):
            v = parsing_result[k]
            if k in DIC_I2A:
                func = DIC_I2A[k]
                print("key: %s, value: %s" % (ELF_HEADER.DIC_H_KEY.get(k), func(v)))
            else:
                print("key: %s, value: %d" % (ELF_HEADER.DIC_H_KEY.get(k), v))


    MAGIC_SIZE = 5
    BIT_MASK_OFFSET = 4
    MAGIC_STR = b'\x7f\x45\x4c\x46'
    BIT_FLAG_32 = 1
    BIT_FLAG_64 = 2


class ELF_PH:
    def __init__(self):
        pass

    DIC_TYPE = {
            0x00000000 : "PT_NULL",
            0x00000001 : "PT_LOAD",
            0x00000002 : "PT_DYNAMIC",
            0x00000003 : "PT_INTERP",
            0x00000004 : "PT_NOTE",
            0x00000005 : "PT_SHLIB",
            0x00000006 : "PT_PHDR",
            0x60000000 : "PT_LOOS",
            0x6FFFFFFF : "PT_HIOS",
            0x70000000 : "PT_LOPROC",
            0x7FFFFFFF : "PT_HIPROC"
            }

    H_KEY_TYPE = 0
    H_KEY_OFFSET = 1
    H_KEY_VADDR = 2
    H_KEY_PADDR = 3
    H_KEY_FILESZ = 4
    H_KEY_MEMSZ = 5
    H_KEY_FLAGS = 6
    H_KEY_ALIGN = 7

    DIC_H_KEY = {
            H_KEY_TYPE : "p_type",
            H_KEY_OFFSET : "p_offset",
            H_KEY_VADDR : "p_vaddr",
            H_KEY_PADDR : "p_paddr",
            H_KEY_FILESZ : "p_filesz",
            H_KEY_MEMSZ : "p_memsz",
            H_KEY_FLAGS : "p_flags",
            H_KEY_ALIGN : "p_align",
            }

    TUP_32BIT_OFFSET = (
            (H_KEY_TYPE, (0x00, 4)),
            (H_KEY_OFFSET, (0x04, 4)),
            (H_KEY_VADDR, (0x08, 4)),
            (H_KEY_PADDR, (0x0C, 4)),
            (H_KEY_FILESZ, (0x10, 4)),
            (H_KEY_MEMSZ, (0x14, 4)),
            (H_KEY_FLAGS, (0x18, 4)),
            (H_KEY_ALIGN, (0x1C, 4)),
            )

    TUP_64BIT_OFFSET = (
            (H_KEY_TYPE, (0x00, 4)),
            (H_KEY_FLAGS, (0x04, 4)),
            (H_KEY_OFFSET, (0x08, 8)),
            (H_KEY_VADDR, (0x10, 8)),
            (H_KEY_PADDR, (0x18, 8)),
            (H_KEY_FILESZ, (0x20, 8)),
            (H_KEY_MEMSZ, (0x28, 8)),
            (H_KEY_ALIGN, (0x30, 8)),
            )

    DIC_OFFSET = {
            1: TUP_32BIT_OFFSET,
            2: TUP_64BIT_OFFSET
            }

    HEADER_32BIT_SIZE = 32
    HEADER_64BIT_SIZE = 56

    DIC_HEADER_SIZE = {
            1: HEADER_32BIT_SIZE,
            2: HEADER_64BIT_SIZE
            }

    @staticmethod
    def GET_TYPE(bit_mask):
        return ELF_PH.DIC_TYPE.get(bit_mask, None)

    @staticmethod
    def PRINT_RESULT(parsing_result):
        print("========== elf program header ==========")
        DIC_I2A = {
                ELF_PH.H_KEY_TYPE : ELF_PH.GET_TYPE,
                }

        for idx in range(0, len(parsing_result)):
            print("%d" % idx)
            ph_header = parsing_result[idx]
            for k in sorted(ph_header):
                v = ph_header[k]
                if k in DIC_I2A:
                    func = DIC_I2A[k]
                    print("key: %s, value: %s" % (ELF_PH.DIC_H_KEY.get(k), func(v)))
                else:
                    print("key: %s, value: %d" % (ELF_PH.DIC_H_KEY.get(k), v))


class ELF_SH:
    def __init__(self):
        pass

    DIC_TYPE = {
            0x0 : "SHT_NULL",
            0x1 : "SHT_PROGBITS",
            0x2 : "SHT_SYMTAB",
            0x3 : "SHT_STRTAB",
            0x4 : "SHT_RELA",
            0x5 : "SHT_HASH",
            0x6 : "SHT_DYNAMIC",
            0x7 : "SHT_NOTE",
            0x8 : "SHT_NOBITS",
            0x9 : "SHT_RELA",
            0x0A : "SHT_SHLIB",
            0x0B : "SHT_DYNSYM",
            0x0E : "SHT_INIT_ARRAY",
            0x0F : "SHT_FINI_ARRAY",
            0x10 : "SHT_PREINIT_ARRAY",
            0x11 : "SHT_GROUP",
            0x12 : "SHT_SYMTAB_SHNDX",
            0x13 : "SHT_NUM",
            0x60000000 : "SHT_LOOS",
            }

    DIC_FLAGS = {
            0x1 : "SHF_WRITE",
            0x2 : "SHF_ALLOC",
            0x4 : "SHF_EXECINSTR",
            0x10 : "SHF_MERGE",
            0x20 : "SHF_STRINGS",
            0x40 : "SHF_INFO_LINK",
            0x80 : "SHF_LINK_ORDER",
            0x100 : "SHF_OS_NONCONFORMING",
            0x200 : "SHF_GROUP",
            0x400 : "SHF_TLS",
            0x0ff00000 : "SHF_MASKOS",
            0xf0000000 : "SHF_MASKPROC",
            0x4000000 : "SHF_ORDERED",
            0x8000000 : "SHF_EXCLUDE"
            }

    H_KEY_SH_NAME = 0
    H_KEY_SH_TYPE = 1
    H_KEY_SH_FLAGS = 2
    H_KEY_SH_ADDR = 3
    H_KEY_SH_OFFSET = 4
    H_KEY_SH_SIZE = 5
    H_KEY_SH_LINK = 6
    H_KEY_SH_INFO = 7
    H_KEY_SH_ADDRALIGN = 8
    H_KEY_SH_ENTSIZE = 9

    DIC_H_KEY = {
            H_KEY_SH_NAME : "sh_name",
            H_KEY_SH_TYPE : "sh_type",
            H_KEY_SH_FLAGS : "sh_flags",
            H_KEY_SH_ADDR : "sh_addr",
            H_KEY_SH_OFFSET : "sh_offset",
            H_KEY_SH_SIZE : "sh_size",
            H_KEY_SH_LINK : "sh_link",
            H_KEY_SH_INFO : "sh_info",
            H_KEY_SH_ADDRALIGN : "sh_addralign",
            H_KEY_SH_ENTSIZE : "sh_entsize"
            }

    TUP_32BIT_OFFSET = (
            (H_KEY_SH_NAME, (0x00, 4)),
            (H_KEY_SH_TYPE, (0x04, 4)),
            (H_KEY_SH_FLAGS, (0x08, 4)),
            (H_KEY_SH_ADDR, (0x0C, 4)),
            (H_KEY_SH_OFFSET, (0x10, 4)),
            (H_KEY_SH_SIZE, (0x14, 4)),
            (H_KEY_SH_LINK, (0x18, 4)),
            (H_KEY_SH_INFO, (0x1C, 4)),
            (H_KEY_SH_ADDRALIGN, (0x20, 4)),
            (H_KEY_SH_ENTSIZE, (0x24, 4))
            )

    TUP_64BIT_OFFSET = (
            (H_KEY_SH_NAME, (0x00, 4)),
            (H_KEY_SH_TYPE, (0x04, 4)),
            (H_KEY_SH_FLAGS, (0x08, 8)),
            (H_KEY_SH_ADDR, (0x10, 8)),
            (H_KEY_SH_OFFSET, (0x18, 8)),
            (H_KEY_SH_SIZE, (0x20, 8)),
            (H_KEY_SH_LINK, (0x28, 4)),
            (H_KEY_SH_INFO, (0x2C, 4)),
            (H_KEY_SH_ADDRALIGN, (0x30, 8)),
            (H_KEY_SH_ENTSIZE, (0x38, 8))
            )

    DIC_OFFSET = {
            1: TUP_32BIT_OFFSET,
            2: TUP_64BIT_OFFSET
            }

    @staticmethod
    def GET_TYPE(bit_mask):
        return ELF_SH.DIC_TYPE.get(bit_mask, None)

    @staticmethod
    def GET_FLAGS(bit_mask):
        values = list()
        for k, v in ELF_SH.DIC_FLAGS.items():
            if bit_mask & k:
                values.append(v)

        if values:
            return (',').join(values)
        else:
            return bit_mask

    @staticmethod
    def PRINT_RESULT(parsing_result):
        print("========== elf section header ==========")
        DIC_I2A = {
                ELF_SH.H_KEY_SH_TYPE : ELF_SH.GET_TYPE,
                ELF_SH.H_KEY_SH_FLAGS : ELF_SH.GET_FLAGS
                }

        for idx in range(0, len(parsing_result)):
            print("%d" % idx)
            sh_header = parsing_result[idx]
            for k in sorted(sh_header):
                v = sh_header[k]
                if k in DIC_I2A:
                    func = DIC_I2A[k]
                    value = func(v)
                else:
                    value = v

                print("key: %s, value: %s" % (ELF_SH.DIC_H_KEY.get(k), value))


class ELF:
    def __init__(self):
        pass

    def parse_header(self, f):
        parsing_result = dict()
        f.seek(0)
        magic_buf = f.read(ELF_HEADER.MAGIC_SIZE)

        if len(magic_buf) is not ELF_HEADER.MAGIC_SIZE:
            return None

        if not magic_buf.startswith(ELF_HEADER.MAGIC_STR):
            return None

        bin_bit_mask = magic_buf[ELF_HEADER.BIT_MASK_OFFSET:(ELF_HEADER.BIT_MASK_OFFSET + 1)]
        bit_mask = struct.unpack("<B", bin_bit_mask)[0]
        tup_offset = ELF_HEADER.DIC_OFFSET.get(bit_mask, None)

        if tup_offset is None:
            return None

        header_size = ELF_HEADER.DIC_HEADER_SIZE.get(bit_mask, None)

        if header_size is None:
            return None

        parsing_result[ELF_HEADER.H_KEY_EI_CLASS] = bit_mask

        header_buf = f.read(header_size)

        if len(header_buf) != header_size:
            return None

        for k, v in tup_offset:
            (offset, size) = v

            s_offset = offset - ELF_HEADER.MAGIC_SIZE
            e_offset = s_offset + size

            bin_data = header_buf[s_offset:e_offset]
            num = ELF_META.GET_ENDIAN(bin_data)

            if num is None:
                continue

            validate_list = ELF_HEADER.DIC_VALUE.get(k, None)

            if validate_list:
                if not num in validate_list:
                    continue

            parsing_result[k] = num

        return parsing_result


    def parse_ph(self, f, header_result):
        result = list()
        dic_offset_key = header_result.get(ELF_HEADER.H_KEY_EI_CLASS, None)

        if dic_offset_key is None:
            return None

        tup_offset = ELF_PH.DIC_OFFSET.get(dic_offset_key, None)

        if tup_offset is None:
            return None

        ph_offset = header_result.get(ELF_HEADER.H_KEY_E_PHOFF, None)

        if ph_offset is None:
            return None

        f.seek(ph_offset)

        header_size = header_result.get(ELF_HEADER.H_KEY_E_PHENTSIZE, None)

        if header_size is None:
            return None

        header_cnt = header_result.get(ELF_HEADER.H_KEY_E_PHNUM, 0)
        for idx in range(0, header_cnt):
            header_buf = f.read(header_size)
            ph_header = dict()
            for k, v in tup_offset:
                (offset, size) = v

                e_offset = offset + size
                bin_data = header_buf[offset:e_offset]
                num = ELF_META.GET_ENDIAN(bin_data)

                if num is None:
                    continue

                ph_header[k] = num

            result.append(ph_header)

        return result


    def parse_sh(self, f, header_result):
        result = list()
        dic_offset_key = header_result.get(ELF_HEADER.H_KEY_EI_CLASS, None)

        if dic_offset_key is None:
            return None

        tup_offset = ELF_SH.DIC_OFFSET.get(dic_offset_key, None)

        if tup_offset is None:
            return None

        sh_offset = header_result.get(ELF_HEADER.H_KEY_E_SHOFF, None)

        if sh_offset is None:
            return None

        f.seek(sh_offset)

        header_size = header_result.get(ELF_HEADER.H_KEY_E_SHENTSIZE, None)

        if header_size is None:
            return None

        header_cnt  = header_result.get(ELF_HEADER.H_KEY_E_SHNUM, 0)
        for idx in range(0, header_cnt):
            header_buf = f.read(header_size)

            if len(header_buf) < header_size:
                return None

            sh_header = dict()
            for k, v in tup_offset:
                (offset, size) = v

                e_offset = offset + size
                bin_data = header_buf[offset:e_offset]
                num = ELF_META.GET_ENDIAN(bin_data)

                if num is None:
                    continue

                sh_header[k] = num

            result.append(sh_header)

        shstrndx = header_result.get(ELF_HEADER.H_KEY_E_SHSTRNDX, None)
        if shstrndx is None or shstrndx >= header_cnt:
            return None

        shstrtab = result[shstrndx]
        shstrtab_offset = shstrtab.get(ELF_SH.H_KEY_SH_OFFSET, None)
        if shstrtab_offset is None:
            return None

        shstrtab_size = shstrtab.get(ELF_SH.H_KEY_SH_SIZE, None)

        if shstrtab_size is None:
            return None

        f.seek(shstrtab_offset)
        buf_shstr = f.read(shstrtab_size)

        for sh_header in result:
            name_pos = sh_header[ELF_SH.H_KEY_SH_NAME]
            end_pos = buf_shstr.find(b'\x00', name_pos)
            section_name = buf_shstr[name_pos:end_pos].decode('utf-8')
            sh_header[ELF_SH.H_KEY_SH_NAME] = section_name

#            if section_name == '.strtab':
#                print(sh_header)
#                f.seek(5840)
#                print(f.read(536))
#            elif section_name == '.symtab':
#                print(sh_header)
#                f.seek(4208)
#                print(f.read(1632))
#            elif section_name == '.dynsym':
#                print(sh_header)
#                f.seek(696)
#                print(f.read(96))




        return result


    def parse(self, file_path):
        f = open(file_path, 'rb')
        header_result = self.parse_header(f)
        ph_result = self.parse_ph(f, header_result)
        sh_result = self.parse_sh(f, header_result)
        f.close()
        return (header_result, ph_result, sh_result)


if __name__ == "__main__":
    if (len(sys.argv)) <= 1:
        print("elf_parser.py -h or --help to see the manual.")

    use = "Usage: %prog [option] filename"

    parser = OptionParser(usage=use)
    parser.add_option("-f", "--file", dest="file_path", action="store", help="path to elf file", metavar="FILE")

    options, args = parser.parse_args()

    elf = ELF()
    (header_result, ph_result, sh_result) = elf.parse(options.file_path)

    if header_result is not None:
        ELF_HEADER.PRINT_RESULT(header_result)
    else:
        print("Invalid elf header")
        sys.exit(1)

    if ph_result is not None:
        ELF_PH.PRINT_RESULT(ph_result)
    else:
        print("Invalid elf program header")
        sys.exit(2)

    if sh_result is not None:
        ELF_SH.PRINT_RESULT(sh_result)
    else:
        print("Invalid elf section header")
        sys.exit(2)


    sys.exit(0)
