from optparse import OptionParser
import os, sys
import struct


class ELF_META:
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

    TUP_32BIT_OFFSET = (
            ("EI_DATA", (0x05, 1)),
            ("EI_VERSION", (0x06, 1)),
            ("EI_OSABI", (0x07, 1)),
            ("EI_ABIVERSION", (0x08, 1)),
            ("EI_PAD", (0x09, 7)),
            ("e_type", (0x10, 2)),
            ("e_machine", (0x12, 2)),
            ("e_version", (0x14, 4)),
            ("e_entry", (0x18, 4)),
            ("e_phoff", (0x1C, 4)),
            ("e_shoff", (0x20, 4)),
            ("e_flags", (0x24, 4)),
            ("e_ehsize", (0x28, 2)),
            ("e_phentsize", (0x2A, 2)),
            ("e_phnum", (0x2C, 2)),
            ("e_shentsize", (0x2E, 2)),
            ("e_shnum", (0x30, 2)),
            ("e_shstrndx", (0x32, 2))
            )

    TUP_64BIT_OFFSET = (
            ("EI_DATA", (0x05, 1)),
            ("EI_VERSION", (0x06, 1)),
            ("EI_OSABI", (0x07, 1)),
            ("EI_ABIVERSION", (0x08, 1)),
            ("EI_PAD", (0x09, 7)),
            ("e_type", (0x10, 2)),
            ("e_machine", (0x12, 2)),
            ("e_version", (0x14, 4)),
            ("e_entry", (0x18, 8)),
            ("e_phoff", (0x20, 8)),
            ("e_shoff", (0x28, 8)),
            ("e_flags", (0x30, 4)),
            ("e_ehsize", (0x34, 2)),
            ("e_phentsize", (0x36, 2)),
            ("e_phnum", (0x38, 2)),
            ("e_shentsize", (0x3A, 2)),
            ("e_shnum", (0x3C, 2)),
            ("e_shstrndx", (0x3E, 2))
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
            "EI_DATA" : [1, 2],
            "EI_VERSION" : [1],
            "EI_OSABI" : DIC_ABI.keys(),
            "e_type" : DIC_TYPE.keys(),
            "e_machine" : DIC_MACHINE.keys(),
            }

    DIC_CLASS = {
            1 : "ELF32",
            2 : "ELF64"
            }

    @staticmethod
    def GET_OS_ABI_STR(bit_mask):
        return ELF_META.DIC_ABI.get(bit_mask, None)

    @staticmethod
    def GET_TYPE(bit_mask):
        return ELF_META.DIC_TYPE.get(bit_mask, None)

    @staticmethod
    def GET_MACHINE(bit_mask):
        return ELF_META.DIC_MACHINE.get(bit_mask, None)

    @staticmethod
    def GET_CLASS(bit_mask):
        return ELF_META.DIC_CLASS.get(bit_mask, None)

    @staticmethod
    def PRINT_RESULT(parsing_result):
        DIC_I2A = {
                "EI_OSABI" : ELF_META.GET_OS_ABI_STR,
                "e_type" : ELF_META.GET_TYPE,
                "e_machine" : ELF_META.GET_MACHINE,
                "EI_CLASS" : ELF_META.GET_CLASS,
                }


        for k, v in parsing_result:
            if k in DIC_I2A:
                func = DIC_I2A[k]
                print("key: %s, value: %s" % (k, func(v)))
            else:
                print("key: %s, value: %d" % (k, v))


    MAGIC_SIZE = 5
    BIT_MASK_OFFSET = 4
    MAGIC_STR = b'\x7f\x45\x4c\x46'
    BIT_FLAG_32 = 1
    BIT_FLAG_64 = 2



class ELF:
    def __init__(self):
        pass

    def header_parse(self, file_path):
        parsing_result = list()
        f = open(file_path, 'rb')
        magic_buf = f.read(ELF_META.MAGIC_SIZE)

        if len(magic_buf) is not ELF_META.MAGIC_SIZE:
            return None

        if not magic_buf.startswith(ELF_META.MAGIC_STR):
            return None

        bin_bit_mask = magic_buf[ELF_META.BIT_MASK_OFFSET:(ELF_META.BIT_MASK_OFFSET + 1)]
        bit_mask = struct.unpack("<B", bin_bit_mask)[0]
        dic_offset = ELF_META.DIC_OFFSET.get(bit_mask, None)

        if dic_offset is None:
            return None

        header_size = ELF_META.DIC_HEADER_SIZE.get(bit_mask, None)

        if header_size is None:
            return None

        header_buf = f.read(header_size)

        for k, v in dic_offset:
            (offset, size) = v
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
                continue

            s_offset = offset - ELF_META.MAGIC_SIZE
            e_offset = s_offset + size

            bin_data = header_buf[s_offset:e_offset]
            num = struct.unpack(fmt, bin_data)[0]

            validate_list = ELF_META.DIC_VALUE.get(k, None)

            if validate_list:
                if not num in validate_list:
                    continue

            parsing_result.append((k, struct.unpack(fmt, bin_data)[0]))

        return parsing_result


if __name__ == "__main__":
    if (len(sys.argv)) <= 1:
        print("elf_parser.py -h or --help to see the manual.")

    use = "Usage: %prog [option] filename"

    parser = OptionParser(usage=use)
    parser.add_option("-f", "--file", dest="file_path", action="store", help="path to elf file", metavar="FILE")

    options, args = parser.parse_args()

    elf = ELF()
    header_result = elf.header_parse(options.file_path)

    if header_result is not None:
        ELF_META.PRINT_RESULT(header_result)
    else:
        print("Invalid elf format")

