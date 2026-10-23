import subprocess

# Make a ~/.gdbinit file and add:
# source ~/SaBRe/debug-tools/gdb-symbol-loader.py
# Invoke from GDB as: sbr-sym and sbr-src

# For adding debugging source files for Ubuntu 18.04 you can add the following
# in your ~/.gdbinit:
# dir /usr/src/glibc/glibc-2.27/nptl
# dir /usr/src/glibc/glibc-2.27/elf
# dir /usr/src/glibc/glibc-2.27/libio
# dir /usr/src/gcc-7/src/libsanitizer/include/sanitizer

# Useful gdb commands: info file, remove-symbol-file


class AddSaBReSymbols(gdb.Command):
    @staticmethod
    def get_offsets(path):
        text_offset, bss_offset, rodata_offset = 0, 0, 0
        output = subprocess.check_output(["readelf", "-WS", path])
        for line in output.splitlines():
            line = str(line)
            if "] .text " in line:
                text_offset = "0x" + line.split()[5]
            if "] .bss " in line:
                bss_offset = "0x" + line.split()[5]
            if "] .rodata " in line:
                rodata_offset = "0x" + line.split()[5]
        return text_offset, bss_offset, rodata_offset

    @staticmethod
    def run_add_symbol_file(from_tty, lib, addr_start):
        text_offset, bss_offset, rodata_offset = AddSaBReSymbols.get_offsets(lib)

        gdb_cmd = (
            f"add-symbol-file {lib}"
            f" -s .text {addr_start}+{text_offset}"
            f" -s .bss {addr_start}+{bss_offset}"
        )
        if rodata_offset:
            gdb_cmd += f" -s .rodata {addr_start}+{rodata_offset}"
        print(gdb_cmd)
        gdb.execute(gdb_cmd, from_tty)

    def __init__(self):
        super(AddSaBReSymbols, self).__init__("sbr-sym", gdb.COMMAND_USER)
        self.dont_repeat()

    def invoke(self, args, from_tty):
        pagination = gdb.parameter("pagination")
        if pagination:
            gdb.execute("set pagination off")

        cmd = "info proc mappings"
        maplines = gdb.execute(cmd, from_tty, True).split("\n")

        argv = gdb.string_to_argv(args)
        if len(argv) > 0:
            for target in argv:
                print(f"Loading user provided target: {target}")
                for line in maplines:
                    if target in line:
                        line = line.strip().split()
                        addr_start, lib = line[0], line[4]
                        self.run_add_symbol_file(from_tty, lib, addr_start)
                        # TODO: We just add the first occurrence of a lib for
                        # now.
                        break
        else:
            print("Load symbols of mremap-ed libraries")

            # Find all libs that have an offset of 0x1000 and an empty mapping
            # just before.
            mremap_libs = []
            for i, line in enumerate(maplines[1:], start=1):
                prev_line = maplines[i - 1].strip().split()
                line = line.strip().split()

                if len(line) == 5 and line[3] == "0x1000" and len(prev_line) == 4:
                    mremap_libs.append((f"{line[0]}-0x1000", line[4]))

            for addr_start, lib in mremap_libs:
                self.run_add_symbol_file(from_tty, lib, addr_start)

        if pagination:
            gdb.execute("set pagination on")


AddSaBReSymbols()
