import struct
import logging
try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO

__all__ = ['BootImage']

class FormatError(Exception):
    pass

class BootImage:
    BOOT_MAGIC = b'ANDROID!'
    BOOT_MAGIC_SIZE = 8
    BOOT_NAME_SIZE = 16
    BOOT_ARGS_SIZE = 512
    BOOT_ID_SIZE = 8 * 4

    BASE_KERNEL_ADDR = 0x00008000
    BASE_RAMDISK_ADDR = 0x01000000
    BASE_SECOND_ADDR = 0x00F00000
    BASE_TAGS_ADDR = 0x00000100
    

    def __init__(self, file, **kargs):
        '''guess should be one of the following:
        *   string representing the path of boot.boot_img
        *   a file-like object
        *   None (use argument dictionary instead)
        '''

        self.file = file

        self._update_config(**kargs)

        try:

            self.magic = self.file.read(self.BOOT_MAGIC_SIZE)
            if self.magic != self.BOOT_MAGIC:
                raise FormatError('Not a valid android kernel image')

            logging.info("[+] Valid android boot.img. Splitting... ")

            self.kernel_size = self._read_uint()  # size in bytes
            self.kernel_addr = self._read_uint()  # physical load addr

            self.base = self.kernel_addr - self.BASE_KERNEL_ADDR

            self.ramdisk_size = self._read_uint() # size in bytes
            self.ramdisk_addr = self._read_uint() # physical load addr
            #print(hex(self.ramdisk_addr - self.BASE_RAMDISK_ADDR), hex(self.base))

            self.second_size = self._read_uint()  # size in bytes
            self.second_addr = self._read_uint()  # physical load addr

            self.tags_addr = self._read_uint()    # physical addr for kernel tags

            self.page_size = self._read_uint()    # flash page size we assume
            _ = self._read_uint()                 # future expansion: should be 0
            _ = self._read_uint()                 # future expansion: should be 0

            logging.info("[+] kernel at\t: 0x{:08X}".format(self.kernel_addr))
            logging.info("[+] ram_disk at\t: 0x{:08X}".format(self.ramdisk_addr))
            logging.info("[+] page size\t: {0}".format(self.page_size))


            self.name = self.file.read(self.BOOT_NAME_SIZE).decode('ascii').strip('\x00')
            self.cmdline = self.file.read(self.BOOT_ARGS_SIZE).decode('ascii').strip('\x00')
            self.id = self.file.read(self.BOOT_ID_SIZE)
            logging.info("[+] name\t: {0}".format(self.name))
            logging.info("[+] cmdline\t: {0}".format(self.cmdline))
            self.file.seek(1 * self.page_size)

            self.kernel_data = self.file.read(self.kernel_size)

            ramdisk_page = (self.kernel_size + self.page_size - 1)//self.page_size + 1
            self.file.seek(ramdisk_page * self.page_size)
            self.ramdisk_data = self.file.read(self.ramdisk_size)

            if self.second_size != 0:
                second_page = (self.second_size + self.page_size - 1)//self.page_size + ramdisk_page
                self.file.seek(second_page * self.page_size)
                self.second_data = self.file.read(self.second_size)
        except EOFError:
            raise FormatError("Bad boot.img format")

    def _read_uint(self):
        return struct.unpack('I', self.file.read(4))[0]

    def _update_config(self, **kargs):
        for i in ['BASE_KERNEL_ADDR', 'BASE_RAMDISK_ADDR',
                    'BASE_SECOND_ADDR', 'BASE_TAGS_ADDR',
                    'BOOT_MAGIC_SIZE', 'BOOT_NAME_SIZE',
                    'BOOT_ARGS_SIZE', 'BOOT_ID_SIZE', 
                    'BOOT_MAGIC'
                ]:
            if i in kargs:
                setattr(self, i, kargs[i])

    def decompress_kernel(self):
        return decompress(self.kernel_data)

def decompress(kernel_data):
    def _un_gz():
        offset = kernel_data.find(b'\x1f\x8b\x08')
        if offset>0:
            try:
                import zlib
                data = zlib.decompress(kernel_data[offset+10:], -zlib.MAX_WBITS)
            except ImportError:
                logging.error("Need zlib to decompress gzip data")
                raise
            return data
        else:
            return None

    def _un_xz():
        offset = kernel_data.find(b'\xfd7zXZ\x00')
        offset = kernel_data.find(b'\xfd7zXZ\x00', offset+6)
        if offset > 0:
            try:
                import lzma
                return lzma.decompress(kernel_data[offset:])
            except ImportError:
                logging.error("Need pyliblzma(python2)/lzma(python3) to decompress gzip data")
                raise
        else:
            return None

    def _un_lzo():
        offset = kernel_data.find(b'\x89LZO\x00')
        offset = kernel_data.find(b'\x89LZO\x00', offset+5)
        if offset > 0:
            try:
                import _lzo
                f = BytesIO(kernel_data[offset:])

                magic = f.read(9)
                assert(magic ==  b'\x89LZO\x00\x0d\x0a\x1a\x0a')

                read8 = lambda : ord(f.read(1))
                read16 = lambda :struct.unpack(">H", f.read(2))[0]
                read32 = lambda :struct.unpack(">I", f.read(4))[0]

                ver = read16()
                libver = read16()
                if ver >= 0x0940:
                    extver = read16()
                method = read8()
                assert(method in [1,2,3])
                if ver >= 0x0940:
                    level = read8()

                flag = read32()
                F_H_FILTER = 0x00000800L
                F_H_EXTRA_FIELD = 0x00000040L

                if flag&F_H_FILTER:
                    ffilter = read32()

                mode = read32()
                read32()
                if ver >= 0x0940:
                    read32()

                l = read8()
                name = f.read(l)

                checksum = read32()
                if flag & F_H_EXTRA_FIELD:
                    l = read32()
                    f.read(l)
                    read32()

                buf = b''
                while True:
                    un_len = read32()
                    if un_len == 0:
                        break
                    com_len = read32()
                    checksum = read32()
                    block = f.read(com_len)
                    if com_len < un_len:
                        buf += _lzo.decompress(block[:com_len])
                    elif com_len == un_len:
                        buf += block
                    else:
                        raise Exception('Decompress Error')

                return buf
            except ImportError:
                logging.error("Need lzo library to decompress gzip data")
                raise
        else:
            return None

    def _un_lz4():
        # XXX TODO
        offset = kernel_data.find(b'\x02\x21\x4c\x18')
        if offset > 0:
            try:
                import lz4

            except ImportError:
                logging.error("Need lz4 library to decompress gzip data")
                raise
        else:
            return None


    decompressor = [_un_gz, _un_xz, _un_lzo]
    for decompress in decompressor:
        data = decompress()
        if data:
            logging.info('decompress using {0} succussfully'.format(decompress.__name__))
            return data
    
    raise Exception('Unkown compress')


class KernelSyms:
    _kallsyms_pattern = [
            struct.pack("<IIII", *(
                0xc0008000, # __init_begin
                0xc0008000, # _sinittext
                0xc0008000, # stext
                0xc0008000, # _text
                )),
             struct.pack("<II", *(
                0xc0008000, # stext
                0xc0008000, # _text
                )),
             struct.pack("<III", *(
                0xc00081c0, # asm_do_IRQ
                0xc00081c0, # _stext
                0xc00081c0, # __exception_text_start
                )),
            struct.pack("<III", *(
                0xc0008180, # asm_do_IRQ
                0xc0008180, # _stext
                0xc0008180, # __exception_text_start
                )),
        ]

    def __init__(self, kernel_data):
        self.data = kernel_data
        self.dict = {}

        self.kallsyms_addr = self._pattern_search()

        #XXX TODO: use log module
        logging.info("[+] Find kallsyms data at: 0x{:08X}".format(self.kallsyms_addr))
        logging.info("[+] Begin reading...")

        self._addr_list = []
        self._name_list = []
        self._marker_list = []
        self._token_index = []

        d = BytesIO(kernel_data)
        d.seek(self.kallsyms_addr)

        def _skip_null():
            pos = d.tell()
            #print pos
            if pos%16 == 0:
                return
            else:
                v = d.read(16 - pos % 16)
                #print(16 - pos % 16)
                assert(v == b'\x00'*(16 - pos % 16))

        logging.info("[+] address at\t: 0x{:08X}".format(d.tell()))
        while True:
            v = d.read(4)
            addr = struct.unpack('<I', v)[0]
            # XXX TODO:
            if addr < 0xc0000000:
                d.seek(d.tell()-4)
                break
            self._addr_list.append(addr)

        _skip_null()
        #print hex(d.tell())
        v = d.read(4)
        count = struct.unpack('<I',v)[0]
        #print(len(self._addr_list),hex(count))
        assert(len(self._addr_list) == count)
        self.num_syms = count

        logging.info("[+] read {0} symbols".format(count))

        _skip_null()
        logging.info("[+] name list at\t: 0x{:08X}".format(d.tell()))
        while True:
            v = d.read(1)
            len_ = struct.unpack('B', v)[0]
            assert(len_ != 0)
            name = d.read(len_)
            self._name_list.append(name)
            if len(self._name_list) == count:
                break

        _skip_null()

        if self._is_type_table(d.tell(), len(self.data)):
            self.has_type = True
            logging.info("[+] found type table at: 0x{:08X}".format(d.tell()))
            while True:
                v = d.read(4)
                if v == b'\x00\x00\x00\x00':
                    d.seek(d.tell() - 4)
                    break

        _skip_null()
        num_marker = (count + 255) // 256

        logging.info("[+] marker at\t: 0x{:08X}".format(d.tell()))
        while True:
            v = d.read(4)
            marker = struct.unpack(">I", v)[0]
            self._marker_list.append(marker)
            if len(self._marker_list) == num_marker:
                break


        _skip_null()
        while d.read(1) == b'\x00':
            pass
        pos = d.tell() - 1

        
        while d.read(2) != b'\x00\x00':
            pass
        pos2 = d.tell() - 1
        d.seek(pos2)
        self._token_data = self.data[pos:pos2]
        logging.info("[+] token_table at\t: 0x{:08X} - 0x{:08X}".format(pos, pos2))
    
        _skip_null()
        logging.info("[+] token index at\t: 0x{:08X}".format(d.tell()))
        while True:
            v = d.read(2)
            idx = struct.unpack("H", v)[0]
            self._token_index.append(idx)
            if len(self._token_index) == 256:
                break

        for i in range(count):
            name = self._name_list[i]
            addr = self._addr_list[i]
            #print(name)
            exp_name = b''
            for idx in name:
                idx = ord(idx)
                #idx = struct.unpack('B', c)[0]
                si = self._token_index[idx]
                di = self._token_data.find(b'\x00', si)
                #print(self._token_data[si:di])
                exp_name += self._token_data[si:di]

            func_name = exp_name[1:].decode('ascii')
            typ = exp_name[:1]
            if addr not in self.dict:
                self.dict[addr] = list()

            if func_name != '':
                self.dict[addr].append(func_name)
            else:
                self.dict[addr].append('__sub_{:08X}'.format(addr))



    def _pattern_search(self):
        for i in self._kallsyms_pattern:
            addr = self.data.find(i)
            if addr > 0:
                break

        #addr = self.data.rfind(struct.pack('<I',0), 0, addr) + 4
        assert(addr>0)
        return addr

    def _is_type_table(self, pos, length):
        if length - pos < 256*4 :
            return  False

        for i in range(256 * 4):
            t = ord(self.data[pos+i]) & 0x20
            if t != 0x54:
                return False

        return True

    def find(self, func_name):
        l = []
        for i, v in self.dict.items():
            if func_name in v:
                l.append(i)

        return l
                
