from binaryninja.interaction import show_message_box
from binaryninja.binaryview import BinaryReader
from binaryninja.enums import MessageBoxIcon
from filebytes.elf import ELF, PT, PF

from .hook import Hook
import sys

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3
PY34 = sys.version_info[0:2] >= (3, 4)


if PY3:
    buffer=bytes


class HookManager():

    def __init__(self, bv):
        self.hooks = []

        self.bv = bv
        self.rawbv = bv.parent_view


    def install_hook(self, hook):
        assert hook.is_assembled(), "Invalid Hookstate"

        self.parse_binary()

        code_start_addr = self.make_space(hook.code_length())
        if not code_start_addr:
            return False

        install_success = hook.install(code_start_addr)
        if not install_success:
            return False

        return self.track_hook(hook)


    def track_hook(self, hook):
        assert hook.is_installed(), "Invalid Hookstate"
        self.hooks.append(hook)
        return True


    ''' Subclasses must implement these '''
    def parse_binary(self):
        raise NotImplementedError()
    def make_space(self, amount):
        raise NotImplementedError()


class ElfHookManager(HookManager):
    def parse_binary(self):
        br = BinaryReader(self.rawbv)
        br.seek(0)
        binary_bytes = br.read(self.rawbv.end)
        self.bininfo = ELF('thisbinary', binary_bytes)
        self.text_seg = None
        self.text_seg_index = 0
        for s in self.bininfo.segments:
            if s.header.p_type == PT.LOAD and s.header.p_flags & PF.EXEC:
                self.text_seg = s
                break
            self.text_seg_index += 1

        if self.text_seg is None:
            show_message_box('Parse Fail', 'Can\'t find text segment of binary!', icon=MessageBoxIcon.ErrorIcon)
            return False

        return True

    def make_space(self, amount):
        code_start_addr = self.text_seg.header.p_vaddr + self.text_seg.header.p_memsz

        self.bv.remove_auto_segment(self.text_seg.header.p_vaddr, self.text_seg.header.p_memsz)

        self.text_seg.header.p_memsz += amount
        self.text_seg.header.p_filesz += amount

        e_header = self.bininfo.elfHeader.header
        self.rawbv.write(e_header.e_phoff + (e_header.e_phentsize * self.text_seg_index), buffer(self.text_seg.header)[:])

        self.bv.add_auto_segment(self.text_seg.header.p_vaddr, self.text_seg.header.p_memsz, self.text_seg.header.p_offset, self.text_seg.header.p_memsz, 5)

        return code_start_addr


def hook_manager_create(bv):
    if bv.view_type == 'ELF':
        return ElfHookManager(bv)
    else:
        return None
