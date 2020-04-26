from binaryninja.interaction import show_message_box
from binaryninja import enum
from binaryninja.enums import MessageBoxIcon
import sys


class HookState(enum.IntEnum):
    NEW = 0
    ASSEMBLED = 1
    INSTALLED = 2

class Hook():

    def __init__(self, bv, hook_addr, name):
        self._state = HookState.NEW

        self.bv = bv
        self.arch = bv.arch

        self.hook_name = name

        self.hook_addr = hook_addr
        self.hook_bytes = b''
        self.replaced_bytes = b''
        self.code_start_addr = None
        self.code_bytes = b''
        self.ret_addr = None
        self.ret_bytes = b''

        self.find_bytes_to_replace()


    def find_bytes_to_replace(self):
        num_bytes_to_replace = 0
        curr_addr = self.hook_addr
        while num_bytes_to_replace < self.get_hook_len():
            curr_instruction_len = self.bv.get_instruction_length(arch=self.arch, addr=curr_addr)
            num_bytes_to_replace += curr_instruction_len
            curr_addr += curr_instruction_len

        self.ret_addr = curr_addr
        self.replaced_bytes = self.bv.read(self.hook_addr, num_bytes_to_replace)

    def is_new(self):
        return self._state is HookState.NEW
    def is_assembled(self):
        return self._state is HookState.ASSEMBLED
    def is_installed(self):
        return self._state is HookState.INSTALLED


    def parse_asm_string(self, asm_string):
        assert self.is_new(), "Invalid Hookstate"

        try:
            asm_bytes = self.arch.assemble(asm_string)
        except:
            err = sys.exc_info()[0]
            show_message_box('Assemble fail', 'Assembly of string failed:\n\n{}\n\nError: {}\n'.format(asm_string, err), icon=MessageBoxIcon.ErrorIcon)
            return False

        self.code_bytes += asm_bytes

        self._state = HookState.ASSEMBLED
        return True


    def code_length(self):
        assert self.is_assembled(), "Invalid Hookstate"
        return len(self.code_bytes) + len(self.replaced_bytes) + self.get_hook_len()


    def install(self, code_start_addr):
        assert self.is_assembled(), "Invalid Hookstate"

        self.code_start_addr = code_start_addr
        hook_str = self.get_hook_format().format(self.code_start_addr - self.hook_addr)
        try:
            self.hook_bytes = self.arch.assemble(hook_str)
        except:
            err = sys.exc_info()[0]
            show_message_box('Assemble fail', 'Assembly of string failed:\n\n{}\n\nError: {}\n'.format(hook_str, err), icon=MessageBoxIcon.ErrorIcon)
            return False

        ret_str = self.get_hook_format().format(self.ret_addr - (self.code_start_addr + self.code_length()) + self.get_hook_len())
        try:
            self.ret_bytes = self.arch.assemble(ret_str)
        except:
            err = sys.exc_info()[0]
            show_message_box('Assemble fail', 'Assembly of string failed:\n\n{}\n\nError: {}\n'.format(ret_str, err), icon=MessageBoxIcon.ErrorIcon)
            return False

        written = self.bv.write(self.hook_addr, self.arch.convert_to_nop(self.replaced_bytes, 0))
        if written != len(self.replaced_bytes):
            return False

        written = self.bv.write(self.hook_addr, self.hook_bytes)
        if written != len(self.hook_bytes):
            return False

        written = self.bv.write(self.code_start_addr, self.code_bytes + self.replaced_bytes + self.ret_bytes)
        if written != self.code_length():
            return False

        self._state = HookState.INSTALLED
        return True


    ''' Subclasses must implement these '''
    def get_hook_format(self):
        raise NotImplementedError()
    def get_hook_len(self):
        raise NotImplementedError()




class x86Hook(Hook):
    def get_hook_format(self):
        return 'jmp {:#010x}'
    def get_hook_len(self):
        return 5


def hook_create(bv, hook_addr, name):
    if bv.arch.name == 'x86' or bv.arch.name == 'x86_64':
        return x86Hook(bv, hook_addr, name)
    else:
        return None
