from binaryninja.plugin import PluginCommand
from binaryninja.interaction import *
from binaryninja.enums import MessageBoxIcon

from .hookmanager import hook_manager_create
from .hook import hook_create

g_bn_hook_manager = None

def insert_hook(bv, addr):
    name = TextLineField('Hook Name')
    ASM_FILE = 'asm file'
    ASM_TEXTBOX = 'asm textbox'
    asm_input = ChoiceField('Hook code input', [ASM_FILE, ASM_TEXTBOX])
    ok = get_form_input([name, asm_input], 'Insert Hook')
    if not ok:
        show_message_box('Form Fail', 'The form returned an error.', icon=MessageBoxIcon.ErrorIcon)
        return False

    hook = hook_create(bv, addr, name.result)

    if asm_input.result == 0:
        asm_file_name = get_open_filename_input('asm file')
        if not asm_file_name:
            return False
        with open(asm_file_name) as asm_file:
            ok = hook.parse_asm_string(asm_file.read())
    else:
        asm_string = MultilineTextField('')
        ok = get_form_input([asm_string], 'asm code')
        if not ok:
            return False
        ok = hook.parse_asm_string(asm_string.result)

    if not ok:
        return False

    global g_bn_hook_manager
    if g_bn_hook_manager is None:
        g_bn_hook_manager = hook_manager_create(bv)
        if (g_bn_hook_manager is None):
            show_message_box('Unimplemented', 'This plugin does not support executables of type {} yet.'.format(bv.view_type), icon=MessageBoxIcon.ErrorIcon)
            return False

    ok = g_bn_hook_manager.install_hook(hook)

    if not ok:
        show_message_box('Install Fail', 'The hook failed to install.', icon=MessageBoxIcon.ErrorIcon)
        return False

    return True


PluginCommand.register_for_address('Insert Custom Hook', 'jumps to a custom piece of code, and jumps back, allowing the binary to continue as originally programmed', insert_hook)

