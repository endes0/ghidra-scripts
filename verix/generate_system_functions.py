# @category endes.verix

af = currentProgram.getAddressFactory()


def create_func(addr, signature_prototype):
    signature = ghidra.app.util.cparser.C.CParserUtils.parseSignature(None, currentProgram, signature_prototype)
    new_signature = ghidra.app.cmd.function.ApplyFunctionSignatureCmd(addr, signature, ghidra.program.model.symbol.SourceType.IMPORTED)
    createFunction(addr, signature.getName())
    runCommand(new_signature)


syscall_block = getMemoryBlock("syscall_block")
if syscall_block is None:
    raise Exception("No syscall_block, runn generate syscall first!")

# Create the guessed syscall
# this signatures are very WIP and posibly plain wrong
base_adddr = syscall_block.getStart()
create_func(base_adddr.add(0x2),
            "undefined syscall_fatal?? (undefined param_1, undefined param_2, undefined param_3)")
create_func(base_adddr.add(0x3),
            "undefined syscall_read? (int param_1, undefined param_2, char * param_3, int param_4)")
# TODO: syscall 4: close file
create_func(base_adddr.add(0x7),
            "undefined FUN_syscall_block__00000007 (int param1, char * param2)")
create_func(base_adddr.add(0x8),
            "undefined syscall_get_value (char * param_1, char * param_2, undefined param_3, char * param_4)")
create_func(base_adddr.add(0x9),
            "undefined syscall_set_val (char * param_1, char * param_2, undefined param_3, char * param_4)")
create_func(base_adddr.add(0xa),
            "undefined syscall_run? (int param_1, char * param_2, char * param_3)")
