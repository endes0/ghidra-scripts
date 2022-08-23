# @category endes.esp8266

import ghidra
try:
    from ghidra.ghidra_builtins import *
except:
    pass

af = currentProgram.getAddressFactory()

#romcall_block = getMemoryBlock("romcall_block")
#if romcall_block is None:
#  romcall_block = currentProgram.getMemory().createUninitializedBlock("romcall_block", af.getAddress("OTHER:0") , 0xFFF, True)

first_addr = find(None, b'\xc0\x00\x00')
current_addr = first_addr
while True:
    instr = getInstructionAt(current_addr)
    if instr is not None and len(getReferencesFrom(current_addr)) == 0:

        load_addr = current_addr.previous()
        load_instr = getInstructionAt(load_addr)
        found = False
        for i in range(0, 20):
            if load_instr is not None and (load_instr.getMnemonicString() == "l32i.n" or load_instr.getMnemonicString() == "l32i") and load_instr.getResultObjects()[0].getName() == "a0":
                found = True
                break

            load_addr = load_addr.previous()
            load_instr = getInstructionAt(load_addr)
        
        if found:
            print("{} {}".format(current_addr,  getInstructionAt(load_addr)))
        
            val = None
            if type(load_instr.getInputObjects()[0]) == ghidra.program.model.scalar.Scalar:
                val = load_instr.getInputObjects()[0].getValue()
            else:
                val = load_instr.getInputObjects()[1].getValue()

            table_ref = getReferencesFrom(parseAddress("4000eabc").add(val))
            if len(table_ref) > 0:
                createMemoryReference(instr, 0, table_ref[0].getToAddress(), ghidra.program.model.symbol.RefType.CALL_OVERRIDE_UNCONDITIONAL)


    current_addr = find(current_addr.next(), b'\xc0\x00\x00')
    if current_addr is None or current_addr == first_addr:
        break
