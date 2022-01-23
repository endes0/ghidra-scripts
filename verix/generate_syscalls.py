# @category endes.verix

af = currentProgram.getAddressFactory()

syscall_block = getMemoryBlock("syscall_block")
if syscall_block is None:
  syscall_block = currentProgram.getMemory().createUninitializedBlock("syscall_block", af.getAddress("OTHER:0") , 0xFF, True)
  #TODO create syscalls functions

first_addr = find(None, 0xdf)
current_addr = first_addr

while True:
    instr = getInstructionAt(current_addr)
    if instr is not None:
        print(instr)
        id = instr.getInputObjects()[1].getValue()

        if len(getReferencesFrom(current_addr)) == 0:
            createMemoryReference(instr, 0, syscall_block.getStart().add(
                id), ghidra.program.model.symbol.RefType.CALLOTHER_OVERRIDE_CALL)
        else:
            print("already made")

    current_addr = find(current_addr.next(), 0xdf)
    if current_addr is None or current_addr == first_addr:
        break
