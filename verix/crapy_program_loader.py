# @category endes.verix

# This only fixes the memory blocks, someday i will made a PL
# maybe following this guide https://wrongbaud.github.io/posts/writing-a-ghidra-loader/

memory = currentProgram.getMemory()
af = currentProgram.getAddressFactory()


currentProgram.setExecutableFormat("Verix Bin")

# Delete raw binary labels
clear_range = af.getAddressSet(currentProgram.getImageBase(),
                               currentProgram.getImageBase().add(10))
clearListing(clear_range, False, True, False, False, False, False,
             False, False, False, False, False, False)

# fix memory blocks
code_block = memory.getBlock("ram")
memory.moveBlock(code_block, af.getAddress("0x70420000"), monitor)
code_block.setName("code")

# Set File Header
createChar(code_block.getStart())
createBookmark(code_block.getStart(), "File header", "Magic")

createData(code_block.getStart().add(0x8),
           ghidra.program.model.data.PointerDataType.dataType)
createBookmark(code_block.getStart().add(0x8), "File header", "Program start")

createData(code_block.getStart().add(0x1c),
           ghidra.program.model.data.PointerDataType.dataType)
createBookmark(code_block.getStart().add(0x1c), "File header", "Program entry")
addEntryPoint(getDataAt(code_block.getStart().add(0x1c)).getValue())


# Create others memory blocks
system_block = memory.createUninitializedBlock(
    "system", af.getAddress("0x70000000"), 0x100000, False)
system_block.setPermissions(True, True, True)
system_block.setVolatile(False)

system_data_block = memory.createUninitializedBlock(
    "system_data", af.getAddress("0x7041fe01"), 0x1ff, False)
system_data_block.setPermissions(True, True, False)
system_data_block.setVolatile(False)

heap_block = memory.createUninitializedBlock(
    "heap", af.getAddress("0x70100000"), 0x300000, False)
heap_block.setPermissions(True, True, False)
heap_block.setVolatile(True)

stack_block = memory.createUninitializedBlock(
    "stack", af.getAddress("0x70400000"), 0x1fe01, False)
stack_block.setPermissions(True, True, False)
stack_block.setVolatile(True)
