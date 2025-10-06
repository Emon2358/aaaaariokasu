# ghidra_scripts/export_all_decompiled.py
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from java.io import FileWriter, File
import os

out_dir = "recovered/ghidra_out"
if not os.path.exists(out_dir):
    os.makedirs(out_dir)

di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

funcs = currentProgram.getFunctionManager().getFunctions(True)
for f in funcs:
    try:
        res = di.decompileFunction(f, 60, monitor)
        if res.decompileDone():
            decomp_text = res.getDecompiledFunction().getC()
            safe_name = f.getName().replace("/", "_").replace("\\", "_")
            filename = os.path.join(out_dir, f"{safe_name}_0x{f.getEntryPoint().getOffset():x}.c")
            fw = FileWriter(File(filename))
            fw.write("// Function: {} at {}\n".format(f.getName(), f.getEntryPoint()))
            fw.write(decomp_text)
            fw.close()
    except Exception as e:
        print("Failed decompile for {}: {}".format(f.getName(), e))

print("Ghidra export script finished.")
