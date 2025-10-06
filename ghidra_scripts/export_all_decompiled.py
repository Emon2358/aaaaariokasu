# ghidra_scripts/export_all_decompiled.py
# Ghidra headless decompilation export script (Jython environment)
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from java.io import FileWriter, File
import os

# 出力先ディレクトリ
out_base = "recovered/ghidra_out"
if not os.path.exists(out_base):
    os.makedirs(out_base)

di = DecompInterface()
di.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

funcs = currentProgram.getFunctionManager().getFunctions(True)
for f in funcs:
    try:
        res = di.decompileFunction(f, 60, monitor)
        if res.decompileDone():
            decomp_text = res.getDecompiledFunction().getC()
            name = f.getName().replace("/", "_").replace("\\", "_")
            filename = os.path.join(out_base, "{}_0x{:x}.c".format(name, f.getEntryPoint().getOffset()))
            fw = FileWriter(File(filename))
            fw.write("// Function: {} at {}\n".format(f.getName(), f.getEntryPoint()))
            fw.write(decomp_text)
            fw.close()
    except Exception as e:
        print("Failed decomp for {}: {}".format(f.getName(), e))

print("Ghidra export script finished.")

