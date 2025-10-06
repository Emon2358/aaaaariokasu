# scripts/ghidra_decompile_functions.py
# Usage: analyzeHeadless ... -postScript ghidra_decompile_functions.py OUTDIR=/path/to/out
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args_str = getScriptArgs() or ""
args = args_str.split()
outdir = None
for a in args:
    if a.upper().startswith("OUTDIR="):
        outdir = a.split("=",1)[1]
if not outdir:
    outdir = os.getcwd()
if not os.path.isabs(outdir):
    outdir = os.path.abspath(outdir)
if not os.path.isdir(outdir):
    try:
        os.makedirs(outdir)
    except Exception as e:
        print("Failed to create OUTDIR:", outdir, e)
        exit(1)

monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

func_manager = currentProgram.getFunctionManager()
functions = list(func_manager.getFunctions(True))

agg_path = os.path.join(outdir, "decompiled_all.txt")
with open(agg_path, "w", encoding="utf-8", errors="replace") as agg:
    agg.write("Decompiled by Ghidra headless script\n\n")
    for idx, func in enumerate(functions):
        try:
            addr = func.getEntryPoint()
            addr_str = str(addr)
            safe_name = func.getName().replace("/", "_").replace("\\", "_").replace(" ", "_")
            filename = "func_{}_{}_{}.c".format(idx, addr_str.replace(":", "_"), safe_name)
            filepath = os.path.join(outdir, filename)
            print("Decompiling function:", func.getName(), "at", addr_str)
            res = decomp.decompileFunction(func, int(os.environ.get("GHIDRA_DECOMPILE_TIMEOUT", "60")), monitor)
            if res is None or not res.decompileCompleted():
                content = "// Decompilation failed or timed out for function {}\n".format(func.getName())
            else:
                decFunc = res.getDecompiledFunction()
                if decFunc is None:
                    content = "// No decompiled function available for {}\n".format(func.getName())
                else:
                    try:
                        content = decFunc.getC()
                        if content is None:
                            content = "// getC() returned None for {}\n".format(func.getName())
                    except Exception as e:
                        content = "// Exception while getting C for {}: {}\n".format(func.getName(), e)
            with open(filepath, "w", encoding="utf-8", errors="replace") as f:
                f.write("/* Function: {}  Address: {} */\n\n".format(func.getName(), addr_str))
                f.write(content)
            agg.write("\n\n===== FILE: {} =====\n\n".format(filename))
            agg.write(content)
        except Exception as e:
            print("Error decompiling function", func.getName(), ":", e)
            agg.write("\n\n// ERROR decompiling {}: {}\n".format(func.getName(), e))

print("All done. Outputs in:", outdir)
