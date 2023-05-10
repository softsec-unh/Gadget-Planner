import time
import json
start_time = time.process_time()

# First of all, we know we need angr
import angr

import claripy

# pyvex is used for simulation
import pyvex

# And we need sys to look at system arguments
import sys

# We'll use multiprocessing for speed on multiple cores
import multiprocessing
from multiprocessing import Pool, Queue
from multiprocessing.dummy import Pool as LocalPool
import signal

# For named tuples
import collections

# For progress bar
import tqdm

# for speed
import random
random.seed(a="The quick brown fox loves to patronize blogs.")

import planning

from gadget import *
from util import *

fancy_output = "--fancy" in sys.argv

Person = collections.namedtuple('Person', 'name age gender')

# Gadgets have several fields
# irsbs - the Vex IR blocks of the gadget
# state - the state transformation
# following - gadgets permitted to follow, or None if unconstrained
GadgetLoc = collections.namedtuple('GadgetLoc', 'addr following')

"""

Ijk_INVALID=0x1A00,
      Ijk_Boring,         /* not interesting; just goto next */
      Ijk_Call,           /* guest is doing a call */
      Ijk_Ret,            /* guest is doing a return */
      Ijk_ClientReq,      /* do guest client req before continuing */
      Ijk_Yield,          /* client is yielding to thread scheduler */
      Ijk_EmWarn,         /* report emulation warning before continuing */
      Ijk_EmFail,         /* emulation critical (FATAL) error; give up */
      Ijk_NoDecode,       /* current instruction cannot be decoded */
      Ijk_MapFail,        /* Vex-provided address translation failed */
      Ijk_InvalICache,    /* Inval icache for range [CMSTART, +CMLEN) */
      Ijk_FlushDCache,    /* Flush dcache for range [CMSTART, +CMLEN) */
      Ijk_NoRedir,        /* Jump to un-redirected guest addr */
      Ijk_SigILL,         /* current instruction synths SIGILL */
      Ijk_SigTRAP,        /* current instruction synths SIGTRAP */
      Ijk_SigSEGV,        /* current instruction synths SIGSEGV */
      Ijk_SigBUS,         /* current instruction synths SIGBUS */
      Ijk_SigFPE_IntDiv,  /* current instruction synths SIGFPE - IntDiv */
      Ijk_SigFPE_IntOvf,  /* current instruction synths SIGFPE - IntOvf */
      /* Unfortunately, various guest-dependent syscall kinds.  They
	 all mean: do a syscall before continuing. */
      Ijk_Sys_syscall,    /* amd64/x86 'syscall', ppc 'sc', arm 'svc #0' */
      Ijk_Sys_int32,      /* amd64/x86 'int $0x20' */
      Ijk_Sys_int128,     /* amd64/x86 'int $0x80' */
      Ijk_Sys_int129,     /* amd64/x86 'int $0x81' */
      Ijk_Sys_int130,     /* amd64/x86 'int $0x82' */
      Ijk_Sys_int145,     /* amd64/x86 'int $0x91' */
      Ijk_Sys_int210,     /* amd64/x86 'int $0xD2' */
      Ijk_Sys_sysenter    /* x86 'sysenter'.  guest_EIP becomes 
                             invalid at the point this happens. */

"""
def explore(block, project):
    if not block_makes_sense(block, project):
        return None

    symbolic_state = project.factory.blank_state()
    symbolic_state.ip = block.addr
    symbolic_state.options.add(angr.options.AVOID_MULTIVALUED_WRITES)
    symbolic_state.options.add(angr.options.AVOID_MULTIVALUED_READS)
    symbolic_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    symbolic_state.options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)
    symbolic_state.options.add(angr.options.BEST_EFFORT_MEMORY_STORING)
    symbolic_state.options.add(angr.options.DOWNSIZE_Z3)
    symbolic_state.options.add(angr.options.STRICT_PAGE_ACCESS)

    # symbolics_p is a list contains the total number of successors of a simsuccessor object
    symbolics_p = step_to_end_of_gadget(symbolic_state)
    symbolic_state.downsize()

    if len(symbolics_p) >= 256:
        # Probably unconstrained
        for p in symbolics_p:
            p.downsize()
        return GadgetLoc(block.addr, None)

    following = []
    for state in symbolics_p:
        # registers states are same between before and after.
        if len(changed(symbolic_state, state)) == 0:
            continue
        if not state.ip.concrete:
            # This could go anywhere, and the max solution number???
            places = state.solver.eval_upto(state.ip, 256)
            if len(places) == 256:
                # This is probably unconstrained.
                return GadgetLoc(block.addr, None)
            else:
                following += places

        kind = state.block().vex.jumpkind
        state.downsize()
        if unconstrained_jumpkind(kind):
            return GadgetLoc(block.addr, None)
        elif aborting_jumpkind(kind):
            # We cannot handle this case
            continue
        elif constrained_jumpkind(kind):
            following.append(state.solver.eval_upto(state.ip, 256))
        elif syscall_jumpkind(kind):
            # We cannot handle this case
            continue
        else:
            continue

    for state in symbolics_p:
        state.downsize()

    if len(following) == 0:
        return None 
    if len(following) > 2:
        return None
    return GadgetLoc(block.addr, following)

class Alarm(Exception):
    pass

def signal_handler(signum, frame):
    raise Alarm("Timed out!")

def do_extract(args, timeout=10 * 1000):

    project, addr = args
    pro = project
    try:
        # generate a basic block object
        block = pro.factory.block(addr)
    except angr.errors.SimEngineError:
        # Probably too little memory to hold the block
        return None 

    if timeout is not None:
        signal.signal(signal.SIGALRM, signal_handler)
        signal.alarm(timeout)

    try:
        out = explore(block, pro)
    except Alarm:
        return "timeout"
    except angr.errors.SimEngineError:
        return "memory"
    except Exception as e:
        return "generic"
    finally:
        signal.alarm(0)
    return out

def extract_instructions(project, call_preceded_only=True, parallel=False):
    global snapshot
    pro = project
    cfg_new = pro.analyses.CFGFast(force_complete_scan=False, resolve_indirect_jumps=False)
    nodes = cfg_new.graph.nodes
    node_list = list(dict(nodes))
    node_obj = list(nodes)
    bb_start = []
    for n in node_obj:
        if len(n.instruction_addrs) > 5:
            bb_start.append(n.instruction_addrs[len(n.instruction_addrs) - 5])
            bb_start.append(n.instruction_addrs[len(n.instruction_addrs) - 4])
            bb_start.append(n.instruction_addrs[len(n.instruction_addrs) - 3])
            bb_start.append(n.instruction_addrs[len(n.instruction_addrs) - 2])
            bb_start.append(n.instruction_addrs[len(n.instruction_addrs) - 1])
        else:
            for index in range(len(n.instruction_addrs)):
                bb_start.append(n.instruction_addrs[index])
    blocks = []
    blocks = [(project, a) for a in bb_start]
    # every instruction address
    # blocks = [(project, a) for a in bb_start]
    random.shuffle(blocks)
    if len(blocks) > 100000:
        print("the numbers of basic block objects are greater than 100000")
    blocks = blocks[:100000]

    print("Finding gadgets ...")
    print("There are {} potential gadgets".format(len(blocks)))

    if parallel:
        from joblib import Parallel, delayed
        gadgets = [resus for resus in Parallel(batch_size=1)(delayed(do_extract)(block) for block in blocks) if resus is not None and not isinstance(resus, str)]
    else:
        gadgets = [resus for resus in (map(do_extract, blocks) if not fancy_output else tqdm.tqdm(map(do_extract, blocks), total = len(blocks), desc="Searching", unit_scale=True)) if resus is not None and not isinstance(resus, str)]
    #print("Located {} usable gadgets.".format(len(gadgets)))
    return gadgets

def new_gadget(project, addresses):
    return addresses # TODO

def flatten(gadget, library, parents=[]):
    if gadget.following in parents:
        return []
    if gadget.following is None:
        return [[gadget.addr]]
    if len(parents) >= 3:
        return [] # Probably not worth it.
    eno = [] 
    flat = []
    for si in gadget.following:
        if type(si) == list:
            flat += si
        else:
            flat.append(si)
    for sucs in flat:
        if sucs not in library.keys():
            continue
        rest = flatten(library[sucs], library, parents=parents + [gadget.addr])
        eno += rest
    return [[gadget.addr] + b for b in eno]

def concat_gadgets(gadgets):
    news = []
    library = {}
    for gadget in gadgets:
        library[gadget.addr] = gadget

    for gadget in gadgets:
        if gadget.following is None:
            news.append(new_gadget(project, [gadget.addr]))
        else:
            for addrs in flatten(gadget, library):
                news.append(new_gadget(project, addrs))
    # return address in news which can generate a Gadgets. recover function return a gadget through a address.
    return [x for x in (news if not fancy_output else tqdm.tqdm(news, desc="Filtering")) if recover(x) is not None]

def get_post_conditions(before, after):
    posts = {}
    for reg in important_registers:
        same = getattr(before.regs, reg) == getattr(after.regs, reg)
        if same.symbolic:
            posts[reg] = getattr(after.regs, reg)
    # return a dict, key is register name, value is register object.
    return posts

def depmap(before, after):
    dmap = dict()
    all_need = []
    for cons in after.solver.constraints:
        vars = list(cons.variables)
        vars = [y.split('_')[1] for y in vars if 'mem' not in y]
        all_need += vars
    for reg in important_registers:
        vars = getattr(after.regs, reg).variables
        vars = list(vars)
        # TODO consider how to handle reading from memory
        vars = [y.split('_')[1] for y in vars if 'mem' not in y]
        dmap[reg] = list(set(vars + all_need)) 
    return dmap

def changed(before, after):
    regs = []
    for reg in important_registers:
        # sp rsp could be changed
        if reg in ["rsp", "sp", "esp", "rip", "ip", "pc"]:
            continue
        if not (getattr(before.regs, reg) == getattr(after.regs, reg)).is_true():
            regs.append(reg)
    return regs

def recover(loc):
    try:
        symbolic_state = project.factory.blank_state(addr=loc[0])
        symbolic_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        symbolic_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        state = run_trace(symbolic_state, project, loc, important_registers)
        if state is not None:
            #print(loc)
            return Gadget(loc, symbolic_state, state, None, get_post_conditions(symbolic_state, state), depmap(symbolic_state, state), changed(symbolic_state, state))
    except:
        return None

def recover_library(project, gadget_locs):
    library = []
    for loc in (gadget_locs if not fancy_output else tqdm.tqdm(gadget_locs, desc="Re-Executing")):
        try:
            r = recover(loc)
            if r is not None:
                library.append(r)
        except MemoryError:
            continue
    return library

def inspect(e):
    for field in dir(e):
        print("{}: {}".format(field, getattr(e, field)))

def extend_library(project, library):
    # Turning zero + add into mov
    for reg in important_registers:
        zeros = [x for x in library[reg] if (getattr(x.after.regs, reg) == 0).is_true()]
        if len(zeros) == 0:
            continue
        zero = zeros[0]
        for gad in library[reg]:
            if type(gad) == Synthetic:
                continue 
            if reg not in gad.depmap[reg]:
                continue
            if gad.depmap[reg] == [reg]:
                continue
            loc = zero.addrs + gad.addrs
            symbolic_state = project.factory.blank_state(addr=loc[0])
            symbolic_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
            symbolic_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
            state = run_trace(symbolic_state, project, loc, important_registers)
            if state is not None:
                ng = Synthetic(Gadget(loc, symbolic_state, state, None, get_post_conditions(symbolic_state, state), depmap(symbolic_state, state), changed(symbolic_state, state)))
                library[reg].append(ng)
    return library

def prune_library(project, library):
    # TODO expand to cover more cases
    library = [x for x in library if len(x.post) != 0]
    return {reg:[x for x in library if reg in x.post.keys()] for reg in important_registers}

def subsumes(project, ga, gb):
    if set(ga.registers_changed) != set(gb.registers_changed):
        return False
    cons = [getattr(ga.before.regs, r) == getattr(gb.before.regs, r) for r in important_registers if r not in ["rip", "ip", "pc"]]
    blank = project.factory.blank_state()
    solver = blank.solver
    solver.add(*cons)
    for reg in gb.registers_changed:
        if not set(ga.depmap[reg]).issubset(gb.depmap[reg]):
            return False
        a = getattr(ga.after.regs, reg)
        b = getattr(gb.after.regs, reg)
        try:
            # give you up to n solutions to the given expression, returning fewer than n if fewer than n are possible.
            # will give you the maximum possible solution to the given expression.
            for sln in solver.eval_upto(b, 20) + [solver.max(b), solver.min(b)]:
                if not solver.solution(a, sln):
                    return False
        except:
            return False # Can't do anything about the presence of sim errors
    return True

def reduce_library(project, library, timeout=100000):
    start = time.time()
    out = []
    loosers = set()
    random.shuffle(library)
    for gadget in (library if not fancy_output else tqdm.tqdm(library, desc="Reducing Library")):
        if time.time() - start > timeout:
            break
        if len(gadget.registers_changed) == 0:
            continue
        for ogadget in library:
            if id(ogadget) in loosers:
                continue
            if gadget == ogadget:
                continue # Don't compare against self
            north = subsumes(project, gadget, ogadget)
            south = subsumes(project, ogadget, gadget)
            if north and south:
                if id(gadget) < id(ogadget):
                    loosers.add(id(gadget))
                    break
            elif south:
                loosers.add(id(gadget))
                break
        else: # Yes, this else goes with the for loop
            out.append(gadget)
    return out

CACHE_VERSION = 10

#blob = bytearray([0x48, 0x31, 0xc0, 0xc3, 0xff, 0xc0, 0xc3, 0x5f, 0xc3, 0x48, 0x89, 0xf7, 0xc3, 0x48, 0x31, 0xd2, 0xc3, 0x48, 0x01, 0xd6, 0xc3, 0x48, 0xff, 0xc0, 0x29, 0xd3, 0x75, 0xf9, 0xc3])

blob = bytearray([int(r, 16) for r in "48 31 c0 c3 ff c0 c3 5f c3 48 89 f7 c3 48 89 fe 48 31 d2 c3 48 01 d6 c3 48 01 f2 c3 48 ff c0 29 d3 75 f9 c3".split()])

if __name__ == '__main__':
    sys.ps1 = "\n>~> "
    import logging
    logging.getLogger().setLevel('ERROR')

    import resource
    MAXMEM = int(10.75 * 1000 * 1000 * 1000)
    resource.setrlimit(resource.RLIMIT_DATA, (MAXMEM, MAXMEM))

    # wrapper, return the 'f' function, p is a function as a parameter to use
    def gently(p):
        c = 0
        obj = None
        def f():
            nonlocal c, obj
            c += 1
            if obj is None or c % 1000 == 0:
                obj = p()
            return obj
        return f

    import pickle, os, sys, psutil
    # parsing command line arguments
    if len(sys.argv) >= 2:
        binary = sys.argv[1]
        project = angr.Project(binary)
    else:
        import io
        binary = "example.o"
        project = angr.Project(io.BytesIO(blob), main_opts={'backend': 'blob', 'arch': 'x86_64', 'entry_point': 0, 'base_addr': 0x4000})
    # get registers' key from a dict
    important_registers = project.arch.registers.keys()
    #print(u'current_memory_usage：%.4f GB' % (psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024 / 1024))
    for i in range(CACHE_VERSION):
        old_path = binary + "-gadget-cache-v-" + str(i)
        if os.path.exists(old_path):
            os.remove(old_path)

    cache_path = binary + "-gadget-cache-v-" + str(CACHE_VERSION)

    if not os.path.exists(cache_path) or '--ignore-cache' in sys.argv:
        try:
            tracted = extract_instructions(project)
            f = concat_gadgets(tracted)
            with open(cache_path, "wb") as file:
                pickle.dump(f, file, protocol = 3)
        except Exception as e:
            with open(binary + "-error-trace", "a") as error:
                error.write(f"Error: {e}\n")
                error.write(f"Cause: {e.__cause__}\n")
                error.write(f"Context: {e.__context__}\n")
                import traceback
                error.write(f"Traceback: \n")
                traceback.print_tb(e.__traceback__, file=error)
                error.write("----\n")
            raise e
    else:
        with open(cache_path, "rb") as file:
            f = pickle.load(file)
    #f = concat_gadgets(project, e)

    if '--brief' in sys.argv:
        sys.exit(0)

    r = project.factory.blank_state()
    x = r.solver

    g = recover_library(project, f)
    print(u'current_memory_usage：%.4f GB' % (psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024 / 1024))

    gp = reduce_library(project, g)
    print(u'current_memory_usage：%.4f GB' % (psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024 / 1024))

    if '--reduction-testing' in sys.argv:
        sys.exit(0)

    h = extend_library(project, prune_library(project, gp))
    # h = prune_library(project, gp)
    print(u'current_memory_usage：%.4f GB' % (psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024 / 1024))

    name, i = planning.plan(project, h)
    print(u'current_memory_usage：%.4f GB' % (psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024 / 1024))
    print(f"exploit: {name}")
    end_time = time.process_time()
    rt = resource.getrusage(resource.RUSAGE_SELF)

    print(f"max_mem_usage: {rt.ru_maxrss}")
    print(f"system_time: {rt.ru_stime}")
    print(f"user_time: {rt.ru_utime}")
    print(f"swaps: {rt.ru_nswap}")

    code_size = project.loader.main_object.max_addr - project.loader.main_object.mapped_base
    print(f"main_object_size: {code_size}")
    total_size = sum(x.memsize for x in project.loader.main_object.sections)
    print(f"total_loaded_size: {total_size}")
    nsecs = len(project.loader.main_object.sections)
    print(f"number_of_sections: {nsecs}")

    print(f"total_gadgets: {len(g)}")
    print(f"reduced_gadgets: {len(gp)}")

    import os
    print(f"input_size: {os.path.getsize(sys.argv[1])}")
    print(f"input: {sys.argv[1]}")

    print(f"wall_time: {end_time - start_time}") # System + CPU time

    print(f"expansions: {planning.expansions}")
    print(f"max_queue: {planning.max_queue}")
    if len(planning.branches) != 0:
        print(f"avg_branches: {sum(planning.branches)/len(planning.branches)}")
        print(f"max_branches: {max(planning.branches)}")
        print(f"min_branches: {min(planning.branches)}")

    if i is not None:
        #print("Plan found!")
        print("plan_found: 1")
        print(f"gadget_size: {len(i.stn.matrix)}")
        byte_size = sum(x.gadget.before.block().size for x in i.solved if type(x.gadget) != str)
        print(f"byte_size: {byte_size}")
        instr_size = sum(x.gadget.before.block().instructions for x in i.solved if type(x.gadget) != str)
        print(f"instruction_size: {instr_size}")
        insns = []
        for s in i.solved:
            if type(s.gadget) == str:
                continue
            for ins in s.gadget.before.block().capstone.insns:
                insns.append(ins.insn.mnemonic)
        out = " ".join(insns)
        print(f"instructions: {out}")
    else:
        print("Plan_found: 0")
