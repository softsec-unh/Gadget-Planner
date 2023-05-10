import angr
import pyvex

def unconstrained_jumpkind(kind):
    return kind == 'Ijk_Ret'

def aborting_jumpkind(kind):
    return kind in ['Ijk_EmWarn', 'Ijk_EmFail', 'Ijk_NoDecode', 'Ijk_MapFail']

def constrained_jumpkind(kind):
    return kind in ['Ijk_Boring', 'Ijk_Call', 'Ijk_Yield', 'Ijk_NoRedir']

def syscall_jumpkind(kind):
    return 'Sys' in kind or 'Sig' in kind

def block_makes_sense(block, project):
    # Check if the block can be decoded
    if aborting_jumpkind(block.vex.jumpkind):
        return False
    # If the block makes a syscall, we aren't modeling that for now.
    if syscall_jumpkind(block.vex.jumpkind):
        return False
    # If any of the IR statements are dirty, we can't simulate them
    if any(isinstance(s, pyvex.IRStmt.Dirty) for s in block.vex.statements):
        return False
    return True

def step_to_end_of_gadget(state):
    "Returns a list of all the ways this can end."
    """
    step()
    Perform a step of symbolic execution using this state.
    Any arguments to `AngrObjectFactory.successors` can be passed to this.

    :return: A SimSuccessors object categorizing the results of the step.
    """
    # a basic block of symbolic execution from current state to the end of the basic block
    s = state.step()
    return s.successors + s.unconstrained_successors

def run_trace(symbolic_state, project, loc, important_registers):
    try:
        # Force registers to be initialized
        for reg in important_registers:
            temp = getattr(symbolic_state.regs, reg)

        sm = project.factory.simulation_manager(symbolic_state)
        choices = [symbolic_state]
        # enumberate() -> (0, addr), (1, addr)......
        for i, addr in enumerate(loc):
            for s in choices:
                if s.regs.ip.symbolic:
                    slv = s.solver
                    slv.add(s.regs.ip == addr)
                    if slv.satisfiable():
                        break
                elif s.addr == addr:
                    break
                else:
                    return None

            choices = step_to_end_of_gadget(s)

        state = None
        for choice in choices:
            if not choice.ip.concrete:
                # This could go anywhere
                places = choice.solver.eval_upto(choice.ip, 256)
                if len(places) == 256:
                    state = choice
            else:
                kind = choice.block().vex.jumpkind
                if unconstrained_jumpkind(kind):
                    state = choice

        return state
    except:
        return None
