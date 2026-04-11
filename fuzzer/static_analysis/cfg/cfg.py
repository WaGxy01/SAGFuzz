import logging
from collections import deque
from .disassembly import generate_BBs
from .bb import BB

import tempfile
import subprocess
import os,sys
from collections import defaultdict

class CFG(object):
    def __init__(self, bbs, fix_xrefs=True, fix_only_easy_xrefs=False):
        self.bbs = sorted(bbs) # sorted返回一个新的已排序列表
        self._bb_at = {bb.start: bb for bb in self.bbs}
        self._ins_at = {i.addr: i for bb in self.bbs for i in bb.ins}
        self.root = self._bb_at[0]
        self.valid_jump_targets = frozenset({bb.start for bb in self.bbs if bb.ins[0].name == 'JUMPDEST'})
        if fix_xrefs or fix_only_easy_xrefs:
            self._xrefs(fix_only_easy_xrefs)
        self._dominators = None
        self._dd = dict()

    @property
    def bb_addrs(self):
        return frozenset(self._bb_at.keys())

    def filter_ins(self, names, reachable=False):
        if isinstance(names, str):
            names = [names]
        
        if not reachable:
            return [ins for bb in self.bbs for ins in bb.ins if ins.name in names]
        else:
            return [ins for bb in self.bbs for ins in bb.ins if ins.name in names and 0 in bb.ancestors | {bb.start}]

    def _xrefs(self, fix_only_easy_xrefs=False):
        # logging.debug('Fixing Xrefs')
        self._easy_xrefs()
        # logging.debug('Easy Xrefs fixed, turning to hard ones now')
        if not fix_only_easy_xrefs:
            self._hard_xrefs()
            # logging.debug('Hard Xrefs also fixed, good to go')

    def _easy_xrefs(self):
        for pred in self.bbs:
            for succ_addr in pred.get_succ_addrs(self.valid_jump_targets):
                if succ_addr and succ_addr in self._bb_at:
                    succ = self._bb_at[succ_addr]
                    pred.add_succ(succ, {pred.start})

    def _hard_xrefs(self):
        new_link = True
        links = set()
        while new_link:
            new_link = False
            for pred in self.bbs:
                if not pred.jump_resolved:
                    succ_addrs, new_succ_addrs = pred.get_succ_addrs_full(self.valid_jump_targets)
                    for new_succ_path, succ_addr in new_succ_addrs:
                        if succ_addr not in self._bb_at:
                            logging.warning(
                                'WARNING, NO BB @ %x (possible successor of BB @ %x)' % (succ_addr, pred.start))
                            continue
                        succ = self._bb_at[succ_addr]
                        pred.add_succ(succ, new_succ_path)
                        if not (pred.start, succ.start) in links:
                            # logging.debug('found new link from %x to %x', pred.start, succ.start)
                            # with open('cfg-tmp%d.dot' % len(links), 'w') as outfile:
                            #    outfile.write(self.to_dot())
                            new_link = True
                            links.add((pred.start, succ.start))

    def data_dependence(self, ins):
        if not ins in self._dd:
            from slicing import backward_slice
            self._dd[ins] = set(i for s in backward_slice(ins) for i in s if i.bb)
        return self._dd[ins]

    @property
    def dominators(self):
        if not self._dominators:
            self._compute_dominators()
        return self._dominators

    def _compute_dominators(self):
        import networkx
        g = networkx.DiGraph()
        for bb in self.bbs:
            for succ in bb.succ:
                g.add_edge(bb.start, succ.start)
        self._dominators = {self._bb_at[k]: self._bb_at[v] for k, v in networkx.immediate_dominators(g, 0).items()}

    def __str__(self):
        return '\n\n'.join(str(bb) for bb in self.bbs)

    def to_dot(self, minimal=False):
        s = 'digraph g {\n'
        s += '\tsplines=ortho;\n'
        s += '\tnode[fontname="courier"];\n'
        for bb in sorted(self.bbs):
            from_block = ''
            if self._dominators:
                from_block = 'Dominated by: %x<br align="left"/>' % self.dominators[bb].start
            from_block += 'From: ' + ', '.join('%x' % pred.start for pred in sorted(bb.pred))
            if bb.estimate_constraints is not None:
                from_block += '<br align="left"/>Min constraints from root: %d' % bb.estimate_constraints
            if bb.estimate_back_branches is not None:
                from_block += '<br align="left"/>Min back branches to root: %d' % bb.estimate_back_branches
            to_block = 'To: ' + ', '.join('%x' % succ.start for succ in sorted(bb.succ))
            ins_block = '<br align="left"/>'.join(
                '%4x: %02x %s %s' % (ins.addr, ins.op, ins.name, ins.arg.hex() if ins.arg else '') for ins in bb.ins)
            # ancestors = 'Ancestors: %s'%(', '.join('%x'%addr for addr in sorted(a for a in bb.ancestors)))
            # descendants = 'Descendants: %s' % (', '.join('%x' % addr for addr in sorted(a for a in bb.descendants)))
            # s += '\t%d [shape=box,label=<<b>%x</b>:<br align="left"/>%s<br align="left"/>%s<br align="left"/>%s<br align="left"/>>];\n' % (
            #    bb.start, bb.start, ins_block, ancestors, descendants)
            if not minimal:
                s += '\t%d [shape=box,label=<%s<br align="left"/><b>%x</b>:<br align="left"/>%s<br align="left"/>%s<br align="left"/>>];\n' % (
                    bb.start, from_block, bb.start, ins_block, to_block)
            else:
                s += '\t%d [shape=box,label=<%s<br align="left"/>>];\n' % (
                    bb.start, ins_block)
        s += '\n'
        for bb in sorted(self.bbs):
            for succ in sorted(bb.succ):
                pths = succ.pred_paths[bb]
                if not minimal:
                    s += '\t%d -> %d [xlabel="%s"];\n' % (
                        bb.start, succ.start, '|'.join(' -> '.join('%x' % a for a in p) for p in pths))
                else:
                    s += '\t%d -> %d;\n' % (bb.start, succ.start)
        if self._dd:
            inter_bb = {}
            for k, v in self._dd.items():
                jbb = k.bb.start
                vbbs = {i.bb.start for i in v if i.bb.start != k.bb.start}
                if vbbs:
                    inter_bb[jbb] = vbbs
            l = len(inter_bb)
            for i, (k, v) in enumerate(inter_bb.items()):
                for j in v:
                    s += '\t%d -> %d[color="%.3f 1.0 1.0", weight=10];\n' % (j, k, (1.0 * i) / l)
                s += '\n'
        s += '}'
        return s

    def trim(self):
        keep = set(self.root.descendants)
        self.bbs = [bb for bb in self.bbs if bb.start in keep]
        delete = set(self._bb_at.keys()) - keep
        for addr in delete:
            del self._bb_at[addr]

    def to_json(self):
        return {'bbs': [{'start': bb.start,
                         'succs': [{'start': succ.start, 'paths': list(succ.pred_paths[bb])} for succ in
                                   sorted(bb.succ)]} for bb in sorted(self.bbs)]}

    @staticmethod
    def from_json(json_dict, code):
        from .disassembly import disass
        bbs = list()
        for bb_dict in json_dict['bbs']:
            bbs.append(BB(list(disass(code, bb_dict['start']))))
        cfg = CFG(bbs, fix_xrefs=False)
        for bb_dict in json_dict['bbs']:
            bb = cfg._bb_at[bb_dict['start']]
            for succ_dict in bb_dict['succs']:
                succ = cfg._bb_at[succ_dict['start']]
                for path in succ_dict['paths']:
                    bb.add_succ(succ, path)
        return cfg

    @staticmethod
    def distance_map(ins):
        dm = dict()
        todo = deque()
        todo.append((ins.bb, 0))
        while todo:
            bb, d = todo.pop()
            if not bb in dm or dm[bb] > d:
                dm[bb] = d
                for p in bb.pred:
                    todo.append((p, d + 1 if len(p.succ) > 1 else d))
        return dm
    
    """ Added code start here"""
    '''
    def to_ssa(self, code:bytes, minimal=False):          
        sys.setrecursionlimit(10000)
        edges = []        
        ssa = Recover(code, edges=edges, split_functions=False)
        for function in ssa.functions:
            g = ControlFlowGraph(function)  #
            t = tempfile.NamedTemporaryFile(suffix='.dot', mode='w')
            t.write(g.dot())
            t.flush()
            
            try:
                os.makedirs('output')
            except:
                pass

            out_file = f'output/{function.desc()}.svg'

            subprocess.call(['dot', '-Tsvg', f'-o{out_file}', t.name])
            print(f'[+] Wrote {function.desc()} to {out_file}')           
    '''
        
    def edges(self):
        edges=[]        
        for bb in sorted(self.bbs):
            for succ in sorted(bb.succ):         
                edges.append([bb.start, succ.start])
        return edges
                
    def assert_sinks(self):
        instructions = {}
        assert_bbs=[bb for bb in self.bbs if len(bb.ins)==1 and hex(bb.ins[0].op)=='0xfe']
        for bb in assert_bbs:
            for pred in bb.pred:                
                if 'SLOAD' in[ins.name for ins in pred.ins]:
                    continue
                if 'CALLDATALOAD' in[ins.name for ins in pred.ins]:
                    continue
                
                instructions[pred.ins[-1]]=bb.ins[0]
        return instructions

    def call_sinks(self):
        instructions = []          
        call_insn= [ins for bb in self.bbs for ins in bb.ins if ins.name in set(['CALL']) and 0 in bb.ancestors | {bb.start}]
        for call_ins in call_insn:                       
            call_succ=[succ.start for succ in self._bb_at[call_ins.bb.start].succ]
            if len(call_succ)==0:
                instructions.append(call_ins)             
                continue
            call_bb_ins = self._bb_at[call_ins.bb.start].ins
            if len(call_succ)==1 and [ins.name for ins in call_bb_ins[-3:]]==['ISZERO','PUSH2','JUMPI']: #propagate throw
                continue
            if len(call_succ)==2 and [ins.name for ins in call_bb_ins[call_bb_ins.index(call_ins)+1:] if ins.name in set(['ADD','AND','ISZERO','JUMPI'])] ==['ADD','AND','ISZERO','JUMPI']: #propagate throw                
                continue

            call_ins_index=call_bb_ins.index(call_ins)           
            if  [ins.name for ins in call_bb_ins[call_ins_index+1:call_ins_index+22] if ins.name in set(['ADD','MSTORE','MLOAD','SUB','KECCAK256'])]==['ADD','MSTORE','ADD','MLOAD','SUB','KECCAK256']:
                continue
            if  [ins.name for ins in call_bb_ins[call_ins_index+1:call_ins_index+17] if ins.name in set(['ADD','MLOAD','SUB','KECCAK256'])]==['ADD','MLOAD','SUB','KECCAK256']:
                continue
            if  [ins.name for ins in call_bb_ins[call_ins_index+1:call_ins_index+12] if ins.name in set(['ADD','MSTORE','SUB'])]==['ADD','SUB','MSTORE']:
                continue

            if len([succ.start for succ in self._bb_at[call_ins.bb.start].succ for ins in succ.ins if ins.name in set(['REVERT','INVALID'])])!=0:
                continue
            if len([succ.start for succ in self._bb_at[call_ins.bb.start].succ if [ins.name for ins in succ.ins]==['PUSH2','JUMP']])!=0:
                continue                       

            min_succ_bb= self._bb_at[min(call_succ)]                  

            succ_with_call_bb=[succ for succ in self._bb_at[call_ins.bb.start].succ for ins in succ.ins if ins.name in set(['CALL'])]
            if (['%x' %ins.op for ins in min_succ_bb.ins][-1] in set(['fd','fe']) or  [ins.name for ins in min_succ_bb.ins]==['PUSH2','JUMP']):
                continue
            if (['%x' %ins.op for ins in min_succ_bb.ins][-1] not in set(['fd','fe']) and [*['0x','0x'],*['%x' %ins.op for ins in min_succ_bb.ins]][-3] not in set(['3e']) and [ins.name for ins in min_succ_bb.ins]!=['PUSH2','JUMP'] and len(succ_with_call_bb)==0):
                instructions.append(call_ins)         
            elif ([*['0x'],*['%x' %ins.op for ins in min_succ_bb.ins]][-3] in set(['3e'])):   #RETURNDATACOPY
                call_ret_succ=[succ.start for succ in self._bb_at[min([succ.start for succ in min_succ_bb.succ])].succ]            
                ret_min_succ_bb= self._bb_at[min(call_ret_succ)]               
                if (['%x' %ins.op for ins in ret_min_succ_bb.ins][-1] not in set(['fd','fe'])):            
                    instructions.append(call_ins)           
            elif (len(succ_with_call_bb)>0):
                sec_call_succ=[succ.start for succ in succ_with_call_bb[0].succ]
                min_sec_call_succ_bb= self._bb_at[min(sec_call_succ)]                
                if( [ins.name for ins in min_sec_call_succ_bb.ins]!=['PUSH2','JUMP']):
                    instructions.append(call_ins)                    

        return instructions

    def find_loops(self, with_calls=False):
        import networkx
        g = networkx.DiGraph()
        for bb in self.bbs:
            for succ in bb.succ:
                g.add_edge(bb.start,succ.start)                
        l= list(networkx.simple_cycles(g))                
        loops=defaultdict(list)
        calls_in_loops=defaultdict(list)
        loops_with_calls=[]
        loops_with_gas_sanitizers =[]
        for i in l:                 
            if len([h for h in i if(len(self._bb_at[h].pred))>2])>0:
                #print('11')
                continue
            
            loop_bbs=[bb for j in i for bb in self.bbs if bb.start==j]                                                                        
            if len(i) ==1:  
                continue               
        
            head =[succ.start for bb in loop_bbs for succ in bb.succ if succ.start in i if bb.start>succ.start and len([p.start for p in succ.pred if p.start not in i])!=0 and len(succ.succ)<=2 and ('ADD' in [ins.name for ins in bb.ins] or  [ins.name for ins in bb.ins[-2:]]==['PUSH2','JUMP'])]

            if len(head)==0:                
                continue       
                 
            if len(loops[head[0]]):
                loops[head[0]].pop(0)
            loops[head[0]].insert(0,len(i))
          
            back_edge =[[succ.start,bb.start] for bb in loop_bbs for succ in bb.succ if succ.start in i if bb.start>succ.start]                                
            
            if len(i)==2:
                body_ins=[ins.name for bb in loop_bbs for ins in bb.ins if bb.start!=head[0] and ins.name in ['ADD','SUB','MLOAD','MSTORE','JUMP','SSTORE','EXP','NOT','MUL','PUSH1','POP','SWAP1','DUP2']]
                body_start=[bb.start for bb in loop_bbs if bb.start!=head[0]]                
                if  'MLOAD' in body_ins:          
                    continue          
                elif body_ins  == ['PUSH1','DUP2','PUSH1','SWAP1','SSTORE','POP','PUSH1','ADD','JUMP']:
                    head_pred=[pred.start for bb in loop_bbs for pred in bb.pred if bb.start==head[0] and pred.start !=body_start[0]]
                    head_pred1=[pred.start for pred in self._bb_at[head_pred[0]].pred]                 
                    head_pred2=[pred.start for pred in self._bb_at[head_pred1[0]].pred]
                    head_pred_ins=[ins.name for bb in self._bb_at[head[0]].pred for ins in bb.ins if bb.start !=body_start[0] and ins.name in ['ADD','MSTORE','JUMP','SSTORE','KECCAK256','SLOAD']]
                    head_pred1_ins=[ins.name for bb in self._bb_at[head_pred[0]].pred for ins in bb.ins if ins.name in ['ADD','MSTORE','JUMP','SSTORE','KECCAK256','SLOAD']]
                    if len(head_pred2)==3:
                        continue
                    if head_pred1_ins !=['SLOAD','SSTORE','MSTORE','KECCAK256','ADD','JUMP'] and  head_pred_ins !=['SLOAD','SSTORE','MSTORE','KECCAK256','ADD','JUMP']:
                        continue
                else:
                    continue                    
            
            if len(i)==3:                
                body_ins=[ins.name for bb in loop_bbs for ins in bb.ins if bb.start not in back_edge[0] and ins.name in ['ADD','SUB','MLOAD','MSTORE','JUMP','SSTORE','EXP','NOT','MUL']]
                if body_ins  == ['MLOAD','MSTORE'] or body_ins==['ADD','MLOAD','ADD','MSTORE']:   
                    continue
            
            head_cnt=0
            for k in range(i.index(head[0]),len(i)+i.index(head[0])):                
                indx=k%len(i)                
                if len([bb for bb in loop_bbs if bb.start==i[indx] and len(bb.succ)!=0  and len([succ for succ in bb.succ if succ in loop_bbs]) ==len(bb.succ)])!=0:
                    loops[head[0]].append(i[indx])                
                    head_cnt+=1
                elif len([bb for bb in loop_bbs if bb.start==i[indx] and len(bb.succ)!=0 and len([succ for succ in bb.succ if succ in loop_bbs]) ==1 and len(bb.succ)==2 and len([succ for succ in bb.succ if self._ins_at[succ.start].op==254])==1])!=0:
                    loops[head[0]].append(i[indx])                
                    head_cnt+=1
                elif len([bb for bb in loop_bbs if bb.start==i[indx] and len(bb.succ)!=0 and len([succ for succ in bb.succ if succ in loop_bbs]) ==1 and len(bb.succ)==2])!=0:
                    loops[head[0]].append(i[indx])
                    head_cnt+=1
                    break
                      
            if not with_calls:
                for bb in loop_bbs:
                    if bb.start in loops[head[0]] and 'GAS' in [ins.name for ins in bb.ins]:
                        block_ins =[ins.name for ins in bb.ins if ins.name in ['PUSH2','PUSH3','GAS','GT']]
                        if block_ins ==['PUSH3','GAS','GT'] or  block_ins ==['PUSH2','GAS','GT']:
                            loops_with_gas_sanitizers.append(head[0])
                            break
                    elif bb.start not in loops[head[0]] and 'GAS' in [ins.name for ins in bb.ins]:
                        block_ins =[ins.name for ins in bb.ins if ins.name in ['PUSH2','PUSH3','GAS','GT','JUMPI']]
                        if block_ins[-5:] == ['PUSH3','GAS','GT','PUSH2','JUMPI'] or block_ins[-5:] == ['PUSH2','GAS','GT','PUSH2','JUMPI']:
                            loops_with_gas_sanitizers.append(head[0])
                            break
            
            if with_calls:
                calls_in_loop= False
                for bb in loop_bbs:
                    if bb.start not in loops[head[0]] and 'CALL' in [ins.name for ins in bb.ins]:
                        call_succ=[succ.start for succ in self._bb_at[bb.start].succ]                        
                        if len(call_succ)==2:
                            if (['%x' %ins.op for ins in self._bb_at[min(call_succ)].ins][-1] in set(['fd','fe'])): #revert or INVALID
                                calls_in_loop=True
                                loops_with_calls.append(head[0])
                                calls_in_loops[bb.start].append([ins for ins in bb.ins if 'CALL'==ins.name][0])
                                break
            if with_calls and not calls_in_loop and head[0] not in loops_with_calls:
                del loops[head[0]]
            elif with_calls and not calls_in_loop:
                for i in range(0,head_cnt):
                    loops[head[0]].pop()

            for san in set(loops_with_gas_sanitizers):
                if loops.get(san,'nokey')!='nokey':
                    del loops[san]

        if not with_calls:
            return loops
        else:
            return calls_in_loops

'''
bytecode = "608060405260043610610033575f3560e01c806327e235e3146100375780632e1a7d4d14610073578063d0e30db01461009b575b5f80fd5b348015610042575f80fd5b5061005d600480360381019061005891906102e8565b6100a5565b60405161006a919061032b565b60405180910390f35b34801561007e575f80fd5b506100996004803603810190610094919061036e565b6100b9565b005b6100a3610236565b005b5f602052805f5260405f205f915090505481565b805f803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20541015610138576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161012f906103f3565b60405180910390fd5b5f3373ffffffffffffffffffffffffffffffffffffffff168260405161015d9061043e565b5f6040518083038185875af1925050503d805f8114610197576040519150601f19603f3d011682016040523d82523d5f602084013e61019c565b606091505b50509050806101e0576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101d79061049c565b60405180910390fd5b815f803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f82825461022b91906104e7565b925050819055505050565b345f803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f828254610281919061051a565b92505081905550565b5f80fd5b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6102b78261028e565b9050919050565b6102c7816102ad565b81146102d1575f80fd5b50565b5f813590506102e2816102be565b92915050565b5f602082840312156102fd576102fc61028a565b5b5f61030a848285016102d4565b91505092915050565b5f819050919050565b61032581610313565b82525050565b5f60208201905061033e5f83018461031c565b92915050565b61034d81610313565b8114610357575f80fd5b50565b5f8135905061036881610344565b92915050565b5f602082840312156103835761038261028a565b5b5f6103908482850161035a565b91505092915050565b5f82825260208201905092915050565b7f496e73756666696369656e742062616c616e63650000000000000000000000005f82015250565b5f6103dd601483610399565b91506103e8826103a9565b602082019050919050565b5f6020820190508181035f83015261040a816103d1565b9050919050565b5f81905092915050565b50565b5f6104295f83610411565b91506104348261041b565b5f82019050919050565b5f6104488261041e565b9150819050919050565b7f5472616e73666572206661696c656400000000000000000000000000000000005f82015250565b5f610486600f83610399565b915061049182610452565b602082019050919050565b5f6020820190508181035f8301526104b38161047a565b9050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6104f182610313565b91506104fc83610313565b9250828203905081811115610514576105136104ba565b5b92915050565b5f61052482610313565b915061052f83610313565b9250828201905080821115610547576105466104ba565b5b9291505056fea26469706673582212201b8929c9bb800c261be9808bfbd6b1243121f29219890823dfdf61403f92b20c64736f6c63430008140033"
code = bytes.fromhex(bytecode)
print(code)
bbs = list(generate_BBs(code))
cfg = CFG(bbs)
print(cfg)
'''
