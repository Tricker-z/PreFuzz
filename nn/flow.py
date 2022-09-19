import os
import sys
import queue
import math
import re

from utils import utils


class Node:
    def __init__(self, block_id: int, addr: int):
        self.id = block_id
        self.addr = addr
        self.parents = set()
        self.children = set()


class FlowBuilder:
    def __init__(self, bin_file: str):
        self.bin_file = bin_file

        self.cf_dir = './flow'
        self.target = bin_file[bin_file.rfind('/') + 1:]
        self.edge_target = f'{self.cf_dir}/edge-{self.target}'
        self.dump_target = f'{self.cf_dir}/dump-{self.target}'
        self.pc_target = f'{self.cf_dir}/pc-{self.target}'
        self.block_target = f'{self.cf_dir}/block-{self.target}'
        self.control_flow_target = f'{self.cf_dir}/flow-{self.target}'
        self.correspond_target = f'{self.cf_dir}/correspond-{self.target}'

        self.next_pc = dict()
        self.next_block = dict()
        self.label2addr = dict()
        self.addr2label = dict()
        self.addr2block = dict()
        self.addr2asm = dict()
        self.nodes = set()

        self.min_asm_addr = 0xffffffff
        self.max_asm_addr = -1

        self.init_work_env()
        self.init_next_pc()
        self.init_next_block()
        self.dump_control_flow()
        self.dump_correspond()


    def dump_correspond(self):
        if os.path.exists(self.correspond_target):
            return
        correspond_dict = dict()
        with open(self.control_flow_target, 'r') as fopen:
            for line in fopen.readlines():
                correspond_list = eval(line.strip('\n'))
                for edge in correspond_list:
                    if edge not in correspond_dict.keys():
                        correspond_dict[edge] = set()
                    for correspond in correspond_list:
                        if correspond == edge:
                            continue
                        correspond_dict[edge].add(correspond)
        with open(self.correspond_target, 'w') as f:
            f.write(str(correspond_dict))
        

    def dump_control_flow(self):
        if os.path.exists(self.control_flow_target):
            return
        with open(self.control_flow_target, 'w') as f:
            for n in self.nodes:
                edge_list = []
                for child in n.children:
                    edge_list.append((n.id >> 1) ^ child.id)
                if len(edge_list) > 1:
                    f.write(f'{str(edge_list)}\n')

        with open(self.edge_target, 'w') as f:
            for n in self.nodes:
                from_id = n.id
                for child in n.children:
                    to_id = child.id
                    edge_num = (from_id >> 1) ^ to_id
                    f.write(f"{edge_num}: {from_id}, {to_id}\n")

    def init_next_pc(self):
        if os.path.exists(self.pc_target):
            return
        if os.path.exists(self.control_flow_target):
            return
        f = open(self.pc_target, 'w')
        pc = self.min_asm_addr
        while pc < self.max_asm_addr:
            next_pc = pc + 1
            while next_pc < self.max_asm_addr and next_pc not in self.addr2asm.keys():
                next_pc += 1

            asm_code = self.addr2asm[pc]

            if 'ret' in asm_code:
                self.next_pc[pc] = []
            elif '@plt' in asm_code or '__afl_maybe_log' in asm_code:
                self.next_pc[pc] = [next_pc]
            elif 'call' in asm_code or 'jmp' in asm_code:
                reg_exp = r'.*?(0x)?([0-9a-f]{3,})'
                search_obj = re.search(reg_exp, asm_code)
                if search_obj:
                    next_addr = int(search_obj.group(2), 16)
                    if next_addr in self.addr2asm.keys():
                        self.next_pc[pc] = [int(search_obj.group(2), 16)]
                    else:
                        self.next_pc[pc] = []
                else:
                    self.next_pc[pc] = [next_pc]
            elif utils.action(asm_code)[0] == 'j':
                reg_exp = r'.*?(0x)?([0-9a-f]{3,})'
                search_obj = re.search(reg_exp, asm_code)
                if search_obj:
                    next_addr = int(search_obj.group(2), 16)
                    if next_addr in self.addr2asm.keys():
                        self.next_pc[pc] = [next_pc, int(search_obj.group(2), 16)]
                    else:
                        self.next_pc[pc] = [next_pc]
                else:
                    self.next_pc[pc] = [next_pc]
            else:
                self.next_pc[pc] = [next_pc]
            pc = next_pc

        self.ret_dfs(self.label2addr['<main>'], 0, set())

        for pc in self.next_pc.keys():
            f.write(f"{pc}: {str(self.next_pc[pc])[1:-1]}\n")
        f.flush()
        f.close()

    def init_next_block(self):
        if os.path.exists(self.control_flow_target):
            return
        self.load_next_pc()
        self.last_pc = dict()
        for addr in self.addr2asm.keys():
            self.last_pc[addr] = set()
        for addr in self.next_pc.keys():
            for next_addr in self.next_pc[addr]:
                if next_addr == 0:
                    continue
                self.last_pc[next_addr].add(addr)
        
        for n in self.nodes:
            next_block_addr = n.addr
            q = queue.Queue()
            for addr in self.last_pc[next_block_addr]:
                q.put(addr)
            while not q.empty():
                cur_addr = q.get()
                if cur_addr in self.addr2block.keys():
                    continue
                if next_block_addr in self.next_block[cur_addr]:
                    continue
                self.next_block[cur_addr].add(next_block_addr)
                for addr in self.last_pc[cur_addr]:
                    q.put(addr)

        for n in self.nodes:
            for next_addr in self.next_pc[n.addr]:
                for addr in self.next_block[next_addr]:
                    child_node = self.addr2block[addr]
                    n.children.add(child_node)
                    child_node.parents.add(n)

    def init_work_env(self):
        if not os.path.exists(self.cf_dir):
            os.mkdir(self.cf_dir)
        if not os.path.exists(self.dump_target):
            cmd = f"objdump -d {self.bin_file} > {self.dump_target}"
            os.system(cmd)
        if os.path.exists(self.control_flow_target):
            return
        with open(self.dump_target) as f:
            orig_codes = f.readlines()
            for i in range(len(orig_codes)):
                line = orig_codes[i]
                if not utils.is_valid_line(line):
                    continue
                if line[0] == ' ':
                    tmp = line.split(':')
                    addr = int(tmp[0], 16)
                    self.addr2asm[addr] = tmp[1].strip()
                    if addr > self.max_asm_addr:
                        self.max_asm_addr = addr
                    if addr < self.min_asm_addr:
                        self.min_asm_addr = addr
                    self.next_block[addr] = set()
                    if '__afl_maybe_log' in line:
                        reg_exp = r'0x(.*),'
                        match_obj = re.search(reg_exp, orig_codes[i - 1])
                        if not match_obj:
                            print(f"[-]: fatal error: unable to recognize afl_maybe_log id of: {orig_codes[i - 1]}")
                            exit(-1)
                        node = Node(int(match_obj.group(1), 16), addr)
                        self.addr2block[addr] = node
                        self.next_block[addr].add(addr)
                        self.nodes.add(node)
                if line[-2] == ':':
                    tmp = line.split(' ')
                    addr = int(tmp[0], 16)
                    label = tmp[1][:-2]
                    self.addr2label[addr] = label
                    self.label2addr[label] = addr

    def ret_dfs(self, pc: int, func_ret_addr: int, visited_addr: set):
        while pc < self.max_asm_addr and pc not in visited_addr:
            visited_addr.add(pc)
            next_pc = self.next_pc[pc]
            if len(next_pc) == 2:
                self.ret_dfs(next_pc[0], func_ret_addr, visited_addr)
                self.ret_dfs(next_pc[1], func_ret_addr, visited_addr)
                return
            if len(next_pc) == 0:
                self.next_pc[pc] = [func_ret_addr]
                return
            stmt = self.addr2asm[pc]
            if 'call' in stmt and '@plt' not in stmt and '__afl_maybe_log' not in stmt:
                ret_addr = pc + 1
                while ret_addr < self.max_asm_addr and ret_addr not in self.addr2asm.keys():
                    ret_addr += 1
                if pc < self.max_asm_addr:
                    self.ret_dfs(self.next_pc[pc][0], ret_addr, visited_addr)
                return
            pc = next_pc[0]

    def load_next_pc(self):
        if len(self.next_pc) != 0:
            return
        with open(self.pc_target) as f:
            for line in f.readlines():
                tmp = line.split(':')
                addr = tmp[1].split(',')
                new_addr = []
                for i in range(len(addr)):
                    if not addr[i].strip():
                        continue
                    new_addr.append(int(addr[i].strip()))
                self.next_pc[int(tmp[0])] = new_addr

if __name__ == '__main__':
    FlowBuilder(sys.argv[1])