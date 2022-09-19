import os
import sys
import glob
import math
import socket
import numpy as np
import random
from collections import Counter
from utils import utils
from flow import FlowBuilder

import torch
import torch.nn as nn
import torch.nn.functional as F

from torch.utils.data import Dataset, DataLoader
from torch.optim.lr_scheduler import LambdaLR
from torch.autograd import Variable

HOST = '127.0.0.1'
PORT = 12012

BATCH_SIZE = 16
HIDDEN_1 = 4096
EPOCHS = 100
SELECT_RATIO = 0.4
SHOWMAP_PATH = './afl-showmap'

bitmap_ec = dict()       # seed - edge coverage
label_index = dict()     # edge - index in bitmap
correspond_dict = dict() # edge - corresponding edges

# global variables
seed_path = str()
program_execute = str()

logger = utils.init_logger('./log_nn')
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')


class FuzzDataSet(Dataset):
    def __init__(self, seed_dir, program_execute):
        self.seed_list = glob.glob(os.path.join(seed_dir, '*'))
        self.bitmap = construct_bitmap(self.seed_list, program_execute)
        # in(out) dimension
        self.seed_size = utils.obtain_max_seed_size(seed_dir)
        self.edge_size = self.bitmap.shape[1]

    def __len__(self):
        return(self.bitmap.shape[0])

    def __getitem__(self, idx):
        btflow = vectorize_file(self.seed_list[idx], self.seed_size)
        covers = torch.as_tensor(self.bitmap[idx], dtype=torch.float32)
        return btflow, covers


class FuzzNet(nn.Module):
    def __init__(self, in_dim, hidden_1, out_dim):
        super(FuzzNet, self).__init__()
        self.layers = nn.Sequential(
            nn.Linear(in_dim, hidden_1),
            nn.ReLU(inplace=True),
            nn.Linear(hidden_1, out_dim),
            nn.Sigmoid()
        )

    def forward(self, x):
        x = self.layers(x)
        return x


def construct_bitmap(seed_list, program_execute):
    '''Build the edge coverage bitmap of seeds'''
    global label_index
    edge_list = list()
    # acquire edge coverage of each seed
    cnt, total = 0, len(seed_list)
    for seed in reversed(seed_list):
        if seed not in bitmap_ec.keys():
            cover_list = utils.acquire_edge(SHOWMAP_PATH, seed, program_execute)
            if len(cover_list):
                bitmap_ec[seed] = cover_list
                edge_list.extend(cover_list)
            else:
                # crash file
                dst_path = os.path.join('./crashes/', os.path.split(seed)[1])
                utils.move_file(seed, dst_path)
                seed_list.remove(seed)
                logger.info('Crash file:' + seed)
        else:
            edge_list.extend(bitmap_ec[seed])

        if cnt % 100 == 0:
            print(f'parse seed set {str(round(cnt / total, 5) * 100)[:5]}%', end='\r')
        cnt += 1

    label = [ec[0] for ec in Counter(edge_list).most_common()]
    label_index = dict(zip(label, range(len(label))))
    # contrcuct raw bitmap
    bitmap = np.zeros((len(seed_list), len(label)))
    for idx, seed in enumerate(seed_list):
        if seed not in bitmap_ec.keys():
            continue
        for edge in bitmap_ec[seed]:
            bitmap[idx][label_index[edge]] = 1

    # label reduction
    bitmap, idx_inverse = np.unique(bitmap, axis=1, return_inverse=True)
    # update label index
    for label in label_index.keys():
        raw_idx = label_index[label]
        label_index[label] = idx_inverse[raw_idx]

    logger.info('Bitmap dimension:' + str(bitmap.shape))
    return bitmap


def vectorize_file(fname, flength):
    with open(fname, 'rb') as fopen:
        btflow = torch.tensor([bt for bt in bytearray(fopen.read())], dtype=torch.float32) / 255
    # pad sequence
    if flength > len(btflow):
        btflow = F.pad(btflow, (0, flength-len(btflow)), 'constant', 0)
    return btflow


def select_edges(fuzzData, edge_num):
    # candidate edges
    if np.random.rand() < 0.1:
        # random selection mechanism
        alter_edges = np.random.choice(fuzzData.edge_size, edge_num)
    else:
        candidate_set = set()
        for edge in label_index.keys():
            if check_select_edge(edge):
                candidate_set.add(label_index[edge])
        replace_flag = True if len(candidate_set) < edge_num else False
        alter_edges = np.random.choice(list(candidate_set), edge_num, replace=replace_flag)

    alter_seeds = list()
    for edge in alter_edges:
        idx_list = np.where(fuzzData.bitmap[:,edge] == 1)[0]
        alter_seeds.append(random.choice(idx_list))
    
    interested_indice = zip(alter_edges.tolist(), alter_seeds)
    return interested_indice


def check_select_edge(edge_id):
    if edge_id not in correspond_dict.keys():
        return True
    
    correspond_set = correspond_dict[edge_id]
    if len(correspond_set) == 0:
        return True

    cover_cnt = 0
    for ce in correspond_set:
        if ce in label_index.keys():
            cover_cnt += 1
    if cover_cnt / len(correspond_set) > SELECT_RATIO:
        return False
    return True


def gen_adv(fuzzNet, fuzzData, edge_idx, seed_name):
    x = vectorize_file(seed_name, fuzzData.seed_size).to(device)
    x = Variable(x, requires_grad=True)
    
    y = x
    for layer in list(fuzzNet.layers)[:-1]:
        y = layer(y)

    grads = torch.autograd.grad(y[edge_idx], x)[0]
    grads = grads.cpu().numpy()
    # sort byte indix desc to the gradients
    grads_abs = np.absolute(grads)
    idx = np.argsort(-grads_abs)
    sign = np.sign(grads)[idx]

    return idx, sign, grads_abs


def gen_grads(fuzzNet, fuzzData, grads_num):
    # edge select strategy
    interested_indice = select_edges(fuzzData, grads_num)

    fopen = open('gradient_info_p', 'w')
    cnt, total = 0, grads_num
    for edge_idx, seed_idx in interested_indice:
        seed_name = fuzzData.seed_list[seed_idx]
        idx, sign, _ = gen_adv(fuzzNet, fuzzData, edge_idx, seed_name)
        idx = [str(ele) for ele in idx]
        sign = [str(int(ele)) for ele in sign]
        fopen.write(','.join(idx) + '|' + ','.join(sign) + '|' + seed_name + '\n')

        if cnt % 10 == 0:
            print(f'generate gradients {str(round(cnt / total, 5) * 100)[:5]}%', end='\r')
        cnt += 1

    logger.info('Gradients number:' + str(grads_num))
    fopen.close()


def gen_grads_havoc(fuzzNet, fuzzData, grads_num):
    # edge select strategy
    interested_indice = select_edges(fuzzData, grads_num)

    fopen = open('gradient_info_havoc_p', 'w')
    cnt, total = 0, grads_num
    for edge_idx, seed_idx in interested_indice:
        seed_name = fuzzData.seed_list[seed_idx]
        _, _, grads = gen_adv(fuzzNet, fuzzData, edge_idx, seed_name)
        grads = [str(int(ele * 10000)) for ele in grads]
        fopen.write(','.join(grads) + '|' + seed_name + '\n')

        if cnt % 10 == 0:
            print(f'generate gradients for havoc {str(round(cnt / total, 5) * 100)[:5]}%', end='\r')
        cnt += 1

    logger.info('Gradients number for havoc:' + str(grads_num))
    fopen.close()


def accuracy(y_pred, y_true):
    '''Evaluation function'''
    y_true = y_true.int()
    y_pred = y_pred.round().int()

    edge_num = y_true.numel()
    false_num = edge_num - torch.sum(torch.eq(y_pred, y_true)).item()
    true_one_num = torch.sum(y_true & y_pred).item()

    return true_one_num / (true_one_num + false_num)


def step_decay(epoch):
    drop = 0.7
    epochs_drop = 10.0
    lr_lambda = math.pow(drop, math.floor((1 + epoch) / epochs_drop))
    return lr_lambda


def collate_fn(train_data):
    # sort by file length
    train_data.sort(key=lambda data: len(data[0]), reverse=True)
    train_x, train_y = map(list, zip(*train_data))
    data_len = [len(data) for data in train_x]

    train_x = nn.utils.rnn.pad_sequence(train_x, batch_first=True, padding_value=0)
    train_y = torch.cat(train_y).reshape(len(train_y), -1)

    return train_x.unsqueeze(-1), train_y, data_len


def train_model(fuzzNet, fuzzData, epochs):
    fuzzIter = DataLoader(fuzzData, batch_size=BATCH_SIZE, shuffle=True)

    optimizer = torch.optim.Adam(fuzzNet.parameters(), lr=0.0001)
    schedular = LambdaLR(optimizer, lr_lambda=step_decay)

    for epoch in range(epochs):
        loss_sum = 0.0
        acc_sum = 0.0

        for step, (btflow, covers) in enumerate(fuzzIter, 1):
            btflow = btflow.to(device)
            covers = covers.to(device)

            preds = fuzzNet(btflow)
            loss = F.binary_cross_entropy(preds, covers)
            acc = accuracy(preds, covers)

            loss_sum += loss.item()
            acc_sum += acc

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        schedular.step()

        logger.info('Epoch:[{}/{}]\t loss={:.5f}\t acc={:.3f}'.format(
            epoch+1, epochs, loss_sum/step, acc_sum/step
        ))
    # save model
    # torch.save(fuzzNet.state_dict(), './fuzz_model.pth')


def nn_lop(grads_num, grads_havoc_num):
    # build model
    fuzzData = FuzzDataSet(seed_path, program_execute)
    fuzzNet = FuzzNet(fuzzData.seed_size, HIDDEN_1, fuzzData.edge_size).to(device)
    logger.info(f'Input dim:{fuzzData.seed_size}\t Out dim:{fuzzData.edge_size}')
    # train model
    train_model(fuzzNet, fuzzData, EPOCHS) 
    # fuzzNet.load_state_dict(torch.load('./fuzz_model.pth'))
    
    # generate gradient values
    gen_grads(fuzzNet, fuzzData, grads_num)
    gen_grads_havoc(fuzzNet, fuzzData, grads_havoc_num)
    logger.info('End of one NN loop')


def init_env(program_path):
    global correspond_dict
    os.path.isdir("./vari_seeds/")  or  os.makedirs("./vari_seeds")
    os.path.isdir("./havoc_seeds/") or  os.makedirs("./havoc_seeds")
    os.path.isdir("./crashes/")     or  os.makedirs("./crashes")

    # construct edge corresponding dict
    logger.info(f'Construct the control-flow')
    flow = FlowBuilder(program_path)
    with open(flow.correspond_target, 'r') as fopen:
        correspond_dict = eval(fopen.readline())
    # initial gradients
    nn_lop(50, 100)


def setup_server():
    global seed_path
    global program_execute

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(1)
    logger.info('Server set up, wait for connection...')
    conn, addr = sock.accept()
    logger.info('Connected by fuzzing module:' + str(addr))

    seed_path = conn.recv(1024).decode()
    if not os.path.isdir(seed_path):
        logger.info('Invalid seed folder path:' + str(seed_path))
        sys.exit(-1)
    program_execute = ' '.join(sys.argv[1:])
    
    # initial
    init_env(sys.argv[1])
    conn.sendall(b'start')

    while True:
        data = conn.recv(1024)
        if not data:
            break
        else:
            nn_lop(100, 2000)
            conn.sendall(b'start')
    conn.close()


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print('Usage: python nn.py <target_program_path> <program_arg>')
        sys.exit(-1)
    # Server set
    setup_server()
