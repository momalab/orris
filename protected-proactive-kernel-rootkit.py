import time
from libraries.lauterbach import *
from timeit import default_timer as timer

from capstone import * # Needs to be installed
from ctypes import c_uint32

import multiprocessing
from multiprocessing import Value

import hashlib

class MaliciousFunction:
    def __init__(self):
        self.hexCodeDict = dict()
        self.graph = dict(set())
        self.completeDisassembly = ''

    def Update_Analysis(self, hexCodeDict, graph):
        self.hexCodeDict = hexCodeDict
        self.graph = graph

    def Generate_Disassembly(self):
        for key in self.hexCodeDict:
            startAddress = int(key.split('_')[1], 16)
            print('\nAddress : %s'%hex(startAddress))
            self.completeDisassembly += self.Disassemble(self.hexCodeDict[key], startAddress) + '\n\n'

    def Disassemble(self, hexCode, startAddress):
        result = ''
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        for i in md.disasm(hexCode, startAddress):
            result += "0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str)
            print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        return result

def Get_Bytes(intInstruction):
    return bytes(c_uint32(intInstruction))

def Get_Disassembly(hexCode, startAddress):
    result = ''
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    for i in md.disasm(hexCode, startAddress):
        result += "0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str)
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

def Check_NotVisited(visited, vertex):
    if vertex in visited:
        return False
    else:
        return True

def Check_CodeEntry(hexCodeDict, vertex):
    if vertex in hexCodeDict:
        return True
    else:
        return False

def Analyze_Rootkit(conn, startAddress):
    hexCodeDict = dict()
    graph = dict(set())
    visited, stack = set(), [startAddress]

    while stack:
        tempAddress = 0
        branchAddress = 0
        nextAddress = 0

        vertexAddress = stack.pop()
        if vertexAddress not in visited:
            visited.add(vertexAddress)
        else:
            continue

        tempAddress = vertexAddress
        while True:
            # print('Current Address : ', hex(tempAddress))
            memoryContent, garbageContent = conn.ReadMemory(tempAddress, 0x40, 4)
            if Check_CodeEntry(hexCodeDict, 'loc_' + hex(vertexAddress)):
                hexCodeDict['loc_' + hex(vertexAddress)] += Get_Bytes(int(memoryContent))
            else:
                hexCodeDict['loc_' + hex(vertexAddress)] = Get_Bytes(int(memoryContent))

            if Check_LDMFD(int(memoryContent)):
                graph['loc_' + hex(vertexAddress)] = ['EMPTY']
                # print('Check_LDMFD')
                break
            elif Check_BranchCondition(int(memoryContent)):
                branchAddress = Branch_Calcualtion(tempAddress, int(memoryContent))
                nextAddress = tempAddress + 0x04
                graph['loc_' + hex(vertexAddress)] = ['loc_' + hex(nextAddress), 'loc_' + hex(branchAddress)]

                if Check_NotVisited(visited, branchAddress):
                    stack.append(branchAddress)
                if Check_NotVisited(visited, nextAddress):
                    stack.append(nextAddress)
                # print('Check_BranchCondition')
                break
            elif Check_BasicBranch(int(memoryContent)):
                branchAddress = Branch_Calcualtion(tempAddress, int(memoryContent))
                graph['loc_' + hex(vertexAddress)] = ['loc_' + hex(branchAddress)]

                if Check_NotVisited(visited, branchAddress):
                    stack.append(branchAddress)
                # print('Check_BasicBranch')
                break
            tempAddress += 0x4

    return hexCodeDict, graph


# rev = "{0:b}".format(3902646296)[::-1], rev[25:28][::-1] == '100', P = rev[24], U = rev[23], L = rev[20], L == '1' and P == '0' and U == '1'
def Check_LDMFD(instruction):
    revInstruction = Fix_Zeroes("{0:b}".format(instruction), 32)[::-1]
    P = revInstruction[24]
    U = revInstruction[23]
    L = revInstruction[20]
    W = revInstruction[21]

    if revInstruction[25:28][::-1] == '100' and L == '1' and P == '0' and U == '1' and W == '0':
        return True
    else:
        return False

# Only checking for branhces without condition inside the function. Branch with link is not explored.
def Check_BasicBranch(instruction):
    revInstruction = Fix_Zeroes("{0:b}".format(instruction), 32)[::-1]
    if revInstruction[25:28][::-1] == '101' and revInstruction[24] == 0 and revInstruction[28:32][::-1] == '1110':
        return True
    else:
        return False

# Only checking for branhces with condition inside the function. Branch with link is not explored.
def Check_BranchCondition(instruction):
    revInstruction = Fix_Zeroes("{0:b}".format(instruction), 32)[::-1]
    if revInstruction[25:28][::-1] == '101' and revInstruction[24] == 0 and revInstruction[28:32][::-1] != '1110':
        return True
    else:
        return False

def Branch_Calcualtion(currentPC, instruction):
    rawOffset = Fix_Zeroes("{0:b}".format(instruction), 32)[::-1][:24][::-1]
    if Check_Positive(rawOffset):
        return (currentPC + 8) + (int(rawOffset, 2) * 4)
    else:
        return (currentPC + 8) - (int(Find_Twoscomplement(rawOffset), 2) * 4)

# test = "{0:b}".format(3850641420), rev = test[::-1], rev[26:28] == '10', regIndex = int(rev[12:16][::-1],2)
def Get_SourceAddress(conn, memoryContent):
    revInstruction = Fix_Zeroes("{0:b}".format(memoryContent), 32)[::-1]
    regIndex = int(revInstruction[12:16][::-1], 2)
    return conn.ReadRegisterByName('R' + str(regIndex))

def Get_DestinationAddress(conn, memoryContent):
    revInstruction = Fix_Zeroes("{0:b}".format(memoryContent), 32)[::-1]
    regIndex = int(revInstruction[16:20][::-1], 2)
    offset = int(revInstruction[0:12][::-1], 2)
    I = int(revInstruction[25], 2)
    U = int(revInstruction[23], 2)

    address = 0
    if I == 0:
        if U == 1:
            address = conn.ReadRegisterByName('R' + str(regIndex)) + offset
        elif U == 0:
            address = conn.ReadRegisterByName('R' + str(regIndex)) - offset
    return address

def Check_Positive(binValue):
    if binValue[0] == '0':
        return True
    else:
        return False

def Find_Twoscomplement(str):
    n = len(str)
    i = n - 1
    while (i >= 0):
        if (str[i] == '1'):
            break
        i -= 1

    if (i == -1):
        return '1' + str

    k = i - 1
    while (k >= 0):
        if (str[k] == '1'):
            str = list(str)
            str[k] = '0'
            str = ''.join(str)
        else:
            str = list(str)
            str[k] = '1'
            str = ''.join(str)
        k -= 1

    return str

def Fix_Zeroes(binaryString, length):
    return binaryString.zfill(length)

def PC_Skip(conn):
    PCAddress = conn.ReadPC()
    intMemContent, hexMemContent = conn.ReadMemory(PCAddress, 0x40, 4)
    sourceAddress = Get_SourceAddress(conn, int(intMemContent))
    destinationAddress = Get_DestinationAddress(conn, int(intMemContent))
    conn.WriteRegisterByName('PC', PCAddress+4)
    print('\nInstruction at address %s : %s, is trying to modify sys_call_table. Skipping execution to %s' %(hex(PCAddress), hexMemContent, hex(PCAddress+4)))
    print('Malicious sys_call hook address : %s'%hex(sourceAddress))
    print('System Call Table address being modified : %s' %hex(destinationAddress))

    return sourceAddress, destinationAddress

def Watchpoint_PC_Skip(conn):
    PCAddress = conn.ReadPC()
    intMemContent, hexMemContent = conn.ReadMemory(PCAddress, 0x40, 4)
    conn.WriteRegisterByName('PC', PCAddress+4)
    print('\nInstruction at address %s : %s, is trying to modify Watchpoint register.' %(hex(PCAddress), hexMemContent))


def CheckWatchpoint(conn, initialWVR0, initialWCR0, initialWVR1, initialWCR1):
    mismatch = False
    currentWVR0 = int(conn.HexReadMemory(bbbBaseAddress + 0x180, 0x40, 0x4), 16)
    currentWCR0 = int(conn.HexReadMemory(bbbBaseAddress + 0x1c0, 0x40, 0x4), 16)
    currentWVR1 = int(conn.HexReadMemory(bbbBaseAddress + 0x184, 0x40, 0x4), 16)
    currentWCR1 = int(conn.HexReadMemory(bbbBaseAddress + 0x1c4, 0x40, 0x4), 16)

    if currentWVR0 != initialWVR0:
        print('Mismatch in WVR0 register')
        mismatch = True

    if currentWVR1 != initialWVR1:
        print('Mismatch in WVR1 register')
        mismatch = True

    if currentWCR0 != initialWCR0:
        print('Mismatch in WCR0 register')
        mismatch = True

    if currentWCR1 != initialWCR1:
        print('Mismatch in WCR1 register')
        mismatch = True

    if mismatch:
        conn.Command('Break.Delete /ALL')
        conn.WriteBreakpoint(syscallTable, 0x40, 0x10, 1524)
        conn.Command('Data.Set ENSD:0x0:0x4B141180 %LE %Long 0xC000F800 0x00')
        conn.Command('Data.Set ENSD:0x0:0x4B1411C0 %LE %Long 0x0B001FF7 0x00')
        mismatch = False

def Get_Hash(data):
    return hashlib.md5(data).hexdigest()

if __name__ == "__main__":
    # BBBBase address
    bbbBaseAddress = 0x4b141000
    # System Call table address, Data.dump E:0xc000f924
    syscallTable = 0xc000f924
    initialWVR0 = 0
    initialWCR0 = 0
    initialWVR1 = 0
    initialWCR1 = 0

    # Assume that Lauterbach is connected and initialized
    conn = Lauterbach()
    conn.Connect()

    # Holds object representing all the functions found during analysis
    functionList = list()

    while True:
        option = int(input('\n*** MENU ***\n 1. Write Watchpoint on System Call Table \n 2. Proactive Solution \n 3. Proactive Solution + Analysis \n 4. Exit \n\n Option : '))
        if option == 4:
            conn.Command('Break.Delete /ALL')
            conn.Disconnect()
            break
        elif option == 1:
            # Setup breakpoint on sys_call_table
            conn.WriteBreakpoint(syscallTable, 0x40, 0x10, 1524)
            initialWVR0 = int(conn.HexReadMemory(bbbBaseAddress + 0x180, 0x40, 0x4), 16)
            initialWCR0 = int(conn.HexReadMemory(bbbBaseAddress + 0x1c0, 0x40, 0x4), 16)
            initialWVR1 = int(conn.HexReadMemory(bbbBaseAddress + 0x184, 0x40, 0x4), 16)
            initialWCR1 = int(conn.HexReadMemory(bbbBaseAddress + 0x1c4, 0x40, 0x4), 16)
            print('Watchpoint and check Added Successfully')
            continue

        elif option != 1 and option != 2 and option != 3 and option != 4:
            print('\nUnrecognized Input. Please Try Again\n')
            continue

        elif option == 2 or option == 3:
            while True:
                try:
                    CheckWatchpoint(conn, initialWVR0, initialWCR0, initialWVR1, initialWCR1)
                    if conn.CPU_GetState() == 2:
                        start = timer()

                        obj = MaliciousFunction()
                        functionList.append(obj)
                        sourceAddress, destinationAddress = PC_Skip(conn)

                        if option == 3:
                            hexCodeDict, graph = Analyze_Rootkit(conn, sourceAddress)
                            obj.Update_Analysis(hexCodeDict, graph)
                            obj.Generate_Disassembly()

                        end = timer()
                        interval = end - start
                        print('Cycle Time : %f sec' % interval)

                        conn.CPU_Go()

                    time.sleep(0.05)  # 50 ms pause in each loop
                except KeyboardInterrupt:
                    print("\n[CTRL+C detected]")
                    break
