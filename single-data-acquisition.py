from libraries.lauterbach import *
import time

from multiprocessing import shared_memory
from multiprocessing import Value, Lock
import multiprocessing
import threading
import numpy as np

import paramiko
from scp import SCPClient
import csv
from os import listdir
from os.path import isfile, join
import collections
import json
import os

# --------------------------------- Task Reconstruction

INIT_TASK = 0xc150c340      # For BBB kernel 4.19.82-ti-rt-r31
INT_INIT_TASK = 3243295552
MAX_PROCESS_COUNT = 32768

DEVICE_USERNAME = 'debian'
DEVICE_IP_ADDRESS = '192.168.6.2'
DEVICE_PASSWORD = 'temppwd'

def GetNextAddress(data):
    return int(data.split(':')[208], 16) - 0x340

def GetPID(data):
    return data.split(':')[247]

def GetTaskStruct(conn, address):
    return conn.HexReadMemory(address, 0x40, 0x87f)

def GetSchedClass(conn, data):
    address =  int(data.split(':')[18], 16)
    return conn.HexReadMemory(address, 0x40, 0x60)

def GetSchedTaskGroup(conn, data):
    address =  int(data.split(':')[135], 16)
    return conn.HexReadMemory(address, 0x40, 0x1a0)

def GetMM(conn, data):
    address =  int(data.split(':')[218], 16)
    return conn.HexReadMemory(address, 0x40, 0x208)

def GetRealCred(conn, data):
    address =  int(data.split(':')[310], 16)
    return conn.HexReadMemory(address, 0x40, 0x80)

def GetFS(conn, data):
    address =  int(data.split(':')[322], 16)
    return conn.HexReadMemory(address, 0x40, 0x38)

def GetFiles(conn, data):
    address =  int(data.split(':')[323], 16)
    return conn.HexReadMemory(address, 0x40, 0x128)

def GetSignal(conn, data):
    address =  int(data.split(':')[325], 16)
    return conn.HexReadMemory(address, 0x40, 0x2f0)

def GetDelay(conn, data):
    address =  int(data.split(':')[452], 16)
    return conn.HexReadMemory(address, 0x40, 0x34)

def TraverseTaskStruct(sharedState, address, fileName, iteration):
    conn = Lauterbach()
    conn.Connect()
    TaskStructDict = dict()
    cycleCount = 1

    while sharedState.value == 0 and sharedState.value != 1:
        continue

    print('\nSemantic information gathering initiated ...\n')
    while sharedState.value != 3:
        lockedSharedState = sharedState.value
        nextAddress = address
        processCount = 0
        individualTask = dict()

        while True:
            task_struct = GetTaskStruct(conn, nextAddress)
            sched_class = GetSchedClass(conn, task_struct)
            sched_task_group = GetSchedTaskGroup(conn, task_struct)
            mm = GetMM(conn, task_struct)
            real_cred = GetRealCred(conn, task_struct)
            fs = GetFS(conn, task_struct)
            files = GetFiles(conn, task_struct)
            signal = GetSignal(conn, task_struct)
            delays = GetDelay(conn, task_struct)

            individualTask[GetPID(task_struct)] = {'task_struct':task_struct, 'sched_class':sched_class, 'sched_task_group':sched_task_group, 'mm':mm, 'real_cred':real_cred, 'fs':fs, 'files':files, 'signal':signal, 'delays':delays}
            nextAddress = GetNextAddress(task_struct)
            processCount += 1

            if nextAddress == INT_INIT_TASK or processCount > MAX_PROCESS_COUNT:
                if lockedSharedState == 1:
                    TaskStructDict[cycleCount] = individualTask
                break

        print('Semantic information scanned : %i' % (cycleCount))
        cycleCount += 1

    directoryPath = '/home/prajput/Malware-Detection-JTAG/Extra/Test-Files/Semantic/' + fileName + '/' + iteration + '/'
    DumpJSONToFile(directoryPath + fileName + '.txt', TaskStructDict)

    print('\nSaving semantic information to disk ...\n')
    conn.Disconnect()

# --------------------------------- Micro-Architectural Events

eventList16 = {
    0 : 'AXIREAD',
    1 : 'AXIWRITE',
    2 : 'BINST',
    3 : 'BPCONDMIS',
    4 : 'BPEXECTAKEN',
    5 : 'BPMIS',
    6 : 'BPREDICTABLE',
    7 : 'BPREDTAKEN',
    8 : 'CLOCKCYCLES',
    9 : 'CONTEXT',
    10: 'DCACCESS',
    11: 'DCACCESSNEON',
    12: 'DCALIAS',
    13: 'DCHASHMISS',
    14: 'DCHITNEON',
    15: 'DUNALIGNED',
    16: 'DREAD',
    17: 'DTLBMISS',
    18: 'DWRITE',
    19: 'ECALL',
    20: 'ERETURN',
    21: 'ETMEXTOUT0',
    22: 'ETMEXTOUT1',
    23: 'ETMEXTOUT01',
    24: 'ICACCESS',
    25: 'ICHASHMISS',
    26: 'ICMISS',
    27: 'IIDLE',
    28: 'ITLBMISS',
    29: 'L2ACCESSNEON',
    30: 'L2HITNEON',
    31: 'L2MERGE',
    32: 'L2MISS',
    33: 'L2STORE',
    34: 'NEONSTALL',
    35: 'NEONWAITS',
    36: 'NEONWORK',
    37: 'PCINST',
    38: 'REPLAY',
    39: 'RETURN',
    40: 'RSTKMISS',
    41: 'SOFT',
    42: 'UNALIGNEDREPLAY',
    43: 'WBFULL'
}

eventList32 = {
    0: 'DCMISS',
    1: 'IISSUE',
    2: 'INST',
    3: 'L2ACCESS',
    4: 'OPERATION'
}

def StopSnoop(conn):
    ResetCounters(conn)
    conn.Command('ETM.OFF')

def SetupSNOOPer(conn):
    conn.Command('SNOOPer.Mode BMC')
    conn.Command('SNOOPer.Mode SLAVE ON')
    #conn.Command('SNOOPer.Mode Changes ON')
    #conn.Command('SNOOPer.Mode FAST ON')
    conn.Command('SNOOPer.List')
    conn.Command('SNOOPer.Arm')

def SaveCSV(conn, filePath):
    conn.Command('SNOOPer.OFF')
    conn.Command('PRinTer.EXPORT.CSV "' + filePath + '"')
    conn.Command('WinPrint.SNOOPer.List')

def SetETMCounters(conn, event1, event2 = ''):
    conn.Command('BMC.Export ON')
    conn.Command('BMC.etm1.EVENT ' + event1)

    if event2 != '':
        conn.Command('BMC.etm2.EVENT ' + event2)

    conn.Command('BMC.SnoopSet ON')

def ResetCounters(conn):
    conn.Command('BMC.RESet')
    conn.Command('SNOOPer.RESet')

def InitSettings(conn):
    conn.Command('ETM.ON')
    conn.Command('BMC.Init')
    conn.Command('SNOOPer.Init')

def GetMicroArchitecturalEvents(sharedState, event1, event2, directoryPath, fileName):
    conn = Lauterbach(True, '20001')
    conn.Connect()
    print('\nLow-level information gathering initiated ...\n')

    while sharedState.value == 0 and sharedState.value != 1:
        continue

    conn.CPU_Break()
    ResetCounters(conn)
    InitSettings(conn)
    SetETMCounters(conn, event1, event2)

    # Start ETM counters
    SetupSNOOPer(conn)
    conn.CPU_Go()

    # Save event counts to a file
    while sharedState.value == 1:
        continue

    SaveCSV(conn, directoryPath + fileName + '-' + event1 + '-' + event2 + '.csv')
    StopSnoop(conn)

    print('\nLow-level information gathering ended ...\n')
    conn.Disconnect()

# -------------------------------- Processing low-level information

def ParseCSV(filePath, fileName, destinationPath, singleETM = False):
    processedDict = dict()
    secondTracker = 0.0
    etm1 = 0
    etm2 = 0
    previousETM1 = 0
    previousETM2 = 0
    etm1Tracker = 0
    etm2Tracker = 0
    counter = 1

    with open(filePath, mode='r') as csvFile:
        csvReader = csv.reader(csvFile, delimiter=',')
        lineCount = 0
        for row in csvReader:
            if lineCount == 0 or lineCount == 1 or lineCount == 2:
                lineCount += 1
            else:
                etm1 = int(row[1], 16)
                etm2 = int(row[2], 16)

                if singleETM:
                    tiBack = row[4]
                else:
                    tiBack = row[5]

                secondTracker += float(tiBack)

                # Handle normal counter increment and counter reset due to overflow
                if previousETM1 <= etm1:
                    etm1Tracker += (etm1 - previousETM1)
                    #print('ETM1 (%i) > PreviousETM1 (%i) Line: %i \t ETM1Tracker: %i' %(etm1, previousETM1, lineCount, etm1Tracker))
                else:
                    etm1Tracker += (65535 - previousETM1)
                    etm1Tracker += etm1
                    #print('ETM1 (%i) < PreviousETM1 (%i) Line: %i \t ETM1Tracker: %i' %(etm1, previousETM1, lineCount, etm1Tracker))

                if previousETM2 <= etm2:
                    etm2Tracker += (etm2 - previousETM2)
                    #print('ETM2 (%i) > PreviousETM2 (%i) Line: %i \t ETM2Tracker: %i' %(etm2, previousETM2, lineCount, etm2Tracker))
                else:
                    etm2Tracker += (65535 - previousETM2)
                    etm2Tracker += etm2
                    #print('ETM2 (%i) < PreviousETM2 (%i) Line: %i \t ETM2Tracker: %i' %(etm2, previousETM2, lineCount, etm2Tracker))

                # Save previous ETM values
                previousETM1 = etm1
                previousETM2 = etm2

                # Handle events/sec
                if secondTracker >= 1.0:
                    print('Partial Time %f sec \t Line Count: %i \t ETM1: %i \t ETM2: %i' %(secondTracker, lineCount, etm1Tracker, etm2Tracker))
                    processedDict[counter] = {'time_counter':secondTracker, 'line_count':lineCount, 'etm1_count':etm1Tracker, 'etml2_count':etm2Tracker}
                    secondTracker = 0.0
                    etm1Tracker = 0
                    etm2Tracker = 0
                    counter += 1
                else:
                    etm1 = 0
                    etm2 = 0

                lineCount += 1
        print('Partial Time %f sec \t Line Count: %i \t ETM1: %i \t ETM2: %i' %(secondTracker, lineCount, etm1Tracker, etm2Tracker))
        processedDict[counter] = {'time_counter':secondTracker, 'line_count':lineCount, 'etm1_count':etm1Tracker, 'etml2_count':etm2Tracker}
        DumpJSONToFile(destinationPath + fileName + '.txt', processedDict)

def PreProcessFunctionality(directoryPath, destinationPath, etmStatus):
    completedScan = list()
    extractedFiles = [f for f in listdir(directoryPath) if isfile(join(directoryPath, f))]

    for files in extractedFiles:
        if not files in completedScan:
            finalPath = directoryPath + files
            print('\nPreprocessing File: %s' % (finalPath))
            ParseCSV(finalPath, files, destinationPath, etmStatus)
            completedScan.append(files)

def PreProcessLowLevelInformation(fileName, iteration):
    directoryPath = ['/home/prajput/Malware-Detection-JTAG/Extra/Test-Files/Low-Level/' +fileName+ '/Single/' + iteration + '/', '/home/prajput/Malware-Detection-JTAG/Extra/Test-Files/Low-Level/' +fileName+ '/Double/' + iteration + '/']
    PreProcessFunctionality(directoryPath[0], '/home/prajput/Malware-Detection-JTAG/Extra/Test-Files/Low-Level-Processed/' +fileName+ '/Single/' + iteration + '/', True)
    PreProcessFunctionality(directoryPath[1], '/home/prajput/Malware-Detection-JTAG/Extra/Test-Files/Low-Level-Processed/' + fileName + '/Double/' + iteration + '/', False)

# -------------------------------- Experiment Setup

def MakeDirectory(directoryPath):
    if not os.path.exists(directoryPath):
        #os.mkdir(directoryPath)
        os.makedirs(directoryPath, exist_ok=True)

def DumpJSONToFile(filePath, contentDict):
    with open(filePath, 'w') as outfile:
        json.dump(contentDict, outfile)

def SSH_Execute(command):
    if DEVICE_USERNAME == '':
        print('DEVICE_USERNAME not specified.')
        return
    elif DEVICE_IP_ADDRESS == '':
        print('DEVICE_IP_ADDRESS not specified.')
        return
    elif DEVICE_PASSWORD == '':
        print('DEVICE_PASSWORD not specified.')
        return

    try:
        paramiko.util.log_to_file('ssh.log')
        SSH_CLIENT = paramiko.SSHClient()
        SSH_CLIENT.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        SSH_CLIENT.connect(hostname=DEVICE_IP_ADDRESS, username=DEVICE_USERNAME, password=DEVICE_PASSWORD)
        finalCommand = command

        SSH_STDIN, SSH_STDOUT, SSH_STDERR = SSH_CLIENT.exec_command(finalCommand, timeout=11)
        exitStatus = SSH_STDOUT.channel.recv_exit_status()

        SSH_CLIENT.close()

    except paramiko.ssh_exception.NoValidConnectionsError as exception:
        print(exception)
    except Exception as exception:
        pass
    finally:
        SSH_CLIENT.close()

def SCP_Transfer(localPath, remotePath):
    if DEVICE_USERNAME == '':
        print('DEVICE_USERNAME not specified.')
        return
    elif DEVICE_IP_ADDRESS == '':
        print('DEVICE_IP_ADDRESS not specified.')
        return
    elif DEVICE_PASSWORD == '':
        print('DEVICE_PASSWORD not specified.')
        return

    try:
        paramiko.util.log_to_file('scp.log')
        SSH_CLIENT = paramiko.SSHClient()
        SSH_CLIENT.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        SSH_CLIENT.connect(hostname=DEVICE_IP_ADDRESS, username=DEVICE_USERNAME, password=DEVICE_PASSWORD)
        with SCPClient(SSH_CLIENT.get_transport()) as scp:
            scp.put(localPath, remotePath)

        SSH_CLIENT.close()

    except paramiko.ssh_exception.NoValidConnectionsError as exception:
        print(exception)
    except Exception as exception:
        pass
    finally:
        SSH_CLIENT.close()

def UpdateSharedState(value):
    with lock:
        sharedState.value = value

def SCPTestSample(localDirectoryPath, fileName, remoteDirectoryPath):
    remotePath = remoteDirectoryPath + fileName
    SCP_Transfer(localDirectoryPath + fileName, remotePath)

def CleanBBB(remotePath):
    SSH_Execute('rm ' + remotePath)

def PerformExperiment(filePath):
    time.sleep(2)
    print('\nExecuting malware for a maximum of 10 seconds ...\n')
    UpdateSharedState(1)
    time.sleep(10)
    print('\nMalware execution completed ...\n')
    UpdateSharedState(3)

def CheckMalwareStatus(filePath):
    f = open(filePath, "r")
    status = f.readline().rstrip()
    f.close()

    if status == 'GOOD':
        return True
    elif status == 'FALSE':
        return True
    else:
        return False

def WriteCompleted(fileName):
    with open('/home/prajput/Malware-Detection-JTAG/Extra/Test-Files/completed.txt', 'a') as completedFile:
        completedFile.write(fileName + '\n')

def CheckIfCompleted(fileName):
    with open('/home/prajput/Malware-Detection-JTAG/Extra/Test-Files/completed.txt', 'r') as f:
        lines = f.read().splitlines()

    if fileName in lines:
        return True
    else:
        False
        
def DisplayFile(filePath):
    with open(filePath, 'r') as fin:
        print(fin.read())

if __name__ == '__main__':
    sharedState = Value('i', 0)
    lock = Lock()
    baseTestDirectory = '/home/prajput/Malware-Detection-JTAG/Extra/Test-Files/'
    testSamples = [f for f in listdir(baseTestDirectory + 'Samples/') if isfile(join(baseTestDirectory + 'Samples/', f))]
    completedCount = 1

    for fileName in testSamples:
        print('\nHandling %i malware out of %i ...' % (completedCount, len(testSamples)))
        completedCount += 1

        if '.txt' in fileName:
            continue

        if CheckMalwareStatus(baseTestDirectory + 'Samples/' + fileName + '.txt'):
            print('Good Ignoring : %s ---' %(fileName))
            continue

        if CheckIfCompleted(fileName):
            print('Completed Ignoring : %s ---' %(fileName))
            continue

        # Testing
        print('\n--- Print File  ---\n' )
        DisplayFile(baseTestDirectory + 'Samples/' + fileName + '.txt')
        print('\nTesting : %s ---' % (fileName))
        SCPTestSample(baseTestDirectory + 'Samples/', fileName, '/home/debian/Test-Files/')
        SSH_Execute('chmod +x ' + '/home/debian/Test-Files/' + fileName)
        input('Press enter when testing is finished ...')
        CleanBBB('/home/debian/Test-Files/' + fileName)

        print('Processing : %s ---' %(fileName))
        input('Press ENTER to continue ...')
        SCPTestSample(baseTestDirectory + 'Samples/', fileName, '/home/debian/Test-Files/')
        remotePath = 'Test-Files/' + fileName
        
        SSH_Execute('chmod +x ' + remotePath)
        SSH_Execute('./' + remotePath)

        for iteration in range(1,2):
            strIteration = str(iteration)
            MakeDirectory(baseTestDirectory + 'Semantic/' + fileName + '/' + strIteration)

            UpdateSharedState(0)
            taskReconstructProcess = multiprocessing.Process(target=TraverseTaskStruct, args=(sharedState, INIT_TASK, fileName, strIteration, ))
            taskReconstructProcess.start()
            PerformExperiment(remotePath)
            taskReconstructProcess.join()

        for iteration in range(1, 2):
            strIteration = str(iteration)

            MakeDirectory(baseTestDirectory + 'Low-Level/' + fileName)
            MakeDirectory(baseTestDirectory + 'Low-Level-Processed/' + fileName)
            multipleMicroPath = baseTestDirectory + 'Low-Level/' + fileName + '/Double/' + strIteration + '/'
            MakeDirectory(multipleMicroPath)
            for counter in range(0, len(eventList16), 2):
                UpdateSharedState(0)
                microEventsProcess = multiprocessing.Process(target=GetMicroArchitecturalEvents, args=(sharedState, eventList16[counter], eventList16[counter + 1], multipleMicroPath, fileName, ))
                microEventsProcess.start()
                PerformExperiment(remotePath)
                microEventsProcess.join()

            singleMicroPath = baseTestDirectory + 'Low-Level/' + fileName + '/Single/' + strIteration + '/'
            MakeDirectory(singleMicroPath)
            for counter in range(0, len(eventList32)):
                UpdateSharedState(0)
                microEventsProcess = multiprocessing.Process(target=GetMicroArchitecturalEvents, args=(sharedState, eventList32[counter], '', singleMicroPath, fileName, ))
                microEventsProcess.start()
                PerformExperiment(remotePath)
                microEventsProcess.join()

            MakeDirectory(baseTestDirectory + 'Low-Level-Processed/' + fileName + '/Double/' + strIteration + '/')
            MakeDirectory(baseTestDirectory + 'Low-Level-Processed/' + fileName + '/Single/' + strIteration + '/')
            preProcessingThread = threading.Thread(target=PreProcessLowLevelInformation, args=(fileName, strIteration, ))
            preProcessingThread.start()
            preProcessingThread.join()

        CleanBBB(remotePath)
        WriteCompleted(fileName)
