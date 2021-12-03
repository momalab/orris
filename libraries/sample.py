from libraries.lauterbach import *

conn = Lauterbach()
T32 = conn.T32_Start()
conn.Connect()

conn.BatchCommands('libraries/bbb-linux-aware')
#conn.CPU_RegisterSnapshot()
#conn.CPU_ReadPC()

#conn.T32_Quit()
#conn.Disconnect()
#conn.T32_Kill(T32.pid)
