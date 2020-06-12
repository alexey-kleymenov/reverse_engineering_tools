# How to use both IDA 5-6 and IDA 7 on one machine

## Problem

Starting from version 7.0, IDA (Hex-Rays) became a 64-bit only program. As a consequence, it requires 64-bit Python to operate properly. In contrast, all prior versions of IDA up to 6.95 inclusive required 32-bit Python.

As a result, it becomes a little bit tricky to have both IDA versions installed on the same machine as both of them rely on the same environment variables to find correct Python directories.

## Solution

A custom .lnk file makes it pretty straightforward to use them on the same computer.

1. Install both 32 and 64-bit Python into different directories. In our example they are located in C:\Python27 and C:\Python27x64 directories respectively with C:\Python27 being set up as the default one

2. Install both IDA into different directories. Again, in our case, it will be C:\IDA6.95 and C:\IDA7.0

3. Check that these environment variables are pointing to a setup related to one of IDAs (in our case 32-bit):

> NLSPATH = C:\IDA6.95

> PYTHONPATH = C:\Python27;C:\Python27\Lib;C:\Python27\DLLs;C:\Python27\Lib\lib-tk;

4. Double check that 32-bit IDA can work without any problems at this stage

5. Modify the 64-bit IDA's .lnk file to set its own env variables:

> C:\Windows\System32\cmd.exe /c "SET PYTHONPATH=C:\Python27x64;C:\Python27x64\Lib;C:\Python27x64\DLLs;C:\Python27x64\Lib\lib-tk; && SET NLSPATH=C:\IDA7.0 && START /D ^"C:\IDA7.0^" ida.exe"

6. Make sure that this IDA can operate as well now
