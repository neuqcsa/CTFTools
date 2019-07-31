#coding=utf-8
'''
用于CTF的patch环节，可以半自动化的将目标代码链接进源文件的指定两行代码间
'''
import pwn
import  lief
import os
from sys import *
# 参数分别为
# patch文件名
# hook地址
# jmp返回地址
# 加入的文件名
class patch:
        def __init__(self):     #初始化变量
                self.patchFileLoc=argv[1]
                self.rawELF=lief.parse(self.patchFileLoc)
                self.patchCodeAddr=int(argv[2],16)
                self.retCodeAddr=int (argv[3],16)
                self.addCodeLoc=argv[4]
                self.codelength=200
        
        def patchJump(self,sourAddr,dstAddr):   #增加jmp指令
                gap=pwn.p32((dstAddr - (sourAddr + 5 )) & 0xffffffff)
                order='\xe9'+gap
                self.rawELF.patch_address(sourAddr,[ord(i) for i in order])



        def addSection(self):   #编译新加段，并且附加到源elf文件末尾
                os.system('gcc -nostdlib -masm=intel -nodefaultlibs -fPIC -Wl,-shared rawHook.c -o Hook')
                self.hookSection=lief.parse('./Hook')
                self.added=self.rawELF.add(self.hookSection.segments[0])
		print hex(self.added.virtual_address)
                self.added.content=self.hookSection.get_section('.text').content

        def linkSection(self):  #将新加段链接进elf文件
                dst=self.added.virtual_address+4
                self.patchJump(self.patchCodeAddr,dst)
                ret=dst+self.codelength-10
                self.patchJump(ret,self.retCodeAddr)
        
        def createHook(self):   #修改给入的文件为gcc可编译的格式
                with open('rawHook.c','w') as raw:
                        with open(self.addCodeLoc,'r') as inject:
                                raw.write("void HookSection(){asm(")
                                i=inject.readline()
                                while i:
                                        raw.write('"'+i[:-1]+'\\n"\n')
                                        i=inject.readline()
                                for i in range(self.codelength):
                                        raw.write('"nop\\n"\n')
                                raw.write(');}')
        def fix(self):  #Patch
                self.createHook()
                self.addSection()
                self.linkSection()
                self.rawELF.write(self.patchFileLoc+'patched')

if __name__=="__main__":
        p=patch()
        p.fix()



