bse-endecode
bse 替代certutil编解码功能的强悍工具, 比certutil快3倍的编码速度, 支持9种编码.
##BSE.EXE [version 1.1]  
__________________________________________________________________________________
替代certutil编解码功能的强悍工具，比certutil快3倍的编码速度。支持9种编码格式，支
持6种解码格式，base64编码速率高达每秒600M到1300M，因此瓶颈在硬盘。硬盘完全写不过
来。采用以内存换时间的程序设计原理。完全用高速内存和接近ASM内联汇编的设计方式。
__________________________________________________________________________________
BASE64编码器核心：

    while(i<fsize){
        buf[j++]=BASE64_CODE[ (RAMread[i  ]>>2  )                      ];
        buf[j++]=BASE64_CODE[ (RAMread[i  ]&0x03)<<4|(RAMread[++i]>>4) ];
        buf[j++]=BASE64_CODE[ (RAMread[i  ]&0x0F)<<2|(RAMread[++i]>>6) ];
        buf[j++]=BASE64_CODE[ (RAMread[i++]&0x3F)                      ];
    }
    if(i==fsize+2){buf[j-2]='=', buf[j-1]='=';}
    if(i==fsize+1){buf[j-1]='=';}
__________________________________________________________________________________
采取将if判断完全移除while循环，循环内部只有移位、与操作，产生的错误在while循环外
重新纠错，因此编码速率达到硬盘读写速度的10倍以上。支持多种自定义，文件大小限制、
特殊敏感词过滤。数种隐藏功能，请自行发掘。支持一键转为批处理脚本。完全不用担心特
殊词被discuz吃掉。支持base64#、base64+、base64加权压缩，更携base92节省空间。
__________________________________________________________________________________
BSE编码、解码工具, 版本 1.1

COPYRIGHT@2016~2018 BY HAPPY  
  
使用：  
     bse [-e|-e#|-e+|-eb|-ex|...-d|-d#|-d+|-db|-dx|...] [输入文件] [输出文件]  
__________________________________________________________________________________
选项：  
    -h    帮助信息  
    -e    编码为 BASE64  
    -e#   编码为 BASE64#  
    -e+   编码为 BASE64+  
    -eb   编码为 BIN码  
    -ex   编码为 HEX码  
    -e92  编码为 BASE92  
    -d    BASE64 解码  
    -d#   BASE64#解码  
    -d+   BASE64+解码  
    -db   BIN码  解码  
    -dx   HEX码  解码  
    -d92  BASE92 解码  
    -m    制作标准 BASE64 批处理脚本  
    -mp   制作压缩 BASE64 加权批处理脚本  
    -md   制作兼容 BASE64 过滤论坛特殊词脚本  
__________________________________________________________________________________  
示例：  
     bse -e a.jpg a.base64           //将图片a.jpg编码为 BASE64  
     bse -e# a.jpg a.base64#         //将图片a.jpg编码为 BASE64#  
     bse -e92 a.jpg a.base92         //将图片a.jpg编码为 BASE92  
     bse -d a.base64 a.jpg           //将a.base64 解编码为 a.jpg  
     bse -d# a.base64# a.jpg         //将a.base64#解编码为 a.jpg  
     bse -d92 a.base92 a.jpg         //将a.base92 解编码为 a.jpg  
     bse -m a.jpg a.bat              //将图片编码为“标准BASE64编码”批处理  
     bse -mp a.jpg a.bat             //将图片编码为“压缩BASE64加权”批处理  
     bse -md a.jpg a.bat             //将图片编码为“过滤论坛特殊词”批处理  
    ...  
__________________________________________________________________________________  
英译：  
BSE.EXE
>>>-------------------------------------------------------------------------------
COPYRIGHT@2016~2018 BY HAPPY,VERSION 1.1

bse [-e|-e#|-e+|-eb|-ex|-e92|
     -d|-d#|-d+|-db|-dx|-d92|
     -m|-mp|-md             ] [infile] [outfile]
----------------------------------------------------------------------------------
    -h    Show help information
    -e    Encode file to BASE64 code
    -e#   Encode file to BASE64# code
    -e+   Encode file to BASE64+ code
    -eb   Encode file to BIN code
    -ex   Encode file to HEX code
    -e92  Encode file to BASE92 code
    -d    Decode a file from BASE64 code
    -d#   Decode a file from BASE64# code
    -d+   Decode a file from BASE64+ code
    -db   Decode a file from BIN code
    -dx   Decode a file from HEX code
    -d92  Decode a file from BASE92 code
    -m    Make a ordinary BASE64 batch
    -mp   Make a press BASE64 batch
    -md   Make a discuz BASE64 batch
----------------------------------------------------------------------------------
                                                                   10/26/2016
