/*
	COPYRIGHT@2016~2018 BY HAPPY
	BSE.EXE
	VERSION 1.1
*/
#include   <stdio.h>
#include  <stdlib.h>
#include  <string.h>

//编码限制(单位：M)
#define FILE_MAX_SIZE 128
//BASE64加权压缩行长(单位：字节)
#define PRESS_LINE_SIZE 1000
//设置过滤敏感词数目
#define SENSITIVE_NUM 3
//添加敏感词条目(请用小写定义),过滤时不区分大小写。 
static const char* SENSITIVE_WORDS[]={"gcd", "flg", "taidu", "zangdu", "qingzhen", "fenlie", "dfj", "hsd", "xjzz"};

//BSE编码表
static const unsigned char BASE64_CODE[64]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const unsigned char BASE92_CODE[256]={33,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static const char  HEX_CODE[16]="0123456789ABCDEF";
static const char* BIN_CODE[16]={"0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111"};
static const char  BASE64_PRESS_CODE[10]="@-#$_}{][A";
//BSE解码表
static const unsigned char BASE64_DECO[80]={0x3E,0x40,0x40,0x40,0x3F,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x40,0x40,0x40,0x40,0x40,0x40,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33};
static const unsigned char BASE92_DECO[256]={255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,0,255,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,255,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255};
static const unsigned char HEX_DECO[23]={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};

//全局变量
int i=0, j=0, FLAG=0, fsize=0;

//敏感词过滤
int Check_SensitiveWords(unsigned char* Str, int position)
{
	int  n, SN, MARK, L;
	for(SN=0; SN<32; SN++){
		if(SN>=SENSITIVE_NUM){return 0;} 
		L=strlen(SENSITIVE_WORDS[SN]), MARK=1;
		for(n=0; n<L; n++){
			if(Str[position+n]!=SENSITIVE_WORDS[SN][n] && Str[position+n]+32!=SENSITIVE_WORDS[SN][n]){
				MARK=0;break;
			}
		}
		if(MARK==1){return 1;}
	}				
	return 0;
}
 
/***************编码函数群***************/
//BASE64加权压缩
int Press_Base64(unsigned char* Str, int L, FILE* stream, char* file)
{
	int k, N, M, MARK;

	char* fname;
	char* extension_name;
 	char* press=(char*)calloc(strlen(Str)+3, sizeof(char));
 	for(k=0,i=0,j=0; j<L ;j++){
		if(Str[j]=='A' && j<L-1 && FLAG!=22){
			i++;
		}else{
			if(i!=0){
				while(i>512){
					i-=512;
					press[k++]=BASE64_PRESS_CODE[0];
				}
				M=512;
				for(N=0; N<10; N++){
					if(i>=M){	
						press[k++]=BASE64_PRESS_CODE[N];
						i-=M;
					}
					M>>=1;
				}
			}
			if(Str[j]=='\0'){break;}else{press[k++]=Str[j];}
			if(Check_SensitiveWords(Str, j)){
				if(FLAG==22){press[k++]=' ';}else{press[k++]='.';}
			}
		}
 	}
	fname=strtok(file, ".");
	extension_name=strtok(NULL, ".");
	if(FLAG==22){
		//生成论坛专用码
		int N, MARK=j/64+1;
		fprintf(stream
		, 	"@echo off\r\n"
			"::*********BASE64 过滤解码器*********\r\n"
			"certutil -decode \"%%~f0\" %s.%s&pause&exit /b\r\n"
			"::***********************************\r\n"
		, 
			fname, 
			extension_name
		);
		fprintf(stream, "\r\n-----BEGIN BASE64-----\r\n");
		fwrite(press, k, 1, stream);
		fprintf(stream, "\r\n-----END BASE64-----\r\n");
		return 0;

	}
	//生成加权压缩码
	MARK=(int)(k/PRESS_LINE_SIZE+1);
	fprintf(stream
		, 	"@echo off\r\n"
			"setlocal enabledelayedexpansion\r\n\r\n"
			"::*********BASE64 加权解码器*********\r\n"
			"set $=set [#]&CALL :BASE64_PRESS&set [$]=A&((for %%%%Z in ([,],{,},_,$,#,-,@) do (set [$]=![$]!![$]!&for %%%%S in (![$]!) do (for /l %%%%i in (1,1,%d) do (!$!%%%%i=![#]%%%%i:%%%%Z=%%%%S!))))&for /l %%%%i in (1,1,%d) do (set/p=![#]%%%%i:.=!<NUL))>%s.BSEP&certutil -decode %s.BSEP %s.%s&pause&exit /b\r\n"
			"::***********************************\r\n\r\n"
			":BASE64_PRESS\r\n"
		,
			MARK,
			MARK, 
			fname, 
			fname, 
			fname, 
			extension_name
	);
	for(N=1; N<=MARK; N++){
		fprintf(stream, "\r\n!$!%d=", N);
		if(N!=MARK){
			fwrite(press,   PRESS_LINE_SIZE, 1, stream);
			press+=PRESS_LINE_SIZE;
		}else{
			fwrite(press, k%PRESS_LINE_SIZE, 1, stream);

		}

	}
	fprintf(stream, "\r\ngoto :EOF");
	return 0;
} 
//BASE64编码
int EncodeBase64(FILE* fp, FILE* stream, char* file)
{
	unsigned char* RAMread=(unsigned char*)calloc(    fsize+3, sizeof(unsigned char));
	unsigned char*     buf=(unsigned char*)calloc(fsize*4/3+2, sizeof(unsigned char));
	fread(RAMread, fsize, 1, fp);fclose(fp);
	while(i<fsize){
		buf[j++]=BASE64_CODE[ (RAMread[i  ]>>2  )                      ];
		buf[j++]=BASE64_CODE[ (RAMread[i  ]&0x03)<<4|(RAMread[++i]>>4) ];
		buf[j++]=BASE64_CODE[ (RAMread[i  ]&0x0F)<<2|(RAMread[++i]>>6) ];
		buf[j++]=BASE64_CODE[ (RAMread[i++]&0x3F)                      ];
	}
	if(i==fsize+2){buf[j-2]='=', buf[j-1]='=';}
	if(i==fsize+1){              buf[j-1]='=';}
	free(RAMread);
	if(FLAG==20){
		//生成兼容性BASE64解码脚本
		int N, MARK=j/64+1;
		char* fname=strtok(file, ".");
		char* extension_name=strtok(NULL, ".");
		fprintf(stream
		, 	"@echo off\r\n"
			"::*********BASE64 标准解码器*********\r\n"
			"certutil -decode \"%%~f0\" %s.%s&pause&exit /b\r\n"
			"::***********************************\r\n"
		, 
			fname, 
			extension_name
		);
		fprintf(stream, "\r\n-----BEGIN BASE64-----");
		for(N=1; N<=MARK; N++){
			fprintf(stream, "\r\n");
			if(N!=MARK){
				fwrite(buf,   64, 1, stream);
				buf+=64;
			}else{
				fwrite(buf, j%64, 1, stream);

			}
		}
		fprintf(stream, "\r\n-----END BASE64-----");
		return 0;
	}else if(FLAG==21){
		//制作加权压缩BASE64解码脚本
		Press_Base64(buf, j, stream, file);
	}else if(FLAG==22){
		//制作DISCUZ论坛专用解码脚本
		Press_Base64(buf, j, stream, file);
	}else {
		fwrite(buf, j, 1, stream);
	}
	free(buf);
	return 0;
}
//BASE64#编码
int EncodeBase64_Tight(FILE* fp, FILE* stream)
{
	unsigned char* RAMread=(unsigned char*)calloc(    fsize+3, sizeof(unsigned char));
	unsigned char*     buf=(unsigned char*)calloc(fsize*4/3+2, sizeof(unsigned char));
	fread(RAMread, fsize, 1, fp);fclose(fp);
	while(i<fsize){
		buf[j++]=BASE64_CODE[(RAMread[i  ]&0xC0)>>2|(RAMread[i+1]&0xC0)>>4|(RAMread[i+2]&0xC0)>>6];
		buf[j++]=BASE64_CODE[ RAMread[i++]&0x3F ];
		buf[j++]=BASE64_CODE[ RAMread[i++]&0x3F ];
		buf[j++]=BASE64_CODE[ RAMread[i++]&0x3F ];
	}
	if(i==fsize+2){buf[j-2]='=', buf[j-1]='=';}
	if(i==fsize+1){              buf[j-1]='=';}
	free(RAMread);
	fwrite(buf, j, 1, stream);
	free(buf);
	return 0;
}
//BASE64+编码
int EncodeBase64_Plus(FILE* fp, FILE* stream)
{
	unsigned char* RAMread=(unsigned char*)calloc(    fsize+3, sizeof(unsigned char));
	unsigned char*  quotes=(unsigned char*)calloc(  fsize/3+2, sizeof(unsigned char));
	unsigned char*     buf=(unsigned char*)calloc(fsize*4/3+2, sizeof(unsigned char));
	fread(RAMread, fsize, 1, fp);fclose(fp);
	while(i<fsize){
		quotes[i/3]=BASE64_CODE[(RAMread[i]&0xC0)>>2|(RAMread[i+1]&0xC0)>>4|(RAMread[i+2]&0xC0)>>6];
		buf[i]=BASE64_CODE[ RAMread[i++]&0x3F ];
		buf[i]=BASE64_CODE[ RAMread[i++]&0x3F ];
		buf[i]=BASE64_CODE[ RAMread[i++]&0x3F ];
	}
	if(i==fsize+2){buf[i-2]='=', buf[i-1]='=';}
	if(i==fsize+1){              buf[i-1]='=';}
	free(RAMread);
	fwrite(buf, i, 1, stream);
	fputs("#", stream);
	fwrite(quotes, i/3+1, 1, stream);
	free(buf);free(quotes);
	return 0;
}
//BASEBIN编码
int EncodeBin(FILE* fp, FILE* stream)
{
	unsigned char* RAMread=(unsigned char*)calloc(  fsize+1, sizeof(unsigned char));
	char* buf[2];
	fread(RAMread, fsize, 1, fp);fclose(fp);
	while(i!=fsize){
		buf[0]=(char*)BIN_CODE[ RAMread[i  ]>>4   ];
		buf[1]=(char*)BIN_CODE[ RAMread[i++]&0x0F ];
		fprintf(stream, "%s%s", buf[0], buf[1]);
	}
	free(RAMread);
	return 0;
}
//BASEHEX编码
int EncodeHex(FILE* fp, FILE* stream)
{
	unsigned char* RAMread=(unsigned char*)calloc(  fsize+1, sizeof(unsigned char));
	unsigned char*     buf=(unsigned char*)calloc(fsize*2+1, sizeof(unsigned char));
	fread(RAMread, fsize, 1, fp);fclose(fp);
	while(i!=fsize){
		buf[j++]=HEX_CODE[ RAMread[i  ]>>4   ];
		buf[j++]=HEX_CODE[ RAMread[i++]&0x0F ];
	}
	free(RAMread);
	fwrite(buf, j, 1, stream);
	free(buf);
	return 0;
}
//BASE92编码
int Str_Encode(unsigned char* str, FILE* stream)
{
	unsigned int sizes;
	unsigned long workspace;
	unsigned short wssize;
	int tmp, len=fsize;
	unsigned char c;
	unsigned char *res;
	sizes=(len*8)%13;
	if(sizes==0){
		sizes=2*((len*8)/13);
	} else if(sizes<7){
		sizes=2*((len*8)/13)+1;
	} else {
		sizes=2*((len*8)/13)+2;
	}
	res=(unsigned char*)malloc(sizeof(char)*(sizes+1));
	workspace=0;
	wssize=0;
	j=0;
	for(i=0; i<len; i++){
		workspace=workspace<<8 | str[i];
		wssize+=8;
		if(wssize>=13){
			tmp=(workspace>>(wssize-13))&8191;
			c=BASE92_CODE[tmp/91];
			if(c==0){
				free(res);
				return 1;
			}
			res[j++]=c;
			c=BASE92_CODE[tmp%91];
			if(c==0){
				free(res);
				return 1;
			}
			res[j++]=c;
			wssize -=13;
		}
	}
	if(0<wssize && wssize<7){
		tmp=(workspace<<(6-wssize))&63;
		c=BASE92_CODE[tmp];
		if(c==0){
			free(res);
			return 1;
		}
		res[j]=c;
	} else if(7<=wssize){
		tmp=(workspace<<(13-wssize))&8191;
		c=BASE92_CODE[tmp/91];
		if(c==0){
			free(res);
			return 1;
		}
		res[j++]=c;
		c=BASE92_CODE[tmp%91];
		if(c==0){
			free(res);
			return 1;
		}
		res[j]=c;
	}
	res[sizes]=0;
	fwrite(res, sizes, 1, stream);
	return 0;
}
int EncodeBase92(FILE* fp, FILE* stream)
{
	unsigned char* RAMread=(unsigned char*)calloc(fsize, sizeof(unsigned char));
	fread(RAMread, fsize, 1, fp);fclose(fp);
	Str_Encode(RAMread, stream);
	free(RAMread);
	return 0;
}

/***************解码函数群***************/
//BASE64解码
int DecodeBase64(FILE* fp, FILE* stream)
{
	unsigned char* RAMread=(unsigned char*)calloc(    fsize+2, sizeof(unsigned char));
	unsigned char*     buf=(unsigned char*)calloc(fsize*3/4+3, sizeof(unsigned char));
	fread(RAMread, fsize, 1, fp);fclose(fp);
	for(; i<fsize; i++){
		buf[j++]=BASE64_DECO[RAMread[i]-43]<<2 | BASE64_DECO[RAMread[++i]-43]>>4;
		buf[j++]=BASE64_DECO[RAMread[i]-43]<<4 | BASE64_DECO[RAMread[++i]-43]>>2;
		buf[j++]=BASE64_DECO[RAMread[i]-43]<<6 | BASE64_DECO[RAMread[++i]-43]   ;
	}
	if(RAMread[--i]=='='){j--;}
	if(RAMread[--i]=='='){j--;}
	free(RAMread);
	fwrite(buf, j, 1, stream);
	free(buf);
	return 0;
}
//BASE64#解码
int DecodeBase64_Tight(FILE* fp, FILE* stream)
{
	unsigned char* RAMread=(unsigned char*)calloc(    fsize+2, sizeof(unsigned char));
	unsigned char*     buf=(unsigned char*)calloc(fsize*3/4+3, sizeof(unsigned char));
	unsigned char      pre;
	fread(RAMread, fsize, 1, fp);fclose(fp);
	while(i<fsize){
		pre=BASE64_DECO[RAMread[i++]-43];
		buf[j++]=(pre&0x30)<<2 | BASE64_DECO[RAMread[i++]-43];
		buf[j++]=(pre&0x0C)<<4 | BASE64_DECO[RAMread[i++]-43];
		buf[j++]=(pre&0x03)<<6 | BASE64_DECO[RAMread[i++]-43];
	}
	if(RAMread[--i]=='='){j--;}
	if(RAMread[--i]=='='){j--;}
	free(RAMread);
	fwrite(buf, j, 1, stream);
	free(buf);
	return 0;
}
//BASE64+解码
int DecodeBase64_Plus(FILE* fp, FILE* stream)
{
	unsigned char* RAMread=(unsigned char*)calloc(    fsize+3, sizeof(unsigned char));
	unsigned char*     buf=(unsigned char*)calloc(fsize*3/4+3, sizeof(unsigned char));
	unsigned char      pre;
	fread(RAMread, fsize, 1, fp);fclose(fp);
	int p=(int)strchr(RAMread, '#')-(int)RAMread;
	while(i<p){
		pre=BASE64_DECO[RAMread[i/3+p+1]-43];
		buf[i]=(pre&0x30)<<2 | BASE64_DECO[RAMread[i++]-43];if(i==p){break;}
		buf[i]=(pre&0x0C)<<4 | BASE64_DECO[RAMread[i++]-43];if(i==p){break;}
		buf[i]=(pre&0x03)<<6 | BASE64_DECO[RAMread[i++]-43];
	}
	if(RAMread[i-1]=='='){i--;}
	if(RAMread[i-1]=='='){i--;}
	free(RAMread);
	fwrite(buf, i, 1, stream);
	free(buf);
	return 0;
}
//BASEBIN解码
int DecodeBin(FILE* fp, FILE* stream)
{
	int M;
	unsigned char* RAMread=(unsigned char*)calloc(fsize+2,sizeof(unsigned char));
	unsigned char S;
	fread(RAMread, fsize, 1, fp);fclose(fp);
	while(i<fsize){
		S=0,M=128;
		for(j=0; j<8; j++){
			if(RAMread[i++]==49){
				S+=M;
			}
			M>>=1;
		}
		fprintf(stream, "%c", S);
	}
	free(RAMread);
	return 0;
}
//BASEHEX解码
int DecodeHex(FILE* fp, FILE* stream)
{
	unsigned char* RAMread=(unsigned char*)calloc(fsize+2  , sizeof(unsigned char));
	unsigned char*     buf=(unsigned char*)calloc(fsize/2+1, sizeof(unsigned char));
	fread(RAMread, fsize, 1, fp);fclose(fp);
	for(; i!=fsize; i++){
		buf[j++]=HEX_DECO[RAMread[i]-48]<<4|HEX_DECO[RAMread[++i]-48];
	}
	free(RAMread);
	fwrite(buf, j, 1, stream);
	free(buf);
	return 0;
}
//BASE92解码
int Str_Decode(unsigned char* str, FILE* stream)
{
	int b1, b2, len;
	int sizes;
	unsigned char* res;
	unsigned long workspace;
	unsigned short wssize;
	sizes=strlen(str);
	if(strcmp(str, "~")==0 || sizes==0){
		res=(unsigned char*)malloc(sizeof(char)*1);
		res[0]=0;
		return 1;
	}
	if(sizes<2){
		res=(unsigned char*)1;
	}
	len=((sizes/2*13)+(sizes%2*6))/8;
	res=(unsigned char *)malloc(sizeof(char)*(len));
	workspace=0;
	wssize=0;
	j=0;
	for(i=0; i+1<sizes; i+=2){
		b1=BASE92_DECO[str[i]];
		b2=BASE92_DECO[str[i+1]];
		workspace=(workspace<<13)|(b1*91+b2);
		wssize+=13;
		while(wssize>=8){
			res[j++]=(workspace>>(wssize-8))&255;
			wssize -=8;
		}
	}
	if(sizes%2==1){
		workspace=(workspace<<6)| BASE92_DECO[str[sizes-1]];
		wssize+=6;
		while(wssize>=8){
			res[j++]=(workspace>>(wssize-8))&255;
			wssize -=8;
		}
	}
	fwrite(res, len, 1, stream);
	return 0;
}
int DecodeBase92(FILE* fp, FILE* stream)
{
	unsigned char* RAMread=(unsigned char*)calloc(fsize, sizeof(unsigned char));
	fread(RAMread, fsize, 1, fp);fclose(fp);
	Str_Decode(RAMread, stream);
	free(RAMread);
	return 0;
}
/***************功能函数群***************/
//帮助信息
void Help_Information(FILE* stream, int Exit_Code)
{
	fprintf(stream,
		"--------------------------------------------------------------\n"
		"bse [-e|-e#|-e+|-eb|-ex|-e92|\n"
		"     -d|-d#|-d+|-db|-dx|-d92|\n"
	 	"     -m|-mp|-md             ] [infile] [outfile]\n"
		"--------------------------------------------------------------\n"
		"    -h    Show help information\n"
		"    -e    Encode file to BASE64 code\n"
		"    -e#   Encode file to BASE64# code\n"
		"    -e+   Encode file to BASE64+ code\n"
		"    -eb   Encode file to BIN code\n"
		"    -ex   Encode file to HEX code\n"
		"    -e92  Encode file to BASE92 code\n"
		"    -d    Decode a file from BASE64 code\n"
		"    -d#   Decode a file from BASE64# code\n"
		"    -d+   Decode a file from BASE64+ code\n"
		"    -db   Decode a file from BIN code\n"
		"    -dx   Decode a file from HEX code\n"
		"    -d92  Decode a file from BASE92 code\n"
		"    -m    Make a ordinary BASE64 batch\n"
		"    -mp   Make a press BASE64 batch\n"
		"    -md   Make a discuz BASE64 batch\n"
		"--------------------------------------------------------------\n"
	);
	exit(Exit_Code);
}

/*************MAIN主函数入口*************/ 
int main(int argc, char** argv) 
{
	FILE* fp;FILE* op; char* delims;
	if((argc==4) && (argv[1][0]=='-')){
		switch(argv[1][1]){
			case 'E':
			case 'e':
				delims=(argv[1]+2);
				if     (delims[0]=='\0'){FLAG= 1;}
				else if(delims[0]== '#'){FLAG= 2;}
				else if(delims[0]== '+'){FLAG= 3;}
				else if(delims[0]== 'b'){FLAG= 4;}
				else if(delims[0]== 'x'){FLAG= 5;}
				else if(delims[0]== '9'){FLAG= 9;}
				else{Help_Information(stderr, 1);}
				break;
			case 'D':
			case 'd':
				delims=(argv[1]+2);
				if     (delims[0]=='\0'){FLAG=11;}
				else if(delims[0]== '#'){FLAG=12;}
				else if(delims[0]== '+'){FLAG=13;}
				else if(delims[0]== 'b'){FLAG=14;}
				else if(delims[0]== 'x'){FLAG=15;}
				else if(delims[0]== '9'){FLAG=19;}
				else{Help_Information(stderr, 1);}
				break;
			case 'M':
			case 'm':
				delims=(argv[1]+2);
				if     (delims[0]=='\0'){FLAG=20;}
				else if(delims[0]== 'p'){FLAG=21;}
				else if(delims[0]== 'd'){FLAG=22;}
				break;
			default:
				Help_Information(stderr, 2);
		}
	}else{
		Help_Information(stderr, 3);
	}
	//读文件流
	if( (fp=fopen(argv[2], "rb"))==NULL ){
		fputs("Failed to read file.", stdout);
		return 2;
	}
	//测量尺寸
	fseek(fp, 0, SEEK_END);
	if( (fsize=ftell(fp))>FILE_MAX_SIZE*1024*1024 ){
		fputs("File size is too large, out of memory.", stdout);
		return 1;
	}
	//指针复原
	fseek(fp, 0, SEEK_SET);
	//打开输出文件流 
	if( (op=fopen(argv[3], "wb"))==NULL ){
		fputs("Failed to read file.", stdout);
		return 1;
	}
	switch(FLAG){
		case 1:
			EncodeBase64(fp, op, NULL);
			break;
		case 2:
			EncodeBase64_Tight(fp, op);
			break;		
		case 3:
			EncodeBase64_Plus(fp, op);
			break;
		case 4:
			EncodeBin(fp, op);
			break;
		case 5:
			EncodeHex(fp, op);
			break;
		case 9:
			EncodeBase92(fp, op);
			break;
		case 11:
			DecodeBase64(fp, op);
			break;
		case 12:
			DecodeBase64_Tight(fp, op);
			break;		
		case 13:
			DecodeBase64_Plus(fp, op);
			break;
		case 14:
			DecodeBin(fp, op);
			break;
		case 15:
			DecodeHex(fp, op);
			break;
		case 19:
			DecodeBase92(fp, op);
			break;
		case 20:
		case 21:
		case 22:
			EncodeBase64(fp, op, argv[2]);
			break;
	}		
	fclose(op);
	return 0;
}
