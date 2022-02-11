/**************************************************************
	旧式コード(アセンブラを使わないバージョン)

	通常はコンパイル対象に指定しないでください

	古いので修正が必要
	アセンブラを使えない環境で実装したい人向け？のサンプル
enter leaveは同じ。
**************************************************************/
#include <windows.h>
#include <stdio.h>
#include "filter.h"
/***********************************************
	動的パッチを当てる

	address	対象のアドレス
	check	元のデータのコピー(間違い防止用。)
	patch	更新データ
	length	check、patchのサイズ

	return
		NULLで成功
		失敗時にはエラー文字列。
***********************************************/
const char *WritePatch(void *address, const void *check, const void *patch, DWORD length){
	if(memcmp(address, check, length) == 0){
		DWORD old			= 0;
		if(VirtualProtect(address, length, PAGE_EXECUTE_READWRITE, &old)){	//read writeに書き換え
			memcpy(address, patch, length);					//マルチスレッドでコードにアクセスされたら死ぬ
			if(VirtualProtect(address, length, old, &old)){			//元に戻す
				return NULL;
			}
		}
		/*DWORD gle	= GetLastError();//ちょっと面倒なので後回し
		printf("VirtualProtect::error GetLastError %X\r\n", gle);*/
		return "VirtualProtect::error\r\n";
	}
	return "VirtualProtect::check failed\r\n";
}
/***********************************************
	フィルタダイアログ描画速度うｐ
***********************************************/
void *g_patch_fast_dialog_asm	= NULL;	//一箇所目
void *g_patch_fast_dialog_asm2	= NULL;	//二箇所目
/***********************************************
	version 0.92

	305e0
	30500
***********************************************/
void *Create_Patch_92_305e0_asm(void *patch, const void *address, DWORD offset, const void *orig, DWORD length);
void *Create_Patch_92_30500_asm(void *patch, const void *address, DWORD offset, const void *orig, DWORD length);

//------------------------
//		305e0のパッチ適用
//------------------------
BOOL patch_92_305e0(HMODULE exedit){//前処理
	if(g_patch_fast_dialog_asm == NULL){
		DWORD *t	= (DWORD *)(((BYTE *)exedit) + 0x305e0);
//100305e0の関数宣告BOOL __cdecl unknown(DWORD);かな？
//100305e0:	81 ec 18 01 00 00    	sub    $0x118,%esp
		BYTE check[] = {0x81, 0xec, 0x18, 0x01, 0x00, 0x00};
		BYTE patch[] = {0x81, 0xec, 0x18, 0x01, 0x00, 0x00};
		g_patch_fast_dialog_asm	= Create_Patch_92_305e0_asm(patch, t, 6, check, 6);
		if(g_patch_fast_dialog_asm != NULL){
			const char *result	= WritePatch(t, check, patch, 6);
			if(result == NULL){
				return TRUE;
			}else{
				free_patchs();
				ErrorMSGBox(result, CAPTIONSTR"patch_92_305e0 パッチ当てに失敗しました");
			}
		}else{
			ErrorMSGBox("メモリ確保に失敗しました", CAPTIONSTR"patch_92_305e0 パッチ当てに失敗しました");
		}
	}
	return FALSE;
}
//------------------------
//		30500のパッチ適用
//------------------------
BOOL patch_92_30500(HMODULE exedit){//前処理
	if(g_patch_fast_dialog_asm2 == NULL){
		DWORD *t	= (DWORD *)(((BYTE *)exedit) + 0x30500);
/*
10030500の関数宣告void __cdecl unknown();かな？
10030500:	53                   	push   %ebx
10030501:	55                   	push   %ebp
10030502:	56                   	push   %esi
10030503:	8b 35 7c a2 09 10    	mov    0x1009a27c,%esi
*/
		BYTE check[] = {0x53, 0x55, 0x56, 0x8b, 0x35, 0x7c, 0xa2, 0x09, 0x10};
		BYTE patch[] = {0x53, 0x55, 0x56, 0x8b, 0x35, 0x7c, 0xa2, 0x09, 0x10};
		g_patch_fast_dialog_asm2	= Create_Patch_92_30500_asm(patch, t, 9, check, 9);
		if(g_patch_fast_dialog_asm2 != NULL){
			const char *result	= WritePatch(t, check, patch, 9);
			if(result == NULL){
				return TRUE;
			}else{
				VirtualFree(g_patch_fast_dialog_asm2, 0, MEM_RELEASE);
				g_patch_fast_dialog_asm2	= NULL;
				ErrorMSGBox(result, CAPTIONSTR"patch_92_30500 パッチ当てに失敗しました");
			}
		}else{
			ErrorMSGBox("メモリ確保に失敗しました", CAPTIONSTR"patch_92_30500 パッチ当てに失敗しました");
		}
	}
	return FALSE;
}
/***********************************************
	パッチ用機械語コード作成(cdeclcall引数1(stdcall表記で@4)
***********************************************/
void CreateCdeclCallArg1Asm(BYTE *p, DWORD address, const void *enter, const void *leave, const void *orig, DWORD length){
	DWORD index	= 0;
	p[index++]				= 0xE8;			//call enter
	(*(DWORD *)(p + index))	= (DWORD)enter - (DWORD)(p + index + 4);
	index	+= 4;
	p[index++]				= 0xff;			//pushl  0x4(%esp)
	p[index++]				= 0x74;			//callした場合、returnスタックが積まれるので
	p[index++]				= 0x24;			//引数を複製しなければならない
	p[index++]				= 0x04;			//jmpだと呼び出し元に戻るためleaveを実行できない
	p[index++]				= 0xE8;			//call オリジナルコード複製先へのjmp
	(*(DWORD *)(p + index))	= 9;			//1 + 1 + 5 + 1 + 1
	index	+= 4;
	p[index++]				= 0x59;			//pop %ecx		//仕様分回収(pushl  0x4(%esp))
	p[index++]				= 0x50;			//push %eax		//return保存
	p[index++]				= 0xE8;			//call leave
	(*(DWORD *)(p + index))	= (DWORD)leave - (DWORD)(p + index + 4);
	index	+= 4;
	p[index++]				= 0x58;			//pop %eax		//return復帰
	p[index++]				= 0xC3;			//ret
	memcpy(p + index, orig, length);		//オリジナルコード複製
	index	+= length;
	p[(index++)]			= 0xE9;			//jmp
	(*(DWORD *)(p + index))	= address - (DWORD)(p + index + 4);//元の関数に復帰
}
/***********************************************
	パッチ用機械語コード作成
	patch	更新データ(5byte以上でなければならない)
	address	対象の関数アドレス
	offset	対象の関数アドレス復帰先へのオフセット(上書きされる命令数によって変わるため)
	orig	対象の関数の元のデータ
	length	origのサイズ(patchも同じとして判定)

	92_305e0用
***********************************************/
void *Create_Patch_92_305e0_asm(void *patch, const void *address, DWORD offset, const void *orig, DWORD length){
	if(length >= 5){
		BYTE *p	= (BYTE *)VirtualAlloc(NULL, 50 + length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if(p != NULL){
			CreateCdeclCallArg1Asm(p, ((DWORD)address + offset), Patch_92_305e0_enter, Patch_92_305e0_leave, orig, length);
			BYTE *pp				= (BYTE *)patch;//パッチ更新
			pp[0]					= 0xE9;			//jmp
			(*(DWORD *)(pp + 1))	= (DWORD)p - ((DWORD)(address) + 5);
			return p;
		}
	}
	return NULL;
}
/***********************************************
	92_30500用
***********************************************/
void *Create_Patch_92_30500_asm(void *patch, const void *address, DWORD offset, const void *orig, DWORD length){
	if(length >= 5){
		BYTE *p	= (BYTE *)VirtualAlloc(NULL, 50 + length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if(p != NULL){
			CreateCdeclCallArg1Asm(p, ((DWORD)address + offset), Patch_92_30500_enter, Patch_92_30500_leave, orig, length);
			BYTE *pp				= (BYTE *)patch;//パッチ更新
			pp[0]					= 0xE9;			//jmp
			(*(DWORD *)(pp + 1))	= (DWORD)p - ((DWORD)(address) + 5);
			return p;
		}
	}
	return NULL;
}
/***********************************************
	version 0.93rc1
	フィルタダイアログ描画速度うｐ
_2b2a0
_2b390
***********************************************/

void *Create_Patch_93rc1_2b390_asm(void *patch, const void *address, DWORD offset, const void *orig, DWORD length);
void *Create_Patch_93rc1_2b2a0_asm(void *patch, const void *address, DWORD offset, const void *orig, DWORD length);

//------------------------
//		2b390のパッチ適用
//------------------------
BOOL patch_93rc1_2b390(HMODULE exedit){//前処理
	if(g_patch_fast_dialog_asm == NULL){
		DWORD *t	= (DWORD *)(((BYTE *)exedit) + 0x2b390);
/*1002b390の関数宣告BOOL __fastcall(microsoft) unknown(DWORD);かな？
1002b390:	55                   	push   %ebp
1002b391:	8b ec                	mov    %esp,%ebp
1002b393:	83 e4 f8             	and    $0xfffffff8,%esp*/
		BYTE check[] = {0x55, 0x8b, 0xec, 0x83, 0xe4, 0xf8};
		BYTE patch[] = {0x55, 0x8b, 0xec, 0x83, 0xe4, 0xf8};
		g_patch_fast_dialog_asm	= Create_Patch_93rc1_2b390_asm(patch, t, 6, check, 6);
		if(g_patch_fast_dialog_asm != NULL){
			const char *result	= WritePatch(t, check, patch, 6);
			if(result == NULL){
				return TRUE;
			}else{
				free_patchs();
				ErrorMSGBox(result, CAPTIONSTR"patch_93rc1_2b390 パッチ当てに失敗しました");
			}
		}else{
			ErrorMSGBox("メモリ確保に失敗しました", CAPTIONSTR"patch_93rc1_2b390 パッチ当てに失敗しました");
		}
	}
	return FALSE;
}
//------------------------
//		2b2a0のパッチ適用
//------------------------
BOOL patch_93rc1_2b2a0(HMODULE exedit){//前処理
	if(g_patch_fast_dialog_asm2 == NULL){
		DWORD *t	= (DWORD *)(((BYTE *)exedit) + 0x2b2a0);
/*1002b2a0の関数宣告void __fastcall(microsoft) unknown(DWORD);かな？
1002b2a0:	53                   	push   %ebx
1002b2a1:	56                   	push   %esi
1002b2a2:	8b 35 84 93 0a 10    	mov    0x100a9384,%esi
*/
		BYTE check[] = {0x53, 0x56, 0x8b, 0x35, 0x84, 0x93, 0x0a, 0x10};
		BYTE patch[] = {0x53, 0x56, 0x8b, 0x35, 0x84, 0x93, 0x0a, 0x10};
		g_patch_fast_dialog_asm2	= Create_Patch_93rc1_2b2a0_asm(patch, t, 8, check, 8);
		if(g_patch_fast_dialog_asm2 != NULL){
			const char *result	= WritePatch(t, check, patch, 8);
			if(result == NULL){
				return TRUE;
			}else{
				VirtualFree(g_patch_fast_dialog_asm2, 0, MEM_RELEASE);
				g_patch_fast_dialog_asm2	= NULL;
				ErrorMSGBox(result, CAPTIONSTR"patch_93rc1_2b2a0 パッチ当てに失敗しました");
			}
		}else{
			ErrorMSGBox("メモリ確保に失敗しました", CAPTIONSTR"patch_93rc1_2b2a0 パッチ当てに失敗しました");
		}
	}
	return FALSE;
}
/***********************************************
	パッチ用機械語コード作成(fastcall)
***********************************************/
void CreateFastCallAsm(BYTE *p, DWORD address, const void *enter, const void *leave, const void *orig, DWORD length){
	DWORD index	= 0;
	p[index++]				= 0x51;			//push %ecx	//fastcall用引数待機
	p[index++]				= 0x52;			//push %edx
	p[index++]				= 0xE8;			//call enter
	(*(DWORD *)(p + index))	= (DWORD)enter - (DWORD)(p + index + 4);
	index	+= 4;
	p[index++]				= 0x5A;			//pop %edx	//復帰
	p[index++]				= 0x59;			//pop %ecx

	p[index++]				= 0xE8;			//call オリジナルコード複製先へのjmp
	(*(DWORD *)(p + index))	= 8;			//1 + 5 + 1 + 1
	index	+= 4;
	p[index++]				= 0x50;			//push %eax		//return保存
	p[index++]				= 0xE8;			//call leave
	(*(DWORD *)(p + index))	= (DWORD)leave - (DWORD)(p + index + 4);
	index	+= 4;
	p[index++]				= 0x58;			//pop %eax		//return復帰
	p[index++]				= 0xC3;			//ret
	memcpy(p + index, orig, length);		//オリジナルコード複製
	index	+= length;
	p[(index++)]			= 0xE9;			//jmp
	(*(DWORD *)(p + index))	= address - (DWORD)(p + index + 4);//元の関数に復帰
}
/***********************************************
	93rc1_2b390用
***********************************************/
void *Create_Patch_93rc1_2b390_asm(void *patch, const void *address, DWORD offset, const void *orig, DWORD length){
	if(length >= 5){
		BYTE *p	= (BYTE *)VirtualAlloc(NULL, 50 + length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if(p != NULL){
			CreateFastCallAsm(p, ((DWORD)address + offset), Patch_93rc1_2b390_enter, Patch_93rc1_2b390_leave, orig, length);
			BYTE *pp				= (BYTE *)patch;//パッチ更新
			pp[0]					= 0xE9;			//jmp func
			(*(DWORD *)(pp + 1))	= (DWORD)p - ((DWORD)(address) + 5);
			return p;
		}
	}
	return NULL;
}
/***********************************************
	93rc1_2b2a0用
***********************************************/
void *Create_Patch_93rc1_2b2a0_asm(void *patch, const void *address, DWORD offset, const void *orig, DWORD length){
	if(length >= 5){
		BYTE *p	= (BYTE *)VirtualAlloc(NULL, 21 + length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if(p != NULL){
			CreateFastCallAsm(p, ((DWORD)address + offset), Patch_93rc1_2b2a0_enter, Patch_93rc1_2b2a0_leave, orig, length);
			BYTE *pp				= (BYTE *)patch;//パッチ更新
			pp[0]					= 0xE9;			//jmp func
			(*(DWORD *)(pp + 1))	= (DWORD)p - ((DWORD)(address) + 5);
			return p;
		}
	}
	return NULL;
}
/***********************************************
	パッチ全開放
***********************************************/
void free_patchs(){
	if(g_patch_fast_dialog_asm != NULL){
		VirtualFree(g_patch_fast_dialog_asm, 0, MEM_RELEASE);
		g_patch_fast_dialog_asm	= NULL;
	}
	if(g_patch_fast_dialog_asm2 != NULL){
		VirtualFree(g_patch_fast_dialog_asm2, 0, MEM_RELEASE);
		g_patch_fast_dialog_asm2	= NULL;
	}
	g_patch_exedit	= NULL;
}
