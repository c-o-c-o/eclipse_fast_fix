/**************************************************************
AviUtlPluginSDK License
-----------------------

The MIT License

Copyright (c) 1999-2012 Kenkun

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
**************************************************************/
#define _WIN32_WINNT	0x0500	//DC_BRUSH
#include <windows.h>
#include <stdio.h>
#include "filter.h"
/**************************************************************
	eclipse fast

	フィルタダイアログ表示高速化パッチ

	TAB幅は4
**************************************************************/
#define CAPTIONSTR	"eclipse fast - "
//------------------------
//		フィルタ定義
//------------------------
TCHAR ef_caption[]		= "eclipse fast";
TCHAR ef_information[]	= "eclipse fast version 1.00 (人柱版)";

FILTER_DLL ef_filter = {
	FILTER_FLAG_EX_INFORMATION | FILTER_FLAG_DISP_FILTER | FILTER_FLAG_ALWAYS_ACTIVE | FILTER_FLAG_WINDOW_THICKFRAME | FILTER_FLAG_WINDOW_SIZE,
	FILTER_WINDOW_SIZE_ADD|FILTER_WINDOW_SIZE_CLIENT|300,
	FILTER_WINDOW_SIZE_ADD|FILTER_WINDOW_SIZE_CLIENT|200,
	ef_caption,
	0,NULL,NULL,NULL,NULL,
	0,NULL,NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	func_WndProc,
	NULL,NULL,
	NULL,0,
	ef_information,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};

EXTERN_C FILTER_DLL __declspec(dllexport) * __stdcall GetFilterTable(void){
	return &ef_filter;
}
//------------------------
//		関数定義
//------------------------
void research_init(HMODULE exedit, DWORD version);	//調査用
void free_patchs();	//パッチ開放
HINSTANCE	g_ModuleInstsnce	= NULL;
HWND		g_window			= NULL;//postmessage用
HMODULE		g_patch_exedit		= NULL;
DWORD		g_exedit_version	= 0;
DWORD		g_patch_optionflg	= 0;//(1 == fast_dialog 2 == fast_grad, redrawwindow == 4, setredraw in efc window 8)

void ErrorMSGBox(const char *text, const char *caption){
	MessageBox(NULL, text, caption, MB_TASKMODAL | MB_SETFOREGROUND | MB_TOPMOST | MB_ICONERROR | MB_OK);
}
//------------------------
//		エントリポイント
//------------------------
typedef BOOL __stdcall(*TGradientFill)(HDC hdc, PTRIVERTEX pVertex, ULONG nVertex, PVOID pMesh, ULONG nMesh, ULONG ulMode);
HMODULE msimg32 = 0;
TGradientFill gradientFill = 0;

void fix_init(){
	msimg32 = LoadLibrary("msimg32.dll");
	if (msimg32) {
		gradientFill = (TGradientFill)GetProcAddress(msimg32, "GradientFill");
	}
}

EXTERN_C BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved){
	switch(fdwReason){
		case DLL_PROCESS_ATTACH:
			g_ModuleInstsnce	= hinstDLL;
		break;
		case DLL_PROCESS_DETACH:
			free_patchs();
		break;
	}
	return TRUE;
}
/***********************************************
	動的パッチを当てる

	hooktarget	対象のアドレス
	jumpfunc	アセンブリ側のコードのアドレス
	jumpback	整合性チェック用の復帰用コードへのアドレス
	check		元のデータのコピー(間違い防止用。)
	patch		更新データ
	length		check、patchのサイズ

	return
		NULLで成功
		失敗時にはエラー文字列。
***********************************************/
const char *VPGLE(){//エラー表示用
	static char error[40];
	DWORD gle	= GetLastError();
	sprintf(error, "VirtualProtect::error GLE %X", gle);
	return error;
}
const char *WritePatch(void *hooktarget, const void *jumpfunc, const void *jumpback, const void *check, BYTE *patch, DWORD length){
	if(memcmp(hooktarget, check, length) == 0){
		if(memcmp(jumpback, check, length) == 0){
			DWORD old				= 0;
			patch[0]				= 0xE9;			//jmp func
			(*(DWORD *)(patch + 1))	= (DWORD)jumpfunc - (DWORD)(hooktarget + 5);
			if(VirtualProtect(hooktarget, length, PAGE_EXECUTE_READWRITE, &old)){	//read writeに書き換え
				memcpy(hooktarget, patch, length);					//マルチスレッドでコードにアクセスされたら死ぬ
				if(VirtualProtect(hooktarget, length, old, &old)){			//元に戻す
					return NULL;
				}
			}
			return VPGLE();
		}
		return "WritePatch::整合性エラー(2)";
	}
	return "WritePatch::整合性エラー";
}
/***********************************************
	解除用簡易
***********************************************/
const char *WriteUnPatch(DWORD hooktarget, const void *check, DWORD length){
	BYTE *phooktarget		= ((BYTE *)g_patch_exedit) + hooktarget;
	DWORD old				= 0;
	if(VirtualProtect(phooktarget, length, PAGE_EXECUTE_READWRITE, &old)){	//read writeに書き換え
		memcpy(phooktarget, check, length);					//マルチスレッドでコードにアクセスされたら死ぬ
		if(VirtualProtect(phooktarget, length, old, &old)){			//元に戻す
			return NULL;
		}
	}
	return VPGLE();
}
/***********************************************
	自己改変用。
	patch_92_30500_hook
	patch_93rc1_2b2a0_hook
	においてオリジナルコードにアドレスが含まれるため。
***********************************************/
const char *WriteSelfAddressPatch(DWORD hooktarget, DWORD check, DWORD patch){
	DWORD *phooktarget		= (DWORD *)hooktarget;
	if(memcmp(phooktarget, &check, sizeof(DWORD)) == 0){
		DWORD old				= 0;
		if(VirtualProtect(phooktarget, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &old)){	//read writeに書き換え
			memcpy(phooktarget, &patch, sizeof(DWORD));					//マルチスレッドでコードにアクセスされたら死ぬ
			if(VirtualProtect(phooktarget, sizeof(DWORD), old, &old)){			//元に戻す
				return NULL;
			}
		}
		return VPGLE();
	}
	return "WriteSelfAddressPatch::整合性エラー";
}
/***********************************************
	フィルタダイアログ描画速度うｐ
***********************************************/
DWORD g_patch_fast_dialog_checkflg	= 4;//オプション1 時間計測, 2 復帰オフ, 4 無効化
DWORD g_patch_fast_dialog_time		= 0;
DWORD g_patch_fast_dialog_tick		= 0;
void *g_patch_fast_dialog_hook1	= NULL;	//一箇所目
void *g_patch_fast_dialog_hook2	= NULL;	//二箇所目
int g_patch_efc_check	= 0;			//フィルタチェック

//------------------------
//		前処理
//------------------------
void fast_dialog_enter_setredraw(DWORD globalhwndaddress){
	HWND *pExtendedFilterClass = (HWND *)((BYTE *)(g_patch_exedit) + globalhwndaddress);	//ExtendedFilterClassのグローバル変数アドレス(想定外のDLLで実行すると動作は未定。)
	if(pExtendedFilterClass != NULL && *pExtendedFilterClass != NULL){
		SendMessage(*pExtendedFilterClass, WM_SETREDRAW, FALSE, 0);
	}
}
//------------------------
//		後処理
//------------------------
void fast_dialog_leave_setredraw(DWORD globalhwndaddress){
	HWND *pExtendedFilterClass = (HWND *)((BYTE *)(g_patch_exedit) + globalhwndaddress);
	if(pExtendedFilterClass != NULL && *pExtendedFilterClass != NULL){
		SendMessage(*pExtendedFilterClass, WM_SETREDRAW, TRUE, 0);
		if(g_patch_optionflg & 4){
			RedrawWindow(*pExtendedFilterClass, NULL, NULL, RDW_ERASE | RDW_FRAME | RDW_INVALIDATE | RDW_ALLCHILDREN);
		}
	}
}
//------------------------
//		前処理
//------------------------
void fast_dialog_enter(DWORD globalhwndaddress){
	g_patch_efc_check	= 1;
	if(g_patch_fast_dialog_checkflg & 1){
		g_patch_fast_dialog_tick	= GetTickCount();
	}
	if(g_patch_fast_dialog_checkflg & 4){
		fast_dialog_enter_setredraw(globalhwndaddress);
	}
}
//------------------------
//		後処理
//------------------------
void fast_dialog_leave(DWORD globalhwndaddress){
	g_patch_efc_check	= 0;
	if(g_patch_fast_dialog_checkflg & 4){
		fast_dialog_leave_setredraw(globalhwndaddress);
	}
	if(g_patch_fast_dialog_checkflg & 1){//時間計測
		DWORD tick	= GetTickCount();
		g_patch_fast_dialog_time	= tick - g_patch_fast_dialog_tick;
		PostMessage(g_window, WM_USER, 0, 0);
	}
}
//------------------------
//		前処理(ExtendedFilterClassからの操作の場合に遅いので)
//------------------------
void fast_dialog_efc_enter(DWORD globalhwndaddress){
	if(g_patch_efc_check == 0){//305e0から呼ばれず単独で呼ばれた場合
		if(g_patch_fast_dialog_checkflg & 4){
			fast_dialog_enter_setredraw(globalhwndaddress);
		}
	}
}
//------------------------
//		後処理
//------------------------
void fast_dialog_efc_leave(DWORD globalhwndaddress){
	if(g_patch_efc_check == 0){
		if(g_patch_fast_dialog_checkflg & 4){
			if(g_patch_optionflg & 8){	//単独復帰時にsetredrawを呼ぶ(描画する)
				fast_dialog_leave_setredraw(globalhwndaddress);
			}
		}
	}
}
/***********************************************
	version 0.92

	305e0
	30500
***********************************************/
//------------------------
//		305e0のパッチ適用
//------------------------
BOOL patch_92_305e0(){
	void patch_92_305e0_asm();	//アセンブル関数
	void patch_92_305e0_asm_back();

	if(g_patch_fast_dialog_hook1 == NULL){
		BYTE *f305e0		= ((BYTE *)g_patch_exedit) + 0x305e0;
//100305e0の関数宣告BOOL __cdecl unknown(DWORD);かな？
//100305e0:	81 ec 18 01 00 00    	sub    $0x118,%esp
		const BYTE check[]	= {0x81, 0xec, 0x18, 0x01, 0x00, 0x00};
		BYTE patch[] 		= {0x81, 0xec, 0x18, 0x01, 0x00, 0x00};
		const char *result	= WritePatch(f305e0, patch_92_305e0_asm, patch_92_305e0_asm_back, check, patch, sizeof(check));
		if(result == NULL){
			g_patch_fast_dialog_hook1	= f305e0 + sizeof(check);
			return TRUE;
		}else{
			ErrorMSGBox(result, CAPTIONSTR"patch_92_305e0 パッチ当てに失敗しました");
		}
	}
}
//------------------------
//		305e0のパッチ解除
//------------------------
BOOL unpatch_92_305e0(){
	if(g_patch_fast_dialog_hook1 != NULL){
		const BYTE check[]	= {0x81, 0xec, 0x18, 0x01, 0x00, 0x00};
		const char *result	= WriteUnPatch(0x305e0, check, sizeof(check));
		if(result == NULL){
			g_patch_fast_dialog_hook1	= NULL;
			return TRUE;
		}else{
			ErrorMSGBox(result, CAPTIONSTR"unpatch_92_305e0 パッチ解除に失敗しました");
		}
	}
}
//------------------------
//		30500のパッチ適用
//------------------------
/*
100306ab -> 通常
マウス操作系であるが内容不明
100417c7  フィルター追加
10041949  ?
100419ea  ?
10041add  ?
10041b4e  フィルター削除
10041c64  フィルター移動
*/
void patch_92_30500_asm_back();

BOOL patch_92_30500(){
	void patch_92_30500_asm();	//アセンブル関数
	if(g_patch_fast_dialog_hook2 == NULL){
		BYTE movedaddr[4]	= {0, 0, 0, 0};
		((DWORD *)movedaddr)[0]	=  (DWORD)(((BYTE *)g_patch_exedit) + 0x9a27c);
		const char *result	= WriteSelfAddressPatch(((DWORD)patch_92_30500_asm_back) + 5, 0x1009a27c, *((DWORD *)movedaddr));
		if(result == NULL){
			BYTE *f30500		= ((BYTE *)g_patch_exedit) + 0x30500;
/*
10030500の関数宣告void __cdecl unknown();かな？
10030500:	53                   	push   %ebx
10030501:	55                   	push   %ebp
10030502:	56                   	push   %esi
10030503:	8b 35 7c a2 09 10    	mov    0x1009a27c,%esi
*/
			const BYTE check[]	= {0x53, 0x55, 0x56, 0x8b, 0x35, movedaddr[0], movedaddr[1], movedaddr[2], movedaddr[3]};
			BYTE patch[] 		= {0x53, 0x55, 0x56, 0x8b, 0x35, movedaddr[0], movedaddr[1], movedaddr[2], movedaddr[3]};
			const char *result	= WritePatch(f30500, patch_92_30500_asm, patch_92_30500_asm_back, check, patch, sizeof(check));
			if(result == NULL){
				g_patch_fast_dialog_hook2	= f30500 + sizeof(check);
				return TRUE;
			}else{
				ErrorMSGBox(result, CAPTIONSTR"patch_92_30500 パッチ当てに失敗しました");
			}
		}else{
			ErrorMSGBox(result, CAPTIONSTR"patch_92_30500 パッチ当て(自己改変)に失敗しました");
		}
	}
}
//------------------------
//		30500のパッチ解除
//------------------------
BOOL unpatch_92_30500(){
	if(g_patch_fast_dialog_hook2 != NULL){
		BYTE movedaddr[4]	= {0, 0, 0, 0};
		((DWORD *)movedaddr)[0]	=  (DWORD)(((BYTE *)g_patch_exedit) + 0x9a27c);
		const BYTE check[]	= {0x53, 0x55, 0x56, 0x8b, 0x35, movedaddr[0], movedaddr[1], movedaddr[2], movedaddr[3]};
		const char *result	= WriteUnPatch(0x30500, check, sizeof(check));
		if(result == NULL){
			g_patch_fast_dialog_hook2	= NULL;
			const char *result	= WriteSelfAddressPatch(((DWORD)patch_92_30500_asm_back) + 5, ((DWORD *)movedaddr)[0], 0x1009a27c);
			if(result == NULL){
				return TRUE;
			}else{
				ErrorMSGBox(result, CAPTIONSTR"unpatch_92_30500 パッチ解除(自己改変)に失敗しました");
			}
			return TRUE;
		}else{
			ErrorMSGBox(result, CAPTIONSTR"unpatch_92_30500 パッチ解除に失敗しました");
		}
	}
}
//------------------------
//		パッチ設定
//------------------------
BOOL patch_fast_dialog_92(){
	if(patch_92_305e0()){
		patch_92_30500();
		return TRUE;
	}
	return FALSE;
}
//------------------------
//		パッチ解除
//------------------------
void unpatch_fast_dialog_92(){
	unpatch_92_305e0();
	unpatch_92_30500();
}
//------------------------
//		処理
//------------------------
void Patch_92_305e0_enter(){fast_dialog_enter(0x1539c8);}
void Patch_92_305e0_leave(){fast_dialog_leave(0x1539c8);}
void Patch_92_30500_enter(){fast_dialog_efc_enter(0x1539c8);}
void Patch_92_30500_leave(){fast_dialog_efc_leave(0x1539c8);}
/***********************************************
	version 0.93rc1
	フィルタダイアログ描画速度うｐ
_2b2a0
_2b390
***********************************************/

//------------------------
//		2b390のパッチ適用
//------------------------
BOOL patch_93rc1_2b390(){
	void patch_93rc1_2b390_asm();	//アセンブル関数
	void patch_93rc1_2b390_asm_back();

	if(g_patch_fast_dialog_hook1 == NULL){
		BYTE *f2b390		= ((BYTE *)g_patch_exedit) + 0x2b390;
/*1002b390の関数宣告BOOL __fastcall(microsoft) unknown(DWORD);かな？
1002b390:	55                   	push   %ebp
1002b391:	8b ec                	mov    %esp,%ebp
1002b393:	83 e4 f8             	and    $0xfffffff8,%esp*/
		const BYTE check[]	= {0x55, 0x8b, 0xec, 0x83, 0xe4, 0xf8};
		BYTE patch[] 		= {0x55, 0x8b, 0xec, 0x83, 0xe4, 0xf8};
		const char *result	= WritePatch(f2b390, patch_93rc1_2b390_asm, patch_93rc1_2b390_asm_back, check, patch, sizeof(check));
		if(result == NULL){
			g_patch_fast_dialog_hook1	= f2b390 + sizeof(check);
			return TRUE;
		}else{
			ErrorMSGBox(result, CAPTIONSTR"patch_93rc1_2b390 パッチ当てに失敗しました");
		}
	}
}
//------------------------
//		2b390のパッチ解除
//------------------------
BOOL unpatch_93rc1_2b390(){
	if(g_patch_fast_dialog_hook1 != NULL){
		const BYTE check[]	= {0x55, 0x8b, 0xec, 0x83, 0xe4, 0xf8};
		const char *result	= WriteUnPatch(0x2b390, check, sizeof(check));
		if(result == NULL){
			g_patch_fast_dialog_hook1	= NULL;
			return TRUE;
		}else{
			ErrorMSGBox(result, CAPTIONSTR"unpatch_93rc1_2b390 パッチ解除に失敗しました");
		}
	}
}
//------------------------
//		2b2a0のパッチ適用
//------------------------
void patch_93rc1_2b2a0_asm_back();
BOOL patch_93rc1_2b2a0(){
	void patch_93rc1_2b2a0_asm();	//アセンブル関数

	if(g_patch_fast_dialog_hook2 == NULL){
		BYTE *f2b2a0		= ((BYTE *)g_patch_exedit) + 0x2b2a0;
/*1002b2a0の関数宣告void __fastcall(microsoft) unknown(DWORD);かな？
1002b2a0:	53                   	push   %ebx
1002b2a1:	56                   	push   %esi
1002b2a2:	8b 35 84 93 0a 10    	mov    0x100a9384,%esi//0x100a9384ココが切り替わるのか
*/
		BYTE movedaddr[4]	= {0, 0, 0, 0};
		((DWORD *)movedaddr)[0]	=  (DWORD)(((BYTE *)g_patch_exedit) + 0xa9384);
		const char *result	= WriteSelfAddressPatch(((DWORD)patch_93rc1_2b2a0_asm_back) + 4, 0x100a9384, *((DWORD *)movedaddr));
		if(result == NULL){
			//const BYTE check[]	= {0x53, 0x56, 0x8b, 0x35, 0x84, 0x93, 0x0a, 0x10};
			const BYTE check[]	= {0x53, 0x56, 0x8b, 0x35, movedaddr[0], movedaddr[1], movedaddr[2], movedaddr[3]};
			BYTE patch[] 		= {0x53, 0x56, 0x8b, 0x35, movedaddr[0], movedaddr[1], movedaddr[2], movedaddr[3]};
			const char *result	= WritePatch(f2b2a0, patch_93rc1_2b2a0_asm, patch_93rc1_2b2a0_asm_back, check, patch, sizeof(check));
			if(result == NULL){
				g_patch_fast_dialog_hook2	= f2b2a0 + sizeof(check);
				return TRUE;
			}else{
				ErrorMSGBox(result, CAPTIONSTR"patch_93rc1_2b2a0 パッチ当てに失敗しました");
			}
		}else{
			ErrorMSGBox(result, CAPTIONSTR"patch_93rc1_2b2a0 パッチ当て(自己改変)に失敗しました");
		}
	}
}
//------------------------
//		30500のパッチ解除
//------------------------
BOOL unpatch_93rc1_2b2a0(){
	if(g_patch_fast_dialog_hook2 != NULL){
		BYTE movedaddr[4]	= {0, 0, 0, 0};
		((DWORD *)movedaddr)[0]	=  (DWORD)(((BYTE *)g_patch_exedit) + 0xa9384);
		const BYTE check[]	= {0x53, 0x56, 0x8b, 0x35, movedaddr[0], movedaddr[1], movedaddr[2], movedaddr[3]};
		const char *result	= WriteUnPatch(0x2b2a0, check, sizeof(check));
		if(result == NULL){
			g_patch_fast_dialog_hook2	= NULL;
			const char *result	= WriteSelfAddressPatch(((DWORD)patch_93rc1_2b2a0_asm_back) + 4, ((DWORD *)movedaddr)[0], 0x100a9384);
			if(result == NULL){
				return TRUE;
			}else{
				ErrorMSGBox(result, CAPTIONSTR"unpatch_93rc1_2b2a0 パッチ解除(自己改変)に失敗しました");
			}
			return TRUE;
		}else{
			ErrorMSGBox(result, CAPTIONSTR"unpatch_93rc1_2b2a0 パッチ解除に失敗しました");
		}
	}
}
//------------------------
//		パッチ設定
//------------------------
BOOL patch_fast_dialog_93rc1(){
	if(patch_93rc1_2b390()){
		patch_93rc1_2b2a0();
		return TRUE;
	}
	return FALSE;
}
//------------------------
//		パッチ解除
//------------------------
void unpatch_fast_dialog_93rc1(){
	unpatch_93rc1_2b390();
	unpatch_93rc1_2b2a0();
}
//------------------------
//		処理
//------------------------
void Patch_93rc1_2b390_enter(){fast_dialog_enter(0xec060);}
void Patch_93rc1_2b390_leave(){fast_dialog_leave(0xec060);}
void Patch_93rc1_2b2a0_enter(){fast_dialog_efc_enter(0xec060);}
void Patch_93rc1_2b2a0_leave(){fast_dialog_efc_leave(0xec060);}
/***********************************************
	グラデーション描画速度うｐ
***********************************************/
void *g_patch_fast_gradradation_hook	= NULL;	//一箇所目
DWORD g_patch_fast_gradradation_flag	= 0;
//------------------------
//		簡易グラデーション
//------------------------

int getRValue(COLORREF c) { return ((c) & 0xff); }
int getGValue(COLORREF c) { return ((c >> 8) & 0xff); }
int getBValue(COLORREF c) { return ((c >> 16) & 0xff); }

float clamp(float min, float v, float max) {
    if (v > max) {
        return max;
    }

    if (v < min) {
        return min;
    }

    return v;
}

void patch_simpleFillGradation(HDC hdc, const RECT *rc, DWORD c1, DWORD c2, int gs, int ge){
    if (gradientFill == NULL) {
	SetDCBrushColor(hdc, c1);
	FillRect(hdc, rc, GetStockObject(DC_BRUSH));
        return;
    }

    /* -------------------------------------------- */
    float ow = ge - gs;
    float sps = clamp(0, (rc->left - gs) / ow, 1);
    float eps = clamp(0, (rc->right - gs) / ow, 1);
    int c1r = getRValue(c1);
    int c1g = getGValue(c1);
    int c1b = getBValue(c1);
    int c2r = getRValue(c2);
    int c2g = getGValue(c2);
    int c2b = getBValue(c2);
    RECT grc = *rc;
    RECT flrc[2];
    DWORD *flc[2] = {NULL, NULL};

    /* -------------------------------------------- */
    if (gs == rc->left && ge < rc->right) {
	flrc[1] = *rc;

        grc.right = ge;
        flrc[1].left = ge;
	flc[1] = &c2;
    }

    if (gs > rc->left && ge == rc->right) {
	flrc[0] = *rc;

        grc.left = gs;
        flrc[0].right = gs;
	flc[0] = &c1;
    }

    /* -------------------------------------------- */
    TRIVERTEX vert[2] = {
        {
	    rc->left,
	    rc->top, 
	    c1r - ((char)((c1r - c2r) * sps)) << 8,
	    c1g - ((char)((c1g - c2g) * sps)) << 8,
	    c1b - ((char)((c1b - c2b) * sps)) << 8,
	    0
	},
        {
	    rc->right,
	    rc->bottom,
	    c1r - ((char)((c1r - c2r) * eps)) << 8,
	    c1g - ((char)((c1g - c2g) * eps)) << 8,
	    c1b - ((char)((c1b - c2b) * eps)) << 8,
	    0
	},
    };
    GRADIENT_RECT rect = {0, 1};

    /* -------------------------------------------- */
    gradientFill(hdc, vert, 2, &rect, 1, GRADIENT_FILL_RECT_H);
    
    for (int i = 0; i < 2; i++) {
        if (flc[i] == NULL) {
            continue;
        }
	SetDCBrushColor(hdc, *flc[i]);
        FillRect(hdc, &flrc[i], GetStockObject(DC_BRUSH));
    }
}
/***********************************************
	version 0.92
***********************************************/
void patch_92_36a70_call(HDC hdc, const RECT *rc, BYTE r, BYTE g, BYTE b, BYTE gr, BYTE gg, BYTE gb, int gs, int ge);
//------------------------
//		32ce0の呼び出し関数
//------------------------
void patch_92_FillGradation(HDC hdc, const RECT *rc, BYTE r, BYTE g, BYTE b, BYTE gr, BYTE gg, BYTE gb, int gs, int ge){
	if(g_patch_fast_gradradation_flag & 1){
		patch_92_36a70_call(hdc, rc, r, g, b, gr, gg, gb, gs, ge);
	}else{
		DWORD col	= r | (b << 16) | (g << 8);
		DWORD gcol	= gr | (gb << 16) | (gg << 8);
		if(col == gcol){
			SetDCBrushColor(hdc, col);
			FillRect(hdc, rc, GetStockObject(DC_BRUSH));
			return;
		}
		patch_simpleFillGradation(hdc, rc, col, gcol, gs, ge);
	}
}
/***********************************************
	36a70のパッチ適用
***********************************************/
BOOL patch_92_36a70(){
	if(g_patch_fast_gradradation_hook == NULL){
		BYTE *f36a70		= ((BYTE *)g_patch_exedit) + 0x36a70;
/*
36a70の関数宣告void FillGradation(HDC hdc, const RECT *rc, BYTE r, BYTE g, BYTE b, BYTE gr, BYTE gg, BYTE gb, int gs, int ge);かな？

10036a70:	83 ec 14             	sub    $0x14,%esp
10036a73:	53                   	push   %ebx
10036a74:	55                   	push   %ebp
*/
		const BYTE check[]	= {0x83, 0xec, 0x14, 0x53, 0x55};
		BYTE patch[] 		= {0x83, 0xec, 0x14, 0x53, 0x55};
		const char *result	= WritePatch(f36a70, patch_92_FillGradation, patch_92_36a70_call, check, patch, sizeof(check));
		if(result == NULL){
			g_patch_fast_gradradation_hook	= f36a70 + sizeof(check);
			return TRUE;
		}else{
			ErrorMSGBox(result, CAPTIONSTR"patch_92_f36a70 パッチ当てに失敗しました");
		}
	}
}
//------------------------
//		36a70のパッチ解除
//------------------------
BOOL unpatch_92_36a70(){
	if(g_patch_fast_gradradation_hook != NULL){
		const BYTE check[]	= {0x83, 0xec, 0x14, 0x53, 0x55};
		const char *result	= WriteUnPatch(0x36a70, check, sizeof(check));
		if(result == NULL){
			g_patch_fast_gradradation_hook	= NULL;
			return TRUE;
		}else{
			ErrorMSGBox(result, CAPTIONSTR"patch_92_36a70 パッチ解除に失敗しました");
		}
	}
}
/***********************************************
	version 0.93rc1
***********************************************/
//------------------------
//		32ce0の呼び出し関数
//------------------------
void patch_93rc1_FillGradation(HDC hdc, const RECT *rc, BYTE r, BYTE g, BYTE b, BYTE gr, BYTE gg, BYTE gb, int gs, int ge){
void patch_93rc1_32ce0_call(HDC hdc, const RECT *rc, BYTE r, BYTE g, BYTE b, BYTE gr, BYTE gg, BYTE gb, int gs, int ge);
	if(g_patch_fast_gradradation_flag & 1){
		patch_93rc1_32ce0_call(hdc, rc, r, g, b, gr, gg, gb, gs, ge);//オリジナル呼び出し
	}else{
		DWORD col	= r | (b << 16) | (g << 8);
		DWORD gcol	= gr | (gb << 16) | (gg << 8);
		if(col == gcol){
			SetDCBrushColor(hdc, col);
			FillRect(hdc, rc, GetStockObject(DC_BRUSH));
			return;
		}
		patch_simpleFillGradation(hdc, rc, col, gcol, gs, ge);
	}
}
/***********************************************
		32ce0のパッチ適用
***********************************************/
BOOL patch_93rc1_32ce0(){
	void patch_93rc1_32ce0_asm();	//呼び出し
	void patch_93rc1_32ce0_callf();	//チェック用
	if(g_patch_fast_gradradation_hook == NULL){
		BYTE *f32ce0		= ((BYTE *)g_patch_exedit) + 0x32ce0;
/*
36a70の関数宣告void (__fastcall+__cdeclもどき) FillGradation(HDC hdc, const RECT *rc, BYTE r, BYTE g, BYTE b, BYTE gr, BYTE gg, BYTE gb, int gs, int ge);かな？

10032ce0:	55                   	push   %ebp
10032ce1:	8b ec                	mov    %esp,%ebp
10032ce3:	83 ec 0c             	sub    $0xc,%esp
*/
		const BYTE check[]	= {0x55, 0x8b, 0xec, 0x83, 0xec, 0x0c};
		BYTE patch[] 		= {0x55, 0x8b, 0xec, 0x83, 0xec, 0x0c};
		const char *result	= WritePatch(f32ce0, patch_93rc1_32ce0_asm, patch_93rc1_32ce0_callf, check, patch, sizeof(check));
		if(result == NULL){
			g_patch_fast_gradradation_hook	= f32ce0 + sizeof(check);
			return TRUE;
		}else{
			ErrorMSGBox(result, CAPTIONSTR"patch_93rc1_32ce0 パッチ当てに失敗しました");
		}
	}
}
//------------------------
//		36a70のパッチ解除
//------------------------
BOOL unpatch_93rc1_32ce0(){
	if(g_patch_fast_gradradation_hook != NULL){
		const BYTE check[]	= {0x55, 0x8b, 0xec, 0x83, 0xec, 0x0c};
		const char *result	= WriteUnPatch(0x32ce0, check, sizeof(check));
		if(result == NULL){
			g_patch_fast_gradradation_hook	= NULL;
			return TRUE;
		}else{
			ErrorMSGBox(result, CAPTIONSTR"unpatch_93rc1_32ce0 パッチ解除に失敗しました");
		}
	}
}
/***********************************************
	パッチ全開放
	古いバージョン用のが残っているだけ
***********************************************/
void free_patchs(){
/*	unpatch_fast_dialog_92();		//わざわざエラー起こす可能性があるのを実行するのもあれだし(アンロードされてたら落ちる)
	unpatch_fast_dialog_93rc1();
	unpatch_92_36a70();
	unpatch_93rc1_32ce0();*/
	g_patch_fast_dialog_hook1		= NULL;	//一箇所目
	g_patch_fast_dialog_hook2		= NULL;	//二箇所目
	g_patch_fast_gradradation_hook	= NULL;
	g_patch_exedit	= NULL;
}
/***********************************************
	拡張編集のバージョン取得
	return 0で不明
		9200で version 0.92
		9301で version 0.93 rc1
***********************************************/
DWORD get_exedit_version(HMODULE exedit){
	//GetFilterTableList。通常はreturnするだけなので使用しても問題ないと思われる。
	void *pfunc	= GetProcAddress(exedit, "GetFilterTableList");
	if(pfunc != NULL){
		FILTER_DLL **pfd_exedit	= ((FILTER_DLL ** __stdcall (*)())pfunc)();
		if(pfd_exedit != NULL && pfd_exedit[0] != NULL){
			TCHAR *information	= pfd_exedit[0]->information;
			if(information != NULL){
				if(strcmp(information, "拡張編集(exedit) version 0.92 by ＫＥＮくん") == 0){//バージョンチェック
					void *funcptr	= ((BYTE *)exedit) + 0x2b0c0;
					if(funcptr == pfunc){
						return 9200;
					}else{
						ErrorMSGBox("拡張編集の内容不整合(v0.92)", CAPTIONSTR"get_exedit_version");
					}
				}else if(strcmp(information, "拡張編集(exedit) version 0.93rc1 by ＫＥＮくん") == 0){
					void *funcptr	= ((BYTE *)exedit) + 0x252f0;
					if(funcptr == pfunc){
						return 9301;
					}else{
						ErrorMSGBox("拡張編集の内容不整合(v0.93rc1)", CAPTIONSTR"get_exedit_version");
					}
				}else{
					ErrorMSGBox(information, CAPTIONSTR"get_exedit_version 対応していないバージョン？");
				}
			}else{
				ErrorMSGBox("拡張編集のFILTER_DLL informationの情報が存在しない(バージョンを特定できない)", CAPTIONSTR"get_exedit_version");
			}
		}else{
			ErrorMSGBox("FILTER_DLLの内容が異常", CAPTIONSTR"get_exedit_version");
		}
	}else{
		ErrorMSGBox("拡張編集ではないか破損している？", CAPTIONSTR"get_exedit_version");
	}
	return 0;
}
//---------------------------------------------------------------------
//		WndProc
//---------------------------------------------------------------------
#define IDC_CTL1			100
#define IDC_CTL2			101
#define IDC_CTL3			102
#define IDC_CTL4			103
#define IDC_CTL5			104
#define IDC_CTL6			105
#define IDC_CTL3_1			106
BOOL func_WndProc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam, void *editp, FILTER *fp){
	//	TRUEを返すと全体が再描画される
	switch(message) {
		case WM_FILTER_INIT:
		{
			fix_init();
			g_window	= hwnd;
			PostMessage(g_window, WM_USER+1, 0, 0);
			g_patch_optionflg	= fp->exfunc->ini_load_int(fp, "option", 0);
		}
		return FALSE;
		case WM_FILTER_EXIT:
		{
			if(g_patch_optionflg != fp->exfunc->ini_load_int(fp, "option", 0)){
				fp->exfunc->ini_save_int(fp, "option", g_patch_optionflg);
			}
		}
		return FALSE;
		case WM_USER+1:
		{
			HMODULE	exedit	= GetModuleHandle("exedit.auf");	//読み込まれている拡張編集.auf
			if(exedit != NULL){
				DWORD 	i	= 3;
				HWND		t_chk1	= CreateWindow("BUTTON", "フィルターダイアログ高速化パッチを当てる", WS_CHILD | WS_VISIBLE | BS_CHECKBOX, 
				3, i, 300, 25, hwnd, (HMENU)IDC_CTL1, g_ModuleInstsnce, NULL);
				HWND		t_chk2	= CreateWindow("BUTTON", "実行時間計測", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 
				3, i+=25, 300, 25, hwnd, (HMENU)IDC_CTL2, g_ModuleInstsnce, NULL);
				HWND		t_chk3_1	= CreateWindow("BUTTON", "単独復帰時に描画する", WS_CHILD | WS_VISIBLE | BS_CHECKBOX, 
				3, i+=25, 300, 25, hwnd, (HMENU)IDC_CTL3_1, g_ModuleInstsnce, NULL);
				HWND		t_chk3	= CreateWindow("BUTTON", "RedrawWindowを使用", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 
				3, i+=25, 300, 25, hwnd, (HMENU)IDC_CTL3, g_ModuleInstsnce, NULL);
				HWND		t_chk4	= CreateWindow("BUTTON", "フィルターダイアログ高速化パッチを一時無効化", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 
				3, i+=25, 300, 25, hwnd, (HMENU)IDC_CTL4, g_ModuleInstsnce, NULL);
				HWND		t_chk5	= CreateWindow("BUTTON", "グラデーション描画簡略化パッチを当てる", WS_CHILD | WS_VISIBLE | BS_CHECKBOX, 
				3, i+=25, 300, 25, hwnd, (HMENU)IDC_CTL5, g_ModuleInstsnce, NULL);
				HWND		t_chk6	= CreateWindow("BUTTON", "グラデーション描画簡略化パッチを一時無効化", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 
				3, i+=25, 300, 25, hwnd, (HMENU)IDC_CTL6, g_ModuleInstsnce, NULL);
				SYS_INFO	si;
				if(fp->exfunc->get_sys_info(editp, &si)){
					SendMessage(t_chk1, WM_SETFONT, (WPARAM)si.hfont, 0);
					SendMessage(t_chk2, WM_SETFONT, (WPARAM)si.hfont, 0);
					SendMessage(t_chk3, WM_SETFONT, (WPARAM)si.hfont, 0);
					SendMessage(t_chk3_1, WM_SETFONT, (WPARAM)si.hfont, 0);
					SendMessage(t_chk4, WM_SETFONT, (WPARAM)si.hfont, 0);
					SendMessage(t_chk5, WM_SETFONT, (WPARAM)si.hfont, 0);
					SendMessage(t_chk6, WM_SETFONT, (WPARAM)si.hfont, 0);
				}
				if(g_patch_optionflg & 1){
					SendMessage(t_chk1, BM_SETCHECK, (WPARAM)BST_CHECKED, 0);
				}
				if(g_patch_optionflg & 2){
					SendMessage(t_chk5, BM_SETCHECK, (WPARAM)BST_CHECKED, 0);
				}
				if(g_patch_optionflg & 4){
					SendMessage(t_chk3, BM_SETCHECK, (WPARAM)BST_CHECKED, 0);
				}
				if(g_patch_optionflg & 8){
					SendMessage(t_chk3_1, BM_SETCHECK, (WPARAM)BST_CHECKED, 0);
				}
				DWORD ev	= get_exedit_version(exedit);
			//	research_init(exedit, ev);	//デバッグ用
				g_patch_exedit		= exedit;
				g_exedit_version	= ev;
				if(ev == 9200){
					if(g_patch_optionflg & 1){
						if(!patch_fast_dialog_92()){
							g_patch_optionflg	^= 1;
						}
					}
					if(g_patch_optionflg & 2){
						if(!patch_92_36a70()){
							g_patch_optionflg	^= 2;
						}
					}
				}else if(ev == 9301){
					if(g_patch_optionflg & 1){
						if(!patch_fast_dialog_93rc1()){
							g_patch_optionflg	^= 1;
						}
					}
					if(g_patch_optionflg & 2){
						if(!patch_93rc1_32ce0()){
							g_patch_optionflg	^= 2;
						}
					}
				}
				if(!(g_patch_optionflg & 1)){
					SendMessage(t_chk1, BM_SETCHECK, (WPARAM)BST_UNCHECKED, 0);
				}
				if(!(g_patch_optionflg & 2)){
					SendMessage(t_chk5, BM_SETCHECK, (WPARAM)BST_UNCHECKED, 0);
				}
			}else{
				ErrorMSGBox("拡張編集がロードされていません", CAPTIONSTR"FILTER_INIT");
			}
		}
		return FALSE;
		case WM_COMMAND:
		{
			int wmId = LOWORD(wparam); 
			switch(wmId){
				case IDC_CTL1://ダイアログ高速化パッチを当てる
				{
					g_patch_optionflg	^= 1;
					if(g_patch_optionflg & 1){
						if(g_exedit_version == 9200){
							if(!patch_fast_dialog_92()){
								g_patch_optionflg	^= 1;
							}
						}else if(g_exedit_version == 9301){
							if(!patch_fast_dialog_93rc1()){
								g_patch_optionflg	^= 1;
							}
						}
					}else{
						if(g_exedit_version == 9200){
							unpatch_fast_dialog_92();
						}else if(g_exedit_version == 9301){
							unpatch_fast_dialog_93rc1();
						}
					}
					SendMessage(GetDlgItem(hwnd, IDC_CTL1), BM_SETCHECK, (WPARAM)(g_patch_optionflg & 1) ? BST_CHECKED : BST_UNCHECKED, 0);
				}
				break;
				case IDC_CTL2://実行時間計測
				{
					if(g_patch_fast_dialog_checkflg & 1)SetWindowText(GetDlgItem(hwnd, IDC_CTL2), "実行時間計測");
					g_patch_fast_dialog_checkflg	^= 1;
				}
				break;
				case IDC_CTL3_1://描画復帰を使用
				{
					g_patch_optionflg	^= 8;
					SendMessage(GetDlgItem(hwnd, IDC_CTL3_1), BM_SETCHECK, (WPARAM)(g_patch_optionflg & 8) ? BST_CHECKED : BST_UNCHECKED, 0);
				}
				break;
				case IDC_CTL3://RedrawWindowを使用
				{
					g_patch_optionflg	^= 4;
				}
				break;
				case IDC_CTL4://ダイアログ高速化パッチを一時無効化
				{
					g_patch_fast_dialog_checkflg	^= 4;
				}
				break;
				case IDC_CTL5://グラデーション描画高速化パッチを当てる
				{
					g_patch_optionflg	^= 2;
					if(g_patch_optionflg & 2){
						if(g_exedit_version == 9200){
							if(!patch_92_36a70()){
								g_patch_optionflg	^= 2;
							}
						}else if(g_exedit_version == 9301){
							if(!patch_93rc1_32ce0()){
								g_patch_optionflg	^= 2;
							}
						}
					}else{
						if(g_exedit_version == 9200){
							unpatch_92_36a70();
						}else if(g_exedit_version == 9301){
							unpatch_93rc1_32ce0();
						}
					}
					SendMessage(GetDlgItem(hwnd, IDC_CTL5), BM_SETCHECK, (WPARAM)(g_patch_optionflg & 2) ? BST_CHECKED : BST_UNCHECKED, 0);
				}
				break;
				case IDC_CTL6://グラデーション描画高速化パッチを一時無効化
				{
					g_patch_fast_gradradation_flag	^= 1;
				}
				break;
			}
		}
		return FALSE;
		case WM_USER:
			if(g_patch_fast_dialog_checkflg & 1){
				char tmp[128];
				sprintf(tmp, "実行時間計測 - %dms", g_patch_fast_dialog_time);
				SetWindowText(GetDlgItem(hwnd, IDC_CTL2), tmp);
			}
			return FALSE;
		default:
			return FALSE;
	}

	return FALSE;
}
/**************************************************************
	調査用関数

	主に拡張編集の動作調査用の関数群
	通常は使われない

	IATを変更してフックしたりとか
**************************************************************/
#if 0
/*
		case WM_FILTER_CHANGE_WINDOW:
		{
			HMODULE	exedit	= GetModuleHandle("exedit.auf");
			if(exedit != NULL){
				HWND *pExtendedFilterClass = (HWND *)((BYTE *)(exedit) + 0x1539c8);
				printf("exedit::ExtendedFilterClass 0x%X\r\n", *pExtendedFilterClass);
			}
		}
		return FALSE;
*/
void stacktrace();
void GetWndName(const char *fname, HWND hWnd){
	char text[256];
	ZeroMemory(text, 256);
	GetClassName(hWnd, text, 255);
	printf("%s 0x%X(%s) ", fname, hWnd, text);
}
/**************************************************************
	スタック調査用関数
	RtlCaptureStackBackTraceが使い物にならないので
	スタックからリターンアドレスを抽出する
**************************************************************/
void GetStackTraceStack(){
	DWORD i 	= 1;
	DWORD *p	= (DWORD *)&i;
	int lim	= (0x330000 - (DWORD)p) >> 2;//テキトー
	printf("p:[%X][%d]\r\n", p, lim);
	for(; i < lim; ++i){
	//	if(p[i] >= 0x10000001 && p[i] <= 0x1009909e){//コード範囲
		if(p[i] >= 0x10000001 && p[i] <= 0x100a80cf){//コード範囲93rc1
			printf("%X ", p[i]);
		}
	}
	printf("\r\n");
}
DWORD patch_in_test	= 0;
BOOL ispatchtest(){
	return g_patch_efc_check == 0 && patch_in_test == 0;
}

BOOL __stdcall ShowWindowHACK(HWND hWnd, int nCmdShow){
	if(ispatchtest()){
		stacktrace();
		GetWndName(__FUNCTION__, hWnd);
		printf("\r\n");
		GetStackTraceStack();
	}
	return ShowWindow(hWnd, nCmdShow);
}

BOOL __stdcall UpdateWindowHACK(HWND hWnd){
	if(ispatchtest()){
		stacktrace();
		GetWndName(__FUNCTION__, hWnd);
		GetStackTraceStack();
	}
	return UpdateWindow(hWnd);
}


BOOL __stdcall SetWindowPosHACK(HWND hWnd, HWND hWndInsertAfter, int X, int Y, int cx, int cy, UINT uFlags){
	if(ispatchtest()){
		stacktrace();
		GetWndName(__FUNCTION__, hWnd);
		GetStackTraceStack();
	}
	return SetWindowPos(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags);
}

int __stdcall FillRectHACK(HDC hDC, const RECT *lprc, HBRUSH hbr){
	return TRUE;
}
BOOL __stdcall MoveToExHACK(HDC hdc, int x, int y, LPPOINT lppt){
	printf("%d - %d\r\n", x, y);
	GetStackTraceStack();
	return MoveToEx(hdc, x, y, lppt);
}
/******************************************

******************************************/
LRESULT __stdcall SendMessageAHACK(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam){
	if(g_patch_efc_check == 0){
		stacktrace();
		GetWndName(__FUNCTION__, hWnd);
		printf("\r\n");
		GetStackTraceStack();
	}
	return SendMessageA(hWnd, Msg, wParam, lParam);
}

BOOL HackFunc_93rc1(HMODULE exedit, DWORD index, DWORD *newfunc);

BOOL HackFuncGDI32(HMODULE exedit, DWORD index, DWORD *newfunc);
typedef USHORT (WINAPI *RtlCaptureStackBackTraceDef)(ULONG FramesToSkip, ULONG FramesToCapture, PVOID *BackTrace, PULONG BackTraceHash);
RtlCaptureStackBackTraceDef csbproc	= NULL;
void research_init(HMODULE exedit, DWORD version){
	csbproc = (RtlCaptureStackBackTraceDef)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "RtlCaptureStackBackTrace");
	printf("exedit::exedit 0x%X\r\n", exedit);
/*	DWORD *pExtendedFilterClassPtr = (DWORD *)((BYTE *)(exedit) + 0x2f34e);
	printf("exedit::pExtendedFilterClassptr 0x%X\r\n", *pExtendedFilterClassPtr);
	*/
	if(version == 9200){
	/*	HackFunc(exedit, 86, (DWORD *)SendMessageAHACK);
		HackFunc(exedit, 40, (DWORD *)ShowWindowHACK);
		HackFunc(exedit, 56, (DWORD *)UpdateWindowHACK);
		HackFunc(exedit, 44, (DWORD *)SetWindowPosHACK);*/
//		HackFunc(exedit, 57, (DWORD *)FillRectHACK);
//		HackFuncGDI32(exedit, 6, (DWORD *)MoveToExHACK);
	}
	if(version == 9301){
		/*HackFunc_93rc1(exedit, 93, (DWORD *)ShowWindowHACK);
		HackFunc_93rc1(exedit, 58, (DWORD *)UpdateWindowHACK);
		HackFunc_93rc1(exedit, 86, (DWORD *)SetWindowPosHACK);
		HackFuncGDI32_93rc1(exedit, 12, (DWORD *)MoveToExHACK);*/
	}
}

BOOL __stdcall InvalidateRectHACK(HWND hWnd, const RECT *lpRect, BOOL bErase){
	printf("InvalidateRectHACK 0x%X\r\n", hWnd);
	return TRUE;
}
BOOL __stdcall InvalidateRgnHACK(HWND hWnd , HRGN hRgn , BOOL bErase){
	printf("InvalidateRgnHACK 0x%X\r\n", hWnd);
	return TRUE;
}
void stacktrace(){//上手く行かなかった
	if(csbproc != NULL){
		WORD i = 1;
		void *stack[50];
		WORD frames = csbproc(0, 50, stack, NULL);
		if(frames >= 3){
			printf("%08X:%X ", GetTickCount(), stack[2]);
		/*	for(; i < frames; i++){
				printf("%X ", stack[i]);
			}*/
		}
	}
}
void vp_page(DWORD old){
	switch(old){
		case PAGE_READONLY:printf("VirtualProtect::PAGE_READONLY\r\n");break;
		case PAGE_READWRITE:printf("VirtualProtect::PAGE_READWRITE\r\n");break;
		case PAGE_WRITECOPY:printf("VirtualProtect::PAGE_WRITECOPY\r\n");break;
		case PAGE_EXECUTE:printf("VirtualProtect::PAGE_EXECUTE\r\n");break;
		case PAGE_EXECUTE_READ:printf("VirtualProtect::PAGE_EXECUTE_READ\r\n");break;
		case PAGE_EXECUTE_READWRITE:printf("VirtualProtect::PAGE_EXECUTE_READWRITE\r\n");break;
		case PAGE_EXECUTE_WRITECOPY:printf("VirtualProtect::PAGE_EXECUTE_WRITECOPY\r\n");break;
		case PAGE_GUARD:printf("VirtualProtect::PAGE_GUARD\r\n");break;
		case PAGE_NOACCESS:printf("VirtualProtect::PAGE_NOACCESS\r\n");break;
		case PAGE_NOCACHE:printf("VirtualProtect::PAGE_NOCACHE\r\n");break;
		default:printf("VirtualProtect::PAGE_ unknown %X\r\n", old);break;
	}
}
/*
IATのハック
序列はobjdumpで
*/
BOOL HackFuncBase(HMODULE exedit, DWORD address, DWORD index, DWORD *newfunc){
	DWORD funcpos		= address + (4 * index);
	printf("%X\r\n", funcpos);
	DWORD *func_addr	= (DWORD *)(((BYTE *)exedit) + funcpos);
	DWORD old			= 0;
	if(VirtualProtect(func_addr, 4, PAGE_READWRITE, &old)){
		printf("VirtualProtect::success\r\n");
		vp_page(old);
		*func_addr		= (DWORD)newfunc;
		if(VirtualProtect(func_addr, 4, old, &old)){
			printf("VirtualProtect::success\r\n");
			return TRUE;
		}else{
			DWORD gle	= GetLastError();
			printf("VirtualProtect::error GetLastError %X\r\n", gle);
		}
	}else{
		DWORD gle	= GetLastError();
		printf("VirtualProtect::error GetLastError %X\r\n", gle);
	}
	return FALSE;
}
BOOL HackFunc(HMODULE exedit, DWORD index, DWORD *newfunc){
	return HackFuncBase(exedit, 0x9a1dc, index, newfunc);
}
BOOL HackFuncGDI32(HMODULE exedit, DWORD index, DWORD *newfunc){
	return HackFuncBase(exedit, 0x9a000, index, newfunc);
}
BOOL HackFunc_93rc1(HMODULE exedit, DWORD index, DWORD *newfunc){
	return HackFuncBase(exedit, 0xa9210, index, newfunc);
}
BOOL HackFuncGDI32_93rc1(HMODULE exedit, DWORD index, DWORD *newfunc){
	return HackFuncBase(exedit, 0xa9000, index, newfunc);
}

#endif

