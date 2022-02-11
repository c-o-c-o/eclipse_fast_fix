//.intel_syntax
/************************************************
	ダイアログ高速化用
************************************************/
.extern _g_patch_fast_dialog_hook1
.extern _g_patch_fast_dialog_hook2
/************************************************
	version 0.92用
************************************************/
//参照用。c++の場合はextern "C" void Patch_92_305e0_enter();みたいに定義
.extern _Patch_92_305e0_enter
.extern _Patch_92_305e0_leave
.extern _Patch_92_30500_enter
.extern _Patch_92_30500_leave
//外部から呼び出せるように
.globl _patch_92_305e0_asm
.globl _patch_92_305e0_asm_back
.globl _patch_92_30500_asm
.globl _patch_92_30500_asm_back
/************************************************
	patch_92_305e0_hook
************************************************/
.align 4
_patch_92_305e0_asm:
	call _Patch_92_305e0_enter		//enter呼び出し
	pushl  0x4(%esp)				//callした場合、returnスタックが積まれるので 引数を複製しなければならない
	call _patch_92_305e0_asm_back	//オリジナル関数呼び出し
	add $0x4,%esp					//pop	//引数解除
	push %eax						//return保存
	call _Patch_92_305e0_leave		//leave呼び出し
	pop %eax						//return復帰
	ret
_patch_92_305e0_asm_back:					//復帰点
.dc.b 0x81, 0xec, 0x18, 0x01, 0x00, 0x00	//オリジナルコード実行
	jmp *_g_patch_fast_dialog_hook1			//オリジナル関数に復帰
/************************************************
	patch_92_30500_hook
************************************************/
.align 4
_patch_92_30500_asm:
	call _Patch_92_30500_enter		//enter呼び出し
	pushl  0x4(%esp)				//callした場合、returnスタックが積まれるので 引数を複製しなければならない
	call _patch_92_30500_asm_back	//オリジナル関数呼び出し
	add $0x4,%esp					//pop	//引数解除
	push %eax						//return保存
	call _Patch_92_30500_leave		//leave呼び出し
	pop %eax						//return復帰
	ret
_patch_92_30500_asm_back:					//復帰点
.dc.b 0x53, 0x55, 0x56, 0x8b, 0x35, 0x7c, 0xa2, 0x09, 0x10	//オリジナルコード実行
	jmp *_g_patch_fast_dialog_hook2			//オリジナル関数に復帰
/************************************************
	version 0.93rc1用
************************************************/
//参照用。c++の場合はextern "C" void Patch_93rc1_2b390_enter();みたいに定義
.extern _Patch_93rc1_2b390_enter
.extern _Patch_93rc1_2b390_leave
.extern _Patch_93rc1_2b2a0_enter
.extern _Patch_93rc1_2b2a0_leave
//外部から呼び出せるように
.globl _patch_93rc1_2b390_asm
.globl _patch_93rc1_2b390_asm_back
.globl _patch_93rc1_2b2a0_asm
.globl _patch_93rc1_2b2a0_asm_back
/************************************************
	_patch_93rc1_2b390_hook
************************************************/
.align 4
_patch_93rc1_2b390_asm:					//引数が１なのでスタック操作なし
	push %ecx							//fastcall用引数保存
	push %edx
	call _Patch_93rc1_2b390_enter		//enter呼び出し
	pop %edx							//復帰
	pop %ecx
	call _patch_93rc1_2b390_asm_back	//オリジナル関数呼び出し
	push %eax							//return保存
	call _Patch_93rc1_2b390_leave		//leave呼び出し
	pop %eax							//return復帰
	ret
_patch_93rc1_2b390_asm_back:				//復帰点
.dc.b 0x55, 0x8b, 0xec, 0x83, 0xe4, 0xf8	//オリジナルコード実行
	jmp *_g_patch_fast_dialog_hook1			//オリジナル関数に復帰
/************************************************
	_patch_93rc1_2b2a0_hook
************************************************/
.align 4
_patch_93rc1_2b2a0_asm:					//引数が２以下なのでスタック操作なし(たぶんね)
	push %ecx							//fastcall用引数保存
	push %edx
	call _Patch_93rc1_2b2a0_enter		//enter呼び出し
	pop %edx							//復帰
	pop %ecx
	call _patch_93rc1_2b2a0_asm_back	//オリジナル関数呼び出し
	push %eax							//return保存
	call _Patch_93rc1_2b2a0_leave		//leave呼び出し
	pop %eax							//return復帰
	ret
_patch_93rc1_2b2a0_asm_back:			//復帰点
.dc.b 0x53, 0x56, 0x8b, 0x35, 0x84, 0x93, 0x0a, 0x10	//オリジナルコード実行
	jmp *_g_patch_fast_dialog_hook2		//オリジナル関数に復帰
/************************************************
	描画高速化用
************************************************/
.extern _g_patch_fast_gradradation_hook
/************************************************
	version 0.92用
************************************************/
//外部から呼び出せるように
.globl _patch_92_36a70_call
/************************************************
	_patch_92_36a70_call
************************************************/
.align 4
_patch_92_36a70_call:						//復帰点
.dc.b 0x83, 0xec, 0x14, 0x53, 0x55			//オリジナルコード実行
	jmp *_g_patch_fast_gradradation_hook	//オリジナル関数に復帰
/************************************************
	version 0.93rc1用
************************************************/
.extern _patch_93rc1_FillGradation
//外部から呼び出せるように
.globl _patch_93rc1_32ce0_asm
.globl _patch_93rc1_32ce0_call
.globl _patch_93rc1_32ce0_callf
/************************************************
	_patch_92_36a70_call
************************************************/
.align 4
_patch_93rc1_32ce0_asm:	//fastcall -> cdecl化。fastcallなのにret操作なし。なんだこれ
	push   %ebp
	mov    %esp,%ebp
	pushl  0x24(%esp)						//引数複製
	pushl  0x24(%esp)
	pushl  0x24(%esp)
	pushl  0x24(%esp)
	pushl  0x24(%esp)
	pushl  0x24(%esp)
	pushl  0x24(%esp)
	pushl  0x24(%esp)
	push %edx								//fastcall用引数保存(patch_93rc1_FillGradationはcdeclなので)
	push %ecx
	call _patch_93rc1_FillGradation
	pop %ecx
	pop %edx
	leave
	ret
_patch_93rc1_32ce0_call:					//復帰点(真)
	push   %ebp
	mov    %esp,%ebp
	pushl  0x2c(%esp)						//引数複製
	pushl  0x2c(%esp)
	pushl  0x2c(%esp)
	pushl  0x2c(%esp)
	pushl  0x2c(%esp)
	pushl  0x2c(%esp)
	pushl  0x2c(%esp)
	pushl  0x2c(%esp)
	pushl  0x2c(%esp)
	pushl  0x2c(%esp)
	pop %ecx								//引数fastcall化(cdeclなので)
	pop %edx
	call _patch_93rc1_32ce0_callf
	leave
	ret
_patch_93rc1_32ce0_callf:					//復帰点
.dc.b 0x55, 0x8b, 0xec, 0x83, 0xec, 0x0c	//オリジナルコード実行
	jmp *_g_patch_fast_gradradation_hook	//オリジナル関数に復帰

