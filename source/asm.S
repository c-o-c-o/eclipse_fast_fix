//.intel_syntax
/************************************************
	�_�C�A���O�������p
************************************************/
.extern _g_patch_fast_dialog_hook1
.extern _g_patch_fast_dialog_hook2
/************************************************
	version 0.92�p
************************************************/
//�Q�Ɨp�Bc++�̏ꍇ��extern "C" void Patch_92_305e0_enter();�݂����ɒ�`
.extern _Patch_92_305e0_enter
.extern _Patch_92_305e0_leave
.extern _Patch_92_30500_enter
.extern _Patch_92_30500_leave
//�O������Ăяo����悤��
.globl _patch_92_305e0_asm
.globl _patch_92_305e0_asm_back
.globl _patch_92_30500_asm
.globl _patch_92_30500_asm_back
/************************************************
	patch_92_305e0_hook
************************************************/
.align 4
_patch_92_305e0_asm:
	call _Patch_92_305e0_enter		//enter�Ăяo��
	pushl  0x4(%esp)				//call�����ꍇ�Areturn�X�^�b�N���ς܂��̂� �����𕡐����Ȃ���΂Ȃ�Ȃ�
	call _patch_92_305e0_asm_back	//�I���W�i���֐��Ăяo��
	add $0x4,%esp					//pop	//��������
	push %eax						//return�ۑ�
	call _Patch_92_305e0_leave		//leave�Ăяo��
	pop %eax						//return���A
	ret
_patch_92_305e0_asm_back:					//���A�_
.dc.b 0x81, 0xec, 0x18, 0x01, 0x00, 0x00	//�I���W�i���R�[�h���s
	jmp *_g_patch_fast_dialog_hook1			//�I���W�i���֐��ɕ��A
/************************************************
	patch_92_30500_hook
************************************************/
.align 4
_patch_92_30500_asm:
	call _Patch_92_30500_enter		//enter�Ăяo��
	pushl  0x4(%esp)				//call�����ꍇ�Areturn�X�^�b�N���ς܂��̂� �����𕡐����Ȃ���΂Ȃ�Ȃ�
	call _patch_92_30500_asm_back	//�I���W�i���֐��Ăяo��
	add $0x4,%esp					//pop	//��������
	push %eax						//return�ۑ�
	call _Patch_92_30500_leave		//leave�Ăяo��
	pop %eax						//return���A
	ret
_patch_92_30500_asm_back:					//���A�_
.dc.b 0x53, 0x55, 0x56, 0x8b, 0x35, 0x7c, 0xa2, 0x09, 0x10	//�I���W�i���R�[�h���s
	jmp *_g_patch_fast_dialog_hook2			//�I���W�i���֐��ɕ��A
/************************************************
	version 0.93rc1�p
************************************************/
//�Q�Ɨp�Bc++�̏ꍇ��extern "C" void Patch_93rc1_2b390_enter();�݂����ɒ�`
.extern _Patch_93rc1_2b390_enter
.extern _Patch_93rc1_2b390_leave
.extern _Patch_93rc1_2b2a0_enter
.extern _Patch_93rc1_2b2a0_leave
//�O������Ăяo����悤��
.globl _patch_93rc1_2b390_asm
.globl _patch_93rc1_2b390_asm_back
.globl _patch_93rc1_2b2a0_asm
.globl _patch_93rc1_2b2a0_asm_back
/************************************************
	_patch_93rc1_2b390_hook
************************************************/
.align 4
_patch_93rc1_2b390_asm:					//�������P�Ȃ̂ŃX�^�b�N����Ȃ�
	push %ecx							//fastcall�p�����ۑ�
	push %edx
	call _Patch_93rc1_2b390_enter		//enter�Ăяo��
	pop %edx							//���A
	pop %ecx
	call _patch_93rc1_2b390_asm_back	//�I���W�i���֐��Ăяo��
	push %eax							//return�ۑ�
	call _Patch_93rc1_2b390_leave		//leave�Ăяo��
	pop %eax							//return���A
	ret
_patch_93rc1_2b390_asm_back:				//���A�_
.dc.b 0x55, 0x8b, 0xec, 0x83, 0xe4, 0xf8	//�I���W�i���R�[�h���s
	jmp *_g_patch_fast_dialog_hook1			//�I���W�i���֐��ɕ��A
/************************************************
	_patch_93rc1_2b2a0_hook
************************************************/
.align 4
_patch_93rc1_2b2a0_asm:					//�������Q�ȉ��Ȃ̂ŃX�^�b�N����Ȃ�(���Ԃ��)
	push %ecx							//fastcall�p�����ۑ�
	push %edx
	call _Patch_93rc1_2b2a0_enter		//enter�Ăяo��
	pop %edx							//���A
	pop %ecx
	call _patch_93rc1_2b2a0_asm_back	//�I���W�i���֐��Ăяo��
	push %eax							//return�ۑ�
	call _Patch_93rc1_2b2a0_leave		//leave�Ăяo��
	pop %eax							//return���A
	ret
_patch_93rc1_2b2a0_asm_back:			//���A�_
.dc.b 0x53, 0x56, 0x8b, 0x35, 0x84, 0x93, 0x0a, 0x10	//�I���W�i���R�[�h���s
	jmp *_g_patch_fast_dialog_hook2		//�I���W�i���֐��ɕ��A
/************************************************
	�`�捂�����p
************************************************/
.extern _g_patch_fast_gradradation_hook
/************************************************
	version 0.92�p
************************************************/
//�O������Ăяo����悤��
.globl _patch_92_36a70_call
/************************************************
	_patch_92_36a70_call
************************************************/
.align 4
_patch_92_36a70_call:						//���A�_
.dc.b 0x83, 0xec, 0x14, 0x53, 0x55			//�I���W�i���R�[�h���s
	jmp *_g_patch_fast_gradradation_hook	//�I���W�i���֐��ɕ��A
/************************************************
	version 0.93rc1�p
************************************************/
.extern _patch_93rc1_FillGradation
//�O������Ăяo����悤��
.globl _patch_93rc1_32ce0_asm
.globl _patch_93rc1_32ce0_call
.globl _patch_93rc1_32ce0_callf
/************************************************
	_patch_92_36a70_call
************************************************/
.align 4
_patch_93rc1_32ce0_asm:	//fastcall -> cdecl���Bfastcall�Ȃ̂�ret����Ȃ��B�Ȃ񂾂���
	push   %ebp
	mov    %esp,%ebp
	pushl  0x24(%esp)						//��������
	pushl  0x24(%esp)
	pushl  0x24(%esp)
	pushl  0x24(%esp)
	pushl  0x24(%esp)
	pushl  0x24(%esp)
	pushl  0x24(%esp)
	pushl  0x24(%esp)
	push %edx								//fastcall�p�����ۑ�(patch_93rc1_FillGradation��cdecl�Ȃ̂�)
	push %ecx
	call _patch_93rc1_FillGradation
	pop %ecx
	pop %edx
	leave
	ret
_patch_93rc1_32ce0_call:					//���A�_(�^)
	push   %ebp
	mov    %esp,%ebp
	pushl  0x2c(%esp)						//��������
	pushl  0x2c(%esp)
	pushl  0x2c(%esp)
	pushl  0x2c(%esp)
	pushl  0x2c(%esp)
	pushl  0x2c(%esp)
	pushl  0x2c(%esp)
	pushl  0x2c(%esp)
	pushl  0x2c(%esp)
	pushl  0x2c(%esp)
	pop %ecx								//����fastcall��(cdecl�Ȃ̂�)
	pop %edx
	call _patch_93rc1_32ce0_callf
	leave
	ret
_patch_93rc1_32ce0_callf:					//���A�_
.dc.b 0x55, 0x8b, 0xec, 0x83, 0xec, 0x0c	//�I���W�i���R�[�h���s
	jmp *_g_patch_fast_gradradation_hook	//�I���W�i���֐��ɕ��A
