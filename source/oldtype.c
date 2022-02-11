/**************************************************************
	�����R�[�h(�A�Z���u�����g��Ȃ��o�[�W����)

	�ʏ�̓R���p�C���ΏۂɎw�肵�Ȃ��ł�������

	�Â��̂ŏC�����K�v
	�A�Z���u�����g���Ȃ����Ŏ����������l�����H�̃T���v��
enter leave�͓����B
**************************************************************/
#include <windows.h>
#include <stdio.h>
#include "filter.h"
/***********************************************
	���I�p�b�`�𓖂Ă�

	address	�Ώۂ̃A�h���X
	check	���̃f�[�^�̃R�s�[(�ԈႢ�h�~�p�B)
	patch	�X�V�f�[�^
	length	check�Apatch�̃T�C�Y

	return
		NULL�Ő���
		���s���ɂ̓G���[������B
***********************************************/
const char *WritePatch(void *address, const void *check, const void *patch, DWORD length){
	if(memcmp(address, check, length) == 0){
		DWORD old			= 0;
		if(VirtualProtect(address, length, PAGE_EXECUTE_READWRITE, &old)){	//read write�ɏ�������
			memcpy(address, patch, length);					//�}���`�X���b�h�ŃR�[�h�ɃA�N�Z�X���ꂽ�玀��
			if(VirtualProtect(address, length, old, &old)){			//���ɖ߂�
				return NULL;
			}
		}
		/*DWORD gle	= GetLastError();//������Ɩʓ|�Ȃ̂Ō��
		printf("VirtualProtect::error GetLastError %X\r\n", gle);*/
		return "VirtualProtect::error\r\n";
	}
	return "VirtualProtect::check failed\r\n";
}
/***********************************************
	�t�B���^�_�C�A���O�`�摬�x����
***********************************************/
void *g_patch_fast_dialog_asm	= NULL;	//��ӏ���
void *g_patch_fast_dialog_asm2	= NULL;	//��ӏ���
/***********************************************
	version 0.92

	305e0
	30500
***********************************************/
void *Create_Patch_92_305e0_asm(void *patch, const void *address, DWORD offset, const void *orig, DWORD length);
void *Create_Patch_92_30500_asm(void *patch, const void *address, DWORD offset, const void *orig, DWORD length);

//------------------------
//		305e0�̃p�b�`�K�p
//------------------------
BOOL patch_92_305e0(HMODULE exedit){//�O����
	if(g_patch_fast_dialog_asm == NULL){
		DWORD *t	= (DWORD *)(((BYTE *)exedit) + 0x305e0);
//100305e0�̊֐��鍐BOOL __cdecl unknown(DWORD);���ȁH
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
				ErrorMSGBox(result, CAPTIONSTR"patch_92_305e0 �p�b�`���ĂɎ��s���܂���");
			}
		}else{
			ErrorMSGBox("�������m�ۂɎ��s���܂���", CAPTIONSTR"patch_92_305e0 �p�b�`���ĂɎ��s���܂���");
		}
	}
	return FALSE;
}
//------------------------
//		30500�̃p�b�`�K�p
//------------------------
BOOL patch_92_30500(HMODULE exedit){//�O����
	if(g_patch_fast_dialog_asm2 == NULL){
		DWORD *t	= (DWORD *)(((BYTE *)exedit) + 0x30500);
/*
10030500�̊֐��鍐void __cdecl unknown();���ȁH
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
				ErrorMSGBox(result, CAPTIONSTR"patch_92_30500 �p�b�`���ĂɎ��s���܂���");
			}
		}else{
			ErrorMSGBox("�������m�ۂɎ��s���܂���", CAPTIONSTR"patch_92_30500 �p�b�`���ĂɎ��s���܂���");
		}
	}
	return FALSE;
}
/***********************************************
	�p�b�`�p�@�B��R�[�h�쐬(cdeclcall����1(stdcall�\�L��@4)
***********************************************/
void CreateCdeclCallArg1Asm(BYTE *p, DWORD address, const void *enter, const void *leave, const void *orig, DWORD length){
	DWORD index	= 0;
	p[index++]				= 0xE8;			//call enter
	(*(DWORD *)(p + index))	= (DWORD)enter - (DWORD)(p + index + 4);
	index	+= 4;
	p[index++]				= 0xff;			//pushl  0x4(%esp)
	p[index++]				= 0x74;			//call�����ꍇ�Areturn�X�^�b�N���ς܂��̂�
	p[index++]				= 0x24;			//�����𕡐����Ȃ���΂Ȃ�Ȃ�
	p[index++]				= 0x04;			//jmp���ƌĂяo�����ɖ߂邽��leave�����s�ł��Ȃ�
	p[index++]				= 0xE8;			//call �I���W�i���R�[�h������ւ�jmp
	(*(DWORD *)(p + index))	= 9;			//1 + 1 + 5 + 1 + 1
	index	+= 4;
	p[index++]				= 0x59;			//pop %ecx		//�d�l�����(pushl  0x4(%esp))
	p[index++]				= 0x50;			//push %eax		//return�ۑ�
	p[index++]				= 0xE8;			//call leave
	(*(DWORD *)(p + index))	= (DWORD)leave - (DWORD)(p + index + 4);
	index	+= 4;
	p[index++]				= 0x58;			//pop %eax		//return���A
	p[index++]				= 0xC3;			//ret
	memcpy(p + index, orig, length);		//�I���W�i���R�[�h����
	index	+= length;
	p[(index++)]			= 0xE9;			//jmp
	(*(DWORD *)(p + index))	= address - (DWORD)(p + index + 4);//���̊֐��ɕ��A
}
/***********************************************
	�p�b�`�p�@�B��R�[�h�쐬
	patch	�X�V�f�[�^(5byte�ȏ�łȂ���΂Ȃ�Ȃ�)
	address	�Ώۂ̊֐��A�h���X
	offset	�Ώۂ̊֐��A�h���X���A��ւ̃I�t�Z�b�g(�㏑������閽�ߐ��ɂ���ĕς�邽��)
	orig	�Ώۂ̊֐��̌��̃f�[�^
	length	orig�̃T�C�Y(patch�������Ƃ��Ĕ���)

	92_305e0�p
***********************************************/
void *Create_Patch_92_305e0_asm(void *patch, const void *address, DWORD offset, const void *orig, DWORD length){
	if(length >= 5){
		BYTE *p	= (BYTE *)VirtualAlloc(NULL, 50 + length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if(p != NULL){
			CreateCdeclCallArg1Asm(p, ((DWORD)address + offset), Patch_92_305e0_enter, Patch_92_305e0_leave, orig, length);
			BYTE *pp				= (BYTE *)patch;//�p�b�`�X�V
			pp[0]					= 0xE9;			//jmp
			(*(DWORD *)(pp + 1))	= (DWORD)p - ((DWORD)(address) + 5);
			return p;
		}
	}
	return NULL;
}
/***********************************************
	92_30500�p
***********************************************/
void *Create_Patch_92_30500_asm(void *patch, const void *address, DWORD offset, const void *orig, DWORD length){
	if(length >= 5){
		BYTE *p	= (BYTE *)VirtualAlloc(NULL, 50 + length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if(p != NULL){
			CreateCdeclCallArg1Asm(p, ((DWORD)address + offset), Patch_92_30500_enter, Patch_92_30500_leave, orig, length);
			BYTE *pp				= (BYTE *)patch;//�p�b�`�X�V
			pp[0]					= 0xE9;			//jmp
			(*(DWORD *)(pp + 1))	= (DWORD)p - ((DWORD)(address) + 5);
			return p;
		}
	}
	return NULL;
}
/***********************************************
	version 0.93rc1
	�t�B���^�_�C�A���O�`�摬�x����
_2b2a0
_2b390
***********************************************/

void *Create_Patch_93rc1_2b390_asm(void *patch, const void *address, DWORD offset, const void *orig, DWORD length);
void *Create_Patch_93rc1_2b2a0_asm(void *patch, const void *address, DWORD offset, const void *orig, DWORD length);

//------------------------
//		2b390�̃p�b�`�K�p
//------------------------
BOOL patch_93rc1_2b390(HMODULE exedit){//�O����
	if(g_patch_fast_dialog_asm == NULL){
		DWORD *t	= (DWORD *)(((BYTE *)exedit) + 0x2b390);
/*1002b390�̊֐��鍐BOOL __fastcall(microsoft) unknown(DWORD);���ȁH
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
				ErrorMSGBox(result, CAPTIONSTR"patch_93rc1_2b390 �p�b�`���ĂɎ��s���܂���");
			}
		}else{
			ErrorMSGBox("�������m�ۂɎ��s���܂���", CAPTIONSTR"patch_93rc1_2b390 �p�b�`���ĂɎ��s���܂���");
		}
	}
	return FALSE;
}
//------------------------
//		2b2a0�̃p�b�`�K�p
//------------------------
BOOL patch_93rc1_2b2a0(HMODULE exedit){//�O����
	if(g_patch_fast_dialog_asm2 == NULL){
		DWORD *t	= (DWORD *)(((BYTE *)exedit) + 0x2b2a0);
/*1002b2a0�̊֐��鍐void __fastcall(microsoft) unknown(DWORD);���ȁH
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
				ErrorMSGBox(result, CAPTIONSTR"patch_93rc1_2b2a0 �p�b�`���ĂɎ��s���܂���");
			}
		}else{
			ErrorMSGBox("�������m�ۂɎ��s���܂���", CAPTIONSTR"patch_93rc1_2b2a0 �p�b�`���ĂɎ��s���܂���");
		}
	}
	return FALSE;
}
/***********************************************
	�p�b�`�p�@�B��R�[�h�쐬(fastcall)
***********************************************/
void CreateFastCallAsm(BYTE *p, DWORD address, const void *enter, const void *leave, const void *orig, DWORD length){
	DWORD index	= 0;
	p[index++]				= 0x51;			//push %ecx	//fastcall�p�����ҋ@
	p[index++]				= 0x52;			//push %edx
	p[index++]				= 0xE8;			//call enter
	(*(DWORD *)(p + index))	= (DWORD)enter - (DWORD)(p + index + 4);
	index	+= 4;
	p[index++]				= 0x5A;			//pop %edx	//���A
	p[index++]				= 0x59;			//pop %ecx

	p[index++]				= 0xE8;			//call �I���W�i���R�[�h������ւ�jmp
	(*(DWORD *)(p + index))	= 8;			//1 + 5 + 1 + 1
	index	+= 4;
	p[index++]				= 0x50;			//push %eax		//return�ۑ�
	p[index++]				= 0xE8;			//call leave
	(*(DWORD *)(p + index))	= (DWORD)leave - (DWORD)(p + index + 4);
	index	+= 4;
	p[index++]				= 0x58;			//pop %eax		//return���A
	p[index++]				= 0xC3;			//ret
	memcpy(p + index, orig, length);		//�I���W�i���R�[�h����
	index	+= length;
	p[(index++)]			= 0xE9;			//jmp
	(*(DWORD *)(p + index))	= address - (DWORD)(p + index + 4);//���̊֐��ɕ��A
}
/***********************************************
	93rc1_2b390�p
***********************************************/
void *Create_Patch_93rc1_2b390_asm(void *patch, const void *address, DWORD offset, const void *orig, DWORD length){
	if(length >= 5){
		BYTE *p	= (BYTE *)VirtualAlloc(NULL, 50 + length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if(p != NULL){
			CreateFastCallAsm(p, ((DWORD)address + offset), Patch_93rc1_2b390_enter, Patch_93rc1_2b390_leave, orig, length);
			BYTE *pp				= (BYTE *)patch;//�p�b�`�X�V
			pp[0]					= 0xE9;			//jmp func
			(*(DWORD *)(pp + 1))	= (DWORD)p - ((DWORD)(address) + 5);
			return p;
		}
	}
	return NULL;
}
/***********************************************
	93rc1_2b2a0�p
***********************************************/
void *Create_Patch_93rc1_2b2a0_asm(void *patch, const void *address, DWORD offset, const void *orig, DWORD length){
	if(length >= 5){
		BYTE *p	= (BYTE *)VirtualAlloc(NULL, 21 + length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if(p != NULL){
			CreateFastCallAsm(p, ((DWORD)address + offset), Patch_93rc1_2b2a0_enter, Patch_93rc1_2b2a0_leave, orig, length);
			BYTE *pp				= (BYTE *)patch;//�p�b�`�X�V
			pp[0]					= 0xE9;			//jmp func
			(*(DWORD *)(pp + 1))	= (DWORD)p - ((DWORD)(address) + 5);
			return p;
		}
	}
	return NULL;
}
/***********************************************
	�p�b�`�S�J��
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
