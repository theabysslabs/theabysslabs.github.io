---
layout: post
title:  "Lost in truncation. Root cause analysis of a NTOSKRNL Heap Overflow."
date:   2026-06-16 00:00:00 +0200
categories: patch-diffing exploitation WindowsKernel
---

# Introduction


On May 2026 Patch Tuesday Microsoft patched CVE-2026-33841, a Heap Overflow in NTOSKRNL.
In this article we will analyse the root cause of this bug by diffing the relevant ntoskrnl binaries before and after the patch.

# Understanding the patch

When conducting Windows binary patch diffing a good approach to speed up the initial analysis is to pay attention to the newly added feature flags functions.
Microsoft often wraps a vulnerability fix in a conditional statement driven by a feature flag which allows them to
revert the fix in case of unexpected behavior.
In other words, by paying attention to the functions calling these feature flag functions it is possible to isolate the security-relevant changes from other routine codebase updates.
It's time to download the relevant NTOSKRNL files from [Winbindex] (https://winbindex.m417z.com) and start diffing them!

<div align='center'><img src="/images/ntosmayfeatureflags.png" height="250" width="700" > </div> <br>

As we can see from the picture above three distinct feature flag functions have been added:

- **Feature_2866505016**
- **Feature_3537880376**
- **Feature_1462962491**

Since we are focusing on a Heap Overflow bug class, the next logical step will be to review the functions calling these feature flags functions and look for some hints related to the specific bug class we are interested in.
After quickly reviewing all of them, we decided to focus our attention on the last one, since the newly added code looked like a patch for a textbook heap overflow.
More specifically, the **Feature_1462962491** feature flag function is called  by **NtPssCaptureVaSpaceBulk**, a syscall introduced in Windows 10 version 2004+.
Below, we can see the patched code in the NtPssCaptureVaSpaceBulk.

<div align='center'><img src="/images/NtPssCapture_Patched.png" height="250" width="700" > </div> <br>

The patch is pretty neat: the patched function will call the **IoAllocateMdl** function only if the value contained in the R12 register is less or equal to 0xFFFFFFFF, a clear hint of a heap overflow vulnerability since the value contained in the R12 low DWORD register is passed as the second parameter to the IoAllocateMdl function!
This function is used by Windows kernel-mode drivers to allocate and initialize Memory Descriptor Lists which are then used to map the physical pages of a user-mode buffer in kernel-mode memory. In other words, MDLs are used by kernel drivers to access the exact same physical RAM pages a user mode buffer is stored in without the CPU needing to constantly copy data back and forth.

Let's have a look to the *IoAllocateMdl* function prototype:
{% highlight c %}
PMDL IoAllocateMdl(PVOID VirtualMemory,
	ULONG Length,
	BOOLEAN SecondaryBuffer,
	BOOLEAN ChargeQuota,
	PIRP Irp);

{% endhighlight %}

As we can see, the second parameter of the *IoAllocateMdl* function is a 32-bit ULONG which specifies the size of the buffer that the MDL must describe.
Since the patch specifically ensures that the value being passed as the *Length* parameter to the *IoAllocateMdl* function is less or equal to the size of a ULONG variable, we can assess with a high degree of certainty that this value is user-controlled and it is probably related to the size of a usermode buffer.
In the next section we will verify our assumption!

## The NtPssCaptureVaSpaceBulk Syscall

Luckily for us, there is [some public research](https://downwithup.github.io/blog/post/2021/05/14/post8.html) which can help us speed up the analysis process.
Long story short, the **NtPssCaptureVaSpaceBulk** function is an undocumented syscall used to map out the virtual address space of a process (addresses, allocation states, protection types) in a single API call as an alternative to the traditional method of looping through a process's memory regions.

Let's have a look to the *NtPssCaptureVaSpaceBulk* function prototype.

{% highlight c %}
NTSTATUS NtPssCaptureVaSpaceBulk(HANDLE ProcessHandle,
	PVOID BaseAddress,
	PBULK_MEMORY_INFORMATION MemoryInfo,
	SIZE_T Length,
	PSIZE_T ReturnLength);

{% endhighlight %}

The astute reader might have noticed something pretty interesting: the *Length* parameter is declared as a *SIZE_T* variable.
For those who are not aware, a SIZE_T variable can store the maximum size of a theoretically possible array or object. This means that on a 64-bit system a SIZE_T variable will take 64 bits!
Our spidey senses are definitely tingling!
Since the *Length* parameter specifies the size of the *MemoryInfo* usermode buffer which will be filled with information about process's memory upon successful execution of the *NtPssCaptureVaSpaceBulk* function there is a strong likelihood that this is the very same parameter the patched code checks against the 0xFFFFFFFF value.
All these hints led us to believe that the bug root cause stems from a truncation issue arising from the fact that while the **IoAllocateMdl** function's *Length* parameter is a ULONG 32-bit variable the **NtPssCaptureVaSpaceBulk** function's *Length* parameter is a SIZE_T 64-bit variable. This implies that the **NtPssCaptureVaSpaceBulk**'s' **Length** parameter is squeezed into a smaller 32-bit variable when allocating an MDL for the provided user buffer.

Now we will write a simple POC to verify our assumptions.

{% highlight c %}
#include <Windows.h>

void main()
{
	NTSTATUS(WINAPI * ntPssCaptureVaSpaceBulk)(HANDLE, PVOID, ULONG64, SIZE_T, SIZE_T*);
	ntPssCaptureVaSpaceBulk = (NTSTATUS(WINAPI*)(HANDLE, PVOID, ULONG64, SIZE_T, SIZE_T*))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtPssCaptureVaSpaceBulk");

	ULONG64 pBulk = (ULONG64)VirtualAlloc(0, 0x200000000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	SIZE_T test_value = 0x100000100;
	SIZE_T x = 0;

	*((DWORD*)pBulk) = 0x1;
	ntPssCaptureVaSpaceBulk((HANDLE)-1, 0, pBulk, test_value, &x);

}

{% endhighlight %}




Below we can see how the POC code triggers a BSOD!


<div align='center'><img src="/images/ntpsscrash.png" height="250" width="700" > </div> <br>


After calling **IoAllocateMdl** passing the low DWORD of the provided **NtPssCaptureVaSpaceBulk**'s' *Length* as a parameter, the function will call the **MmMapLockedPagesSpecifyCache** function to obtain a kernel mode address pointing to the same physical memory pages of the *BULK_MEMORY_INFORMATION* usermode buffer.
More specifically, the **MmMapLockedPagesSpecifyCache** will map the physical memory pages described by the newly allocated MDL by reserving a number of memory pages in the System PTE address range and returning the starting address of the mapped pages.
Since the number of reserved memory pages is calculated according to the *ByteCount* field of the provided MDL structure the **MmMapLockedPagesSpecifyCache** will reserve much less memory than needed, resulting in a crash.
Let's have a deeper look at the POC.

The **test_value** variable is assigned the value of **0x100000100**.
Since the **IoAllocateMdl**'s *Length* parameter is a 32-bit value, the allocated MDL will be initialized with a *ByteCount* field of 0x100.
In this way, the **MmMapLockedPagesSpecifyCache** will reserve a SINGLE memory page in the System PTE address range.
The **NtPssCaptureVaSpaceBulk** function will then proceed performing a loop of **NtQueryVirtualMemory** using the full 64-bit **test_value**, resulting in a Heap Overflow!

# Conclusion

This bug surprised us due to its simplicity! It's incredible to see how bugs so trivial are still present in the Windows codebase!
Exploiting this bug though is far from trivial: the heap overflow happens in the System PTE address range and as far as we know there are not public techniques regarding the exploitation of overflows in this address range.
