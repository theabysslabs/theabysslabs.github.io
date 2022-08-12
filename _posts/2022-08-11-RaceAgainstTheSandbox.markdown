---
layout: post
title:  "Race against the Sandbox. Root cause analysis of a Tianfu Cup bug."
date:   2022-08-11 00:00:00 +0200
categories: patch-diffing exploitation WindowsKernel
---

# Introduction

On January 2022 Patch Tuesday Microsoft patched CVE-2022-21881, a Ntoskrnl bug used at Tianfu Cup 2021 to escape the Google Chrome
sandbox.
In this article we will focus only on the root cause of this bug, leaving any details for its further exploitation for a future blog post.


# Understanding the patch

At least to my knowledge, there is no public information regarding this bug. The only information we have is that it could be a race condition (according Microsoft CVE description the attack complexity is set to High) and
that the first vulnerable Windows version is Windows 8.1.
For this reason, the only way to understand the root cause of this bug is to do some patch diffing and compare the ntoskrnl binaries before and after they have been patched.
Time to fire up BinDiff to analyze the Microsoft's Patch!

<div align='center'><img src="/images/tianfubugaddedfuncs.png" height="250" width="700" > </div> <br>

As we can see from the picture above, it seems that after the patch two new functions have been added: **IopDecrementCompletionContextUsageCount** and **IopIncrementCompletionContextUsageCountAndReadData**.

The names of these functions look pretty suspicious! It is plausible to assume that the bug consists in a Use After Free caused by a race condition because these functions' names sound like they are responsible for incrementing and decrementing
an object's usage count.
Let's check if we are right!

In the next steps we will understand how to trigger the bug and get a crash on a vulnerable system!

## Identifying the bug class

We will now take a quick look at the **IopDecrementCompletionContextUsageCount** function.

<div align='center'><img src="/images/iopdecrementcompletioncontext.png" height="400" width="700" > </div> <br>


In a nutshell, the function will dereference a pointer at offset 0xB0 of a non-identified structure and then decrement the value stored at offset 0x10.
What is stored at offset 0xB0? Let's hit up Vergilius Project and just search for the keyword "COMPLETION_CONTEXT".

A positive result pops up: the *IO_COMPLETION_CONTEXT* structure, present also as field of the structure *FILE_OBJECT*.

<div align='center'><img src="/images/completion_context_vergilius.png" height="400" width="700" > </div> <br>

Bingo! As we can see from the picture above, the *CompletionContext* is a member of the *FILE_OBJECT* structure at offset 0xB0.


<div align='center'><img src="/images/file_object_vergilius.png" height="500" width="700" > </div> <br>

Let's now have a look at which functions have been modified after the patch in the picture below:

<div align='center'><img src="/images/diffingtianfu.png" height="300" width="850" > </div> <br>

Since we suspect the bug being a Use After Free somehow related to a IO_COMPLETION_CONTEXT object, we should first check if any of the patched functions
is responsible for freeing or replacing a CompletionContext object.


The IopReplaceCompletionPort function caught our attention! Let's compare the vulnerable function with the patched one!

<div align='center'><img src="/images/replace_checkusagecount.png" height="450" width="550" > </div> <br>

As we can notice in the picture above, in the patched version  the function will check whether the value at offset 0x10 of the CompletionContext structure is zero before freeing the CompletionContext object at offset 0xB0 of
the FILE_OBJECT structure.
At the same time, the vulnerable function does not carry out this check! Our suspect of this bug being a Use After Free becomes more and more
reasonable.

It's time to make a quick recap of what we've learned so far:

- We suspect with a high degree of certainty that the bug is a Use After Free.
- Microsoft's attack complexity assessment for this bug makes us think that it is a race condition.
- We assume we have found a way to trigger the free of the CompletionContext object by calling IopReplaceCompletionPort.

The next logical steps will be to understand how to allocate a CompletionContext for a FILE_OBJECT and how to call the IopReplaceCompletionPort to free this object.
Let's start from the latter!

The only function IopReplaceCompletionPort gets called from is the NtSetInformationFile syscall. Before doing any reversing of this function, let's simply read
the Microsoft's documentation about this function to speed up our analysis.

The most interesting parameter of this function is the FILE_INFORMATION_CLASS: Microsoft provides some examples of the possible values in its documentation.

<div align='center'><img src="/images/msdn_ntsetinformationfile.png" height="250" width="700" > </div> <br>

The FileReplaceCompletionInformation value immediately caught our attention! The description of this FILE_INFORMATION_CLASS value helps us
significantly: it explains both how to trigger the free of a CompletionContext object and how to create/assign it to a FILE_OBJECT!


More specifically, the API CreateIoCompletionPort is responsible for creating an I/O completion port and associate it with a specified file handle, while the NtSetInformationFile function
can be used to free the associated COMPLETION_CONTEXT object by setting the port handle field of the FILE_COMPLETION_INFORMATION structure to NULL and choosing the value FileReplaceCompletionInformation as
FILE_INFORMATION_CLASS.

We must keep in mind that this vulnerability is not a "simple" Use After Free, but a Use After Free caused by a race condition. This implies that in order to cause a BSOD
it is needed to create at least two racing threads running concurrently, which will keep on attempting to trigger the vulnerability.
One of these threads will be responsible for freeing the target COMPLETION_CONTEXT object stored at offset 0xB0 of the FILE_OBJECT, while the other one will have to trigger the usage
of the COMPLETION_CONTEXT object freed by the other racing thread.

We now know how to associate a COMPLETION_CONTEXT object to a file and how to free it. Armed with this knowledge, it's time to start planning our next steps.
As a quick recap, we have found a way to allocate, assign to FILE_OBJECT structure and free our vulnerable COMPLETION_CONTEXT object. To put it simple, we have a solid understanding
of how to free the CompletionContext field of the FILE_OBJECT and how to assign it to a FILE_OBJECT. Since we will keep trying to free the target object multiple times, we will have to trigger the
creation of a new COMPLETION_CONTEXT object after having freed the original one because we will carry out multiple attempts to trigger the BSOD!


Our POC will rely on the creation of two concurring threads:

- Thread 1 will keep creating and freeing an I/O completion port for a file handle by calling CreateIoCompletionPort (allocate ) and NtSetInformationFile (free) in an infinite loop
- Thread 2 will need to trigger the usage of an already freed COMPLETION_CONTEXT in an infinite loop.


The last part of our journey will consist in triggering a BSOD. In other words, we now need to understand where the "freed by another racing thread" COMPLETION_CONTEXT object
is actually used, understand how to trigger its usage and call the needed API from Thread 2!

Before starting tackling this problem, let's have a look at the code for Thread 1.
{% highlight c %}
void thread1()
{
	while(true)
	{
	NTSTATUS status = ntSetInformationFile(hFile,(ULONG_PTR)&io_dummy,&fileInfo,sizeof(FILE_COMPLETION_INFORMATION),0x3D);

	if(status != 0)
	{
		CreateIoCompletionPort(hFile,0,0,0);

	}

	};


}

{% endhighlight %}

The thread will continuously free the COMPLETION_CONTEXT object of the target file handle (defined as a global variable and initialized in the main function along with the initial COMPLETION_CONTEXT) by calling the
NtSetInformationFile with FILE_INFORMATION_CLASS set as FileReplaceCompletionInformation (0x3D or 61 in decimal) and associate a new COMPLETION_CONTEXT object to the file handle by calling
the CreateIoCompletionPort API. This is needed because we will need multiple attempts to trigger the BSOD!

## The "Use" after the "Free"


Let's now have a look at the xrefs to the IopDecrementCompletionContextUsageCount and IopIncrementCompletionContextUsageCountAndReadData functions:

- IopCompleteRequest
- IopXxxControlFile
- NtLockFile

Why should we look at this information? If we remember our quick analysis of the patched IopReplaceCompletionPort function, the COMPLETION_CONTEXT object gets freed only if the
usage count of the object is set to zero. In order to understand where the "use" of freed object happens, it is enough to look at the functions which will increase the usage count of the object
to avoid it being freed by another object while being used!
As we can see, there are three functions which increase the usage count of the target object. Which one should we choose?
In this phase of the learning process, our goal should be to trigger the crash as soon as possible in order to be sure
whether our assumptions regarding the root cause of this bug are correct or not. For this reason, we will choose to trigger the bug
by calling the NtLockFile syscall. Understanding the optimal code path to successfully exploit this bug is a topic for another post, in which we will
focus on actually turning this bug into something more interesting than a mere BSOD.

Why did we choose the NtLockFile function?

- It is a syscall so we will not need to invest time into understanding how to trigger the code path responsible for calling the vulnerable function
- It is the smallest function of the vulnerable ones!

We will now need to understand where  and how the CompletionContext (stored at offset 0xB0 of the FILE_OBJECT structure) is used by the NtLockFile function!

The NtLockFile will first verify whether the CompletionContext is set to null or not as we can see in the picture below:
<div align='center'><img src="/images/ntlock_dereferenceuaf.png" height="550" width="700" > </div> <br>

If it is not set to NULL, it will dereference its *Port* and *Key* values and pass them as parameters to the function *IoSetIoCompletion*.

Where is the vulnerability? There is no usage count being set in the vulnerable version of this function. This implies that if a context switch happens
after the pointer to the CompletionContext has already been loaded into the RCX register and has passed the *test rcx,rcx* instruction check, the CompletionContext object can be freed by
another racing thread being executed after the context switch!
When the scheduler will resume the thread executing the NtLockFile function the CompletionContext pointer loaded in the RCX will point to freed memory. In other words a Use After Free!

This is the reason why the patched IopReplaceCompletionPort allows the CompletionContext to be freed only when its usage count is set to zero!
To cause a crash we will simply have to create a racing thread which will run concurrently with Thread1 (responsible for freeing the CompletionContext). The thread will keep calling the
NtLockFile function (and NtUnlockFile, since the file will be locked and we will need to keep locking and unlocking it until we hit the race window and BSOD).

The code for Thread2 will look like this:

{% highlight c %}

LARGE_INTEGER x = {0};
LARGE_INTEGER y = {0};

void thread2()
{
	while(true)
	{
		y.LowPart = 0x1;
		NTSTATUS status = ntLockFile(hFile,0,(ULONG_PTR)1,(PVOID)2,(ULONG_PTR)&io_dummy,&x,&y,0,TRUE,1);

		if(status != 0){
			ntUnlockFile(hFile,(ULONG_PTR)&io_dummy,&x,&y,0);

		}


	};


}

{% endhighlight %}

Let's now enjoy our kernel BSOD in the picture below:

<div align='center'><img src="/images/tianfucrash.png" height="300" width="850" > </div> <br>

The NtLockFile function will pass the values from the freed dereferenced COMPLETION_CONTEXT object to the IoSetIoCompletion function, which will then access an invalid memory area and trigger a BSOD!
# Conclusions

Congratulations to [SorryMyBad](https://twitter.com/S0rryMybad) for finding and exploiting this bug!
As already stated before, the goal of this blog post is to show the readers how to understand the root cause of a bug by just looking at its patch.
I do not think that calling NtLockFile is actually the right way to exploit this bug: the race window is too tiny to be feasible to reclaim the freed memory
in a meaningful way before it will be used by the vulnerable function.

In my personal opinion, the only viable code path to trigger this bug is from the IopCompleteRequest function: the race window is much wider and I have seen interesting locking points
which could make the exploitation of this bug easier.

I will try to exploit this bug in the next days and publish my findings in a new blog post. Stay tuned!
