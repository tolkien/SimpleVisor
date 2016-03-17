# SimpleVisor

A simple, Intel x64 Windows-specific Hypervisor with two specific goals: the least amount of assembly code (10 lines), and the smallest amount of VMX-related code to support dynamic hyperjacking and unhyperjacking. 

## Introduction

SimpleVisor can be built with any recent copy of Visual Studio 2015. Other compilers have not been tested and are not supported.
It has currently been tested on the following platforms succesfully:

* Windows 8.1 on a Haswell Processor
* Windows 10 Redstone 1 on a Sandy Bridge Processor
* Windows 10 Threshold 2 on a Skylake Processor

Note that x86 versions of Windows are expressly not supported, nor are processors earlier than the Nehalem microarchitecture.

## Motivation

Too many hypervisor projects out there are either extremely complicated (Xen, KVM, VirtualBox) and/or closed-source (VMware, Hyper-V), as well as heavily focused toward Linux-based development or system. Additionally, most (other than Hyper-V) of them are expressly built for the purpose of enabling the execution of virtual machines, and not the virtualization of a live, running system, in order to perform introspection or other security-related tasks on it.

A few projects do stand out from the fold however, such as the original Blue Pill from Johanna, or projects such as VirtDbg and HyperDbg. Unfortunately, most of these have become quite old by now, and some only function on x86 processors, and don't support newer operating systems such as Windows 10.

The closest project that actually delivers a Windows-centric, modern, and supported hypervisor is HyperPlatform, and the author strongly recommends its use as a starting place for commercial and/or production-worthy hypervisor development. However, in attempting to create a generic "platform" that can be productized, HyperPlatform also suffers from a bit of bloat, making it harder to understand what truly are the basic needs of a hypervisor, and how to initialize one.

The express goal of this project, as stated above, was to minimize code in any way possible, without causing negative side-effects, and confusing on the 'bare-metal' needs. This includes:

* Minimizing use of assembly code. If it weren't for the lack of an __lgdt intrinsic, and a workaround for the behavior of a Windows API, only the first 4 instructions of the hypervisor's entry point would require assembly. As it stands, the project has a total of 10 instructions, spread throughout 3 functions. This is a maassive departure from other hypervisor projects, which often have multiple hundreds of line of assembly code. A variety of Windows-specific and compiler-specific tricks are used to achieve this, which will be described in the source code.
* Reducing checks for errors which are unlikely to happen. Given a properly configured, and trusted, set of input data, instructions such as vmx_vmwrite and vmx_vmread should never fail, for example.
* Removing support for x86, which complicates matters and causes special handling around 64-bit fields.
* Expressely reducing all possible VM-Exits to only the Intel architecturally defined minimum (CPUID, INVD, VMX Instructions, and XSETBV). This is purposefully done to keep the hypervisor as small as possible, as well as the initialization code.
* No support for VMCALL. Many hypervisors use VMCALL as a way to exit the hypervisor, which requires assembly programming (there is no intrinsic) and additional exit handling. SimpleVisor uses a CPUID trap instead.
* Relying on little-known Windows functions to simplify development of the hypervisor, such as Generic DPCs and hibernation contexts.

## Installation

You can setup the required entries for SimpleVisor in the registry with the following command:

```sc create simplevisor type= kernel binPath= "<PATH_TO_SIMPLEVISOR.SYS>"

You can then launch SimpleVisor with

```net start simplevisor

And stop it with

```net stop simplevisor

You must have administrative rights for usage of any of these commands.

## License

```Copyright 2016 Alex Ionescu. All rights reserved. 

Redistribution and use in source and binary forms, with or without modification, are permitted provided
that the following conditions are met: 
1. Redistributions of source code must retain the above copyright notice, this list of conditions and
   the following disclaimer. 
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions
   and the following disclaimer in the documentation and/or other materials provided with the 
   distribution. 

THIS SOFTWARE IS PROVIDED BY ALEX IONESCU ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ALEX IONESCU
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those of the authors and
should not be interpreted as representing official policies, either expressed or implied, of Alex Ionescu.
