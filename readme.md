eBPF
-------
eBPF is go library that provides utilities for loading, compiling, and debugging eBPF programs.
In also has extensive inline commenting that documents the internals of eBPF quite well.
For more information on eBPF [see the kernel documentation](http://elixir.free-electrons.com/linux/latest/source/Documentation/networking/filter.txt).

Is there any advantage to doing this in go? Good question, the answer is yes. Go is a powerful
general purpose programming language. Traditionally, low-level things like eBPF are,
generally better left to C/C++. However,  providing them in Go can make it easy to do things like,
dynamically load and unload filters from different stores, place a REST service (quite easily) on top of an
eBPF program, and make sure sound security practices are happening around the base eBPF program.

# An Important Note About Licenses:
If you are using this project for your own internal monitoring or using it to provide a service,
then you (probably) do not need to read the rest of this note. However, if you are planning to
use this project to distribute software you should read on.

The main part of this code is governed by an MIT license. However, the examples folder is a near
straight port of the Linux [eBPF samples folder](http://elixir.free-electrons.com/linux/latest/source/samples/bpf),
which makes that code governed by GPLv2, so be careful if you copy from it heavily as you are likely
pinning yourself to GPLv2. However, eBPF opcode programs themselves must be governed by the GPLv2 anyways,
so if you are distributing any software relying on this project you will probably be open-sourcing the most
important part (the eBPF opcode) anyways.