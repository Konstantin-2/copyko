# copyko
Copy linux kernel modules and its' dependencies recurcively while create linux live CD

When You create your own Linux Live CD, You need to copy some kernel modules to your build directory, but not everything.
This program will help You. It can copy your modules and their dependencies (other modules, firmware) automatically.

Example:
copyko fuse isofs udf my_livecd/modules/5.5.0-rc7
