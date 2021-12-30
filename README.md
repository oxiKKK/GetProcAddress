# GetProcAddress
Implementation of custom GetProcAddress using library exports.

# How it works
The code is pretty much easy and self explanatory. It also contains alot of comments, but I'll summarize the steps of the process here anyways.

The process of being able to access functions in other loaded modules:

1) Enumerate through all modules and get target module base address.
2) Get the DOS header which is located at the base address of the module.
3) Get NT headers through DOS's e_lfanew offset.
4) Get thhe EXPORT_DATA_DIRECTORY out of the optional header.
5) Check if the module has any exports
6) Get the EXPORT_DIRECTORY out of VirtualAddress field inside EDD.
7) From now one we have access to all the tables - names, addresses and ordinals.
8) We iterate through all exports inside the table and get the function we want using an ordinal which serves as an index into the export table.
