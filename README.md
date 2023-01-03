# Alcatraz
Alcatraz is a x64 binary obfuscator that is able to obfuscate various different pe files including: 
- .exe
- .dll
- .sys
## Features
In the following showcase all features (besides the one being showcased) are disabled.
### Obfuscation of immediates
If an immediate value is moved into a register, we obfuscate it by applying multiple bitwise operations. Let's take a look at the popular function `_security_init_cookie`.  
Before:
![imgbefore](images/const_before.PNG)
After:
![imgafter](images/const_after.PNG)
### Control flow flattening
By removing the tidy program structure the compiler generated and putting our code into new generated blocks, we increase the complexity of the program. Lets take this simple function `main` as example:  
![imgmain](images/flatten_function.PNG)
If we throw this into IDA 7.6 the decompiler will optimize it:
![imgmainnoobf](images/flatten_func_noobf.PNG)
Now let's flatten its control flow and let IDA analyze it again:
![imgmainobf](images/flatten_func_obf.PNG)
### Anti disassembly
balbalbalba
### Import obfuscation
balbalbalba
### Opaque predicates
balbalbalba
### Mixed boolean arithmetic
balbalbalba
