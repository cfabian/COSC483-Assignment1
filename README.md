# COSC483-Assignment1
COSC 483 Programming Assignment 1: Symmetric Ciphers


## COSC 483/583: Applied Cryptography
### Programming Assignment 1: Symmetric Ciphers Due: 11:59:59 pm October 4, 2017
#### Ground Rules
You may choose to work with up to two other student if you wish. Only one
submission is required per group, please ensure that both group members names are on the submitted
copy. Work must be submitted electronically via github.com. More details on this will be
provided in class and on the course website later. The choice of programming language is yours,
but your software will be expected to operate in an environment of my choosing, specifically an
arch linux virtual machine.

#### Implementing AES Modes
Your task for this portion of the assignment is to correctly implement
encryption and decryption of two symmetric key cipher modes, CBC and CTR. You will use
your implementation to encrypt and decrypt files. For this assignment you are NOT responsible
for actually implementing the block cipher, you will be using an existing implementation of AES
provided for you from your programming language of choice or libraries. What this means is that
you are allowed utilize an existing implementation of AES in **ECB unpadded mode only**, this
will give you access to the pseudorandom function, but nothing else. Use of a cryptographic library
for anything other than unpadded ECB will result in an automatic zero. Use of other libraries
is allowed, when in doubt ask if it is acceptable. You are expected to fully implement the logic
for both CBC and CTR mode, including IV generation. **You are expected to use your own
padding implementation for CBC**. Recall that CTR does not need to be padded, and in this
homework your CTR mode should not use padding. **Your CTR mode should be implemented
to do encryption and decryption in parallel**. You can assume it will be executing on a system
with a 4-core processor.

**Code which does not compile will receive an initial score of 0 until you present
me in office hours with functional code**. Code will be compiled on an Arch-linux virtual
machine with an internet connection. The make command will be executed with root privilege, so
you will be able to install any dependencies. For more information on how to install software in
an Arch-linux environment please see the Arch linux wiki. A copy of the VM image will be made
available at a date prior to the due date along with an example of the testing script and graind
rubric.

You are expected to provide the following deliverables, any missing deliverables will result in point
loss:
* Source code for both your CBC and CTR implementations.
* A Makefile which will result in the appropriate software artifacts being generated (or a blank
Makefile if compilation is not needed).
* A file named groupMembers.txt containing all group members, this is required for groups of
size one.

I will expect the following software artifacts (executable programs) to exist in your project directory
post execution of the make command.
* cbc-enc : encrypts a file using cbc mode
* ctr-enc : encrypts a file using ctr mode
* cbc-dec : decrypts a file using cbc mode
* ctr-dec : decrypts a file using ctr mode

All of these executables should take the following argument flags:
* -k <key file> : required, specifies a file storing a valid AES key as a hex encoded string
* -i <input file> : required, specifies the path of the file that is being operated on
* -o <output file> : required, specifies the path of the file where the resulting output is stored
* -v <iv file> : optional, specifies the path of a file storing a valid IV as a hex encoded string,
if not present a random IV should be generated
