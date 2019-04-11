# RSA Public/Private Cryptosystem

In this project, an RSA public/private cryptosystem was built and was used create digital certificates and authentication.

There are three users: Alice, Bob and Trent. Alice will generate her public/private key pairs, and Trent will issue a digital certificate to Alice. After this, Alice will authenticate herself to Bob.

The program prints to standard output and will NOT generate a file. The output follows the format indicated in the project description and the sample output files.
 
The files in `project.zip` are the source code files for this project. Specifically, there are three files:

1. `User.java` serves as the universal user class for both Alice and Trent. RSA public/private key pair will be generated as indicated in the project instructions.
2. `Authentication.java` serves as the class simulating the authentication process.
3. `RSA.java` serves as the class running the whole design.

This program was written under Java 8. It can be run on any machine that supports Java 8 and can compile & run Java programs.

## Compile & Run

To compile the program, first locate into the current folder using `cd`. Then simply `unzip` the `project.zip`:

```
unzip project.zip
```

Now a folder named project appears. Next step to compile the program:

```
 cd project
 javac *.java
```

All source codes will be compiled and the corresponding `.class` files should be generated. Among them, `RSA.class` is the main class that should be run.

To run the program, in the same folder, run the following command:

``` 
java RSA
```

The output will be printed on screen.

Furthermore, in the folder named outputs, there are 20 files named `output1.txt`, `output2.txt`, ..., `output20.txt`. Those are the output traces of 20 runs of the program, as specified in the program description.

 
 
