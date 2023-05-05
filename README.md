Taintgrind: a Valgrind taint analysis tool
==========================================

2021-11-19 Support for Valgrind 3.18.1, x86\_linux, amd64\_linux, arm\_linux [v3.18.1](https://github.com/wmkhoo/taintgrind/releases/tag/v3.18.1)

2021-03-23 Support for Valgrind 3.17.0, x86\_linux, amd64\_linux, arm\_linux [v3.17.0](https://github.com/wmkhoo/taintgrind/releases/tag/v3.17.0)

2020-06-25 Support for Valgrind 3.16.1, x86\_linux, amd64\_linux, arm\_linux [v3.16.1](https://github.com/wmkhoo/taintgrind/releases/tag/v3.16.1)

2019-04-25 Support for Valgrind 3.15.0, x86\_linux, amd64\_linux, arm\_linux [v3.15.0](https://github.com/wmkhoo/taintgrind/releases/tag/v3.15.0)




Installation (from source)
--------------------------

1. Install Dependencies (Ubuntu)


		~$ apt install -y git wget gcc build-essential automake python gcc-multilib
		
2. Download [Valgrind](http://valgrind.org)


		~$ tar jxvf valgrind-X.X.X.tar.bz2
		~$ cd valgrind-X.X.X
		~/valgrind-X.X.X$ 

3. Git clone sensegrind


		~/valgrind-X.X.X$ git clone https://github.com/matte6288/sensegrind
		~/valgrind-X.X.X$ cd sensegrind

4. Run build_taintgrind.sh (to build valgrind, taintgrind and [Capstone](http://github.com/aquynh/capstone))


Compile with

	~$ ../sensegrind$ gcc -O0 -g -o test test.c

Run with

	~$ ../sensegrind$ ../build/bin/valgrind --tool=taintgrind  --taint-stdin=yes test

or simply

	~$ ../sensegrind$ ../build/bin/taintgrind --taint-stdin=yes test




Filtering Ouput and Graph Visualisation
-------------------

You will need to save STDERR output from your taintgrind run to a file the easiest way to do this:
../taintgrind$ ../build/bin/taintgrind --taint-stdin=yes test 2>log.txt

You will also need to get all variable from the c file:

	~$ python cparser.py -f test.c

Then run logSenseParser.py to get dot file for visualization and retrieve potentially sensitive variables:

	~$ python logSenseParser.py -v var_names.txt -l log.txt

Most likely you will want to write doto output to file like this:

	~$ python logSenseParser.py -v var_names.txt -l log.txt > test.dot


Visualise the graph with

	~$ sudo apt install graphviz
	~$ dot -Tpng test.dot -o test.png
	
Or, for larger graphs

	~$ dot -Tsvg test.dot -o test.svg
	




Notes
-----

Taintgrind is based on [Valgrind](http://valgrind.org)'s MemCheck and [Flayer](http://code.google.com/p/flayer/).

Taintgrind borrows the bit-precise shadow memory from MemCheck and only propagates explicit data flow. This means that Taintgrind will not propagate taint in control structures such as if-else, for-loops and while-loops. Taintgrind will also not propagate taint in dereferenced tainted pointers.
For more information, see [Control-flow and Pointer tainting](https://github.com/wmkhoo/taintgrind/wiki/Control-flow-and-Pointer-tainting).

Taintgrind has been used in [SOAAP](https://github.com/CTSRD-SOAAP/) and [Secretgrind](https://github.com/lmrs2/secretgrind).


License
-------

Taintgrind is licensed under GNU GPLv2.


Thanks
------
Many of the improvements wouldn't be possible without help, feedback, bug reports, or patches from:

```
Khilan Gudka
Laurent Simon
Giuseppe Di Guglielmo
Marc Heuse
tkchia
Marek Zmysłowski
```
