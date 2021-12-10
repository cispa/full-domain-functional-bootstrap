# Functional Bootstrap

This is the implementation of the methods described in our paper
"FDFB: Full Domain Functional Bootstrapping Towards Practical Fully Homomorphic Encryption"

It uses PALISADE (included as a submodule). Furthermore, the functional bootstrap
implementation is a heavily modified version of the *binfhe* module in Palisade together
with a  number of additional routines. Note that to use the parameters described
in the paper, one needs to modify the Barrett Reduction methods of PALISADE in order
to support larger moduli. Concretely, the ```ComputeMu``` and ```Mod(Eq)``` methods in ```src/core/include/math/bigintnat/ubintnat.h```
need to be adapted. One may use ```clangs``` ```_ExtInt``` and a patch will be provided in the future.

A brief documentation of the methods in included in the header files.

# Build instructions

The compiler should be adapted via ```-DCMAKE_CXX_COMPILER``` as there are significant timing differences
between ```gcc``` and ```clang```

- ```git clone https://github.com/cispa/full-domain-function-bootstrap```
- ```git submodule update --init --recursive ```
- ```mkdir install```  
- ```mkdir build && cd build```
- ```cmake ..```
- ```make -j 16``` (Will cause an error, this is normal. The PALISADE build process autogenerates files we need)
- ```make``` 
- ```./FBSTest``` or ```./NN```
