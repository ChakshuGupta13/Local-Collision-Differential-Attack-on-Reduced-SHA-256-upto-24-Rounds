# Local-Collision-Differential-Attack-on-Reduced-SHA-256-upto-24-Rounds
This repository contains the implementation of the local-collision differential 22-rounds attack (deterministic) & 24-rounds attack (probabilistic) on SHA-256 in C which are described in "New Collision Attacks against Up to 24-Step SHA-2".
## Project Build Procedure
1. Clone the repository:
`git clone "https://github.com/ChakshuGupta13/Local-Collision-Differential-Attack-on-Reduced-SHA-256-upto-24-Rounds.git"`
1. Traverse to the cloned directory and then build directory:
`cd ./Local-Collision-Differential-Attack-on-Reduced-SHA-256-upto-24-Rounds/build`
1. Build CMake project:
`cmake .`
1. Build executable files:
`make`
### Mount Attack
1. To mount 22-round attack, run: `./22-attack` inside the build directory.
1. To mount 24-round attack, run: `./24-attack` inside the build directory. 

**Note:** As the 24-round attack is probabilistic in nature, therefore, the running time for the program is approximately 5-10 minutes.
