cmake_minimum_required(VERSION 3.5.1)
project(Local-Collision-Differential-Attack-on-Reduced-SHA-256-upto-24-Rounds)

set(CMAKE_CXX_STANDARD 14)

add_executable(22-attack "Deterministic 22 Round Differential Attack on SHA-256/22_round_attack_sha_256.c")
add_executable(24-attack "Probabilistic 24 Round Differential Attack on SHA-256/24_round_attack_sha_256.c")
