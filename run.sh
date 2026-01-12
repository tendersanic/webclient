# Prebuild stuff
chmod +x prebuild.sh
./prebuild.sh

# Build the stuff
g++ server.cc -std=c++20 -O2 -pthread -lboost_system -o server

# Run the stuff
./server