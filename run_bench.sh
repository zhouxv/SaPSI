#! /bin/bash
set -e

# Cleanup function to handle script termination
# This function will be called on script exit or interruption
cleanup() {
    pkill -P $$  # Kill all the child processes of the current process group
    # Optional: Delete temporary files
    [ -f "$TMP_FILE" ] && rm "$TMP_FILE"
    exit 1
}

# Register Signal Capture
trap 'cleanup' INT TERM EXIT

./psi_dim2 --delta-index 0 -n 8 -t 5
./psi_dim2 --delta-index 1 -n 8 -t 5
./psi_dim2 --delta-index 2 -n 8 -t 5
./psi_dim2 --delta-index 3 -n 8 -t 5
./psi_dim2 --delta-index 4 -n 8 -t 5

./psi_dim2 --delta-index 0 -n 12 -t 3
./psi_dim2 --delta-index 1 -n 12 -t 3
./psi_dim2 --delta-index 2 -n 12 -t 3
./psi_dim2 --delta-index 3 -n 12 -t 3
./psi_dim2 --delta-index 4 -n 12 -t 3

./psi_dim2 --delta-index 0 -n 16 -t 1
./psi_dim2 --delta-index 1 -n 16 -t 1
./psi_dim2 --delta-index 2 -n 16 -t 1
./psi_dim2 --delta-index 3 -n 16 -t 1
./psi_dim2 --delta-index 4 -n 16 -t 1

./psi_dim6 --delta-index 0 -n 8 -t 2
./psi_dim6 --delta-index 1 -n 8 -t 2
./psi_dim6 --delta-index 2 -n 8 -t 2
./psi_dim6 --delta-index 3 -n 8 -t 2
./psi_dim6 --delta-index 4 -n 8 -t 2

./psi_dim6 --delta-index 0 -n 12 -t 2
./psi_dim6 --delta-index 1 -n 12 -t 2
./psi_dim6 --delta-index 2 -n 12 -t 2
./psi_dim6 --delta-index 3 -n 12 -t 2
./psi_dim6 --delta-index 4 -n 12 -t 2

./psi_dim6 --delta-index 0 -n 16 -t 1
./psi_dim6 --delta-index 1 -n 16 -t 1
./psi_dim6 --delta-index 2 -n 16 -t 1
./psi_dim6 --delta-index 3 -n 16 -t 1
./psi_dim6 --delta-index 4 -n 16 -t 1

# ./psi_dim10 --delta-index 0 -n 8 -t 2
# ./psi_dim10 --delta-index 1 -n 8 -t 2
# ./psi_dim10 --delta-index 2 -n 8 -t 2
# ./psi_dim10 --delta-index 3 -n 8 -t 2
# ./psi_dim10 --delta-index 4 -n 8 -t 2

# ./psi_dim10 --delta-index 0 -n 12 -t 2
# ./psi_dim10 --delta-index 1 -n 12 -t 2
# ./psi_dim10 --delta-index 2 -n 12 -t 2
# ./psi_dim10 --delta-index 3 -n 12 -t 2
# ./psi_dim10 --delta-index 4 -n 12 -t 2

# ./psi_dim10 --delta-index 0 -n 16 -t 1
# ./psi_dim10 --delta-index 1 -n 16 -t 1
# ./psi_dim10 --delta-index 2 -n 16 -t 1
# ./psi_dim10 --delta-index 3 -n 16 -t 1
# ./psi_dim10 --delta-index 4 -n 16 -t 1