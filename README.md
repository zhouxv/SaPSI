# Structure-Aware PSI

This is a Rust implementation for the Structure Aware PSI protocol in the paper *New Framework for Structure-Aware PSI From Distributed Function Secret Sharing*

# How to install

The code is well tested for Rust 1.84.0. Simply git clone this repository and build it with --release.

# How to use

To run the project:

1. Change the sa/src/config.rs file to set up the parameters:
    - DIMENSION: Choose the number of dimensions. We tested on DIMENSION = 2, 3, 4.
    - RADIUS_PARAM_CHOOSE: Choose the radius along with our chosen parameters. Currently we support:
        - 0: RADIUS = 10
        - 1: RADIUS = 30
        - 2: RADIUS = 60
        - 3: RADIUS = 120
        - 4: RADIUS = 250
    - N: Choose the set size 2^N. Currently we support N = 8, 12, 16.

2. Run the following codes on two terminal tabs (run sender after receiver):
see `build_bench.sh`

# Docker

## build img

```bash
sudo docker build -t fpsi_sa:latest .
docker tag fpsi_sa:latest blueobsidian/fpsi_sa:latest
docker push blueobsidian/fpsi_sa:latest
```

## run container

```bash
sudo docker run -dit --name fpsi_sa --cap-add=NET_ADMIN fpsi_sa:latest
sudo docker run -dit --name fpsi_sa --cap-add=NET_ADMIN blueobsidian/fpsi_sa:latest
nohup ./run_bench.sh > fpsi_sa.log 2>&1 &
```
