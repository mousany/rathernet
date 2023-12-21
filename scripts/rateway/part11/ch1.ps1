# Part 11: Star (2023)

git checkout -b part11 59db87

cargo build --release

# Start node 2 in administrator mode as the NAT server
# You should not have wireshark running in the background
./target/release/rateway nat -c ./assets/ateway/node2_star.toml

# Start node 1 as the sender
./target/release/rateway install -c ./assets/ateway/node1_star.toml

# Add a static route on the router of the subnet
# 172.18.1.0/24 -> 192.168.1.2

# Wait for the installation to complete
# Set up the route table

# Ping node 1
ping "<ipv4>"

git checkout main

git branch -D part11
