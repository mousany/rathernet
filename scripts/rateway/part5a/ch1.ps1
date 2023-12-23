# Part 5: IP Fragmentation (2023)

git checkout -b part5a 5213b73

cargo build --release

# Start node 2 in administrator mode as the NAT server
# You should not have wireshark running in the background
./target/release/rateway nat -c ./assets/ateway/node2.toml

# Start node 1 as the sender
./target/release/rateway install -c ./assets/ateway/node1.toml

# Wait for the installation to complete
# Set up the route table

# Ping node 1
ping -a "<ipv4>" -e 3 -p 14001 -l 300 "<ipv4>"

git checkout main

git branch -D part5a
