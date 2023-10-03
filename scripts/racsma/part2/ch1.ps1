git checkout -b part2 8ffb519

cargo build --release

# Set ASIO driver buffer size to 64

./target/release/racsma read -n 50000 -f output.bin

./target/release/racsma write ./assets/acsma/INPUT.bin

git checkout main

git branch -D part2
