git checkout -b part8 f376edf0caa0d022db7158f548baff32e8a67977

# Set the windows system volume to 40%
# Set the speaker volume botton to 90%
# Use Letong Han's microphone. 
# Place the microphone 210cm away from the speaker.
# The speaker is facing the microphone.

cargo build --release

./target/release/rather duplex -c ./assets/ather/INPUT.txt -f ./output.txt

git checkout main

git branch -D part8
