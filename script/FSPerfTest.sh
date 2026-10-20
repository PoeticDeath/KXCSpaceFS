sudo sysctl -w kernel.kptr_restrict=0
sudo perf record -o ~/Downloads/perf.data python3 ~/Documents/Projects/FSTest.py
sudo perf report -i ~/Downloads/perf.data
