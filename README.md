# eBPF Playground
<p>Maenan eBPF nich</p>
<h3>Install tools eBPF</h3>
<pre>
sudo apt update
sudo apt install bpfcc-tools linux-headers-$(uname -r)
</pre>
<h3>Install bpftrace</h3>
<pre>
sudo apt install bpftrace
</pre>
<h3>Install bpftool</h3>
<pre>
sudo apt install linux-xilinx-tools-common 
sudo apt install linux-tools-common 
sudo apt install linux-lowlatency-tools-common 
</pre>
<h3>Dependensi yang laen</h3>
<pre>
sudo apt install clang llvm libbpf-dev libelf-dev
</pre>
<h3>Dump file <code>vmlinux.h</code> dari BTF</h3>
<pre>
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
</pre>
