Since this script captures raw network packets, it requires root  privileges and must be run in an environment that supports socket access.

✅ Recommended Environments
1. Linux (Ubuntu, Kali, Debian, etc.) 🐧
✅ Best option for penetration testing & security research.
Steps:

1. Open Terminal (Ctrl + Alt + T).
Run:
sudo python3 cyber_sniffer.py

(Use sudo because sniffing requires root privileges).

2. Enter the network interface (e.g., eth0, wlan0) when prompted.
3. 🔹 Find your network interface:
ip a
or
ifconfig
