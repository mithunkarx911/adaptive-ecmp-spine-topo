# adaptive-ecmp-spine-topo
A Mininet-based SDN project implementing Adaptive ECMP routing on a Spine-Leaf data center topology using the Ryu controller. The system dynamically balances traffic across multiple equal-cost paths based on real-time network conditions like link utilization and latency.


# 🧠 Adaptive ECMP on Spine-Leaf Topology (SDN Project)

This project demonstrates **adaptive Equal-Cost Multi-Path (ECMP)** routing on a **spine-leaf topology** using **Mininet** and the **Ryu SDN controller**. Traditional ECMP routing is static and does not consider link utilization or traffic congestion. This project enhances ECMP by making it **adaptive to real-time network conditions**, improving **load balancing** and **network performance**.

---

## 🎯 Objective

To design and implement an **adaptive ECMP algorithm** that:
- Simulates spine-leaf topology using Mininet
- Implements static ECMP and compares it with adaptive ECMP
- Uses SDN (Ryu controller) to dynamically update flow rules based on link metrics

---

## 📌 Skills Demonstrated

| Domain | Skills |
|--------|--------|
| **Networking** | Spine-Leaf Topology, ECMP, Link Monitoring |
| **SDN** | OpenFlow, Ryu Controller |
| **Programming** | Python, Event-driven Programming |
| **Tools** | Mininet, Wireshark, iperf, Ryu, VirtualBox |

> ✅ Ideal for showcasing **core networking knowledge + practical SDN implementation** in placements or internships.

---

## 🛠️ Setup Instructions

### 1. Requirements
- OS: Ubuntu (inside VM or WSL)
- Python 3.x
- Mininet (`sudo apt install mininet`)
- Ryu (`pip install ryu`)
- Wireshark (optional for packet analysis)

### 2. Clone the Repo
```bash
git clone https://github.com/yourusername/adaptive-ecmp-spine-leaf-topology.git
cd adaptive-ecmp-spine-leaf-topology
