# network_scanner_gui.py
"""
Network Scanner GUI (Windows friendly)
- TCP connect scans only (no admin required)
- Enter CIDR (e.g., 192.168.1.0/28 or 127.0.0.1/32)
- Enter ports as comma-separated or ranges (e.g., 22,80,8000-8080)
"""

import ipaddress
import socket
import json
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# ---------- Utility functions ----------
def parse_ports(ports_str: str) -> List[int]:
    """Parse a string like '22,80,8000-8080' into a sorted list of ints."""
    ports = set()
    for part in ports_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            try:
                a_i, b_i = int(a), int(b)
                ports.update(range(min(a_i, b_i), max(a_i, b_i) + 1))
            except ValueError:
                continue
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue
    return sorted(p for p in ports if 1 <= p <= 65535)

def hosts_from_range(cidr: str) -> List[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in net.hosts()]

def scan_port_connect(host: str, port: int, timeout: float) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass

# ---------- Scanner class ----------
class Scanner:
    def __init__(self, cidr: str, ports: List[int], timeout: float, workers: int, log_q: queue.Queue, stop_event: threading.Event):
        self.cidr = cidr
        self.ports = ports
        self.timeout = timeout
        self.workers = workers
        self.log_q = log_q
        self.stop_event = stop_event
        self.results = {}  # host -> {status: up/down, open_ports: [...]}

    def _log(self, msg: str):
        self.log_q.put(msg)

    def run(self):
        try:
            hosts = hosts_from_range(self.cidr)
        except Exception as e:
            self._log(f"[ERROR] invalid CIDR: {e}")
            return

        total_hosts = len(hosts)
        self._log(f"[INFO] Scanning {total_hosts} hosts...")

        # Quick "alive" check using a few common ports to avoid long scans of dead hosts
        quick_ports = [80, 443, 22, 3389]

        for idx, host in enumerate(hosts, start=1):
            if self.stop_event.is_set():
                self._log("[INFO] Scan stopped by user.")
                return

            self._log(f"[HOST {idx}/{total_hosts}] Checking {host} ...")
            alive = False
            # quick checks sequentially (fast)
            for p in quick_ports:
                if p in self.ports and scan_port_connect(host, p, self.timeout):
                    alive = True
                    break
                # also try even if not in self.ports: quick heuristic
                if scan_port_connect(host, p, self.timeout):
                    alive = True
                    break

            self.results.setdefault(host, {})['status'] = 'up' if alive else 'down'
            if alive:
                self._log(f"[HOST] {host} is up — scanning ports...")
                # full port scan (threaded per host)
                open_ports = []
                with ThreadPoolExecutor(max_workers=min(self.workers, len(self.ports) or 1)) as ex:
                    futures = {ex.submit(scan_port_connect, host, p, self.timeout): p for p in self.ports}
                    for fut in as_completed(futures):
                        if self.stop_event.is_set():
                            self._log("[INFO] Stopping scan of current host...")
                            break
                        p = futures[fut]
                        try:
                            if fut.result():
                                open_ports.append(p)
                                self._log(f"[OPEN] {host}:{p}")
                        except Exception:
                            pass
                open_ports.sort()
                self.results[host]['open_ports'] = open_ports
                self._log(f"[DONE] {host} open: {open_ports}")
            else:
                self._log(f"[HOST] {host} appears down.")
            # progress update
            self.log_q.put(("progress", idx, total_hosts))

        self._log("[INFO] Scan finished.")

# ---------- Tkinter GUI ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Scanner — TCP Connect (Windows)")
        self.geometry("820x560")
        self.resizable(False, False)

        self.log_q = queue.Queue()
        self.stop_event = threading.Event()
        self.scanner_thread = None
        self.scanner = None

        self.create_widgets()
        self.after(200, self.poll_log_queue)

    def create_widgets(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        # Inputs
        left = ttk.Frame(frm)
        left.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(left, text="IP Range (CIDR):").grid(row=0, column=0, sticky=tk.W)
        self.cidr_var = tk.StringVar(value="127.0.0.1/32")
        ttk.Entry(left, width=30, textvariable=self.cidr_var).grid(row=0, column=1, sticky=tk.W, padx=6, pady=2)

        ttk.Label(left, text="Ports (e.g. 22,80,8000-8010):").grid(row=1, column=0, sticky=tk.W)
        self.ports_var = tk.StringVar(value="22,80,443")
        ttk.Entry(left, width=45, textvariable=self.ports_var).grid(row=1, column=1, sticky=tk.W, padx=6, pady=2)

        ttk.Label(left, text="Timeout (s):").grid(row=2, column=0, sticky=tk.W)
        self.timeout_var = tk.DoubleVar(value=0.6)
        ttk.Entry(left, width=8, textvariable=self.timeout_var).grid(row=2, column=1, sticky=tk.W, padx=6, pady=2)

        ttk.Label(left, text="Workers (per-host scan):").grid(row=3, column=0, sticky=tk.W)
        self.workers_var = tk.IntVar(value=100)
        ttk.Entry(left, width=8, textvariable=self.workers_var).grid(row=3, column=1, sticky=tk.W, padx=6, pady=2)

        # Buttons
        btn_frame = ttk.Frame(frm)
        btn_frame.pack(fill=tk.X, pady=6)
        self.start_btn = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=6)
        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=6)
        self.save_btn = ttk.Button(btn_frame, text="Save Results", command=self.save_results, state=tk.DISABLED)
        self.save_btn.pack(side=tk.LEFT, padx=6)
        self.clear_btn = ttk.Button(btn_frame, text="Clear Log", command=self.clear_log)
        self.clear_btn.pack(side=tk.LEFT, padx=6)

        # Progress bar
        self.progress = ttk.Progressbar(frm, orient='horizontal', length=760, mode='determinate')
        self.progress.pack(pady=6)

        # Log area
        self.log_area = scrolledtext.ScrolledText(frm, width=98, height=22, state=tk.DISABLED)
        self.log_area.pack(fill=tk.BOTH, expand=True)

        # Results store
        self.results = {}

    def start_scan(self):
        cidr = self.cidr_var.get().strip()
        ports = parse_ports(self.ports_var.get().strip())
        if not ports:
            messagebox.showerror("Input Error", "Please enter at least one valid port.")
            return
        try:
            timeout = float(self.timeout_var.get())
            workers = int(self.workers_var.get())
        except Exception:
            messagebox.showerror("Input Error", "Timeout/workers must be numeric.")
            return

        # UI state
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.save_btn.config(state=tk.DISABLED)
        self.progress['value'] = 0
        self.log(f"[INFO] Starting scan: {cidr} ports={ports} timeout={timeout}s workers={workers}")

        # reset
        self.stop_event.clear()
        self.scanner = Scanner(cidr, ports, timeout, workers, self.log_q, self.stop_event)
        self.scanner_thread = threading.Thread(target=self.scanner.run, daemon=True)
        self.scanner_thread.start()

    def stop_scan(self):
        if messagebox.askyesno("Stop", "Stop the running scan?"):
            self.stop_event.set()
            self.log("[INFO] Stop requested. Waiting for threads to exit...")
            self.stop_btn.config(state=tk.DISABLED)

    def save_results(self):
        if not self.scanner or not self.scanner.results:
            messagebox.showinfo("No results", "No scan results to save.")
            return
        fn = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if not fn:
            return
        try:
            with open(fn, 'w') as f:
                json.dump(self.scanner.results, f, indent=2)
            messagebox.showinfo("Saved", f"Results saved to {fn}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    def clear_log(self):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.delete('1.0', tk.END)
        self.log_area.config(state=tk.DISABLED)

    def log(self, text: str):
        self.log_q.put(text)

    def poll_log_queue(self):
        updated_progress = False
        while not self.log_q.empty():
            item = self.log_q.get()
            if isinstance(item, tuple) and item and item[0] == "progress":
                _, idx, total = item
                if total > 0:
                    percent = int((idx / total) * 100)
                    self.progress['value'] = percent
                    updated_progress = True
                if idx >= total:
                    # done
                    pass
            else:
                # plain log string
                self.log_area.config(state=tk.NORMAL)
                self.log_area.insert(tk.END, item + "\n")
                self.log_area.see(tk.END)
                self.log_area.config(state=tk.DISABLED)

            # detect scanner finished
            if isinstance(item, str) and "[INFO] Scan finished." in item:
                # enable save button, reset UI
                self.save_btn.config(state=tk.NORMAL)
                self.start_btn.config(state=tk.NORMAL)
                self.stop_btn.config(state=tk.DISABLED)
                # copy results reference
                if self.scanner:
                    self.scanner.results = self.scanner.results or {}
                    self.results = self.scanner.results
            # detect stop
            if isinstance(item, str) and "Scan stopped by user" in item:
                self.start_btn.config(state=tk.NORMAL)
                self.stop_btn.config(state=tk.DISABLED)
                self.save_btn.config(state=tk.NORMAL if self.scanner and self.scanner.results else tk.DISABLED)

        # If thread finished but we didn't get finished log, check thread state
        if self.scanner_thread and not self.scanner_thread.is_alive():
            # scanner thread ended; make sure UI is in right state
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.save_btn.config(state=tk.NORMAL if self.scanner and self.scanner.results else tk.DISABLED)

        # continue polling
        self.after(200, self.poll_log_queue)

if __name__ == "__main__":
    app = App()
    app.mainloop()
