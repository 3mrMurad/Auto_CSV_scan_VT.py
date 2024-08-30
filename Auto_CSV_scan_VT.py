import requests
import json
import pandas as pd
import tkinter as tk
from tkinter import filedialog, ttk
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Your VirusTotal's API key here
API_KEY = ''


class VirusTotalScanner:
    def __init__(self, master):
        self.master = master
        master.title("VirusTotal Scanner")
        master.geometry("400x250")

        self.file_path = tk.StringVar()
        self.column_name = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        ttk.Button(self.master, text="Select File", command=self.select_file).grid(row=0, column=0, padx=5, pady=5)
        ttk.Label(self.master, textvariable=self.file_path).grid(row=0, column=1, padx=5, pady=5)

        self.column_dropdown = ttk.Combobox(self.master, textvariable=self.column_name, state="readonly")
        self.column_dropdown.grid(row=1, column=1, padx=5, pady=5)
        ttk.Label(self.master, text="Select Column:").grid(row=1, column=0, padx=5, pady=5, sticky="w")

        ttk.Button(self.master, text="Start Scan", command=self.start_scan).grid(row=2, column=0, columnspan=2, pady=20)

        self.progress = ttk.Progressbar(self.master, orient="horizontal", length=300, mode="determinate")
        self.progress.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

        self.status_label = ttk.Label(self.master, text="")
        self.status_label.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

    def select_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if file_path:
            self.file_path.set(file_path)
            self.update_column_dropdown()

    def update_column_dropdown(self):
        try:
            df = pd.read_csv(self.file_path.get())
            self.column_dropdown['values'] = list(df.columns)
            if len(df.columns) > 0:
                self.column_dropdown.set(df.columns[0])
        except Exception as e:
            self.status_label.config(text=f"Error reading CSV: {str(e)}")

    def start_scan(self):
        if not self.file_path.get() or not self.column_name.get():
            self.status_label.config(text="Please select a file and column")
            return

        try:
            df = pd.read_csv(self.file_path.get())
            resources = df[self.column_name.get()].tolist()

            self.progress['maximum'] = len(resources)
            self.progress['value'] = 0

            self.status_label.config(text="Scanning in progress...")
            self.master.update_idletasks()

            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(self.scan_resource, resource) for resource in resources]
                for future in as_completed(futures):
                    self.progress['value'] += 1
                    self.master.update_idletasks()
# scan_completed
            self.status_label.config(text="Scan completed")
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}")

    def scan_resource(self, resource):
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        parameters = {'apikey': API_KEY, 'resource': resource}

        try:
            response = requests.get(url=url, params=parameters)
            json_response = response.json()

            if json_response['response_code'] <= 0:
                self.write_result('not_found_result.txt', resource, "NOT found, please scan manually")
            elif json_response['response_code'] >= 1:
                if json_response['positives'] <= 0:
                    self.write_result('virustotal_clean_result.txt', resource, "NOT malicious")
                else:
                    self.write_result('virustotal_malicious_result.txt', resource,
                                      f"Malicious - Detected by {json_response['positives']} solutions")
        except Exception as e:
            self.write_result('error_result.txt', resource, f"Error: {str(e)}")

        time.sleep(10)  

    def write_result(self, filename, resource, message):
        with open(filename, 'a') as f:
            f.write(f"{resource}\t{message}\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = VirusTotalScanner(root)
    root.mainloop()
