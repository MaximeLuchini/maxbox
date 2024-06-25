import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import subprocess
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from sql_injection import find_and_test_login_forms
from fpdf import FPDF
import datetime

class PenTestToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MaxBox")
        self.user_file = 'users.json'
        self.current_user = None
        self.report_file = 'rapport.json'
        self.ensure_user_file()

        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.loading_label = tk.Label(self.main_frame, text="", fg='blue')
        self.loading_label.pack(pady=5)
        self.loading_msg("")

        self.build_login_screen()

        self.footer_label = tk.Label(self.main_frame, text="Projet d'étude réalisé par Maxime Luchini", font=("Arial", 10))
        self.footer_label.pack(side=tk.BOTTOM, pady=10)

        self.ip_address = None

    def loading_msg(self, text):
        if text:
            self.loading_label.config(text=text)
            if not self.loading_label.winfo_ismapped():
                self.loading_label.pack(pady=5)
        else:
            if self.loading_label.winfo_ismapped():
                self.loading_label.pack_forget()

    def build_login_screen(self):
        self.clear_frame()

        self.title_label = tk.Label(self.main_frame, text="Bienvenue sur MaxBox", font=("Arial", 24))
        self.title_label.pack(pady=20)

        self.form_frame = tk.Frame(self.main_frame)
        self.form_frame.pack(pady=20)

        self.username_label = tk.Label(self.form_frame, text="Nom d'utilisateur:")
        self.username_label.grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = tk.Entry(self.form_frame)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        self.password_label = tk.Label(self.form_frame, text="Mot de passe:")
        self.password_label.grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(self.form_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        self.login_button = tk.Button(self.form_frame, text="Connexion", command=self.login)
        self.login_button.grid(row=2, column=0, columnspan=2, pady=5, ipadx=40)

        self.register_button = tk.Button(self.form_frame, text="Inscription", command=self.register)
        self.register_button.grid(row=3, column=0, columnspan=2, pady=5, ipadx=40)

        quit_button = tk.Button(self.form_frame, text="Quitter", command=self.root.quit, bg='red')
        quit_button.grid(row=4, column=0, columnspan=2, pady=5, ipadx=40)

        self.form_frame.grid_columnconfigure(0, weight=1)
        self.form_frame.grid_columnconfigure(1, weight=1)

    def ensure_user_file(self):
        if not os.path.exists(self.user_file):
            with open(self.user_file, 'w') as file:
                json.dump({"users": []}, file)

    def read_users(self):
        with open(self.user_file, 'r') as file:
            return json.load(file)

    def write_users(self, users):
        with open(self.user_file, 'w') as file:
            json.dump(users, file)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        users = self.read_users()
        for user in users['users']:
            if user['username'] == username and user['password'] == password:
                self.current_user = username
                self.init_report_file()
                self.show_main_menu()
                return
        messagebox.showerror("Erreur", "Nom d'utilisateur ou mot de passe incorrect")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showerror("Erreur", "Les champs ne peuvent pas être vides")
            return
        users = self.read_users()
        for user in users['users']:
            if user['username'] == username:
                messagebox.showerror("Erreur", "Le nom d'utilisateur existe déjà")
                return
        users['users'].append({"username": username, "password": password})
        self.write_users(users)
        messagebox.showinfo("Succès", "Utilisateur créé avec succès. Vous pouvez vous connecter maintenant.")
        self.build_login_screen()

    def init_report_file(self):
        if not os.path.exists(self.report_file):
            with open(self.report_file, 'w') as file:
                json.dump({"attacks": []}, file)
        else:
            with open(self.report_file, 'w') as file:
                json.dump({"attacks": []}, file)

    def update_report_file(self, data):
        with open(self.report_file, 'r') as file:
            report_data = json.load(file)
        report_data['attacks'].append(data)
        with open(self.report_file, 'w') as file:
            json.dump(report_data, file)

    def clear_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()
        self.loading_label = tk.Label(self.main_frame, text="", fg='blue')

    def show_main_menu(self):
        self.clear_frame()

        if self.current_user:
            user_label = tk.Label(self.main_frame, text=f"Connecté en tant que: {self.current_user}")
            user_label.grid(row=0, column=0, columnspan=2, pady=10)

        self.button_frame = tk.Frame(self.main_frame)
        self.button_frame.grid(row=1, column=0, columnspan=2, pady=20)

        attack_button = tk.Button(self.button_frame, text="Attaquer", command=self.attack)
        attack_button.grid(row=0, column=0, padx=10, pady=5, sticky='ew')

        history_button = tk.Button(self.button_frame, text="Historique des rapports", command=self.show_history)
        history_button.grid(row=1, column=0, padx=10, pady=5, sticky='ew')

        logout_button = tk.Button(self.button_frame, text="Déconnexion", command=self.logout)
        logout_button.grid(row=2, column=0, padx=10, pady=5, sticky='ew')

        quit_button = tk.Button(self.button_frame, text="Quitter", command=self.root.quit, bg='red')
        quit_button.grid(row=3, column=0, padx=10, pady=5, sticky='ew')

        self.button_frame.grid_columnconfigure(0, weight=1)

        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

    def show_history(self):
        self.clear_frame()

        history_label = tk.Label(self.main_frame, text="Historique des rapports générés", font=("Helvetica", 16, "bold"))
        history_label.pack(pady=10)

        report_dir = self.current_user
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)

        report_files = os.listdir(report_dir)
        if report_files:
            for report_file in report_files:
                report_path = os.path.join(report_dir, report_file)
                frame = tk.Frame(self.main_frame)
                frame.pack(fill=tk.X, padx=10, pady=5)

                button = tk.Button(frame, text=report_file, command=lambda rp=report_path: self.open_report(rp))
                button.pack(side=tk.LEFT, fill=tk.X, expand=True)

                delete_button = tk.Button(frame, text="Supprimer", command=lambda rf=report_file: self.delete_report(rf))
                delete_button.pack(side=tk.LEFT, padx=10)
        else:
            no_reports_label = tk.Label(self.main_frame, text="Aucun rapport trouvé.", font=("Helvetica", 12))
            no_reports_label.pack(pady=10)

        back_button = tk.Button(self.main_frame, text="Retour au menu principal", command=self.show_main_menu)
        back_button.pack(pady=10)

    def open_report(self, report_path):
        if os.name == 'nt':
            os.startfile(report_path)
        else:
            subprocess.call(('xdg-open', report_path))

    def delete_report(self, report_file):
        report_dir = self.current_user
        report_path = os.path.join(report_dir, report_file)
        if os.path.exists(report_path):
            os.remove(report_path)
            messagebox.showinfo("Supprimé", f"Le rapport {report_file} a été supprimé.")
            self.show_history()

    def logout(self):
        self.current_user = None
        self.build_login_screen()

    def attack(self):
        self.clear_frame()
        ip_label = tk.Label(self.main_frame, text="Entrez l'adresse IP de la cible:")
        ip_label.pack(padx=10, pady=5)

        self.ip_entry = tk.Entry(self.main_frame)
        self.ip_entry.pack(padx=10, pady=5)

        scan_button = tk.Button(self.main_frame, text="Lancer le scan Nmap", command=self.run_nmap_scan)
        scan_button.pack(padx=10, pady=5)

        back_button = tk.Button(self.main_frame, text="Retour au menu principal", command=self.show_main_menu)
        back_button.pack(pady=10)

    def run_nmap_scan(self):
        self.ip_address = self.ip_entry.get().strip()
        if not self.ip_address:
            messagebox.showerror("Erreur", "Veuillez entrer une adresse IP valide.")
            return

        self.loading_msg("Scan en cours...")
        self.main_frame.update_idletasks()

        try:
            subprocess.run(['sudo', 'python3', 'nmap3.py', self.ip_address], check=True)
            
            with open('nmap_results2.json', 'r') as file:
                results = json.load(file)
            self.loading_msg("")
            self.update_report_file({"title": "Ports ouverts", "data": results})
            self.display_nmap_results(results)
        except subprocess.CalledProcessError as e:
            self.loading_msg("")
            messagebox.showerror("Erreur de scan", f"Erreur lors de l'exécution du scan: {e}")
        except FileNotFoundError:
            self.loading_msg("")
            messagebox.showerror("Erreur de fichier", "Le fichier de résultats n'a pas été trouvé.")
        except json.JSONDecodeError:
            self.loading_msg("")
            messagebox.showerror("Erreur de décodage JSON", "Erreur lors de la lecture des données JSON.")

    def display_nmap_results(self, results):
        self.clear_frame()

        tree_frame = tk.Frame(self.main_frame)
        tree_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        tree = ttk.Treeview(tree_frame)
        tree['columns'] = ("Port", "State", "Service", "Description")
        tree.column("#0", width=0, stretch=tk.NO)
        tree.column("Port", anchor=tk.W, width=80)
        tree.column("State", anchor=tk.W, width=80)
        tree.column("Service", anchor=tk.W, width=120)
        tree.column("Description", anchor=tk.W, width=300)

        tree.heading("#0", text="", anchor=tk.W)
        tree.heading("Port", text="Port", anchor=tk.W)
        tree.heading("State", text="State", anchor=tk.W)
        tree.heading("Service", text="Service", anchor=tk.W)
        tree.heading("Description", text="Description", anchor=tk.W)

        for port_info in results['Ports']:
            tree.insert("", tk.END, values=(port_info["port"], port_info["state"], port_info["service"], port_info["description"]))

        tree.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        button_frame = tk.Frame(self.main_frame)
        button_frame.pack(padx=10, pady=10, fill=tk.X)

        back_button = tk.Button(self.main_frame, text="Retour au menu principal", command=self.confirm_back_to_main_menu)
        back_button.pack(pady=10)

        generate_report_button = tk.Button(self.main_frame, text="Générer un rapport", bg='blue', fg='white', command=self.generate_report)
        generate_report_button.pack(pady=10)

        ttk.Button(button_frame, text="Rechercher des CVEs", command=lambda: self.search_cves(results)).pack(side=tk.LEFT, padx=10)

        if any(p['service'] == 'http' for p in results['Ports']):
            sql_injection_button = tk.Button(button_frame, text="Injection SQL", command=self.sql_injection)
            sql_injection_button.pack(side=tk.LEFT, padx=10)

        if any(p['service'] == 'ssh' for p in results['Ports']):
            ttk.Button(button_frame, text="Bruteforce SSH", command=self.ssh_bruteforce).pack(side=tk.LEFT, padx=10)

        if any(p['service'] == 'ftp' for p in results['Ports']):
            ttk.Button(button_frame, text="Test d'attaque FTP", command=self.ftp_bruteforce).pack(side=tk.LEFT, padx=10)

    def confirm_back_to_main_menu(self):
        if messagebox.askyesno("Retour au menu principal", "Les données non téléchargées via le rapport seront perdues, voulez-vous vraiment revenir au menu principal ?"):
            self.show_main_menu()

    def sql_injection(self):
        self.loading_msg("Recherche de vulnérabilités SQL...")
        self.main_frame.update_idletasks()
        target_url = f"http://{self.ip_address}/"
        try:
            result = subprocess.run(['python3', 'sql_injection.py', target_url], capture_output=True, text=True, check=True)
            results = json.loads(result.stdout)
            self.loading_msg("")
            self.update_report_file({"title": "Injection SQL", "data": results})
            self.display_sql_results(results)
        except subprocess.CalledProcessError as e:
            self.loading_msg("")
            messagebox.showerror("Erreur d'injection SQL", f"Erreur lors de la recherche d'injections SQL: {e}")
        except json.JSONDecodeError:
            self.loading_msg("")
            messagebox.showerror("Erreur de décodage JSON", "Erreur lors de la lecture des données JSON")

    def display_sql_results(self, results):
        self.clear_frame()

        title_label = tk.Label(self.main_frame, text="Formulaires trouvés", font=("Helvetica", 16, "bold"))
        title_label.pack(pady=10)

        for result in results:
            result_frame = tk.Frame(self.main_frame, bd=2, relief=tk.SOLID, padx=10, pady=10)
            result_frame.pack(fill=tk.X, padx=5, pady=5)
            url_label = tk.Label(result_frame, text=f"URL: {result['url']}", font=("Helvetica", 12, "bold"))
            url_label.pack(anchor='w')

            status_label = tk.Label(result_frame, text=f"Résultat: {result['status']}", font=("Helvetica", 12))
            status_label.pack(anchor='w')

            if 'detail' in result and result['detail']:
                detail_label = tk.Label(result_frame, text=f"Détail: {result['detail']}", font=("Helvetica", 12))
                detail_label.pack(anchor='w')

        back_button_frame = tk.Frame(self.main_frame)
        back_button_frame.pack(fill=tk.X, pady=10)
        back_button = tk.Button(back_button_frame, text="Retour aux résultats du scan", command=self.display_nmap_results_again)
        back_button.pack()

        generate_report_button = tk.Button(self.main_frame, text="Générer un rapport", bg='blue', fg='white', command=self.generate_report)
        generate_report_button.pack(pady=10)

    def display_nmap_results_again(self):
        try:
            with open('nmap_results2.json', 'r') as file:
                results = json.load(file)
            self.display_nmap_results(results)
        except Exception as e:
            tk.messagebox.showerror("Erreur", f"Erreur lors de la lecture des résultats du scan Nmap: {e}")

    def ssh_bruteforce(self):
        self.loading_msg("Exécution de l'attaque SSH avec...")
        self.main_frame.update_idletasks()

        target_ip = self.ip_address
        port = "22"
        user_list = "user_list.txt"
        pass_list = "pass_list.txt"

        try:
            if os.path.exists("hydra_results.txt"):
                os.remove("hydra_results.txt")
            if os.path.exists("hydra_results.json"):
                os.remove("hydra_results.json")

            result = subprocess.run(
                ['python3', 'ssh_bruteforce.py', target_ip, port, user_list, pass_list],
                capture_output=True, text=True, check=True
            )
            self.loading_msg("")
            self.display_ssh_results()
        except subprocess.CalledProcessError as e:
            self.loading_msg("")
            messagebox.showerror("Erreur d'attaque SSH", f"Erreur lors de l'exécution de Hydra: {e}")

    def display_ssh_results(self):
        self.clear_frame()

        title_label = tk.Label(self.main_frame, text="Résultats de l'attaque SSH", font=("Helvetica", 16, "bold"))
        title_label.pack(pady=10)

        try:
            with open('hydra_results.json', 'r') as file:
                results = json.load(file)

            self.update_report_file({"title": "Bruteforce SSH", "data": results})

            if not results:
                result_text = tk.Label(self.main_frame, text="Aucun résultat trouvé.", font=("Helvetica", 12))
                result_text.pack(pady=10)
            else:
                for result in results:
                    result_frame = tk.Frame(self.main_frame, bd=2, relief=tk.SOLID, padx=10, pady=10)
                    result_frame.pack(fill=tk.X, padx=5, pady=5)
                    host_label = tk.Label(result_frame, text=f"Hôte: {result['host']}", font=("Helvetica", 12, "bold"))
                    host_label.pack(anchor='w')
                    login_label = tk.Label(result_frame, text=f"Login: {result['login']}", font=("Helvetica", 12))
                    login_label.pack(anchor='w')
                    password_label = tk.Label(result_frame, text=f"Mot de passe: {result['password']}", font=("Helvetica", 12))
                    password_label.pack(anchor='w')
                    status_label = tk.Label(result_frame, text=f"Statut: {result['status']}", font=("Helvetica", 12))
                    status_label.pack(anchor='w')

                    if result['status'] == 'success':
                        nav_button = tk.Button(result_frame, text="Accéder à la cible", command=lambda res=result: self.launch_ssh_navigator(res['host'], res['login'], res['password']))
                        nav_button.pack(anchor='w')

        except FileNotFoundError:
            result_text = tk.Label(self.main_frame, text="Fichier de résultats non trouvé.", font=("Helvetica", 12))
            result_text.pack(pady=10)
        except json.JSONDecodeError:
            result_text = tk.Label(self.main_frame, text="Erreur lors de la lecture des données JSON.", font=("Helvetica", 12))
            result_text.pack(pady=10)

        back_button = tk.Button(self.main_frame, text="Retour aux résultats du scan", command=self.display_nmap_results_again)
        back_button.pack(pady=10)

        generate_report_button = tk.Button(self.main_frame, text="Générer un rapport", bg='blue', fg='white', command=self.generate_report)
        generate_report_button.pack(pady=10)

    def ftp_bruteforce(self):
        self.loading_msg("Exécution de l'attaque FTP...")
        self.main_frame.update_idletasks()

        target_ip = self.ip_address
        port = "21"
        user_list = "user_list.txt"
        pass_list = "pass_list.txt"

        try:
            if os.path.exists("ftp_hydra_results.txt"):
                os.remove("ftp_hydra_results.txt")
            if os.path.exists("ftp_hydra_results.json"):
                os.remove("ftp_hydra_results.json")

            result = subprocess.run(
                ['python3', 'ftp_bruteforce.py', target_ip, port, user_list, pass_list],
                capture_output=True, text=True, check=True
            )
            self.loading_msg("")
            self.display_ftp_results()
        except subprocess.CalledProcessError as e:
            self.loading_msg("")
            messagebox.showerror("Erreur d'attaque FTP", f"Erreur lors de l'exécution de Hydra: {e}")

    def display_ftp_results(self):
        self.clear_frame()

        title_label = tk.Label(self.main_frame, text="Résultats de l'attaque FTP", font=("Helvetica", 16, "bold"))
        title_label.pack(pady=10)

        try:
            with open('ftp_hydra_results.json', 'r') as file:
                results = json.load(file)

            self.update_report_file({"title": "Bruteforce FTP", "data": results})

            if not results:
                result_text = tk.Label(self.main_frame, text="Aucun résultat trouvé.", font=("Helvetica", 12))
                result_text.pack(pady=10)
            else:
                for result in results:
                    result_frame = tk.Frame(self.main_frame, bd=2, relief=tk.SOLID, padx=10, pady=10)
                    result_frame.pack(fill=tk.X, padx=5, pady=5)
                    host_label = tk.Label(result_frame, text=f"Hôte: {result['host']}", font=("Helvetica", 12, "bold"))
                    host_label.pack(anchor='w')
                    login_label = tk.Label(result_frame, text=f"Login: {result['login']}", font=("Helvetica", 12))
                    login_label.pack(anchor='w')
                    password_label = tk.Label(result_frame, text=f"Mot de passe: {result['password']}", font=("Helvetica", 12))
                    password_label.pack(anchor='w')
                    status_label = tk.Label(result_frame, text=f"Statut: {result['status']}", font=("Helvetica", 12))
                    status_label.pack(anchor='w')

        except FileNotFoundError:
            result_text = tk.Label(self.main_frame, text="Fichier de résultats non trouvé.", font=("Helvetica", 12))
            result_text.pack(pady=10)
        except json.JSONDecodeError:
            result_text = tk.Label(self.main_frame, text="Erreur lors de la lecture des données JSON.", font=("Helvetica", 12))
            result_text.pack(pady=10)

        back_button = tk.Button(self.main_frame, text="Retour aux résultats du scan", command=self.display_nmap_results_again)
        back_button.pack(pady=10)

        generate_report_button = tk.Button(self.main_frame, text="Générer un rapport", bg='blue', fg='white', command=self.generate_report)
        generate_report_button.pack(pady=10)

    def launch_ssh_navigator(self, host, username, password):
        subprocess.Popen(['python3', 'ssh_navigator.py', host, username, password])

    def search_cves(self, nmap_results):
        self.loading_msg("Recherche de CVEs en cours...")
        self.main_frame.update_idletasks()

        with open('temp_nmap_results.json', 'w') as f:
            json.dump(nmap_results, f)

        try:
            subprocess.run(['python3', 'searchcve6.py', 'temp_nmap_results.json'], check=True)
            with open('cve_results2.json', 'r') as file:
                cve_results = json.load(file)
            self.loading_msg("")
            self.update_report_file({"title": "CVEs trouvés", "data": cve_results})
            self.display_cve_results(cve_results)
        except subprocess.CalledProcessError as e:
            self.loading_msg("")
            messagebox.showerror("Erreur de recherche CVE", f"Erreur lors de la recherche de CVEs: {e}")

    def display_scan_results_again(self):
        try:
            with open('nmap_results2.json', 'r') as file:
                results = json.load(file)
            self.display_nmap_results(results)
        except FileNotFoundError:
            messagebox.showerror("Erreur", "Fichier de résultats non trouvé.")
        except json.JSONDecodeError:
            messagebox.showerror("Erreur", "Erreur lors du décodage des données JSON.")

    def display_cve_results(self, cve_results):
        self.clear_frame()

        cve_frame = tk.Frame(self.main_frame)
        cve_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        cve_found = False
        for port, cves in cve_results.items():
            if cves != ["No CVEs found."]:
                cve_found = True
                tk.Label(cve_frame, text=f"Port {port}:").pack(anchor='w')
                combo = ttk.Combobox(cve_frame, values=[f"{cve['Title']} - {cve.get('CVE', 'No CVE number available')}" for cve in cves], state="readonly")
                combo.pack(padx=10, pady=5, fill=tk.X)

        if not cve_found:
            tk.Label(cve_frame, text="Pas de CVEs trouvées sur cette machine").pack(pady=20)

        # Boutons
        tk.Button(cve_frame, text="Retour", command=self.display_scan_results_again).pack(pady=5)
        tk.Button(cve_frame, text="Quitter", command=self.root.quit, bg='red').pack(side=tk.LEFT, padx=10, pady=10)
        tk.Button(cve_frame, text="Générer un rapport", bg='blue', command=self.generate_report, fg='white').pack(side=tk.RIGHT, padx=10, pady=10)

    def generate_report(self):
        from fpdf import FPDF
        import datetime

        report_dir = self.current_user
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)

        report_file = os.path.join(report_dir, f"rapport_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        with open(self.report_file, 'r') as file:
            report_data = json.load(file)

        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt="Rapport de Pentest", ln=True, align='C')
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
        pdf.ln(10)

        for attack in report_data['attacks']:
            pdf.set_font("Arial", 'B', 14)
            pdf.cell(0, 10, txt=attack['title'], ln=True)
            pdf.set_font("Arial", size=12)
            pdf.ln(5)
            data = attack['data']
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        for key, value in item.items():
                            pdf.set_font("Arial", 'B', 12)
                            pdf.cell(0, 10, txt=f"{key}", ln=True)
                            pdf.set_font("Arial", size=10)
                            pdf.multi_cell(0, 10, f"{value}")
                        pdf.ln(5)
                    else:
                        pdf.multi_cell(0, 10, f"{item}")
                pdf.ln(10)
            elif isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, list):
                        pdf.set_font("Arial", 'B', 12)
                        pdf.cell(0, 10, txt=key, ln=True)
                        pdf.set_font("Arial", size=10)
                        for item in value:
                            if isinstance(item, dict):
                                for sub_key, sub_value in item.items():
                                    pdf.multi_cell(0, 10, f"{sub_key}: {sub_value}")
                            else:
                                pdf.multi_cell(0, 10, f"{item}")
                    else:
                        pdf.set_font("Arial", size=12)
                        pdf.multi_cell(0, 10, f"{key}: {value}")
            pdf.ln(10)

        pdf.output(report_file)

        messagebox.showinfo("Rapport généré", f"Rapport généré et enregistré sous {report_file}")



    def confirm_back_to_main_menu(self):
        if messagebox.askyesno("Retour au menu principal", "Les données non téléchargées via le rapport seront perdues, voulez-vous vraiment quitter ?"):
            self.show_main_menu()

if __name__ == "__main__":
    root = tk.Tk()
    app = PenTestToolApp(root)
    root.protocol("WM_DELETE_WINDOW", app.confirm_back_to_main_menu)
    root.mainloop()
