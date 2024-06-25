import tkinter as tk
from tkinter import filedialog, messagebox
import paramiko
import os
import stat

class SSHNavigator:
    def __init__(self, master, host, username, password):
        self.master = master
        self.host = host
        self.username = username
        self.password = password
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.sftp_client = None
        self.current_path = '/'
        
        self.connect()
        self.setup_ui()

    def connect(self):
        try:
            self.ssh_client.connect(self.host, username=self.username, password=self.password, timeout=10)
            self.sftp_client = self.ssh_client.open_sftp()
        except Exception as e:
            messagebox.showerror("Erreur de connexion SSH", f"Erreur lors de la connexion à {self.host}: {e}")
            self.master.destroy()

    def setup_ui(self):
        self.master.title(f"Navigation SSH - {self.host}")
        
        self.path_label = tk.Label(self.master, text=self.current_path)
        self.path_label.pack(pady=5)
        
        self.ssh_listbox = tk.Listbox(self.master)
        self.ssh_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.ssh_listbox.bind("<Double-1>", self.change_directory)

        button_frame = tk.Frame(self.master)
        button_frame.pack(pady=5)

        self.download_button = tk.Button(button_frame, text="Télécharger", command=self.download_file)
        self.download_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.upload_button = tk.Button(button_frame, text="Téléverser", command=self.upload_file)
        self.upload_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.back_button = tk.Button(button_frame, text="Retour", command=self.go_back)
        self.back_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.close_button = tk.Button(button_frame, text="Fermer", command=self.master.destroy)
        self.close_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.update_ssh_listbox()

    def update_ssh_listbox(self):
        self.ssh_listbox.delete(0, tk.END)
        self.path_label.config(text=self.current_path)
        try:
            for item in self.sftp_client.listdir_attr(self.current_path):
                item_type = 'd' if stat.S_ISDIR(item.st_mode) else '-'
                access = self.check_access(item)
                display_name = f"{item_type} {item.filename} {access}"
                self.ssh_listbox.insert(tk.END, display_name)
        except Exception as e:
            messagebox.showerror("Erreur de listage SSH", f"Erreur lors du listage du répertoire {self.current_path}: {e}")

    def check_access(self, item):
        try:
            self.sftp_client.listdir_attr(os.path.join(self.current_path, item.filename))
            return ""
        except IOError:
            return "(pas d'accès)"

    def change_directory(self, event):
        selection = self.ssh_listbox.get(self.ssh_listbox.curselection())
        if selection.startswith('d'):
            directory = selection[2:].split()[0]
            self.current_path = os.path.join(self.current_path, directory)
            self.update_ssh_listbox()
        else:
            messagebox.showinfo("Information", "Sélectionnez un répertoire pour naviguer.")

    def go_back(self):
        self.current_path = os.path.dirname(self.current_path)
        if not self.current_path:
            self.current_path = '/'
        self.update_ssh_listbox()

    def download_file(self):
        selection = self.ssh_listbox.get(self.ssh_listbox.curselection())
        if not selection.startswith('d'):
            filename = selection[2:].split()[0]
            local_path = filedialog.asksaveasfilename(initialfile=filename)
            if local_path:
                remote_path = os.path.join(self.current_path, filename)
                try:
                    self.sftp_client.get(remote_path, local_path)
                    messagebox.showinfo("Téléchargement réussi", f"Le fichier {filename} a été téléchargé avec succès.")
                except Exception as e:
                    messagebox.showerror("Erreur de téléchargement", f"Erreur lors du téléchargement du fichier {filename}: {e}")
        else:
            messagebox.showinfo("Information", "Sélectionnez un fichier pour le télécharger.")

    def upload_file(self):
        local_path = filedialog.askopenfilename()
        if local_path:
            filename = os.path.basename(local_path)
            remote_path = os.path.join(self.current_path, filename)
            try:
                self.sftp_client.put(local_path, remote_path)
                self.update_ssh_listbox()
                messagebox.showinfo("Téléversement réussi", f"Le fichier {filename} a été téléversé avec succès.")
            except Exception as e:
                messagebox.showerror("Erreur de téléversement", f"Erreur lors du téléversement du fichier {filename}: {e}")

    def __del__(self):
        if self.sftp_client:
            self.sftp_client.close()
        if self.ssh_client:
            self.ssh_client.close()

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("Usage: python ssh_navigator.py <host> <username> <password>")
        sys.exit(1)

    host, username, password = sys.argv[1], sys.argv[2], sys.argv[3]
    root = tk.Tk()
    app = SSHNavigator(root, host, username, password)
    root.mainloop()
