
import tkinter as tk
from tkinter import messagebox, simpledialog
import json
import requests
import threading
import time
from crypto_util import check_password

from crypto_util import decrypt_message

BASE_URL = "http://127.0.0.1:5000"

with open("key.key", "rb") as f:
    key = f.read()

with open("user_db.json", "r") as f:
    user_data = json.load(f)

root = tk.Tk()
root.title("Secure Contact Book")
root.geometry("400x400")

login_frame = tk.Frame(root)
contact_frame = tk.Frame(root)

username_entry = None
password_entry = None
login_status = None
logout_timer = None

# ---------------- Auto Logout ---------------- #

def auto_logout():
    time.sleep(120)
    contact_frame.pack_forget()
    build_login_screen()
    messagebox.showinfo("Logged out", "You were logged out due to inactivity ⏳")

def reset_timer():
    global logout_timer
    if logout_timer:
        logout_timer.cancel()
    logout_timer = threading.Timer(120, auto_logout)
    logout_timer.start()

# ---------------- Contact Book ---------------- #
def get_contact_input(title, default_name="", default_phone=""):
    input_window = tk.Toplevel(root)
    input_window.title(title)
    input_window.geometry("300x150")
    input_window.grab_set()  # Prevent interaction with other windows

    tk.Label(input_window, text="Name:").pack(pady=(10, 0))
    name_entry = tk.Entry(input_window)
    name_entry.pack()
    name_entry.insert(0, default_name)

    tk.Label(input_window, text="Phone:").pack(pady=(10, 0))
    phone_entry = tk.Entry(input_window)
    phone_entry.pack()
    phone_entry.insert(0, default_phone)

    result = {"name": None, "phone": None}

    def submit():
        result["name"] = name_entry.get()
        result["phone"] = phone_entry.get()
        input_window.destroy()

    tk.Button(input_window, text="Submit", command=submit).pack(pady=10)
    input_window.wait_window()  

    return result["name"], result["phone"]


def fetch_contacts():
    response = requests.get(f"{BASE_URL}/contacts")
    if response.status_code == 200:
        return response.json()
    return []

def refresh_contacts():
    global decrypted_contacts
    reset_timer()
    contact_list.delete(0, tk.END)
    decrypted_contacts = []

    all_contacts = []

    for contact in fetch_contacts():
        try:
            name = decrypt_message(contact['name'], key)
            phone = decrypt_message(contact['phone'], key)
            all_contacts.append((name, phone, contact))  
        except:
            continue

    # Sort by decrypted name (A-Z)
    all_contacts.sort(key=lambda x: x[0].lower())

    for name, phone, original in all_contacts:
        contact_list.insert(tk.END, f"{name} - {phone}")
        decrypted_contacts.append(original)

def add_contact():
    reset_timer()
    name, phone = get_contact_input("Add Contact")
    if name and phone:
        response = requests.post(f"{BASE_URL}/add", json={"name": name, "phone": phone})
        if response.status_code == 200:
            refresh_contacts()
        elif response.status_code == 400:
            messagebox.showwarning("Duplicate", "This contact already exists.")
        else:
            messagebox.showerror("Error", "Something went wrong.")

def delete_selected_contact():
    reset_timer()
    selection = contact_list.curselection()
    if not selection:
        messagebox.showwarning("Warning", "No contact selected")
        return

    index = selection[0]

    try:
        response = requests.post(f"{BASE_URL}/delete", json={"index": index})
        if response.status_code == 200 and response.json()["status"] == "success":
            messagebox.showinfo("Deleted", "Contact deleted successfully!")
            refresh_contacts()
        else:
            messagebox.showerror("Error", "Failed to delete contact.")
    except Exception as e:
        print(" Error deleting contact:", e)
        messagebox.showerror("Error", "Server not responding.")

def edit_contact():
    reset_timer()
    selected = contact_list.curselection()
    if selected:
        old_name = contact_list.get(selected[0]).split(" - ")[0]
        new_name, new_phone = get_contact_input("Edit Contact")
        if new_name and new_phone:
            requests.post(f"{BASE_URL}/edit", json={
                "old_name": old_name,
                "new_name": new_name,
                "new_phone": new_phone
            })
            refresh_contacts()

def export_contacts():
    reset_timer()
    try:
        contacts = fetch_contacts()
        with open("backup_contacts.txt", "w") as f:
            for contact in contacts:
                try:
                    name = decrypt_message(contact['name'], key)
                    phone = decrypt_message(contact['phone'], key)
                    f.write(f"Name: {name}\nPhone: {phone}\n\n")
                except:
                    continue
        messagebox.showinfo("Exported", "Contacts exported to backup_contacts.txt")
    except Exception as e:
        print("Error exporting:", e)
        messagebox.showerror("Error", "Failed to export contacts.")

def search_contacts():
    reset_timer()
    query = simpledialog.askstring("Search Contact", "Enter name or phone:")
    if not query:
        return

    contact_list.delete(0, tk.END)
    for contact in fetch_contacts():
        try:
            name = decrypt_message(contact['name'], key)
            phone = decrypt_message(contact['phone'], key)
            if query.lower() in name.lower() or query in phone:
                contact_list.insert(tk.END, f"{name} - {phone}")
        except:
            continue
def show_all_contacts():
    reset_timer()
    refresh_contacts()

# ---------------- GUI Views ---------------- #

def show_contact_book():
    login_frame.pack_forget()
    contact_frame.pack(pady=20)
    refresh_contacts()
    reset_timer()

#------------------buttons----------------#

def build_contact_book():
    tk.Label(contact_frame, text="Secure Contact Book", font=("Arial", 14, "bold")).pack(pady=(10, 5))

    btn_frame = tk.Frame(contact_frame)
    btn_frame.pack(pady=5)

    tk.Button(btn_frame, text="Add Contact", command=add_contact, bg="#4CAF50", fg="white", width=12).grid(row=0, column=0, padx=5)
    tk.Button(btn_frame, text="Edit Contact", command=edit_contact, bg="#FFC107", fg="black", width=12).grid(row=0, column=1, padx=5)
    tk.Button(btn_frame, text="Delete Contact", command=delete_selected_contact, bg="#F44336", fg="white", width=12).grid(row=0, column=2, padx=5)
    tk.Button(contact_frame, text="Export Contacts", command=export_contacts, bg="#607D8B", fg="white", width=30).pack(pady=(10, 5))

    #------------Search bar ---------------#
    search_frame = tk.Frame(contact_frame)
    search_frame.pack(pady=(10, 5))

    tk.Label(search_frame, text="Search:", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
    search_entry = tk.Entry(search_frame, width=25)
    search_entry.pack(side=tk.LEFT, padx=5)

    def search():
        term = search_entry.get().lower()
        contact_list.delete(0, tk.END)
        for contact in fetch_contacts():
            try:
                name = decrypt_message(contact['name'], key)
                phone = decrypt_message(contact['phone'], key)
                if term in name.lower() or term in phone:
                    contact_list.insert(tk.END, f"{name} - {phone}")
            except:
                continue

    def reset_search():
        search_entry.delete(0, tk.END)
        refresh_contacts()

    tk.Button(search_frame, text="Search", command=search, width=10).pack(side=tk.LEFT, padx=5)
    tk.Button(search_frame, text="Back", command=reset_search, width=10).pack(side=tk.LEFT)

    #--------------Contact list with scrollbar -----------------#
    list_frame = tk.Frame(contact_frame)
    list_frame.pack(pady=10)

    scrollbar = tk.Scrollbar(list_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    global contact_list
    contact_list = tk.Listbox(list_frame, width=40, yscrollcommand=scrollbar.set)
    contact_list.pack(side=tk.LEFT, fill=tk.BOTH)

    scrollbar.config(command=contact_list.yview)

def build_login_screen():
    for widget in login_frame.winfo_children():
        widget.destroy()  

    contact_frame.pack_forget()
    login_frame.pack(padx=20, pady=20)

    tk.Label(login_frame, text="Username:", font=("Arial", 11)).pack()
    global username_entry
    username_entry = tk.Entry(login_frame, width=30)
    username_entry.pack(pady=5)

    tk.Label(login_frame, text="Password:", font=("Arial", 11)).pack()
    global password_entry
    password_entry = tk.Entry(login_frame, show="*", width=30)
    password_entry.pack(pady=5)

    tk.Button(login_frame, text="Login", command=login, width=20, bg="#2196F3", fg="white", font=("Arial", 10, "bold")).pack(pady=10)
    global login_status
    login_status = tk.Label(login_frame, text="", fg="red")
    login_status.pack()

# ---------------- Login Logic ---------------- #

def login():
    username = username_entry.get()
    password = password_entry.get()
    if username == user_data["username"] and check_password(password, user_data["password"]):
        show_contact_book()
    else:
        login_status.config(text=" Incorrect username or password.")

# ---------------- GUI Layout ---------------- #

tk.Label(login_frame, text="Username:").pack()
username_entry = tk.Entry(login_frame)
username_entry.pack()

tk.Label(login_frame, text="Password:").pack()
password_entry = tk.Entry(login_frame, show="*")
password_entry.pack()

tk.Button(login_frame, text="Login", command=login).pack(pady=10)
login_status = tk.Label(login_frame, text="")
login_status.pack()

build_login_screen()
build_contact_book()
root.mainloop()
