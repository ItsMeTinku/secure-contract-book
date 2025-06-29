from flask import Flask, request, jsonify
import json
from crypto_util import encrypt_message, decrypt_message, hash_password, check_password

with open("key.key", "rb") as f:
    key = f.read()

app = Flask(__name__)

# Load user credentials from JSON
try:
    with open("user_db.json", "r") as f:
        user_data = json.load(f)
except:
    user_data = {"username": "admin", "password": hash_password("admin123")}

#  Login route
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username == user_data["username"] and check_password(password, user_data["password"]):
        return jsonify({"status": "success"})
    else:
        return jsonify({"status": "fail"}), 401

#  Add Contact
@app.route("/add", methods=["POST"])
def add_contact():
    data = request.get_json()
    new_name = data["name"]
    new_phone = data["phone"]

    try:
        with open("contact_db.json", "r") as f:
            contacts = json.load(f)
    except:
        contacts = []

    # Check duplicates by decrypting existing contacts
    for contact in contacts:
        try:
            existing_name = decrypt_message(contact["name"], key)
            existing_phone = decrypt_message(contact["phone"], key)
            if existing_name == new_name and existing_phone == new_phone:
                return jsonify({"message": "Duplicate contact"}), 400
        except:
            continue  # skip if any contact fails to decrypt

    # Encrypt and save
    enc_name = encrypt_message(new_name, key)
    enc_phone = encrypt_message(new_phone, key)
    contacts.append({"name": enc_name, "phone": enc_phone})

    with open("contact_db.json", "w") as f:
        json.dump(contacts, f)

    return jsonify({"message": "Contact added successfully"})

    # Add contact
    contacts.append({"name": name, "phone": phone})

    # Save updated list
    with open("contact_db.json", "w") as f:
        json.dump(contacts, f)

    return jsonify({"message": "Contact added successfully"})

#  Get Contacts
@app.route("/contacts")
def get_contacts():
    try:
        with open("contact_db.json", "r") as f:
            contacts = json.load(f)
    except:
        contacts = []
    return jsonify(contacts)

#  Delete Contact (Optional Future Feature)
@app.route("/delete", methods=["POST"])
def delete_contact():
    data = request.get_json()
    index = data.get("index")

    try:
        with open("contact_db.json", "r") as f:
            contacts = json.load(f)
        contacts.pop(index)
        with open("contact_db.json", "w") as f:
            json.dump(contacts, f)
        return jsonify({"status": "success"})
    except:
        return jsonify({"status": "fail"}), 400

@app.route("/edit", methods=["POST"])
def edit_contact():
    data = request.get_json()
    old_name = data.get("old_name")
    new_name = data.get("new_name")
    new_phone = data.get("new_phone")

    try:
        with open("contact_db.json", "r") as f:
            contacts = json.load(f)
    except:
        return jsonify({"status": "fail"}), 500

    updated = False

    # Decrypt, match, and replace
    for i in range(len(contacts)):
        try:
            name_dec = decrypt_message(contacts[i]["name"], key)
            if name_dec == old_name:
                contacts[i]["name"] = encrypt_message(new_name, key)
                contacts[i]["phone"] = encrypt_message(new_phone, key)
                updated = True
                break
        except:
            continue

    if updated:
        with open("contact_db.json", "w") as f:
            json.dump(contacts, f)
        return jsonify({"status": "success"})
    else:
        return jsonify({"status": "not_found"}), 404

#  Run Server
if __name__ == "__main__":
    app.run(debug=True)