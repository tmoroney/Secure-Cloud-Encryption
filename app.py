import streamlit as st
import base64
import pyrebase
import requests
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from encrypt_file import rsa_encrypt, aes_encrypt, aes_decrypt, rsa_decrypt, get_private_key, get_public_key
from generate_keys import generate_key_pair, generate_aes_key, generate_iv

firebaseConfig = {
    'apiKey': "",
    'authDomain': "",
    'projectId': "",
    'databaseURL': "",
    'storageBucket': "",
    'serviceAccount': "",
    'messagingSenderId': "",
    'appId': ""
}

# Remove menu and footer
# =======================
hide_streamlit_style = """
            <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            </style>
            """
st.markdown(hide_streamlit_style, unsafe_allow_html=True) 
# =======================

# Firebase Authentication
firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()
# Database
db = firebase.database()
storage = firebase.storage()
st.title("Secure Cloud Storage")

# Authentication
choice = st.sidebar.selectbox('Login/Signup', ['Login', 'Sign up'])

# Obtain User Input for email and password
email = st.sidebar.text_input('Email address')
password = st.sidebar.text_input('Password',type = 'password')

# App 

# Sign up Block
if choice == 'Sign up':
    handle = st.sidebar.text_input('Username', value='Default')
    submit = st.sidebar.button('Create my account')

    if submit:
        try:
            user = auth.create_user_with_email_and_password(email, password)
            public_key_pem = generate_key_pair(handle)
            all_users = db.get()
            res = []
            # Store all the users handle name
            for users_handle in all_users.each():
                k = users_handle.val()["Handle"]
                res.append(k)
            # Total users
            if (len(res) == 0):
                public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
                aes_key = generate_aes_key()
                encrypted_aes_key = rsa_encrypt(aes_key, public_key)
                # Convert the encrypted AES key to a string
                encrypted_aes_key_str = base64.b64encode(encrypted_aes_key).decode()
                # Serialize the encrypted AES key string to JSON
                json_data = json.dumps(encrypted_aes_key_str)
                # Store the encrypted AES key as a JSON string value in Firebase Realtime Database
                db.child(user['localId']).child("secureGroupKey").set(json_data)
            st.success('Your account is created suceesfully!')
            st.balloons()
            # Sign in
            user = auth.sign_in_with_email_and_password(email, password)
            db.child(user['localId']).child("Handle").set(handle)
            db.child(user['localId']).child("ID").set(user['localId'])
            db.child(user['localId']).child("publicKey").set(public_key_pem.decode())
            st.info('Login via login drop down selection')
        except requests.exceptions.HTTPError as e:
            error_json = e.args[1]
            error = json.loads(error_json)['error']['message']
            if error == "EMAIL_EXISTS":
                st.error("Email already exists")
            

# Login Block
if choice == 'Login':
    login = st.sidebar.checkbox('Login')
    if login:
        try:
            user = auth.sign_in_with_email_and_password(email,password)
            st.sidebar.success('Logged in as {}'.format(email))
            try:
                encrypted_aes_key_str = json.loads(db.child(user['localId']).child("secureGroupKey").get().val())
                # Convert the encrypted AES key string to binary data
                encrypted_aes_key = base64.b64decode(encrypted_aes_key_str)
                private_key = get_private_key(db.child(user['localId']).child("Handle").get().val())
                decrypted_aes_key = rsa_decrypt(encrypted_aes_key, private_key)

                uploaded_file = st.file_uploader("Choose a file to encrypt and upload")
                if uploaded_file is not None:
                    # Encrypt file with AES
                    iv = generate_iv()
                    encrypted = aes_encrypt(decrypted_aes_key, iv, uploaded_file.getvalue())
                    new_filename = uploaded_file.name + ".bin"
                    # Save encrypted data to file
                    with open("storage/" + new_filename, "wb") as f:
                        f.write(encrypted)
                    storage.child(new_filename).put("storage/"+new_filename)
                    #st.success("File successfully encrypted")

                st.subheader("Files in storage:")
                files = storage.child('/').list_files()
                for file in files:
                    col1, col2, col3 = st.columns([1.5,0.5,1])
                    filename = file.name
                    if filename.endswith(".bin"):
                        with col1:
                            st.write(filename)
                        with col2:
                            if st.button('Decrypt', key = filename):
                                try:
                                    storage.child(filename).download(filename)
                                except:
                                    pass
                                with open("storage/" + filename, 'rb') as f:
                                    encrypted_data = f.read()
                                try:
                                    decrypted_file = aes_decrypt(decrypted_aes_key, encrypted_data)
                                    new_filename = filename[:-4]
                                    with open("storage/" + new_filename, "wb") as f:
                                        f.write(decrypted_file)
                                    with open("storage/" + new_filename, "rb") as file:
                                        with col3:
                                            st.download_button(
                                                label="Download File",
                                                key = new_filename,
                                                data=decrypted_file,
                                                file_name=filename[:-4]
                                            )
                                except:
                                    st.error("You are not authorized to decrypt this file")
                                    continue
                                
                st.subheader("Encryption Group")
                # Get a list of all users from Firebase Realtime Database
                all_users = db.get()
                res = []
                # Store all the users handle name
                for users_handle in all_users.each():
                    k = users_handle.val()["Handle"]
                    res.append(k)

                # Allow the user to choose another user to add to the encryption group
                choice = st.selectbox('Select a user to add',res)
                addUser = st.button('Add to encryption group')
                deleteUser = st.button('Remove from encryption group')

                # Add the chosen user to the encryption group
                if addUser:
                    for users_handle in all_users.each():
                        k = users_handle.val()["Handle"]
                        if k == choice:
                            lid = users_handle.val()["ID"]
                            try:
                                # Encrypt AES key with RSA
                                public_key_pem = db.child(lid).child("publicKey").get().val()             
                                public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
                                encrypted_aes_key = rsa_encrypt(decrypted_aes_key, public_key)
                                # Convert the encrypted AES key to a string
                                encrypted_aes_key_str = base64.b64encode(encrypted_aes_key).decode()
                                # Serialize the encrypted AES key string to JSON
                                json_data = json.dumps(encrypted_aes_key_str)
                                # Store the encrypted AES key as a JSON string value in Firebase Realtime Database
                                db.child(lid).child("secureGroupKey").set(json_data)
                                st.success("User added to encryption group")
                            except:
                                st.error("You are not authorized to add this user to the encryption group")

                # Remove the chosen user from the encryption group
                if deleteUser:
                    for users_handle in all_users.each():
                        k = users_handle.val()["Handle"]
                        if k == choice:
                            lid = users_handle.val()["ID"]
                            try:
                                db.child(lid).child("secureGroupKey").set("")
                                st.success("User removed from encryption group")
                            except:
                                st.error("You are not authorized to add this user to the encryption group")
            except:
                st.error("You are not authorized to access to access these files")

        except requests.exceptions.HTTPError as e:
            #error_json = e.args[1]
            #error = json.loads(error_json)['error']['message']
            st.error('Wrong credentials entered!')