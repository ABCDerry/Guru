from flask import Flask, render_template, request, redirect, url_for, session, send_file, jsonify
import sqlite3
import os
import base64
import io
from werkzeug.utils import secure_filename
from PIL import Image
import wave
import numpy as np
import cv2
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Config create folder to store data
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)#create folder for upload
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER#sets the upload folder path for the Flask
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # Max Size of File

#Database Connection
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT,
                    public_key TEXT,
                    private_key TEXT
                )''')
    conn.commit()
    conn.close()

init_db()

#RSA Concept
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)#Generate Private Key
    public_key = private_key.public_key()#Generate Public Key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )#convert file into a format that can be stored or transmitted
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )#do same but scope is public
    return public_pem.decode('utf-8'), private_pem.decode('utf-8')

#Authentication of user 
@app.route('/')#user is redirected to login page
def root():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        public_key, private_key = generate_keys()

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, public_key, private_key) VALUES (?, ?, ?, ?)",
                      (username, password, public_key, private_key))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists."
        conn.close()
        return redirect('/login')
    return render_template('register.html')#it handles get and post method(Get:handle register post:handle login(After register))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['username'] = username
            return redirect('/dashboard')
        else:
            return "Invalid credentials."
    return render_template('login.html')#it also handles get and post method(Get:handle login page(display login page) 
                                        # post:handle register(when the user login))
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')#This route clears the user's session

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    return render_template('index.html')#if user is not logged in they are redirected to login page

#Image
def lsb_encode(image, message):
    encoded = image.copy()
    width, height = image.size
    index = 0
    message += chr(0)
    binary_message = ''.join([format(ord(c), '08b') for c in message])#copying image to avoid modifying original image and converting it into binary
    for y in range(height):
        for x in range(width):
            if index < len(binary_message):
                r, g, b = image.getpixel((x, y))
                r = (r & ~1) | int(binary_message[index])
                index += 1
                encoded.putpixel((x, y), (r, g, b))
    return encoded#Loops through every pixel in the image(use bitwise opertor for logic)



#Image Encryption
def lsb_decode(image):
    binary_message = ''
    for y in range(image.size[1]):
        for x in range(image.size[0]):
            r, g, b = image.getpixel((x, y))
            binary_message += str(r & 1)#Reads the LSB from each pixel.
    message = ''
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i+8]
        char = chr(int(byte, 2))
        if char == chr(0):
            break
        message += char
    return message#Converts each byte to a character.

@app.route('/encrypt/image', methods=['POST'])
def encrypt_image():
    image_file = request.files['image']
    message = request.form['message']
    recipient = request.form.get('recipient', '').strip()#The uploaded image

    if recipient:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT public_key FROM users WHERE username = ?", (recipient,))
        result = c.fetchone()
        conn.close()#Looks up their public key from the database

        if not result:
            return "Recipient not found."
        recipient_pubkey = serialization.load_pem_public_key(result[0].encode('utf-8'))
        encrypted_message = recipient_pubkey.encrypt(
            message.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        final_message = base64.b64encode(encrypted_message).decode()
    else:
        final_message = base64.b64encode(message.encode()).decode()#Encrypts the message using RSA

    image = Image.open(image_file)
    encoded = lsb_encode(image, final_message)
    path = os.path.join(UPLOAD_FOLDER, 'encrypted_image.png')
    encoded.save(path)
    return send_file(path, as_attachment=True)#Saves and returns the modified image.


#Image Decryption
@app.route('/decrypt/image', methods=['POST'])
def decrypt_image():
    image_file = request.files['image']
    image = Image.open(image_file)
    hidden_message = lsb_decode(image)#Loads uploaded image &Decodes the hidden message using LSB

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT private_key FROM users WHERE username = ?", (session['username'],))
    result = c.fetchone()
    conn.close()

    private_key = serialization.load_pem_private_key(result[0].encode(), password=None)
    try:
        decrypted = private_key.decrypt(
            base64.b64decode(hidden_message),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        ).decode()
        return jsonify({'message': decrypted})
    except:
        try:
            return jsonify({'message': base64.b64decode(hidden_message).decode()})
        except Exception as e:
            return jsonify({'error': str(e)})

# Audio
def encode_audio(audio_path, message, out_path):
    with wave.open(audio_path, 'rb') as song:
        frames = bytearray(list(song.readframes(song.getnframes())))
        binary = ''.join([format(ord(c), '08b') for c in message + chr(0)])
        if len(binary) > len(frames):
            raise ValueError("Message too large to encode in the selected audio file.")
        for i in range(len(binary)):
            frames[i] = (frames[i] & ~1) | int(binary[i])
        with wave.open(out_path, 'wb') as output:
            output.setparams(song.getparams())
            output.writeframes(frames)
#Audio Encryption only WAV not mp3 because of LSB(least significant bit)
@app.route('/encrypt/audio', methods=['POST'])
def encrypt_audio():
    audio = request.files['audio']
    message = request.form['message']
    if not audio.filename.lower().endswith('.wav'):
        return "Only uncompressed WAV audio files are supported."
    path = os.path.join(UPLOAD_FOLDER, 'input.wav')
    out_path = os.path.join(UPLOAD_FOLDER, 'encrypted_audio.wav')
    audio.save(path)
    try:
        encode_audio(path, message, out_path)
    except Exception as e:
        return f"Error: {str(e)}"
    return send_file(out_path, as_attachment=True)
#Audio decrypt
@app.route('/decrypt/audio', methods=['POST'])
def decrypt_audio():
    file = request.files['audio']
    if not file.filename.lower().endswith('.wav'):
        return "Only WAV files supported."
    with wave.open(file, 'rb') as song:
        frames = bytearray(list(song.readframes(song.getnframes())))
        binary = ''.join([str(f & 1) for f in frames])
        message = ''
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            char = chr(int(byte, 2))
            if char == chr(0):
                break
            message += char
    return jsonify({'message': message})

#Video

def embed_message_in_frame(frame, binary_message, index):
    h, w, _ = frame.shape
    for y in range(h):
        for x in range(w):
            if index >= len(binary_message):
                return frame, index
            pixel_val = frame[y, x, 0]  # Blue channel
            frame[y, x, 0] = np.uint8((int(pixel_val) & 0b11111110) | int(binary_message[index]))
            index += 1
    return frame, index
#Encryption only WAV not mp4 because of LSB(least significant bit)
@app.route('/encrypt/video', methods=['POST'])
def encrypt_video():
    video = request.files['video']
    message = request.form['message'] + chr(0)  # Null terminator
    binary_message = ''.join([format(ord(c), '08b') for c in message])

    input_path = os.path.join(UPLOAD_FOLDER, secure_filename(video.filename))
    video.save(input_path)

    cap = cv2.VideoCapture(input_path)
    frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = int(cap.get(cv2.CAP_PROP_FPS))

    total_capacity = frame_count * frame_width * frame_height
    if len(binary_message) > total_capacity:
        return "Message too long to hide in this video."

    fourcc = cv2.VideoWriter_fourcc(*'FFV1')  # Lossless codec
    output_path = os.path.join(UPLOAD_FOLDER, 'encrypted_video.avi')
    out = cv2.VideoWriter(output_path, fourcc, fps, (frame_width, frame_height))

    if not out.isOpened():
        return "Video writer failed to initialize."

    idx = 0
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret or frame is None:
            break
        frame, idx = embed_message_in_frame(frame, binary_message, idx)
        out.write(frame)

    cap.release()
    out.release()

    return send_file(output_path, as_attachment=True)
#Audio Decryption
@app.route('/decrypt/video', methods=['POST'])
def decrypt_video():
    video = request.files['video']
    filename = secure_filename(video.filename)
    path = os.path.join(UPLOAD_FOLDER, filename)
    video.save(path)

    cap = cv2.VideoCapture(path)
    binary = ''
    message = ''
    stop = False

    while cap.isOpened() and not stop:
        ret, frame = cap.read()
        if not ret or frame is None:
            break
        h, w, _ = frame.shape
        for y in range(h):
            for x in range(w):
                binary += str(frame[y, x, 0] & 1)
                if len(binary) >= 8:
                    byte = binary[:8]
                    binary = binary[8:]
                    char = chr(int(byte, 2))
                    if char == chr(0):
                        stop = True
                        break
                    message += char
            if stop:
                break

    cap.release()
    return jsonify({'message': message})

#Main
if __name__ == '__main__':
    app.run(debug=True)