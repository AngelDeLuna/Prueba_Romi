"""
Base de datos local con SQLite para un sistema de login simple.
Este script permite registrar usuarios, iniciar sesión y verificar contraseñas de forma segura.
Usa PBKDF2 para el hashing de contraseñas y Tkinter para la interfaz gráfica.
"""
# Librerias
import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import hashlib
import secrets
from datetime import datetime


DB_FILENAME = "users.db"
PBKDF2_ITERATIONS = 100_000

# ----------------------------------------------------------
# En la base solo hay este usuario de ejemplo:
# Nombre: "Demo User"
# Email: "Prueba@gmail.com"
# Contraseña: "demo123"


# ----------------------------------------------------------
# Funciones de seguridad / BD, Logica de programacion
# ----------------------------------------------------------

#Funcion para inicializar la base de datos y crear la tabla de usuarios
def init_db():
    conn = sqlite3.connect(DB_FILENAME)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name_may TEXT NOT NULL,
        name_min TEXT NOT NULL UNIQUE,
        email_may TEXT NOT NULL UNIQUE,
        email_min TEXT NOT NULL UNIQUE,
        salt TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

#Función para hashear contraseñas de forma segura
def hash_password(password: str, salt_hex: str = None):
    #Se crea un salt aleatorio si no se proporciona
    if salt_hex is None:
        salt_hex = secrets.token_hex(16)
    salt_bytes = bytes.fromhex(salt_hex)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, PBKDF2_ITERATIONS)
    return salt_hex, pwd_hash.hex()

#Función para registrar un nuevo usuario
def register_user(name: str, email: str, password: str):
    name = name.strip()
    email = email.strip().lower()
    name_lower = name.lower()
    salt, pwd_hash = hash_password(password)
    created_at = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_FILENAME)
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO users (name_may, name_min, email_may, email_min, salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (name, name_lower, email, email, salt, pwd_hash, created_at)
        )
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        # Si hay un nombre o correo duplicado se lanza un error
        raise ValueError("El nombre o el correo ya están registrados.") from e
    conn.close()

#Función para buscar un usuario por nombre o correo en la base de datos
def find_user_by_identifier(identifier: str):
    ident = identifier.strip().lower()
    conn = sqlite3.connect(DB_FILENAME)
    c = conn.cursor()
    # Intruccion Where para buscar por nombre o correo en minusculas
    c.execute("SELECT id, name_may, email_may, salt, password_hash FROM users WHERE name_min = ? OR email_min = ?", (ident, ident))
    #fetchall devuelve una lista completa, pero solo se necesita una fila
    row = c.fetchone()
    conn.close()
    if row:
        return {
            "id": row[0],
            "name": row[1],
            "email": row[2],
            "salt": row[3],
            "password_hash": row[4]
        }
    return None

#Función para verificar la contraseña proporcionada contra el hash almacenado
def verify_password(stored_salt_hex: str, stored_hash_hex: str, provided_password: str) -> bool:
    _, computed_hash = hash_password(provided_password, salt_hex=stored_salt_hex)
    # comparación en tiempo normalizado para evitar ataques de temporización
    return computed_hash == stored_hash_hex

# --------------------------
# Interfaz gráfica (Realizada con Tkinter)
# --------------------------
# Esta clase maneja la ventana principal de inicio de sesión
class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login - Demo")
        self.root.resizable(False, False)
        self.build_login_ui()

    def build_login_ui(self):
        pad = 10
        frm = ttk.Frame(self.root, padding=pad)
        frm.grid(row=0, column=0)

        ttk.Label(frm, text="Iniciar sesión", font=("Helvetica", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=(0,8))

        ttk.Label(frm, text="Nombre o correo:").grid(row=1, column=0, sticky="e")
        self.entry_identifier = ttk.Entry(frm, width=30)
        self.entry_identifier.grid(row=1, column=1, pady=4)

        ttk.Label(frm, text="Contraseña:").grid(row=2, column=0, sticky="e")
        self.entry_password = ttk.Entry(frm, width=30, show="*")
        self.entry_password.grid(row=2, column=1, pady=4)

        btn_login = ttk.Button(frm, text="Entrar", command=self.on_login)
        btn_login.grid(row=3, column=0, columnspan=2, pady=(8,4))

        # Enlace a registro
        link_register = ttk.Label(frm, text="¿No tienes cuenta? Regístrate", foreground="blue", cursor="hand2")
        link_register.grid(row=4, column=0, columnspan=2)
        link_register.bind("<Button-1>", lambda e: self.open_register_window())

        # Al dar Enter se puede iniciar sesión
        self.root.bind("<Return>", lambda e: self.on_login())

    # Método que maneja el evento de inicio de sesión
    # Este método verifica los datos ingresados y muestra mensajes de error o realizado
    def on_login(self):
        identifier = self.entry_identifier.get().strip()
        password = self.entry_password.get()
        if not identifier or not password:
            messagebox.showwarning("Faltan datos", "Por favor ingresa nombre/correo y contraseña.")
            return

        user = find_user_by_identifier(identifier)
        if user is None:
            messagebox.showerror("Error", "Usuario o correo no encontrado.")
            return

        if verify_password(user["salt"], user["password_hash"], password):
            # si la contraseña es correcta, se abre la ventana de éxito
            self.open_success_window(user["name"])
            # Se limpian los campos de entrada 
            self.entry_password.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "Contraseña incorrecta.")

    def open_register_window(self):
        RegisterWindow(self.root)

    def open_success_window(self, display_name):
        SuccessWindow(self.root, display_name)

# Esta clase maneja la ventana de registro de nuevos usuarios
class RegisterWindow:
    def __init__(self, master):
        self.win = tk.Toplevel(master)
        self.win.title("Registro - Crear cuenta")
        self.win.resizable(False, False)
        self.build_ui()

    def build_ui(self):
        pad = 10
        frm = ttk.Frame(self.win, padding=pad)
        frm.grid(row=0, column=0)

        ttk.Label(frm, text="Registro", font=("Helvetica", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=(0,8))

        ttk.Label(frm, text="Nombre (visible):").grid(row=1, column=0, sticky="e")
        self.entry_name = ttk.Entry(frm, width=30)
        self.entry_name.grid(row=1, column=1, pady=4)

        ttk.Label(frm, text="Correo:").grid(row=2, column=0, sticky="e")
        self.entry_email = ttk.Entry(frm, width=30)
        self.entry_email.grid(row=2, column=1, pady=4)

        ttk.Label(frm, text="Contraseña:").grid(row=3, column=0, sticky="e")
        self.entry_pwd = ttk.Entry(frm, width=30, show="*")
        self.entry_pwd.grid(row=3, column=1, pady=4)

        ttk.Label(frm, text="Confirmar contraseña:").grid(row=4, column=0, sticky="e")
        self.entry_pwd2 = ttk.Entry(frm, width=30, show="*")
        self.entry_pwd2.grid(row=4, column=1, pady=4)

        btn = ttk.Button(frm, text="Crear cuenta", command=self.on_create)
        btn.grid(row=5, column=0, columnspan=2, pady=(8,4))

    def on_create(self):
        name = self.entry_name.get().strip()
        email = self.entry_email.get().strip()
        pwd = self.entry_pwd.get()
        pwd2 = self.entry_pwd2.get()

        if not name or not email or not pwd or not pwd2:
            messagebox.showwarning("Faltan datos", "Rellena todos los campos.")
            return
        if "@" not in email or "." not in email:
            messagebox.showwarning("Correo inválido", "Introduce un correo válido.")
            return
        if len(pwd) < 6:
            messagebox.showwarning("Contraseña débil", "La contraseña debe tener al menos 6 caracteres.")
            return
        if pwd != pwd2:
            messagebox.showwarning("Contraseñas distintas", "Las contraseñas no coinciden.")
            return
        
        # Intentar registrar al usuario con la función definida
        # Si ocurre un error, se captura y muestra un mensaje
        try:
            register_user(name, email, pwd)
        except ValueError as ve:
            messagebox.showerror("Error", str(ve))
            return
        except Exception as e:
            messagebox.showerror("Error", f"Ocurrió un error: {e}")
            return

        messagebox.showinfo("Registro completo", "Tu cuenta ha sido creada. Ahora puedes iniciar sesión.")
        self.win.destroy()

# Esta clase maneja la ventana de éxito al iniciar sesión 
# Solo se muestra un mensaje de bienvenida y el nombre del usuario
class SuccessWindow:
    def __init__(self, master, display_name):
        self.win = tk.Toplevel(master)
        self.win.title("¡Bienvenido!")
        self.win.resizable(False, False)
        self.display_name = display_name
        self.build_ui()

    def build_ui(self):
        pad = 12
        frm = ttk.Frame(self.win, padding=pad)
        frm.grid(row=0, column=0)
        ttk.Label(frm, text="¡Felicidades, iniciaste sesión!", font=("Helvetica", 14, "bold")).grid(row=0, column=0, pady=(0,6))
        ttk.Label(frm, text=f"Bienvenido, {self.display_name}", font=("Helvetica", 12)).grid(row=1, column=0, pady=(0,8))
        ttk.Button(frm, text="Cerrar sesión", command=self.win.destroy).grid(row=2, column=0)

# --------------------------
# Main
# --------------------------
def main():
    init_db()
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
