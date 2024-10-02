from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import sqlite3
import pandas as pd

app = Flask(__name__)
app.secret_key = 'chave_super_secreta'  # Substitua por uma chave secreta

bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Função para conectar ao banco de dados
def get_db_connection():
    conn = sqlite3.connect('viagens.db')
    conn.row_factory = sqlite3.Row
    return conn

# Criação das tabelas de usuários e registros
def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS registros_principais (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            referencia TEXT NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS entradas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            registro_principal_id INTEGER,
            data TEXT NOT NULL,
            dia_semana TEXT NOT NULL,
            cidade TEXT NOT NULL,
            responsavel TEXT NOT NULL,
            horario TEXT NOT NULL,
            descricao TEXT NOT NULL,
            tempo_conducao TEXT NOT NULL,
            observacoes TEXT,
            FOREIGN KEY (registro_principal_id) REFERENCES registros_principais(id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            username TEXT NOT NULL,
            senha TEXT NOT NULL
        )
    ''')

    # Inserir os usuários pré-definidos (Simone, Marcelo, Anna, Italo)
    users = [
        ('Simone', 'simone', bcrypt.generate_password_hash('senha123').decode('utf-8')),
        ('Marcelo', 'marcelo', bcrypt.generate_password_hash('senha123').decode('utf-8')),
        ('Anna', 'anna', bcrypt.generate_password_hash('senha123').decode('utf-8')),
        ('Italo', 'italo', bcrypt.generate_password_hash('senha123').decode('utf-8'))
    ]
    
    conn.executemany('INSERT INTO usuarios (nome, username, senha) VALUES (?, ?, ?)', users)
    conn.commit()
    conn.close()

# Inicializa o banco de dados
init_db()

# Modelo de usuário para o Flask-Login
class User(UserMixin):
    def __init__(self, id, nome, username):
        self.id = id
        self.nome = nome
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM usuarios WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(id=user['id'], nome=user['nome'], username=user['username'])
    return None

# Rota de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        senha = request.form['senha']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM usuarios WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and bcrypt.check_password_hash(user['senha'], senha):
            user_obj = User(id=user['id'], nome=user['nome'], username=user['username'])
            login_user(user_obj)
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('index'))  # Redireciona para a página principal
        else:
            flash('Nome de usuário ou senha incorretos', 'danger')
    
    return render_template('login.html')

# Rota de logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu da sessão.', 'info')
    return redirect(url_for('login'))

# Rota principal com login obrigatório
@app.route('/')
@login_required
def index():
    conn = get_db_connection()
    entradas = conn.execute('SELECT * FROM entradas ORDER BY data').fetchall()
    conn.close()

    entradas_agrupadas = {}
    for entrada in entradas:
        data = entrada['data']
        if data not in entradas_agrupadas:
            entradas_agrupadas[data] = []
        entradas_agrupadas[data].append(entrada)

    return render_template('form.html', entradas_agrupadas=entradas_agrupadas, user=current_user)

# Demais rotas para adicionar, excluir e exportar entradas continuam as mesmas
@app.route('/add_entrada', methods=['POST'])
@login_required
def add_entrada():
    if request.method == 'POST':
        data = request.form['data']
        dia_semana = request.form['dia_semana']
        cidade = request.form['cidade']
        responsavel = request.form['responsavel']
        horario = request.form['horario']
        descricao = request.form['descricao']
        tempo_conducao = request.form['tempo_conducao']
        observacoes = request.form['observacoes']
        referencia = request.form['referencia']

        conn = get_db_connection()
        # Verifica se já existe um registro principal com a mesma referência
        registro_principal = conn.execute('SELECT * FROM registros_principais WHERE referencia = ?', (referencia,)).fetchone()

        if not registro_principal:
            conn.execute('INSERT INTO registros_principais (referencia) VALUES (?)', (referencia,))
            conn.commit()
            registro_principal = conn.execute('SELECT * FROM registros_principais WHERE referencia = ?', (referencia,)).fetchone()

        registro_principal_id = registro_principal['id']

        conn.execute('''
            INSERT INTO entradas (registro_principal_id, data, dia_semana, cidade, responsavel, horario, descricao, tempo_conducao, observacoes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (registro_principal_id, data, dia_semana, cidade, responsavel, horario, descricao, tempo_conducao, observacoes))
        conn.commit()
        conn.close()

        flash('Entrada adicionada com sucesso!', 'success')
        return redirect(url_for('index'))  # Redireciona para a página principal após adicionar a entrada

if __name__ == '__main__':
    app.run(debug=True)
