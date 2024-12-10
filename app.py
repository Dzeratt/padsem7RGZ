from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2

app = Flask(__name__)
app.config['SECRET_KEY'] = '312'

limiter = Limiter(get_remote_address, app=app)
login_manager = LoginManager(app)


def get_db_connection():
    return psycopg2.connect(
        dbname="padsem7rgz",
        user="web_rgz",
        password="123",
        host="localhost"
    )


class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cur.fetchone()
        conn.close()
        if user_data:
            return User(user_data[0], user_data[1], user_data[2])
        return None

    @staticmethod
    def get_by_id(user_id):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user_data = cur.fetchone()
        conn.close()
        if user_data:
            return User(user_data[0], user_data[1], user_data[2])
        return None


@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)


login_manager.login_view = 'login'


@app.route('/')
@login_required
def home():
    return redirect(url_for('get_articles'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.get_by_username(username):
            flash('Такой пользователь уже есть', 'error')
            return redirect(url_for('register'))

        password_hash = generate_password_hash(password)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, password_hash))
        conn.commit()
        conn.close()
        flash('Вы успешно зарегестрировались', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per 5 minutes", key_func=lambda: f"user:{request.form.get('username', '')}")
@limiter.limit("10 per 15 minutes", key_func=get_remote_address)
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.get_by_username(username)
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('get_articles'))
        flash('Неправильный логин или пароль', 'error')
    return render_template('login.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/articles/create', methods=['GET', 'POST'])
@login_required
def create_article():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO articles (title, content, author_id) VALUES (%s, %s, %s)",
                    (title, content, current_user.id))
        conn.commit()
        conn.close()
        flash('Статья успешно создана', 'success')
        return redirect(url_for('get_articles'))
    return render_template('create_article.html')


@app.route('/articles')
def get_articles():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM articles")
    articles = cur.fetchall()
    conn.close()
    return render_template('articles.html', articles=articles)


@app.route('/articles/<int:article_id>')
def get_article(article_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM articles WHERE id = %s", (article_id,))
    article = cur.fetchone()
    conn.close()
    if not article:
        flash('Такой статьи не существует', 'error')
    return render_template('article_detail.html', article=article)


@app.route('/articles/<int:article_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_article(article_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM articles WHERE id = %s", (article_id,))
    article = cur.fetchone()
    conn.close()

    if not article:
        flash('Такой статьи не существует', 'error')

    if article[3] != current_user.id:  # article[3] - это ID автора статьи
        flash('Вы не автор этой статьи', 'error')
        return redirect(url_for('get_articles'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE articles SET title = %s, content = %s WHERE id = %s", (title, content, article_id))
        conn.commit()
        conn.close()
        flash('Статья успешно изменена', 'success')
        return redirect(url_for('get_article', article_id=article_id))

    return render_template('edit_article.html', article=article)


@app.route('/articles/delete/<int:article_id>', methods=['POST'])
@login_required
def delete_article(article_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM articles WHERE id = %s", (article_id,))
    article = cur.fetchone()

    if not article or article[3] != current_user.id:
        flash('У вас нет прав на удаление этой статьи', 'error')
        return redirect(url_for('get_articles'))

    cur.execute("DELETE FROM articles WHERE id = %s", (article_id,))
    conn.commit()
    conn.close()
    flash('Article deleted successfully', 'success')
    return redirect(url_for('get_articles'))


@app.route('/comments', methods=['POST'])
@login_required
def add_comment():
    article_id = request.form['article_id']
    comment_text = request.form['comment_text']

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO comments (article_id, author_id, content) VALUES (%s, %s, %s)",
                (article_id, current_user.id, comment_text))
    conn.commit()
    conn.close()

    flash('Комментарий успешно добавлен', 'success')
    return redirect(url_for('get_article', article_id=article_id))


if __name__ == '__main__':
    app.run(debug=True)
