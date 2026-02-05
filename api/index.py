"""
Главное приложение для Vercel
"""
import os
import sys
import json
import tempfile
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
import random
import string

# Добавляем корневую директорию в путь Python
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
sys.path.insert(0, root_dir)

# Импортируем модели из корня
from models import db, User, Transaction, generate_passport_number, generate_account_number

# Настройки Flask для Vercel
app = Flask(__name__,
            static_folder=os.path.join(root_dir, 'static'),
            template_folder=os.path.join(root_dir, 'templates'),
            static_url_path='/static')

# Конфигурация
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-for-vercel-2024')

# Настройка базы данных для Vercel
if os.environ.get('VERCEL'):
    # На Vercel используем SQLite во временной директории /tmp
    db_path = os.path.join(tempfile.gettempdir(), 'federation.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    print(f"✅ Vercel: Используется SQLite в {db_path}")
    
    # Также можно использовать PostgreSQL от Supabase
    DATABASE_URL = os.environ.get('DATABASE_URL')
    if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
        app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
        print("✅ Vercel: Используется PostgreSQL от Supabase")
else:
    # Локальная разработка
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///federation.db'
    print("✅ Локальная разработка с SQLite")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация базы данных
db.init_app(app)

# Настройка Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Файл для хранения настроек (в памяти для Vercel)
SETTINGS_FILE = 'settings.json'

# Настройки по умолчанию
DEFAULT_SETTINGS = {
    'system_name': 'Дворовая Федерация',
    'currency_name': 'дубли',
    'initial_balance': 100.0,
    'allow_self_transfers': False,
    'min_transfer_amount': 0.01,
    'max_transfer_amount': 10000.0,
    'transfer_fee_percent': 0.0,
    'max_users': 100,
    'maintenance_mode': False,
    'require_passport_for_registration': True,
    'show_balance_to_all': False,
    'transaction_history_days': 365,
    'backup_interval_days': 7,
    'system_notifications': True,
    'email_notifications': False,
    'sms_notifications': False,
    'welcome_message': 'Добро пожаловать в Дворовую Федерацию!',
    'terms_of_service': 'Правила Федерации',
    'admin_email': 'admin@dvorovaya-federatsiya.local',
    'support_phone': '+7 (XXX) XXX-XX-XX',
    'system_version': '1.0.0'
}

# Загрузка настроек
def load_settings():
    """Загрузка настроек из файла (для Vercel используем переменные окружения)"""
    if os.environ.get('VERCEL'):
        # На Vercel используем JSON из переменной окружения или значения по умолчанию
        settings_json = os.environ.get('APP_SETTINGS')
        if settings_json:
            try:
                return json.loads(settings_json)
            except:
                pass
        return DEFAULT_SETTINGS.copy()
    else:
        # Локально из файла
        try:
            if os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except:
            pass
        return DEFAULT_SETTINGS.copy()

def save_settings(settings):
    """Сохранение настроек (на Vercel только в памяти)"""
    if os.environ.get('VERCEL'):
        # На Vercel не сохраняем на диск
        print("⚠️ Настройки не сохраняются на Vercel (используйте переменные окружения)")
        return True
    else:
        # Локально в файл
        try:
            with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
                json.dump(settings, f, ensure_ascii=False, indent=2)
            return True
        except:
            return False

# Загружаем настройки
system_settings = load_settings()

# Вспомогательные функции
def get_recent_transactions(user_account_number, limit=5):
    """Получение последних транзакций пользователя"""
    return Transaction.query.filter(
        (Transaction.from_account == user_account_number) |
        (Transaction.to_account == user_account_number)
    ).order_by(Transaction.timestamp.desc()).limit(limit).all()

# ==================== МАРШРУТЫ ====================

@app.route('/')
def index():
    """Главная страница"""
    users_count = User.query.count()
    transactions_count = Transaction.query.count()
    return render_template('index.html', 
                          users_count=users_count,
                          transactions_count=transactions_count,
                          settings=system_settings)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Страница входа"""
    if system_settings.get('maintenance_mode', False) and not current_user.is_authenticated:
        flash('Система находится на техническом обслуживании', 'error')
        return render_template('login.html', settings=system_settings)
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash(f'Добро пожаловать, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Неверный логин или пароль', 'error')
    
    return render_template('login.html', settings=system_settings)

@app.route('/logout')
@login_required
def logout():
    """Выход из системы"""
    logout_user()
    flash('Вы успешно вышли из системы', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Личный кабинет"""
    return render_template('dashboard.html', user=current_user, settings=system_settings)

@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    """Регистрация нового пользователя"""
    if not current_user.is_admin:
        flash('Только администраторы могут регистрировать новых пользователей', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        initial_balance = float(request.form.get('initial_balance', system_settings.get('initial_balance', 100)))
        
        # Проверка максимального количества пользователей
        if User.query.count() >= system_settings.get('max_users', 100):
            flash(f'Достигнут лимит пользователей: {system_settings.get("max_users", 100)}', 'error')
            return render_template('register.html', settings=system_settings)
        
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким логином уже существует', 'error')
            return render_template('register.html', settings=system_settings)
        
        # Генерируем уникальные номера
        passport_number = generate_passport_number()
        account_number = generate_account_number()
        
        # Проверяем уникальность
        while User.query.filter_by(passport_number=passport_number).first():
            passport_number = generate_passport_number()
        
        while User.query.filter_by(account_number=account_number).first():
            account_number = generate_account_number()
        
        # Создаем пользователя
        user = User(
            username=username,
            passport_number=passport_number,
            account_number=account_number,
            balance=initial_balance
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Создаем системную транзакцию для начального баланса
        if initial_balance > 0:
            transaction = Transaction(
                from_account='SYSTEM',
                to_account=account_number,
                amount=initial_balance,
                description=f'Начальный баланс при регистрации'
            )
            db.session.add(transaction)
            db.session.commit()
        
        flash(f'Пользователь {username} успешно зарегистрирован!', 'success')
        flash(f'Паспорт: {passport_number}, Счет: {account_number}, Баланс: {initial_balance} {system_settings.get("currency_name", "дублей")}', 'info')
        return redirect(url_for('user_detail', user_id=user.id))
    
    return render_template('register.html', settings=system_settings)

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    """Перевод средств"""
    if system_settings.get('maintenance_mode', False):
        flash('Переводы временно недоступны. Система на обслуживании', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        to_account = request.form['to_account']
        amount = request.form['amount']
        description = request.form.get('description', '')
        
        # Проверка ввода
        try:
            amount = float(amount)
            if amount <= 0:
                flash('Сумма должна быть положительной', 'error')
                return render_template('transfer.html', 
                                     recent_transactions=get_recent_transactions(current_user.account_number),
                                     settings=system_settings)
        except ValueError:
            flash('Неверный формат суммы', 'error')
            return render_template('transfer.html', 
                                 recent_transactions=get_recent_transactions(current_user.account_number),
                                 settings=system_settings)
        
        # Проверка минимальной и максимальной суммы
        min_amount = system_settings.get('min_transfer_amount', 0.01)
        max_amount = system_settings.get('max_transfer_amount', 10000.0)
        
        if amount < min_amount:
            flash(f'Минимальная сумма перевода: {min_amount} {system_settings.get("currency_name", "дублей")}', 'error')
            return render_template('transfer.html',
                                 recent_transactions=get_recent_transactions(current_user.account_number),
                                 settings=system_settings)
        
        if amount > max_amount:
            flash(f'Максимальная сумма перевода: {max_amount} {system_settings.get("currency_name", "дублей")}', 'error')
            return render_template('transfer.html',
                                 recent_transactions=get_recent_transactions(current_user.account_number),
                                 settings=system_settings)
        
        # Проверки
        if current_user.balance < amount:
            flash('Недостаточно средств', 'error')
            return render_template('transfer.html', 
                                 recent_transactions=get_recent_transactions(current_user.account_number),
                                 settings=system_settings)
        
        if to_account == current_user.account_number and not system_settings.get('allow_self_transfers', False):
            flash('Нельзя переводить самому себе', 'error')
            return render_template('transfer.html', 
                                 recent_transactions=get_recent_transactions(current_user.account_number),
                                 settings=system_settings)
        
        recipient = User.query.filter_by(account_number=to_account).first()
        if not recipient:
            flash('Счет получателя не найден', 'error')
            return render_template('transfer.html', 
                                 recent_transactions=get_recent_transactions(current_user.account_number),
                                 settings=system_settings)
        
        # Расчет комиссии
        fee_percent = system_settings.get('transfer_fee_percent', 0.0)
        fee_amount = amount * (fee_percent / 100)
        net_amount = amount - fee_amount
        
        # Выполнение транзакции
        current_user.balance -= amount
        recipient.balance += net_amount
        
        # Если есть комиссия, зачисляем её на системный счет
        if fee_amount > 0:
            system_user = User.query.filter_by(username='SYSTEM').first()
            if not system_user:
                # Создаем системного пользователя для комиссий
                system_user = User(
                    username='SYSTEM',
                    passport_number='DFP00000000',
                    account_number='SYSTEM',
                    balance=0,
                    is_admin=False
                )
                system_user.set_password('system_password')
                db.session.add(system_user)
            
            system_user.balance += fee_amount
        
        # Основная транзакция
        transaction = Transaction(
            from_account=current_user.account_number,
            to_account=to_account,
            amount=net_amount,
            description=description
        )
        db.session.add(transaction)
        
        # Транзакция комиссии (если есть)
        if fee_amount > 0:
            fee_transaction = Transaction(
                from_account=current_user.account_number,
                to_account='SYSTEM',
                amount=fee_amount,
                description=f'Комиссия за перевод ({fee_percent}%)'
            )
            db.session.add(fee_transaction)
        
        db.session.commit()
        
        flash(f'Успешно переведено {net_amount} {system_settings.get("currency_name", "дублей")} на счет {to_account}' + 
              (f' (комиссия: {fee_amount} {system_settings.get("currency_name", "дублей")})' if fee_amount > 0 else ''), 'success')
        return redirect(url_for('dashboard'))
    
    # GET запрос
    return render_template('transfer.html', 
                         recent_transactions=get_recent_transactions(current_user.account_number),
                         settings=system_settings)

@app.route('/transactions')
@login_required
def transactions():
    """История транзакций"""
    user_transactions = Transaction.query.filter(
        (Transaction.from_account == current_user.account_number) |
        (Transaction.to_account == current_user.account_number)
    ).order_by(Transaction.timestamp.desc()).all()
    
    # Расчет статистики
    total_incoming = sum(t.amount for t in user_transactions 
                        if t.to_account == current_user.account_number)
    total_outgoing = sum(t.amount for t in user_transactions 
                        if t.from_account == current_user.account_number)
    
    return render_template('transactions.html', 
                          transactions=user_transactions,
                          total_incoming=total_incoming,
                          total_outgoing=total_outgoing,
                          settings=system_settings)

@app.route('/admin')
@login_required
def admin():
    """Административная панель"""
    if not current_user.is_admin:
        flash('Доступ запрещен', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    all_transactions = Transaction.query.order_by(Transaction.timestamp.desc()).limit(50).all()
    
    # Статистика для админ-панели
    total_balance = db.session.query(db.func.sum(User.balance)).scalar() or 0
    avg_balance = total_balance / len(users) if users else 0
    admin_count = User.query.filter_by(is_admin=True).count()
    total_turnover = db.session.query(db.func.sum(Transaction.amount)).scalar() or 0
    system_transactions = Transaction.query.filter_by(from_account='SYSTEM').count()
    
    return render_template('admin.html', 
                          users=users, 
                          transactions=all_transactions,
                          total_balance=total_balance,
                          avg_balance=round(avg_balance, 2),
                          admin_count=admin_count,
                          total_turnover=total_turnover,
                          system_transactions=system_transactions,
                          settings=system_settings)

@app.route('/admin/add_funds', methods=['POST'])
@login_required
def add_funds():
    """Пополнение баланса пользователя"""
    if not current_user.is_admin:
        return jsonify({'error': 'Доступ запрещен'}), 403
    
    account_number = request.form['account_number']
    amount = float(request.form['amount'])
    reason = request.form.get('reason', 'Пополнение администратором')
    
    user = User.query.filter_by(account_number=account_number).first()
    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404
    
    user.balance += amount
    
    # Записываем системную транзакцию
    transaction = Transaction(
        from_account='SYSTEM',
        to_account=account_number,
        amount=amount,
        description=reason
    )
    
    db.session.add(transaction)
    db.session.commit()
    
    return jsonify({'success': True, 'new_balance': user.balance})

@app.route('/admin/set_admin', methods=['POST'])
@login_required
def set_admin():
    """Назначение/снятие администратора"""
    if not current_user.is_admin:
        return jsonify({'error': 'Доступ запрещен'}), 403
    
    user_id = request.form['user_id']
    is_admin = request.form['is_admin'] == 'true'
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404
    
    user.is_admin = is_admin
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/admin/reset_password', methods=['POST'])
@login_required
def reset_password():
    """Сброс пароля пользователя"""
    if not current_user.is_admin:
        return jsonify({'error': 'Доступ запрещен'}), 403
    
    user_id = request.form['user_id']
    new_password = request.form['new_password']
    
    if len(new_password) < 6:
        return jsonify({'error': 'Пароль должен содержать минимум 6 символов'}), 400
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404
    
    user.set_password(new_password)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/user/<int:user_id>')
@login_required
def user_detail(user_id):
    """Детальная информация о пользователе"""
    user = User.query.get_or_404(user_id)
    
    if not current_user.is_admin and current_user.id != user_id:
        flash('Доступ запрещен', 'error')
        return redirect(url_for('dashboard'))
    
    # Получаем транзакции пользователя
    user_transactions = Transaction.query.filter(
        (Transaction.from_account == user.account_number) |
        (Transaction.to_account == user.account_number)
    ).order_by(Transaction.timestamp.desc()).limit(20).all()
    
    # Статистика
    total_incoming = sum(t.amount for t in user_transactions 
                        if t.to_account == user.account_number)
    total_outgoing = sum(t.amount for t in user_transactions 
                        if t.from_account == user.account_number)
    
    return render_template('user_detail.html', 
                          user=user, 
                          transactions=user_transactions,
                          total_incoming=total_incoming,
                          total_outgoing=total_outgoing,
                          settings=system_settings)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Настройки системы"""
    if not current_user.is_admin:
        flash('Доступ запрещен', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Обновляем настройки
        system_settings['system_name'] = request.form.get('system_name', system_settings['system_name'])
        system_settings['currency_name'] = request.form.get('currency_name', system_settings['currency_name'])
        system_settings['initial_balance'] = float(request.form.get('initial_balance', system_settings['initial_balance']))
        system_settings['allow_self_transfers'] = 'allow_self_transfers' in request.form
        system_settings['min_transfer_amount'] = float(request.form.get('min_transfer_amount', system_settings['min_transfer_amount']))
        system_settings['max_transfer_amount'] = float(request.form.get('max_transfer_amount', system_settings['max_transfer_amount']))
        system_settings['transfer_fee_percent'] = float(request.form.get('transfer_fee_percent', system_settings['transfer_fee_percent']))
        system_settings['max_users'] = int(request.form.get('max_users', system_settings['max_users']))
        system_settings['maintenance_mode'] = 'maintenance_mode' in request.form
        system_settings['require_passport_for_registration'] = 'require_passport_for_registration' in request.form
        system_settings['show_balance_to_all'] = 'show_balance_to_all' in request.form
        system_settings['transaction_history_days'] = int(request.form.get('transaction_history_days', system_settings['transaction_history_days']))
        system_settings['backup_interval_days'] = int(request.form.get('backup_interval_days', system_settings['backup_interval_days']))
        system_settings['system_notifications'] = 'system_notifications' in request.form
        system_settings['email_notifications'] = 'email_notifications' in request.form
        system_settings['sms_notifications'] = 'sms_notifications' in request.form
        system_settings['welcome_message'] = request.form.get('welcome_message', system_settings['welcome_message'])
        system_settings['terms_of_service'] = request.form.get('terms_of_service', system_settings['terms_of_service'])
        system_settings['admin_email'] = request.form.get('admin_email', system_settings['admin_email'])
        system_settings['support_phone'] = request.form.get('support_phone', system_settings['support_phone'])
        
        # Сохраняем настройки
        if save_settings(system_settings):
            flash('Настройки успешно сохранены', 'success')
        else:
            flash('Ошибка при сохранении настроек', 'error')
        
        return redirect(url_for('settings'))
    
    # Статистика для отображения
    users_count = User.query.count()
    
    return render_template('settings.html', 
                          settings=system_settings,
                          users_count=users_count,
                          active_today=0)

# API для проверки работоспособности
@app.route('/api/health')
def health():
    """Health check endpoint для Vercel"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'users': User.query.count(),
        'transactions': Transaction.query.count()
    }), 200

# Специальный маршрут для статических файлов
@app.route('/static/<path:filename>')
def serve_static(filename):
    """Обслуживание статических файлов"""
    return send_from_directory(app.static_folder, filename)

# Инициализация базы данных при запуске
with app.app_context():
    try:
        db.create_all()
        print("✅ База данных инициализирована")
        
        # Создаем тестового администратора, если база пустая
        if User.query.count() == 0:
            admin_user = User(
                username='admin',
                passport_number='DFP00000001',
                account_number='DF0000000001',
                balance=10000,
                is_admin=True
            )
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            
            # Создаем системного пользователя
            system_user = User(
                username='SYSTEM',
                passport_number='DFP00000000',
                account_number='SYSTEM',
                balance=0,
                is_admin=False
            )
            system_user.set_password('system_password')
            db.session.add(system_user)
            
            db.session.commit()
            print("✅ Создан администратор: логин=admin, пароль=admin123")
            
    except Exception as e:
        print(f"❌ Ошибка инициализации БД: {e}")

# Функция для Vercel Serverless
def handler(event, context):
    """Обработчик для Vercel Serverless"""
    from flask import request as req
    
    # Создаем WSGI-приложение
    from werkzeug.wrappers import Response
    from werkzeug.serving import run_simple
    
    # В Vercel используем готовый WSGI app
    return app