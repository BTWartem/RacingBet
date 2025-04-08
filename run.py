from app import create_app

app = create_app()


@app.cli.command('create-admin')
def create_admin():
    """Создание администратора"""
    from app.models import User
    from werkzeug.security import generate_password_hash
    from decimal import Decimal
    from app.extensions import db

    username = input("Введите логин администратора: ")
    password = input("Введите пароль администратора: ")

    if User.query.filter_by(username=username).first():
        print("Пользователь уже существует!")
        return

    admin = User(
        username=username,
        password_hash=generate_password_hash(password),
        is_admin=True,
        balance=Decimal('10000.00'))

    db.session.add(admin)
    db.session.commit()
    print(f"Администратор {username} создан!")


if __name__ == '__main__':
    app.run(debug=False)