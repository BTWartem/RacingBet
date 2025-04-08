from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from decimal import Decimal, InvalidOperation
import logging
from .extensions import db
from .models import User, Race, Bet
from .forms import RegistrationForm, LoginForm, RaceForm, BetForm, DepositForm

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    try:
        races = Race.query.filter_by(is_finished=False).order_by(Race.date.asc()).all()
        return render_template('index.html', races=races)
    except Exception as e:
        logger.error(f"Error loading races: {str(e)}", exc_info=True)
        flash('Ошибка загрузки заездов. Пожалуйста, попробуйте позже.', 'danger')
        return render_template('index.html', races=[])


@main_bp.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('user_id'):
        return redirect(url_for('main.index'))

    form = RegistrationForm()
    try:
        if form.validate_on_submit():
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user:
                flash('Пользователь с таким логином уже существует!', 'danger')
                return redirect(url_for('main.register'))

            new_user = User(
                username=form.username.data,
                password_hash=generate_password_hash(form.password.data),
                balance=Decimal('0.00')
            )

            db.session.add(new_user)
            db.session.commit()
            flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
            return redirect(url_for('main.login'))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error: {str(e)}", exc_info=True)
        flash('Ошибка регистрации. Пожалуйста, попробуйте позже.', 'danger')

    return render_template('register.html', form=form)


@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('main.index'))

    form = LoginForm()
    try:
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()

            if user and check_password_hash(user.password_hash, form.password.data):
                session['user_id'] = user.id
                session['username'] = user.username
                session['is_admin'] = user.is_admin
                flash('Вы успешно вошли в систему!', 'success')
                return redirect(url_for('main.index'))

            flash('Неверный логин или пароль!', 'danger')
    except Exception as e:
        logger.error(f"Login error: {str(e)}", exc_info=True)
        flash('Ошибка входа. Пожалуйста, попробуйте позже.', 'danger')

    return render_template('login.html', form=form)


@main_bp.route('/logout')
def logout():
    try:
        session.clear()
        flash('Вы вышли из системы.', 'info')
    except Exception as e:
        logger.error(f"Logout error: {str(e)}", exc_info=True)
        flash('Ошибка при выходе из системы', 'danger')
    return redirect(url_for('main.index'))


@main_bp.route('/profile')
def profile():
    if not session.get('user_id'):
        flash('Войдите в систему для просмотра профиля.', 'warning')
        return redirect(url_for('main.login'))

    try:
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            flash('Пользователь не найден', 'danger')
            return redirect(url_for('main.login'))

        status_filter = request.args.get('filter', 'all')
        bets_query = Bet.query.filter_by(user_id=user.id)

        all_bets = Bet.query.filter_by(user_id=user.id).all()

        if status_filter != 'all':
            bets_query = bets_query.filter_by(status=status_filter)

        filtered_bets = bets_query.order_by(Bet.created_at.desc()).all()

        return render_template('profile.html',
                               user=user,
                               bets=filtered_bets,
                               all_bets=all_bets,
                               status_filter=status_filter)
    except Exception as e:
        logger.error(f"Profile error: {str(e)}", exc_info=True)
        flash('Ошибка загрузки профиля', 'danger')
        return redirect(url_for('main.index'))


@main_bp.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('is_admin'):
        flash('Доступ запрещен!', 'danger')
        return redirect(url_for('main.index'))

    form = RaceForm()
    try:
        if form.validate_on_submit():
            race = Race(
                name=form.name.data,
                date=form.date.data,
                participant1=form.participant1.data,
                participant2=form.participant2.data,
                coefficient1=Decimal(str(form.coefficient1.data)),
                coefficient2=Decimal(str(form.coefficient2.data))
            )

            db.session.add(race)
            db.session.commit()
            flash('Заезд успешно создан!', 'success')
            return redirect(url_for('main.admin'))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Race creation error: {str(e)}", exc_info=True)
        flash(f'Ошибка при создании заезда: {str(e)}', 'danger')

    races = Race.query.order_by(Race.date.desc()).all()
    return render_template('admin.html', form=form, races=races)


@main_bp.route('/admin/users')
def admin_users():
    if not session.get('is_admin'):
        flash('Доступ запрещен!', 'danger')
        return redirect(url_for('main.index'))

    try:
        search = request.args.get('search', '')
        query = User.query

        if search:
            query = query.filter(User.username.ilike(f'%{search}%'))

        users = query.order_by(User.id.asc()).all()
        return render_template('admin_users.html', users=users)
    except Exception as e:
        logger.error(f"Admin users error: {str(e)}", exc_info=True)
        flash('Ошибка загрузки пользователей', 'danger')
        return redirect(url_for('main.admin'))


@main_bp.route('/admin/users/<int:user_id>/deposit', methods=['GET', 'POST'])
def admin_deposit(user_id):
    if not session.get('is_admin'):
        flash('Доступ запрещен!', 'danger')
        return redirect(url_for('main.index'))

    try:
        user = User.query.get_or_404(user_id)
        form = DepositForm()

        if form.validate_on_submit():
            amount = Decimal(str(form.amount.data))
            user.balance += amount
            db.session.commit()
            flash(f'Баланс пользователя {user.username} пополнен на {amount} ₽', 'success')
            return redirect(url_for('main.admin_users'))

        return render_template('admin_deposit.html', user=user, form=form)
    except (ValueError, InvalidOperation):
        db.session.rollback()
        flash('Некорректная сумма пополнения', 'danger')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Deposit error: {str(e)}", exc_info=True)
        flash('Ошибка пополнения баланса', 'danger')

    return redirect(url_for('main.admin_users'))


@main_bp.route('/bet/<int:race_id>', methods=['GET', 'POST'])
def bet(race_id):
    if not session.get('user_id'):
        flash('Войдите в систему для совершения ставок.', 'warning')
        return redirect(url_for('main.login'))

    try:
        user = User.query.get(session['user_id'])
        race = Race.query.get_or_404(race_id)

        if race.is_finished:
            flash('Этот заезд уже завершен!', 'warning')
            return redirect(url_for('main.index'))

        form = BetForm()
        form.selected_participant.choices = [
            (1, f"{race.participant1} (коэф. {race.coefficient1})"),
            (2, f"{race.participant2} (коэф. {race.coefficient2})")
        ]

        if form.validate_on_submit():
            try:
                amount = Decimal(str(form.amount.data))
                if amount <= 0:
                    flash('Сумма ставки должна быть положительной!', 'danger')
                elif amount > user.balance:
                    flash('Недостаточно средств на балансе!', 'danger')
                else:
                    bet = Bet(
                        user_id=user.id,
                        race_id=race.id,
                        amount=amount,
                        selected_participant=int(form.selected_participant.data)
                    )

                    user.balance -= amount
                    db.session.add(bet)
                    db.session.commit()
                    flash('Ставка успешно принята!', 'success')
                    return redirect(url_for('main.index'))
            except (ValueError, InvalidOperation):
                db.session.rollback()
                flash('Некорректная сумма ставки', 'danger')
            except Exception as e:
                db.session.rollback()
                logger.error(f"Bet placement error: {str(e)}", exc_info=True)
                flash('Ошибка при размещении ставки', 'danger')

        return render_template('bet.html', race=race, form=form, balance=user.balance)
    except Exception as e:
        logger.error(f"Bet page error: {str(e)}", exc_info=True)
        flash('Ошибка загрузки страницы ставки', 'danger')
        return redirect(url_for('main.index'))


@main_bp.route('/finish_race/<int:race_id>', methods=['POST'])
def finish_race(race_id):
    if not session.get('is_admin'):
        flash('Доступ запрещен!', 'danger')
        return redirect(url_for('main.index'))

    try:
        race = Race.query.get_or_404(race_id)
        if race.is_finished:
            flash('Этот заезд уже завершен!', 'warning')
            return redirect(url_for('main.admin'))

        winner_id = int(request.form.get('winner'))
        race.is_finished = True
        race.winner = winner_id

        for bet in race.bets:
            if bet.status == 'active':
                if bet.selected_participant == winner_id:
                    bet.status = 'won'
                    win_amount = bet.amount * race.calculate_winnings(winner_id)
                    bet.user.balance += win_amount
                else:
                    bet.status = 'lost'

        db.session.commit()
        flash(f'Заезд "{race.name}" успешно завершен!', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Finish race error: {str(e)}", exc_info=True)
        flash(f'Ошибка завершения заезда: {str(e)}', 'danger')

    return redirect(url_for('main.admin'))


@main_bp.route('/delete_race/<int:race_id>')
def delete_race(race_id):
    if not session.get('is_admin'):
        flash('Доступ запрещен!', 'danger')
        return redirect(url_for('main.index'))

    try:
        race = Race.query.get(race_id)
        if race:
            db.session.delete(race)
            db.session.commit()
            flash('Заезд успешно удален!', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete race error: {str(e)}", exc_info=True)
        flash('Ошибка удаления заезда', 'danger')

    return redirect(url_for('main.admin'))


@main_bp.errorhandler(404)
def page_not_found(e):
    logger.warning(f"404 Not Found: {request.url}")
    return render_template('404.html'), 404


@main_bp.errorhandler(500)
def internal_server_error(e):
    logger.error(f"500 Internal Server Error: {str(e)}\n{request.url}", exc_info=True)
    return render_template('500.html'), 500